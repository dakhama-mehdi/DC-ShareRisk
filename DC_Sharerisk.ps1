<#
.SYNOPSIS
    Audits non-standard shares on all Domain Controllers and detects
    dangerous or non-compliant ACLs.

.DESCRIPTION
    This script enumerates all shares exposed by every Domain Controller
    (except default ones: SYSVOL, NETLOGON, ADMIN$, C$, IPC$).  
    Each discovered share is inspected, and its ACL is analyzed to detect:
        - unauthorized accounts (not included in the trusted groups list)
        - unsafe permissions (not included in the allowed rights whitelist)

    The goal is to quickly identify misconfigurations, unapproved shares,
    or excessive permissions that may introduce security risks on Domain
    Controllers.

    No RSAT is required. The list of DCs is retrieved via .NET calls
    using [System.DirectoryServices.ActiveDirectory.Domain].

.NOTES
    Author  : Dakhama Mehdi
    Purpose : DC share auditing + ACL security validation
    License : Free for internal / community use
#>
$Results = @()

function get-ShareACL {
    param (
        [string]$FilePath,
        [string[]]$TrustGroups,      # List of trusted identities (ignored during ACL checks)
        [string[]]$Permissiontrust   # Whitelisted permissions considered safe
    )

    $results = @()
    try {
        # Retrieve the ACL from the given file path
        $acl = Get-Acl -Path $FilePath
    } catch {
        # ACL cannot be read (network error / permission denied / inaccessible share)
        return
    }

    foreach ($entry in $acl.Access) {
        # Only analyze non-inherited ACEs and accounts not in the trusted list
        if ($entry.IsInherited -eq $false -and
            $TrustGroups -notcontains $entry.IdentityReference.Value) {

            # Split multiple rights into a list
            $rightsList = "$($entry.FileSystemRights)" -split ',\s*'

            # Identify rights that are *not* in the allowed whitelist
            $hasUnsafeRight = $rightsList | Where-Object { $Permissiontrust -notcontains $_ }

            # If at least one unsafe right is detected, report the ACE
            if ($hasUnsafeRight) {
                $results += [pscustomobject]@{
                    FilePath   = $FilePath
                    Pattern    = 'WrongACL'
                    Account    = $entry.IdentityReference.Value
                    Permission = $hasUnsafeRight
                }
            }
        }
    }

    # --------------------------
    # Aggregation by File + Account
    # --------------------------

    # Group by FilePath + Account to avoid duplicate entries
    $grouped = $results | Group-Object FilePath, Account

    # Build consolidated "Reason" entries per account
    $reasonsPerFile = @()
    foreach ($g in $grouped) {
        $filePath = $g.Group[0].FilePath
        $pattern  = $g.Group[0].Pattern
        $account  = $g.Group[0].Account

        # Unique list of unsafe permissions
        $perms = $g.Group | Select-Object -ExpandProperty Permission | Sort-Object -Unique

        # Human-readable reason line
        $reason = "$account has '" + ($perms -join ", ") + "'"

        $reasonsPerFile += [pscustomobject]@{
            FilePath = $filePath
            Pattern  = $pattern
            Reason   = $reason
        }
    }

    return $reasonsPerFile
}



Function Get-RemoteDiskShares {
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName
    )

    # Query remote shares using NET VIEW (compatible with non-RSAT environments)
    $output = net view "\\$ComputerName" /all 2>&1
    $typeKeyword = $null
    $buffer = @()
    $results = @()

    foreach ($line in $output) {
        $line = $line.Trim()

        # Ignore separators and empty lines
        if ($line.Length -eq 0 -or $line -match '^[-=]{3,}$') {
            continue
        }

        # Split columns based on multiple spaces
        $cols = $line -split '\s{2,}'
        if ($cols.Count -lt 2) { continue }

        # Store share entry
        $entry = [PSCustomObject]@{
            Name     = $cols[0].Trim()
            Type     = $cols[1].Trim()
            Computer = $ComputerName
            Comment  = if ($cols.Count -ge 3) { $cols[-1].Trim() } else { '' }
        }

        $buffer += $entry

        # Detect the type of valid shares based on SYSVOL or NETLOGON type
        if (-not $typeKeyword -and ($entry.Name -like '*SYSVOL*' -or $entry.Name -like '*NETLOGON*')) {
            $typeKeyword = $entry.Type
        }
    }

    # Keep only shares matching the same "Type" as SYSVOL/NETLOGON
    # Exclude default administrative shares
    if ($typeKeyword) {
        $results = $buffer | Where-Object {
            $_.Type -eq $typeKeyword -and
            $_.Name -notmatch '^(ADMIN\$|[A-Z]\$|IPC\$|SYSVOL|NETLOGON)$'
        }
    }

    return $results
}



Write-Host "Check Share on Domain controllers" -ForegroundColor Green

# Whitelisted permissions considered safe on shares
$SafeRights = @(
    'Read','ReadAndExecute',
    'Synchronize','ReadAttributes',
    'ReadExtendedAttributes','ReadPermissions',
    'AppendData','ReadData','ExecuteFile',
    '-1610612736','Synchronize','268435456'  # Raw AccessMask values accepted as safe
)

# Get list of domain controllers using .NET (RSAT not required)
$listOfDCs = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers

foreach ($DC in $listOfDCs) {
   
    Write-Host "Check Shares on $DC" -ForegroundColor Cyan

    try {
        # Retrieve remote share list
        $Shares = Get-RemoteDiskShares -ComputerName $DC

        foreach ($share in $Shares) {

            # UNC path to the remote share
            $SharePath = "\\$DC\$($share.Name)"

            if (Test-Path $SharePath) {

                # ACL analysis for this share
                $Findings = get-ShareACL -FilePath $SharePath -TrustGroups $Trustgroups -PermissionTrust $SafeRights

                if ($Findings) {
                    # Store every issue detected
                    foreach ($finding in $Findings) {
                        $Results += [PSCustomObject]@{
                            DC        = $DC
                            Share     = $share.Name
                            Type      = $share.Type
                            ACL       = $finding.Pattern
                            Reason    = $finding.Reason
                            Comment   = $share.Comment
                        }
                    }
                } else {
                    # Share is considered clean
                    $Results += [PSCustomObject]@{
                        DC        = $DC
                        Share     = $share.Name
                        Type      = $share.Type
                        ACL       = 'Clean'
                        Reason    = '-'
                        Comment   = $share.Comment
                    }
                }
            } 
            else {
                # Test-Path failed → share inaccessible
                $Results += [PSCustomObject]@{
                    DC        = $DC
                    Share     = $share.Name
                    Type      = $share.Type
                    ACL       = 'Inaccessible'
                    Reason    = 'Test-Path failed'
                    Comment   = $share.Comment
                }
            }
        }

    } catch {
        Write-Warning "Error on $DC : $_"
    }
}

# Final output
$Results | Format-Table -AutoSize
