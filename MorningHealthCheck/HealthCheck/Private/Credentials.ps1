# Encrypted credential store.
#
# Each credential is saved as <Name>.cred.xml with Export-Clixml. On Windows the password is encrypted
# with DPAPI: only the same Windows account, on the same computer, can decrypt it. That is why the
# credentials must be created while logged on as (or "runas") the account that runs the scheduled task.

function Get-HCCredentialPath {
    param([Parameter(Mandatory)][string]$Folder, [Parameter(Mandatory)][string]$Name)
    Join-Path $Folder ('{0}.cred.xml' -f $Name)
}

function Assert-HCCredentialName {
    param([string]$Name)
    if ($Name -notmatch '^[A-Za-z0-9._-]{1,64}$') {
        throw "Invalid credential name '$Name'. Use letters, digits, dot, underscore or hyphen (max 64)."
    }
}

function Protect-HCFolder {
    # Restricts a folder to the current user, SYSTEM and local Administrators (no inheritance).
    param([Parameter(Mandatory)][string]$Path)
    if (-not $IsWindows) { return }
    $acl = [System.Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $propagation = [System.Security.AccessControl.PropagationFlags]::None
    $sids = @(
        [System.Security.Principal.WindowsIdentity]::GetCurrent().User,
        [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18'),       # SYSTEM
        [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')    # Administrators
    )
    foreach ($sid in $sids) {
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', $inherit, $propagation, 'Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Save-HCCredential {
    param(
        [Parameter(Mandatory)][string]$Folder,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][pscredential]$Credential,
        [string]$Description
    )
    if (-not $IsWindows) {
        throw 'The credential store uses Windows DPAPI. On this platform Export-Clixml would NOT encrypt the password, so saving is refused.'
    }
    Assert-HCCredentialName $Name
    if (-not (Test-Path -LiteralPath $Folder)) {
        New-Item -ItemType Directory -Path $Folder -Force | Out-Null
        Protect-HCFolder -Path $Folder
    }
    $record = [pscustomobject]@{
        Name        = $Name
        Credential  = $Credential
        Description = $Description
        CreatedBy   = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        CreatedOn   = (Get-Date).ToString('yyyy-MM-dd HH:mm')
        Computer    = [Environment]::MachineName
    }
    $path = Get-HCCredentialPath -Folder $Folder -Name $Name
    $record | Export-Clixml -LiteralPath $path -Force
    return $path
}

function Import-HCCredential {
    param([Parameter(Mandatory)][string]$Folder, [Parameter(Mandatory)][string]$Name)
    Assert-HCCredentialName $Name
    $path = Get-HCCredentialPath -Folder $Folder -Name $Name
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Credential '$Name' has not been stored. Run: .\Set-HealthCheckCredential.ps1 -Name $Name"
    }
    $who = if ($IsWindows) { [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } else { $env:USER }
    try {
        $record = Import-Clixml -LiteralPath $path -ErrorAction Stop
        $cred = if ($record -is [pscredential]) { $record } else { $record.Credential }
        if ($cred -isnot [pscredential]) { throw 'file does not contain a credential' }
        $null = $cred.GetNetworkCredential().Password   # force decryption now
        return $cred
    } catch {
        $creator = if ($record -and $record.CreatedBy) { " It was created by $($record.CreatedBy) on $($record.Computer)." } else { '' }
        throw ("Credential '$Name' cannot be decrypted by $who on $([Environment]::MachineName).$creator " +
            'DPAPI-protected credentials only open for the account and computer that saved them - re-create it as the scheduled-task account. ' +
            "($($_.Exception.Message))")
    }
}

function Get-HCCredentialInventory {
    # Lists stored credentials without revealing secrets.
    param([Parameter(Mandatory)][string]$Folder)
    if (-not (Test-Path -LiteralPath $Folder)) { return }
    foreach ($file in Get-ChildItem -LiteralPath $Folder -Filter '*.cred.xml' | Sort-Object Name) {
        $name = $file.Name -replace '\.cred\.xml$', ''
        $info = [ordered]@{ Name = $name; UserName = ''; CreatedBy = ''; CreatedOn = ''; Readable = $false; Problem = '' }
        try {
            $record = Import-Clixml -LiteralPath $file.FullName -ErrorAction Stop
            $cred = if ($record -is [pscredential]) { $record } else { $record.Credential }
            $info.UserName = $cred.UserName
            $info.CreatedBy = $record.CreatedBy
            $info.CreatedOn = $record.CreatedOn
            $null = $cred.GetNetworkCredential().Password
            $info.Readable = $true
        } catch {
            $info.Problem = $_.Exception.Message
        }
        [pscustomobject]$info
    }
}
