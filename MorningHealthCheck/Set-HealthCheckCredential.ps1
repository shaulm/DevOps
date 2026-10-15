#Requires -Version 7.4
<#
.SYNOPSIS
    Stores, lists and removes the encrypted credentials used by the morning health check.

.DESCRIPTION
    Each credential is saved as Credentials\<Name>.cred.xml. The password is encrypted with Windows DPAPI
    for the CURRENT Windows account on the CURRENT computer - nobody else (and no other machine) can
    decrypt it. Run this script as the account that the scheduled task uses, on the monitoring server:

        runas /user:CONTOSO\svc-healthcheck "pwsh -NoProfile -File C:\Scripts\MorningHealthCheck\Set-HealthCheckCredential.ps1 -Missing"

    The credentials folder is restricted to that account, SYSTEM and local Administrators.

.EXAMPLE
    .\Set-HealthCheckCredential.ps1 -Missing
    Prompts for every credential the config refers to that is not stored yet.

.EXAMPLE
    .\Set-HealthCheckCredential.ps1 -Name netapp -UserName svc_healthcheck

.EXAMPLE
    .\Set-HealthCheckCredential.ps1 -Name checkpoint -UserName api-key
    Check Point API key: type the key in the password field.

.EXAMPLE
    .\Set-HealthCheckCredential.ps1 -List
#>
[CmdletBinding(DefaultParameterSetName = 'Set')]
param(
    [Parameter(ParameterSetName = 'Set', Mandatory, Position = 0)][string]$Name,
    [Parameter(ParameterSetName = 'Set')][string]$UserName,
    [Parameter(ParameterSetName = 'Set')][string]$Description,
    [Parameter(ParameterSetName = 'Missing', Mandatory)][switch]$Missing,
    [Parameter(ParameterSetName = 'List', Mandatory)][switch]$List,
    [Parameter(ParameterSetName = 'Remove', Mandatory)][string]$Remove,
    [string]$ConfigPath = (Join-Path $PSScriptRoot 'config/HealthCheck.config.psd1')
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'HealthCheck/HealthCheck.psm1') -Force

$config = $null
if (Test-Path -LiteralPath $ConfigPath) { $config = Import-HCConfig -Path $ConfigPath }
$settings = New-HCSettings -Config $(if ($config) { $config } else { @{ General = @{} } }) -ScriptRoot $PSScriptRoot
$folder = $settings.CredentialFolder
$me = if ($IsWindows) { [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } else { [Environment]::UserName }

function Save-One {
    param([string]$CredentialName, [string]$User, [string]$Purpose)
    $message = "Credential '$CredentialName'" + $(if ($Purpose) { " - $Purpose" }) + '. For an API key or RADIUS secret, put it in the password field.'
    $credential = Get-Credential -UserName $User -Message $message
    if (-not $credential) { Write-Warning "Skipped '$CredentialName'."; return }
    $path = Save-HCCredential -Folder $folder -Name $CredentialName -Credential $credential -Description $Purpose
    $null = Import-HCCredential -Folder $folder -Name $CredentialName   # read it back once
    Write-Host "Saved '$CredentialName' ($($credential.UserName)) to $path" -ForegroundColor Green
}

switch ($PSCmdlet.ParameterSetName) {
    'List' {
        $items = @(Get-HCCredentialInventory -Folder $folder)
        if (-not $items) { Write-Host "No credentials stored in $folder"; break }
        $items | Format-Table Name, UserName, CreatedBy, CreatedOn, Readable -AutoSize
        if ($items | Where-Object { -not $_.Readable }) {
            Write-Warning "Credentials marked Readable=False were created by another account or computer; $me cannot decrypt them."
        }
    }
    'Remove' {
        $path = Get-HCCredentialPath -Folder $folder -Name $Remove
        if (-not (Test-Path -LiteralPath $path)) { throw "Credential '$Remove' not found in $folder" }
        Remove-Item -LiteralPath $path -Force
        Write-Host "Removed '$Remove'." -ForegroundColor Yellow
    }
    'Missing' {
        if (-not $config) { throw "Config file not found: $ConfigPath" }
        $targets = @(Resolve-HCTargets -Config $config)
        $names = Get-HCReferencedCredentialNames -Targets $targets -Email $config.Email
        if (-not $names) { Write-Host 'The config does not reference any credentials.'; break }
        $todo = @($names | Where-Object { -not (Test-Path -LiteralPath (Get-HCCredentialPath -Folder $folder -Name $_)) })
        if (-not $todo) { Write-Host "All $(@($names).Count) referenced credentials are already stored. Use -List to check they are readable." -ForegroundColor Green; break }
        Write-Host "Storing $($todo.Count) credential(s) for $me (only this account on $([Environment]::MachineName) can decrypt them)." -ForegroundColor Cyan
        foreach ($n in $todo) {
            $users = @($targets | Where-Object { (Get-HCReferencedCredentialNames -Targets @($_)) -contains $n } | ForEach-Object { "$($_.Type) $($_.Name)" })
            if ($config.Email.Credential -eq $n) { $users += 'SMTP (Exchange)' }
            Save-One -CredentialName $n -Purpose ('used by ' + (Format-HCList -Items $users -Max 4))
        }
    }
    default {
        Save-One -CredentialName $Name -User $UserName -Purpose $Description
        Write-Host "Encrypted for $me on $([Environment]::MachineName) - the scheduled task must run as this account." -ForegroundColor Cyan
    }
}
