# Runs the checks for one target / all targets.

function Invoke-HCTarget {
    # Runs the check function for one target and always returns a completed context, even on errors.
    param([Parameter(Mandatory)][hashtable]$Target, [Parameter(Mandatory)][hashtable]$Settings)
    $ctx = New-HCContext -Target $Target
    $credential = $null
    if ($Target.Credential) {
        $entry = $Settings.Credentials[$Target.Credential]
        if ($entry -is [pscredential]) { $credential = $entry }
        else {
            $why = if ($entry) { [string]$entry } else { "credential '$($Target.Credential)' is not loaded" }
            Add-HCCheck $ctx 'Credential' 'Unknown' $why
        }
    }
    $function = "Invoke-HCCheck$($Target.Type)"
    try {
        & $function -Context $ctx -Target $Target -Credential $credential -Settings $Settings
    } catch {
        Add-HCCheck $ctx 'Check execution' 'Unknown' ('Unexpected error: ' + (Get-HCErrorText $_))
        Add-HCLog $ctx ($_ | Out-String)
    }
    foreach ($license in @($Target.Licenses)) {
        if ($license) { Add-HCManualLicense -Context $ctx -License $license -Settings $Settings }
    }
    Complete-HCContext -Context $ctx
}

function Invoke-HCAllTargets {
    <#
      Checks all targets, in parallel by default (ForEach-Object -Parallel, PowerShell 7).
      Targets that do not finish within MaxRunMinutes are reported as Unknown.
    #>
    param(
        [Parameter(Mandatory)][object[]]$Targets,
        [Parameter(Mandatory)][hashtable]$Settings,
        [Parameter(Mandatory)][string]$ModulePath,
        [switch]$Sequential
    )
    $results = [System.Collections.Generic.List[object]]::new()
    if ($Sequential -or $Targets.Count -le 1) {
        foreach ($t in $Targets) {
            Write-Verbose "Checking $($t.Type) $($t.Name)"
            $results.Add((Invoke-HCTarget -Target $t -Settings $Settings))
        }
    } else {
        $parallel = $Targets | ForEach-Object -ThrottleLimit $Settings.ThrottleLimit -TimeoutSeconds ($Settings.MaxRunMinutes * 60) -Parallel {
            Import-Module $using:ModulePath -WarningAction SilentlyContinue
            Invoke-HCTarget -Target $_ -Settings $using:Settings
        }
        foreach ($r in @($parallel)) { if ($r) { $results.Add($r) } }
    }
    foreach ($t in $Targets) {
        $done = $results | Where-Object { $_.Type -eq $t.Type -and $_.Name -eq $t.Name }
        if (-not $done) {
            $ctx = New-HCContext -Target $t
            Add-HCCheck $ctx 'Check execution' 'Unknown' "Did not finish within $($Settings.MaxRunMinutes) minutes"
            $results.Add((Complete-HCContext -Context $ctx))
        }
    }
    return $results.ToArray()
}
