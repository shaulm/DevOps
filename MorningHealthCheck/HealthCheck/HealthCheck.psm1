# HealthCheck module - loads the shared helpers and one check file per system type.
# Every function is prefixed with "HC" to avoid clashing with other modules.

$moduleRoot = $PSScriptRoot
foreach ($folder in 'Private', 'Checks') {
    foreach ($file in Get-ChildItem -Path (Join-Path $moduleRoot $folder) -Filter '*.ps1' | Sort-Object Name) {
        . $file.FullName
    }
}

Export-ModuleMember -Function *-HC*
