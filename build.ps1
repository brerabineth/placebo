# build placebo into a single self-contained file: dist/placebo.ps1
# order: src numeric (incl. cli dispatcher). zero dependencies beyond powershell itself.

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$outDir = Join-Path $root 'dist'
$outFile = Join-Path $outDir 'placebo.ps1'

New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$header = @'
# placebo 0.1.0 - the fake fix, dissected.
# single-file build. static triage for paste-and-run commands: the analyzed
# command is never executed, decoded bytes are never run, nothing leaves the machine.
# usage: pwsh ./placebo.ps1 --help        (or powershell.exe on windows powershell 5.1)

'@

$parts = @($header)
$files = Get-ChildItem -LiteralPath (Join-Path $root 'src') -Filter '*.ps1' | Sort-Object Name
foreach ($f in $files) {
    if ($f.Name -eq '99_cli.ps1') { continue }
    $parts += "# ---- $($f.Name) ----"
    $parts += [System.IO.File]::ReadAllText($f.FullName)
}

# cli dispatcher last: its own guard decides script vs library context (no double exit)
$parts += '# ---- 99_cli.ps1 (entrypoint) ----'
$parts += [System.IO.File]::ReadAllText((Join-Path $root 'src\99_cli.ps1'))

[System.IO.File]::WriteAllText($outFile, (($parts -join "`n`n") + "`n"))
Write-Output "built: $outFile ($((Get-Item $outFile).Length) bytes)"
