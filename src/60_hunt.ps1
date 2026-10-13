# placebo - Invoke-PlaceboHunt: sweep local residue that outlives the fake captcha page.

function Find-PlaceboHistoryFiles {
    $out = [System.Collections.Generic.HashSet[string]]::new()
    $roots = @()
    if (Test-PlaceboWindows) {
        foreach ($envName in @('USERPROFILE', 'PUBLIC')) {
            $v = [Environment]::GetEnvironmentVariable($envName)
            if ($v) { $roots += $v }
        }
    } else {
        if ($env:HOME) { $roots += $env:HOME }
    }
    foreach ($root in $roots) {
        $candidates = @(
            (Join-Path $root 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'),
            (Join-Path $root 'Documents\WindowsPowerShell\profile.ps1'),
            (Join-Path $root '.bash_history'),
            (Join-Path $root '.zsh_history'),
            (Join-Path $root '.local\share\powershell\PSReadLine\ConsoleHost_history.txt'),
            (Join-Path $root '.local/share/powershell/PSReadLine/ConsoleHost_history.txt')
        )
        foreach ($c in $candidates) { if (Test-Path -LiteralPath $c -PathType Leaf) { [void]$out.Add($c) } }
        # any additional *history*.txt under PSReadLine dir
        $psr = Join-Path $root 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine'
        if (Test-Path -LiteralPath $psr -PathType Container) {
            foreach ($f in (Get-ChildItem -LiteralPath $psr -Filter '*history*.txt' -File -ErrorAction SilentlyContinue)) { [void]$out.Add($f.FullName) }
        }
    }
    return @($out)
}

function Find-PlaceboStartupItems {
    $out = @()
    if (Test-PlaceboWindows) {
        foreach ($kind in @('Startup', 'CommonStartup')) {
            try {
                $dir = [Environment]::GetFolderPath($kind)
                if ($dir -and (Test-Path -LiteralPath $dir)) {
                    foreach ($f in (Get-ChildItem -LiteralPath $dir -File -ErrorAction SilentlyContinue)) { $out += $f.FullName }
                }
            } catch { continue }
        }
    } else {
        $auto = Join-Path $env:HOME '.config/autostart'
        if (Test-Path -LiteralPath $auto -PathType Container) {
            foreach ($f in (Get-ChildItem -LiteralPath $auto -File -ErrorAction SilentlyContinue)) { $out += $f.FullName }
        }
    }
    return @($out | Select-Object -Unique)
}

function Get-PlaceboRegistryEvidence {
    # windows-only. run/runonce/runmru values as pseudo command strings.
    if (-not (Test-PlaceboWindows)) { return @{ Available = $false; Items = @() } }
    $items = @()
    $keys = @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU'
    )
    foreach ($k in $keys) {
        try {
            if (-not (Test-Path -LiteralPath $k)) { continue }
            $props = Get-ItemProperty -LiteralPath $k -ErrorAction Stop
            foreach ($p in $props.PSObject.Properties) {
                if ($p.Name -match '^PS') { continue }
                $val = ''
                if ($p.Value -is [byte[]]) { $val = [System.Text.Encoding]::Unicode.GetString($p.Value) }
                else { $val = [string]$p.Value }
                $val = $val -replace [string][char]1, ' '
                if ($val.Trim().Length -gt 0) { $items += @{ Key = $k; Name = $p.Name; Value = $val } }
            }
        } catch { continue }
    }
    return @{ Available = $true; Items = $items }
}

function Get-PlaceboTaskEvidence {
    if (Test-PlaceboWindows) {
        $items = @()
        try {
            $tasks = Get-ScheduledTask -ErrorAction Stop
            foreach ($t in $tasks) {
                foreach ($a in $t.Actions) {
                    if ($null -eq $a) { continue }
                    $exe = [string]$a.Execute
                    $args2 = [string]$a.Arguments
                    if (("$exe $args2").Trim().Length -gt 0) {
                        $items += @{ Source = "scheduled-task:$($t.TaskPath)$($t.TaskName)"; Text = "$exe $args2".Trim() }
                    }
                }
            }
        } catch { }
        return @{ Available = $true; Items = $items }
    }
    # unix: crontab + /etc/cron.d (read-only)
    $items = @()
    try {
        $cron = & crontab -l 2>$null
        if ($LASTEXITCODE -eq 0 -and $cron) {
            foreach ($l in @($cron)) { if ([string]$l -and -not [string]$l.StartsWith('#')) { $items += @{ Source = 'crontab'; Text = [string]$l } } }
        }
    } catch { }
    if (Test-Path '/etc/cron.d' -PathType Container) {
        foreach ($f in (Get-ChildItem '/etc/cron.d' -File -ErrorAction SilentlyContinue)) {
            $lines = Read-PlaceboTextFile -Path $f.FullName
            foreach ($l in (Get-PlaceboLines -Lines $lines)) { $items += @{ Source = "cron.d/$($f.Name)"; Text = $l } }
        }
    }
    return @{ Available = $true; Items = $items }
}

function Invoke-PlaceboHunt {
    <#
    .SYNOPSIS
        hunt clickfix residue on this machine: histories, autostart keys, runmru,
        startup payloads, scheduled tasks. every hit re-scored by the triage engine.
    .EXAMPLE
        Invoke-PlaceboHunt
        Invoke-PlaceboHunt -Paths C:\incident\dump -Json
    #>
    [CmdletBinding()]
    param(
        [string[]]$Paths,
        [int]$MaxDepth = 3,
        [switch]$NoRegistry,
        [switch]$NoTasks,
        [switch]$Reveal,
        [switch]$Json
    )
    $targets = @()
    $findings = [System.Collections.Generic.List[object]]::new()
    $scanned = [System.Collections.Generic.HashSet[string]]::new()

    $mini = {
        param($text, $source, $lineNo, $maxDepth, $reveal)
        if ([string]::IsNullOrWhiteSpace($text)) { return $null }
        $norm = Get-PlaceboNormalized -Text $text
        if ($norm.Length -lt 3) { return $null }
        $trace = Invoke-PlaceboDecode -Text $norm -MaxDepth $maxDepth
        $lf = @(); $lf += @{ Layer = 0; Findings = (Invoke-PlaceboRuleScan -Text $norm) }
        $i = 1; foreach ($t in $trace) { $lf += @{ Layer = $i; Findings = (Invoke-PlaceboRuleScan -Text $t.Text) }; $i++ }
        $scored = Invoke-PlaceboScore -LayerFindings $lf
        if ($scored.Findings.Count -eq 0) { return $null }
        $allText = $norm; foreach ($t in $trace) { $allText += "`n" + $t.Text }
        return @{
            Source  = $source
            Line    = $lineNo
            Excerpt = (Hide-PlaceboText -Text (Get-PlaceboTruncated -Text $text -Max 160) -Reveal:$reveal)
            Score   = $scored.Score
            Verdict = $scored.Verdict
            Top     = @($scored.Findings | Select-Object -First 4 | ForEach-Object { "$($_.Id) $($_.Name)" })
            Iocs    = (Get-PlaceboIocs -Text $allText)
        }
    }

    # 1. histories
    $histFiles = Find-PlaceboHistoryFiles
    foreach ($h in $histFiles) {
        $targets += "history:$h"
        [void]$scanned.Add($h)
        $lines = Read-PlaceboTextFile -Path $h
        $ln = 0
        foreach ($l in (Get-PlaceboLines -Lines $lines)) {
            $ln++
            $hit = & $mini $l "history:$h" $ln $MaxDepth $Reveal
            if ($hit) { $findings.Add($hit) }
        }
    }

    # 2. extra paths (dirs or files; text + embedded strings for binaries like .lnk)
    foreach ($p in @($Paths)) {
        if ([string]::IsNullOrWhiteSpace($p)) { continue }
        if (-not (Test-Path -LiteralPath $p)) { continue }
        $files = @()
        if (Test-Path -LiteralPath $p -PathType Container) {
            $files = @(Get-ChildItem -LiteralPath $p -File -Recurse -ErrorAction SilentlyContinue | Select-Object -First 200 | ForEach-Object { $_.FullName })
        } else { $files = @((Resolve-Path -LiteralPath $p).Path) }
        foreach ($f in $files) {
            [void]$scanned.Add($f)
            $targets += "path:$f"
            $isTextLike = ($f -match '\.(txt|ps1|psm1|bat|cmd|vbs|js|log|history|desktop|sh|zsh)$')
            if ($isTextLike) {
                $lines = Read-PlaceboTextFile -Path $f
                $ln = 0
                foreach ($l in (Get-PlaceboLines -Lines $lines)) {
                    $ln++
                    $hit = & $mini $l "file:$f" $ln $MaxDepth $Reveal
                    if ($hit) { $findings.Add($hit) }
                }
            } else {
                foreach ($s in (Get-PlaceboEmbeddedStrings -Path $f)) {
                    $hit = & $mini $s "embedded:$f" 0 $MaxDepth $Reveal
                    if ($hit) { $findings.Add($hit) }
                }
            }
        }
    }

    # 3. registry
    $reg = @{ Available = $false; Items = @() }
    if (-not $NoRegistry) {
        $reg = Get-PlaceboRegistryEvidence
        if ($reg.Available) {
            foreach ($item in $reg.Items) {
                $targets += "registry:$($item.Key)\$($item.Name)"
                $hit = & $mini $item.Value "registry:$($item.Key)[$($item.Name)]" 0 $MaxDepth $Reveal
                if ($hit) { $findings.Add($hit) }
            }
        }
    }

    # 4. startup items
    foreach ($s in (Find-PlaceboStartupItems)) {
        [void]$scanned.Add($s)
        $targets += "startup:$s"
        $isTextLike = ($s -match '\.(txt|ps1|bat|cmd|vbs|js|desktop|sh)$')
        if ($isTextLike) {
            $lines = Read-PlaceboTextFile -Path $s
            $ln = 0
            foreach ($l in (Get-PlaceboLines -Lines $lines)) {
                $ln++
                $hit = & $mini $l "startup:$s" $ln $MaxDepth $Reveal
                if ($hit) { $findings.Add($hit) }
            }
        } else {
            foreach ($s2 in (Get-PlaceboEmbeddedStrings -Path $s)) {
                $hit = & $mini $s2 "embedded:$s" 0 $MaxDepth $Reveal
                if ($hit) { $findings.Add($hit) }
            }
        }
    }

    # 5. scheduled tasks
    $tasks = @{ Available = $false; Items = @() }
    if (-not $NoTasks) {
        $tasks = Get-PlaceboTaskEvidence
        foreach ($item in $tasks.Items) {
            $targets += $item.Source
            $hit = & $mini $item.Text $item.Source 0 $MaxDepth $Reveal
            if ($hit) { $findings.Add($hit) }
        }
    }

    # roll up: worst verdict + dedupe by source+line
    $maxScore = 0; $worst = 'clean'
    $seenKeys = [System.Collections.Generic.HashSet[string]]::new()
    $final = @()
    foreach ($f in $findings) {
        $key = "$($f.Source)|$($f.Line)|$($f.Excerpt)"
        if (-not $seenKeys.Add($key)) { continue }
        $final += $f
        if ($f.Score -gt $maxScore) { $maxScore = $f.Score }
        if ((Get-PlaceboVerdictOrder -Verdict $f.Verdict) -gt (Get-PlaceboVerdictOrder -Verdict $worst)) { $worst = $f.Verdict }
    }
    $final = @($final | Sort-Object -Property @{ Expression = 'Score'; Descending = $true })

    return @{
        Machine      = $env:COMPUTERNAME
        Platform     = $PSVersionTable.Platform
        IsWindows    = (Test-PlaceboWindows)
        RegistryAvailable = $reg.Available
        TasksAvailable    = $tasks.Available
        TargetsScanned    = $targets.Count
        FilesScanned      = $scanned.Count
        Findings     = $final
        MaxScore     = $maxScore
        Verdict      = $worst
    }
}
