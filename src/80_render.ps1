# placebo - renderers: ansi terminal, json, markdown. ascii-only output art.

function Get-PlaceboVerdictColor {
    param([Parameter(Mandatory)][string]$Verdict)
    switch ($Verdict) {
        'critical'   { return '31' }   # red
        'malicious'  { return '31' }
        'suspicious' { return '33' }   # yellow
        default      { return '32' }   # green
    }
}

function Format-PlaceboBanner {
    # pure ascii; printed only when attached to a real terminal
    $lines = @(
        ' ____  _        _    ____ _____ ____   ___  '
        '|  _ \| |      / \  / ___| ____| __ ) / _ \ '
        '| |_) | |     / _ \| |   |  _| |  _ \| | | |'
        '|  __/| |___ / ___ \ |___| |___| |_) | |_| |'
        '|_|   |_____/_/   \_\____|_____|____/ \___/ '
        'the fake fix, dissected. static triage - nothing executes.'
    )
    return ($lines -join "`n")
}

$script:PlaceboEsc = [char]27

function Format-PlaceboTerminal {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Report, [switch]$Hunt, [switch]$NoBanner)

    $e = $script:PlaceboEsc
    $sb = [System.Text.StringBuilder]::new()
    if (-not $NoBanner) { [void]$sb.AppendLine((Format-PlaceboBanner)); [void]$sb.AppendLine('') }

    if ($Hunt) {
        $color = Get-PlaceboVerdictColor -Verdict $Report.Verdict
        [void]$sb.AppendLine("hunt verdict: $($e)[${color}m$($Report.Verdict.ToUpper())$($e)[0m  worst-score $($Report.MaxScore)/100")
        [void]$sb.AppendLine("targets scanned: $($Report.TargetsScanned)   files: $($Report.FilesScanned)   registry: $(if ($Report.RegistryAvailable) {'available'} else {'n/a'})   tasks: $(if ($Report.TasksAvailable) {'available'} else {'n/a'})")
        [void]$sb.AppendLine('')
        if ($Report.Findings.Count -eq 0) {
            [void]$sb.AppendLine('no paste-and-run residue found.')
            return $sb.ToString()
        }
        [void]$sb.AppendLine("findings: $($Report.Findings.Count)")
        foreach ($f in $Report.Findings) {
            $c = Get-PlaceboVerdictColor -Verdict $f.Verdict
            [void]$sb.AppendLine('')
            [void]$sb.AppendLine("$($e)[${c}m$($f.Verdict.ToUpper())$($e)[0m  score $($f.Score)/100  src: $($f.Source)$(if ($f.Line) {":$($f.Line)"})")
            [void]$sb.AppendLine("  $((Get-PlaceboTruncated -Text $f.Excerpt -Max 140))")
            foreach ($t in $f.Top) { [void]$sb.AppendLine("  - $t") }
            if ($f.Iocs.Urls.Count -gt 0) { [void]$sb.AppendLine("  urls: $(@($f.Iocs.Urls | Select-Object -First 2) -join ' ')") }
        }
        return $sb.ToString()
    }

    # triage view
    $color = Get-PlaceboVerdictColor -Verdict $Report.Verdict
    [void]$sb.AppendLine("triage verdict: $($e)[${color}m$($Report.Verdict.ToUpper())$($e)[0m  score $($Report.Score)/100")
    [void]$sb.AppendLine("command: $($Report.Command)")
    if ($Report.Layers.Count -gt 0) {
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('decode layers:')
        foreach ($l in $Report.Layers) {
            [void]$sb.AppendLine("  [$($l.Depth)] $($l.Kind)  in: $($l.Input)")
            [void]$sb.AppendLine("      out: $($l.Decoded)")
        }
        [void]$sb.AppendLine("final payload is layer [$($Report.Layers[-1].Depth)] text above.")
    }
    if ($Report.Findings.Count -gt 0) {
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('rules hit:')
        foreach ($f in $Report.Findings) {
            $layers = (@($f.Layers) -join ',')
            [void]$sb.AppendLine("  [$($f.Id)] $($f.Name)  w$($f.Weight) x$($f.Count)  layer:$layers  $($f.Mitre)")
        }
    }
    $iocs = $Report.Iocs
    $iocLines = @()
    if ($iocs.Urls.Count)    { $iocLines += ('  urls:     ' + (@($iocs.Urls) -join ', ')) }
    if ($iocs.Ips.Count)     { $iocLines += ('  ips:      ' + (@($iocs.Ips) -join ', ')) }
    if ($iocs.Domains.Count) { $iocLines += ('  domains:  ' + (@($iocs.Domains) -join ', ')) }
    if ($iocs.Onions.Count)  { $iocLines += ('  onions:   ' + (@($iocs.Onions) -join ', ')) }
    if ($iocs.Paths.Count)   { $iocLines += ('  paths:    ' + (@($iocs.Paths | Select-Object -First 5) -join ', ')) }
    if ($iocs.Registry.Count){ $iocLines += ('  registry: ' + (@($iocs.Registry | Select-Object -First 3) -join ', ')) }
    if ($iocs.Hashes.Count)  { $iocLines += ('  hashes:   ' + (@($iocs.Hashes | Select-Object -First 3) -join ', ')) }
    if ($iocs.Synthetic.Count) { $iocLines += ('  note: synthetic/reserved iocs present: ' + (@($iocs.Synthetic | Select-Object -First 3) -join ', ')) }
    if ($iocLines.Count -gt 0) {
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('iocs:')
        foreach ($l in $iocLines) { [void]$sb.AppendLine($l) }
    }
    if ($Report.Score -ge 10) {
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('do not run it. the fake fix is the delivery mechanism.')
    }
    return $sb.ToString()
}

function ConvertTo-PlaceboJson {
    # triage report only; hunt reports use ConvertTo-PlaceboJsonHunt
    param([Parameter(Mandatory)]$Report)
    $o = [ordered]@{
        tool = 'placebo'
        command = $Report.Command
        score = $Report.Score
        verdict = $Report.Verdict
        layers = @(); findings = @(); iocs = $null
    }
    foreach ($l in $Report.Layers) {
        $o.layers += [ordered]@{ depth = $l.Depth; kind = $l.Kind; input = $l.Input; decoded = $l.Decoded }
    }
    foreach ($f in $Report.Findings) {
        $o.findings += [ordered]@{
            id = $f.Id; name = $f.Name; mitre = $f.Mitre; weight = $f.Weight
            count = $f.Count; layers = @($f.Layers); context = $f.Context
        }
    }
    $o.iocs = [ordered]@{
        urls = @($Report.Iocs.Urls); ips = @($Report.Iocs.Ips); domains = @($Report.Iocs.Domains)
        onions = @($Report.Iocs.Onions); paths = @($Report.Iocs.Paths); registry = @($Report.Iocs.Registry)
        hashes = @($Report.Iocs.Hashes); synthetic = @($Report.Iocs.Synthetic)
    }
    return ($o | ConvertTo-Json -Depth 6 -Compress)
}

function ConvertTo-PlaceboJsonHunt {
    param([Parameter(Mandatory)]$Report)
    $o = [ordered]@{
        tool = 'placebo'
        mode = 'hunt'
        platform = "$($Report.Platform)"
        is_windows = $Report.IsWindows
        registry_available = $Report.RegistryAvailable
        tasks_available = $Report.TasksAvailable
        targets_scanned = $Report.TargetsScanned
        files_scanned = $Report.FilesScanned
        max_score = $Report.MaxScore
        verdict = $Report.Verdict
        findings = @()
    }
    foreach ($f in $Report.Findings) {
        $o.findings += [ordered]@{
            source = $f.Source; line = $f.Line; excerpt = $f.Excerpt
            score = $f.Score; verdict = $f.Verdict; top = @($f.Top)
        }
    }
    return ($o | ConvertTo-Json -Depth 6 -Compress)
}

function ConvertTo-PlaceboMarkdown {
    param([Parameter(Mandatory)]$Report, [switch]$Hunt)
    $sb = [System.Text.StringBuilder]::new()
    if ($Hunt) {
        [void]$sb.AppendLine("# placebo hunt report")
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine("- verdict: **$($Report.Verdict)** (worst score $($Report.MaxScore)/100)")
        [void]$sb.AppendLine("- targets scanned: $($Report.TargetsScanned), files: $($Report.FilesScanned)")
        [void]$sb.AppendLine("- registry: $(if ($Report.RegistryAvailable) { 'available' } else { 'unavailable' }), tasks: $(if ($Report.TasksAvailable) { 'available' } else { 'unavailable' })")
        [void]$sb.AppendLine('')
        if ($Report.Findings.Count -eq 0) { [void]$sb.AppendLine('no paste-and-run residue found.'); return $sb.ToString() }
        [void]$sb.AppendLine('| verdict | score | source | excerpt |')
        [void]$sb.AppendLine('|---|---|---|---|')
        foreach ($f in $Report.Findings) {
            $ex = ($f.Excerpt -replace '\|', '\|')
            [void]$sb.AppendLine("| $($f.Verdict) | $($f.Score) | $($f.Source) | $ex |")
        }
        return $sb.ToString()
    }
    [void]$sb.AppendLine("# placebo triage report")
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine("- verdict: **$($Report.Verdict)** (score $($Report.Score)/100)")
    [void]$sb.AppendLine("- command: '$($Report.Command)'")
    if ($Report.Layers.Count -gt 0) {
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('## decode layers')
        [void]$sb.AppendLine('')
        foreach ($l in $Report.Layers) {
            [void]$sb.AppendLine("- layer [$($l.Depth)] **$($l.Kind)**: '$($l.Decoded)'")
        }
    }
    if ($Report.Findings.Count -gt 0) {
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('## rules hit')
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('| id | rule | weight | hits | layers | mitre |')
        [void]$sb.AppendLine('|---|---|---|---|---|---|')
        foreach ($f in $Report.Findings) {
            $name = ($f.Name -replace '\|', '\|')
            [void]$sb.AppendLine("| $($f.Id) | $name | $($f.Weight) | $($f.Count) | $(@($f.Layers) -join ',') | $($f.Mitre) |")
        }
    }
    $iocs = $Report.Iocs
    $hasIocs = @($iocs.Urls).Count + @($iocs.Ips).Count + @($iocs.Domains).Count + @($iocs.Paths).Count + @($iocs.Registry).Count + @($iocs.Hashes).Count
    if ($hasIocs -gt 0) {
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('## iocs')
        [void]$sb.AppendLine('')
        if (@($iocs.Urls).Count)    { [void]$sb.AppendLine("- urls: $(@($iocs.Urls) -join ', ')") }
        if (@($iocs.Ips).Count)     { [void]$sb.AppendLine("- ips: $(@($iocs.Ips) -join ', ')") }
        if (@($iocs.Domains).Count) { [void]$sb.AppendLine("- domains: $(@($iocs.Domains) -join ', ')") }
        if (@($iocs.Paths).Count)   { [void]$sb.AppendLine("- paths: $(@($iocs.Paths) -join ', ')") }
        if (@($iocs.Registry).Count){ [void]$sb.AppendLine("- registry: $(@($iocs.Registry) -join ', ')") }
        if (@($iocs.Hashes).Count)  { [void]$sb.AppendLine("- hashes: $(@($iocs.Hashes) -join ', ')") }
    }
    return $sb.ToString()
}
