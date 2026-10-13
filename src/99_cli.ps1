# placebo - cli dispatcher. included ONLY in the built single-file dist/placebo.ps1.
# display text goes through [Console]::Out (real stdout, never captured by exit());
# this function returns ONLY the process exit code.

function Invoke-PlaceboCli {
    [CmdletBinding()]
    param([Parameter(ValueFromRemainingArguments)][string[]]$ArgsList)

    # keep verdict colors alive even when stdout is piped (renderers/tests parse them)
    if ($PSVersionTable.PSVersion.Major -ge 7 -and (Get-Variable PSStyle -Scope Global -ErrorAction SilentlyContinue)) {
        $global:PSStyle.OutputRendering = 'Ansi'
    }

    function Out-Text { param([string]$T) [Console]::Out.WriteLine($T) }
    function Out-Err  { param([string]$T) [Console]::Error.WriteLine($T) }

    $mode = 'triage'
    $positional = @()
    $optJson = $false; $optMd = $false; $optReveal = $false; $optNoBanner = $false
    $failOn = ''; $outFile = ''; $maxDepth = 4; $paths = @(); $profileName = 'mixed'
    $optNoReg = $false; $optNoTasks = $false

    $i = 0
    while ($i -lt $ArgsList.Count) {
        $a = $ArgsList[$i]
        switch ($a) {
            'triage'   { $mode = 'triage' }
            'hunt'     { $mode = 'hunt' }
            'forge'    { $mode = 'forge' }
            'rules'    { $mode = 'rules' }
            'paths'    { $mode = 'paths' }
            'version'  { $mode = 'version' }
            'argv'     { $mode = 'argv' }
            '--json'   { $optJson = $true }
            '--md'     { $optMd = $true }
            '--reveal' { $optReveal = $true }
            '--no-banner' { $optNoBanner = $true }
            '--no-registry' { $optNoReg = $true }
            '--no-tasks'    { $optNoTasks = $true }
            '--help'   { $mode = 'help' }
            '-h'       { $mode = 'help' }
            default {
                # string-split option parsing: no regex, identical on every platform
                if ($a.Contains('=')) {
                    $eq = $a.IndexOf('=')
                    $k = $a.Substring(0, $eq).ToLowerInvariant()
                    $v = $a.Substring($eq + 1)
                    switch ($k) {
                        '--fail-on'   { $failOn = $v }
                        '--out'       { $outFile = $v }
                        '--max-depth' { $maxDepth = [int]$v }
                        '--profile'   { $profileName = $v }
                        '--paths'     { $paths += $v }
                        '--path'      { $paths += $v }
                        default       { Out-Err "unknown option: $a"; return 64 }
                    }
                }
                elseif ($a.StartsWith('-') -and $a.Length -gt 1) { Out-Err "unknown option: $a"; return 64 }
                else { $positional += $a }
            }
        }
        $i++
    }

    try {
        switch ($mode) {
            'help' {
                Out-Text (@"
placebo - the fake fix, dissected. static triage for paste-and-run commands.

usage:
  placebo.ps1 triage '<command>' [--json|--md] [--reveal] [--max-depth=N] [--out=FILE]
  placebo.ps1 triage -                 read command from stdin
  placebo.ps1 hunt [--paths=DIR] [--json|--md] [--fail-on=BAND] [--no-registry] [--no-tasks]
  placebo.ps1 forge --out=DIR --profile=clickfix-basic|clickfix-enc|terminalfix|mixed
  placebo.ps1 rules                    list detection rules
  placebo.ps1 paths                    list hunt target locations on this machine
  placebo.ps1 version

exit codes: 0 clean, 1 suspicious, 2 malicious, 3 critical, 10 --fail-on gate tripped, 64 error
static analysis only. the command is never executed. nothing leaves the machine.
"@)
                return 0
            }
            'version' {
                Out-Text 'placebo 0.1.0'
                return 0
            }
            'argv' {
                $i2 = 0
                foreach ($x in $ArgsList) { Out-Text ("arg[$i2]=<$x> len=" + $x.Length); $i2++ }
                return 0
            }
            'rules' {
                foreach ($r in (Get-PlaceboRules)) {
                    Out-Text ("[{0}] w{1,-3} {2,-34} {3,-10} {4}" -f $r.Id, $r.Weight, $r.Name, $r.Mitre, $r.Note)
                }
                return 0
            }
            'paths' {
                Out-Text 'history files:'
                foreach ($h in (Find-PlaceboHistoryFiles)) { Out-Text "  $h" }
                Out-Text 'startup items:'
                foreach ($s in (Find-PlaceboStartupItems)) { Out-Text "  $s" }
                Out-Text "registry: $(if (Test-PlaceboWindows) { 'available' } else { 'unavailable (not windows)' })"
                Out-Text "scheduled tasks: $(if (Test-PlaceboWindows) { 'available' } else { 'crontab + /etc/cron.d (read-only)' })"
                return 0
            }
            'forge' {
                $dir = $outFile
                if (-not $dir) { Out-Err 'forge requires --out=DIR'; return 64 }
                $p = New-PlaceboFixture -OutDir $dir -Profile $profileName
                Out-Text "synthetic fixture written: $p (profile: $profileName)"
                return 0
            }
            'triage' {
                $cmd = ''
                if ($positional.Count -ge 1) { $cmd = $positional[0] }
                if ($cmd -eq '-') { $cmd = [Console]::In.ReadToEnd() }
                if (-not $cmd) { Out-Err 'triage requires a command string or - for stdin'; return 64 }
                $report = Invoke-PlaceboTriage -Command $cmd -MaxDepth $maxDepth -Reveal:$optReveal
                $text = if ($optJson) { ConvertTo-PlaceboJson -Report $report }
                        elseif ($optMd) { ConvertTo-PlaceboMarkdown -Report $report }
                        else { Format-PlaceboTerminal -Report $report -NoBanner:$optNoBanner }
                Out-Text $text
                if ($outFile) { [System.IO.File]::WriteAllText($outFile, $text + [Environment]::NewLine) }
                if ($failOn) {
                    if ((Get-PlaceboVerdictOrder -Verdict $report.Verdict) -ge (Get-PlaceboVerdictOrder -Verdict $failOn)) { return 10 }
                }
                switch ($report.Verdict) { 'suspicious' { return 1 } 'malicious' { return 2 } 'critical' { return 3 } default { return 0 } }
            }
            'hunt' {
                $report = Invoke-PlaceboHunt -Paths $paths -MaxDepth $maxDepth -Reveal:$optReveal -NoRegistry:$optNoReg -NoTasks:$optNoTasks
                $text = if ($optJson) { ConvertTo-PlaceboJsonHunt -Report $report }
                        elseif ($optMd) { ConvertTo-PlaceboMarkdown -Report $report -Hunt }
                        else { Format-PlaceboTerminal -Report $report -Hunt -NoBanner:$optNoBanner }
                Out-Text $text
                if ($outFile) { [System.IO.File]::WriteAllText($outFile, $text + [Environment]::NewLine) }
                if ($failOn) {
                    if ((Get-PlaceboVerdictOrder -Verdict $report.Verdict) -ge (Get-PlaceboVerdictOrder -Verdict $failOn)) { return 10 }
                }
                switch ($report.Verdict) { 'suspicious' { return 1 } 'malicious' { return 2 } 'critical' { return 3 } default { return 0 } }
            }
            default { Out-Err "unknown mode: $mode"; return 64 }
        }
    } catch {
        Out-Err $_.Exception.Message
        return 64
    }
}

# run when executed as a script (not dot-sourced as a library)
if ($MyInvocation.InvocationName -ne '.') {
    exit (Invoke-PlaceboCli -ArgsList $args)
}
