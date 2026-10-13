# placebo - detection rules. static regex on normalized text + decoded layers only.
# every rule id is stable; add new rules with new ids, never renumber.

function Get-PlaceboRules {
    @(
        # --- execution of downloaded / hidden code ---
        @{ Id='PF-001'; Name='Invoke-Expression (iex)';              Mitre='T1059.001'; Weight=30; Patterns=@('\biex\b', '\bInvoke-Expression\b'); Note='executes a string as code: the final hop of most cradles' }
        @{ Id='PF-002'; Name='Invoke-Command / icm';                  Mitre='T1021.006'; Weight=28; Patterns=@('\bicm\b', '\bInvoke-Command\b'); Note='scriptblock or remote execution via winrm' }
        @{ Id='PF-003'; Name='WebClient download cradle';             Mitre='T1105';     Weight=32; Patterns=@('New-Object\s+(?:-ComObject\s+)?(?:System\.)?Net\.WebClient', '\[System\.Net\.WebClient\]'); Note='classic downloader object' }
        @{ Id='PF-004'; Name='DownloadString/DownloadFile/Data';      Mitre='T1105';     Weight=28; Patterns=@('\.Download(?:String|File|Data)\s*\('); Note='pulls remote payload to disk or memory' }
        @{ Id='PF-005'; Name='Invoke-WebRequest / iwr / curl / wget'; Mitre='T1105';     Weight=22; Patterns=@('\biwr\b', '\bInvoke-WebRequest\b', '\bcurl(?:\.exe)?\b', '\bwget(?:\.exe)?\b'); Note='network fetch primitive (context matters)' }
        @{ Id='PF-006'; Name='pipe fetch into shell';                 Mitre='T1059';     Weight=38; Patterns=@('(?:curl|wget|iwr|Invoke-WebRequest)[^|]{0,120}\|\s*(?:iex|iwr|sh|bash|zsh|powershell|pwsh)'); Note='download piped straight into an interpreter' }
        @{ Id='PF-007'; Name='certutil urlcache';                     Mitre='T1105';     Weight=34; Patterns=@('certutil(?:\.exe)?\s+[^\r\n]{0,40}(?:-urlcache|-verifyctl)', '-urlcache\s+-split\s+-f'); Note='lolbas downloader' }
        @{ Id='PF-008'; Name='bitsadmin transfer';                    Mitre='T1197';     Weight=34; Patterns=@('bitsadmin(?:\.exe)?\s+/(?:transfer|create)'); Note='background intelligent transfer abuse' }
        @{ Id='PF-009'; Name='msiexec remote install';                Mitre='T1218.007'; Weight=36; Patterns=@('msiexec(?:\.exe)?\s+/i\s+(?:https?://|\\\\)'); Note='remote msi execution' }
        @{ Id='PF-010'; Name='mshta remote/uncommon';                 Mitre='T1218.005'; Weight=40; Patterns=@('mshta(?:\.exe)?\s+(?:https?://|javascript:|vbscript:|\\\\)'); Note='hta execution straight from url' }
        @{ Id='PF-011'; Name='rundll32 urlmon/javascript';            Mitre='T1218.011'; Weight=38; Patterns=@('rundll32(?:\.exe)?\s+(?:urlmon(?:,|,\s*)URLDownloadToFileA?|javascript:)'); Note='rundll32 as proxy execution' }
        @{ Id='PF-012'; Name='regsvr32 /i:http scrobj';               Mitre='T1218.010'; Weight=40; Patterns=@('regsvr32(?:\.exe)?\s+/i\s*:?https?://', 'regsvr32(?:\.exe)?\s+/i\s+.*scrobj\.dll'); Note='squiblydoo scriptlet loading' }
        @{ Id='PF-013'; Name='wmic process call create';              Mitre='T1047';     Weight=34; Patterns=@('wmic(?:\.exe)?\s+process\s+call\s+create'); Note='wmi remote/local process launch' }
        @{ Id='PF-014'; Name='wscript/cscript execution';             Mitre='T1059.007'; Weight=28; Patterns=@('[cw]script(?:\.exe)?\s', '\.vbs\b', '\.js\b\s*/'); Note='windows script host execution' }
        @{ Id='PF-015'; Name='powershell encoded command';            Mitre='T1027';     Weight=30; Patterns=@('-e(?:nc|ncodedcommand)?\s+(?:[A-Za-z0-9+/=]{8,}|"?\s*[A-Za-z0-9+/=]{8,})', '-EncodedCommand'); Note='base64 utf-16le command blob' }
        @{ Id='PF-016'; Name='hidden window + bypass flags';          Mitre='T1564.003'; Weight=20; Patterns=@('(?:-w\s*(?:h|h\s?idden|hidden)|-windowstyle\s+hidden)', '-nop\b', '-noprofile\b', '-ep\s+bypass', '-executionpolicy\s+bypass'); Note='stealth launch flags (two or more raise score via stacking)' }
        @{ Id='PF-017'; Name='frombase64string';                      Mitre='T1132.001'; Weight=15; Patterns=@('FromBase64String\s*\(', '\[Convert\]::FromBase64'); Note='inline base64 materialization' }
        @{ Id='PF-018'; Name='reverse shell /dev/tcp';                Mitre='T1059.004'; Weight=45; Patterns=@('/dev/tcp/', '/dev/udp/'); Note='bash built-in socket backconnect' }
        @{ Id='PF-019'; Name='netcat / fifo reverse shell';           Mitre='T1059.004'; Weight=45; Patterns=@('\bnc(?:at)?\b[^&;]{0,80}\s-e\b', 'mkfifo[^;]{0,120}\bnc\b', '\bnc\b[^;]{0,60}-e\s/bin/(ba)?sh'); Note='classic fifo/nc listener shell' }
        @{ Id='PF-020'; Name='sudo with network fetch';               Mitre='T1548.003'; Weight=30; Patterns=@('sudo\s+(?:curl|wget|bash|sh)\b'); Note='rooted download execution' }
        @{ Id='PF-021'; Name='python/py -c exec';                     Mitre='T1059.006'; Weight=28; Patterns=@('\bpython3?\b\s+-c\b', '\bpy\s+-[23]?\s+-c\b', '\bexec\s*\(\s*[^)]{0,40}(?:base64|decode)'); Note='inline interpreter exec' }
        @{ Id='PF-022'; Name='osascript / osacompile';                Mitre='T1059.002'; Weight=32; Patterns=@('osascript\s+-e', 'osacompile\s+-o'); Note='macos script execution' }

        # --- persistence ---
        @{ Id='PF-023'; Name='run/runonce registry key';              Mitre='T1547.001'; Weight=36; Patterns=@('reg\s+add\s+[^\r\n]{0,80}\\Run(?:Once)?\b', 'CurrentVersion\\\\Run(?:Once)?\b', 'CurrentVersion\\Run(?:Once)?\b'); Note='user/system autostart key write' }
        @{ Id='PF-024'; Name='schtasks create';                       Mitre='T1053.005'; Weight=32; Patterns=@('schtasks(?:\.exe)?\s+/create', 'Register-ScheduledTask\b', 'New-ScheduledTaskTrigger\b'); Note='scheduled task persistence' }
        @{ Id='PF-025'; Name='service creation';                      Mitre='T1543.003'; Weight=34; Patterns=@('sc(?:\.exe)?\s+create\b', 'New-Service\b'); Note='windows service install' }
        @{ Id='PF-026'; Name='startup folder drop';                   Mitre='T1547.009'; Weight=30; Patterns=@('(?:Start Menu\\Programs\\Startup|Startup\\)', '%APPDATA%\\Microsoft\\Windows\\Start Menu'); Note='payload copied to startup folder' }
        @{ Id='PF-027'; Name='wmi event subscription';                Mitre='T1546.003'; Weight=40; Patterns=@('Register-WmiEvent\b', 'Register-CimIndicationEvent\b', '__EventConsumer'); Note='wmi permanent subscription' }
        @{ Id='PF-028'; Name='cron persistence';                      Mitre='T1053.003'; Weight=32; Patterns=@('\(crontab\s+-l[^)]{0,80}echo[^)]{0,80}\)\s*\|\s*crontab', 'crontab\s+-\s', '/etc/cron\.(?:d|daily|hourly)\b'); Note='unix cron write' }
        @{ Id='PF-029'; Name='ssh authorized_keys append';            Mitre='T1098.004'; Weight=40; Patterns=@('authorized_keys', 'ssh-keygen\b[^;]{0,60}>>', 'ssh-copy-id\b'); Note='account manipulation via ssh keys' }
        @{ Id='PF-030'; Name='shell profile append';                  Mitre='T1546.004'; Weight=34; Patterns=@('(?i)(\.bashrc|\.bash_profile|\.zshrc|profile\.ps1|\$PROFILE)\b\s*(?:<<|>>|-append)', '\$PROFILE\b[^;]{0,60}-append'); Note='event-triggered shell config modification' }
        @{ Id='PF-031'; Name='shortcut (.lnk) payload';               Mitre='T1547.009'; Weight=26; Patterns=@('WScript\.Shell\b.{0,80}CreateShortcut', '\.lnk\b.{0,40}(?:powershell|cmd|mshta)'); Note='shortcut points at interpreter' }

        # --- defense evasion ---
        @{ Id='PF-032'; Name='defender tampering';                    Mitre='T1562.001'; Weight=40; Patterns=@('Set-MpPreference\b.{0,120}-Disable(?:RealtimeMonitoring|IOAVProtection|BehaviorMonitoring)', 'Add-MpPreference\s+-Exclusion', 'Remove-MpPreference\s+-Exclusion'); Note='defender disable/exclusion' }
        @{ Id='PF-033'; Name='firewall/netsh tampering';              Mitre='T1562.004'; Weight=32; Patterns=@('netsh(?:\.exe)?\s+advfirewall\s+(?:firewall\s+add|set\s+allprofiles)'); Note='firewall rule or profile manipulation' }
        @{ Id='PF-034'; Name='clear/stop logging';                    Mitre='T1070.001'; Weight=38; Patterns=@('Clear-EventLog\b', 'wevtutil(?:\.exe)?\s+cl\s', 'Set-PSReadlineOption.{0,60}HistorySaveStyle\s+SaveNothing'); Note='log/history wiping' }
        @{ Id='PF-035'; Name='string obfuscation';                    Mitre='T1027';     Weight=10; Patterns=@('(?:\{\s*\d+\s*\}){2,}\"?\s*-f\s', '(?:\[char\]\s*\d+\s*\+\s*){3,}', '\$\{?\w{1,3}\}?\s*-f\s', '-join\s*(?:\(\[char\]\)|\$\w+)'); Note='format-string/char arithmetic obfuscation' }
        @{ Id='PF-036'; Name='backtick/quote splitting';              Mitre='T1027';     Weight=8;  Patterns=@('\w`\w', '\w"\s*\+\s*"\w'); Note='in-word backticks or quote-concat splitting' }
        @{ Id='PF-037'; Name='reversed payload marker';               Mitre='T1027';     Weight=14; Patterns=@('-join\s*\(\s*\[\w+\]::Reverse\b', '\)\s*\)\s*\[-1\.\.-1\]', '\[[A-Za-z]+\]::Reverse\b', '\bArray::Reverse\b'); Note='string reversal tricks' }
        @{ Id='PF-038'; Name='token-looking secret in payload';       Mitre='T1552.001'; Weight=24; Patterns=@('gh[pousr]_[A-Za-z0-9]{20,}', 'AKIA[0-9A-Z]{16}', 'sk-[A-Za-z0-9_-]{16,}'); Note='live-looking credential inside the command' }

        # --- clipboard / terminalfix era ---
        @{ Id='PF-039'; Name='clipboard write';                       Mitre='T1115';     Weight=18; Patterns=@('Set-Clipboard\b', '\|\s*clip(?:\.exe)?\b', 'pbcopy\b'); Note='writes to clipboard: address-swap / command-swap' }
        @{ Id='PF-040'; Name='clipboard read';                        Mitre='T1115';     Weight=16; Patterns=@('Get-Clipboard\b', 'pbpaste\b', 'powershell\s+Get-Clipboard'); Note='reads clipboard: paste hijack chains' }
        @{ Id='PF-041'; Name='cmd /c chain';                          Mitre='T1059.003'; Weight=14; Patterns=@('cmd(?:\.exe)?\s+/c\b', 'cmd(?:\.exe)?\s+/k\b'); Note='cmd proxy execution' }
        @{ Id='PF-042'; Name='explorer/win+r style launch';           Mitre='T1204';     Weight=12; Patterns=@('explorer(?:\.exe)?\s+(?:ms-settings|shell:)', '\bWin\s*\+\s*R\b'); Note='user-action launcher abuse' }
        @{ Id='PF-043'; Name='taskkill / process stop';               Mitre='T1562.001'; Weight=20; Patterns=@('taskkill(?:\.exe)?\s+/f\s+/im\s', 'Stop-Process\s+-Name\s+(?:MsMpEng|SecurityHealth)'); Note='security process termination' }
        @{ Id='PF-044'; Name='hosts file modification';               Mitre='T1565.002'; Weight=30; Patterns=@('(?i)(?:>>|Add-Content|Out-File|Set-Content)[^;]{0,60}(?:\\\\)?(?:etc[/\\]hosts|System32[/\\]drivers[/\\]etc[/\\]hosts)'); Note='hosts file redirect' }
        @{ Id='PF-045'; Name='disk wipe / cipher';                    Mitre='T1485';     Weight=45; Patterns=@('cipher\s+/w\s*:', 'rd\s+/s\s+/q\s+[a-zA-Z]:\\\\', 'rm\s+-rf\s+/(?:\s|$)'); Note='destructive disk operation' }
        @{ Id='PF-046'; Name='base64 blob embed';                     Mitre='T1132.001'; Weight=12; Patterns=@('[A-Za-z0-9+/=]{120,}'); Note='long base64 region (verify by decode)' }
    )
}

$script:PlaceboRuleCache = $null

function Test-PlaceboRulesValid {
    param([switch]$ThrowOnError)
    $bad = @()
    foreach ($r in (Get-PlaceboRules)) {
        foreach ($p in $r.Patterns) {
            try { [void][regex]::new($p, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::CultureInvariant) }
            catch { $bad += "$($r.Id): $p" }
        }
    }
    if ($bad.Count -gt 0 -and $ThrowOnError) { throw "invalid rule regex: $($bad -join '; ')" }
    return ($bad.Count -eq 0)
}

function Invoke-PlaceboRuleScan {
    # returns findings: one entry per rule with >=1 hit; counts + first context
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    if ($null -eq $script:PlaceboRuleCache) { $script:PlaceboRuleCache = Get-PlaceboRules }
    $findings = @()
    foreach ($r in $script:PlaceboRuleCache) {
        $count = 0; $first = ''
        foreach ($p in $r.Patterns) {
            try {
                foreach ($m in [regex]::Matches($Text, $p, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::CultureInvariant)) {
                    $count++
                    if (-not $first) { $first = (Get-PlaceboTruncated -Text $m.Value -Max 80) }
                }
            } catch { continue }
        }
        if ($count -gt 0) {
            $findings += @{ Id = $r.Id; Name = $r.Name; Mitre = $r.Mitre; Weight = $r.Weight; Count = $count; Context = $first; Note = $r.Note }
        }
    }
    return $findings
}
