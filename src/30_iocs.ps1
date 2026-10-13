# placebo - IOC extraction. all offline regex; RFC 5737/example ranges flagged as synthetic.

function Get-PlaceboIocs {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)

    $urls = @()
    foreach ($m in [regex]::Matches($Text, '(?i)\bhttps?://[^\s"''<>)]{4,}')) {
        $urls += $m.Value.TrimEnd('.', ',', ';')
    }
    $ips = @()
    foreach ($m in [regex]::Matches($Text, '\b(?:\d{1,3}\.){3}\d{1,3}\b')) {
        $parts = $m.Value.Split('.')
        $ok = $true
        foreach ($p in $parts) { if ([int]$p -gt 255) { $ok = $false; break } }
        if ($ok) { $ips += $m.Value }
    }
    $domains = @()
    foreach ($m in [regex]::Matches($Text, '(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,}(?:com|net|org|io|ru|cn|xyz|top|info|biz|cc|su|me|dev|app|co|live|shop|site|online|store)\b')) {
        $domains += $m.Value.ToLowerInvariant()
    }
    # onion v2/v3
    $onions = @()
    foreach ($m in [regex]::Matches($Text, '\b[a-z2-7]{16}\.onion\b|\b[a-z2-7]{56}\.onion\b')) { $onions += $m.Value }
    # windows / unix paths of interest
    $paths = @()
    foreach ($m in [regex]::Matches($Text, '(?i)(?:[a-z]:\\[^\s";|<>]{3,120}|(?:/tmp|/etc|/var|/home|/root|/Users)[^\s";|<>]{2,120}|\%(?:TEMP|APPDATA|LOCALAPPDATA|PROGRAMDATA|USERPROFILE)\%[^\s";|<>]{2,120})')) {
        $paths += $m.Value.TrimEnd('.', ',', ';')
    }
    # registry writes of interest
    $regs = @()
    foreach ($m in [regex]::Matches($Text, '(?i)HKEY_[A-Z_]+\\[^\s";]{3,140}|HK(?:CU|LM|CR)\\[^\s";]{3,140}')) { $regs += $m.Value }
    # sha256/sha1/md5
    $hashes = @()
    foreach ($m in [regex]::Matches($Text, '\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{32}\b')) { $hashes += $m.Value.ToLowerInvariant() }

    $uniq = { param($arr) ,@($arr | Select-Object -Unique) }
    $result = @{
        Urls    = & $uniq $urls
        Ips     = & $uniq $ips
        Domains = & $uniq $domains
        Onions  = & $uniq $onions
        Paths   = & $uniq $paths
        Registry = & $uniq $regs
        Hashes  = & $uniq $hashes
    }
    # synthetic ranges / reserved example names -> mark them so nobody mistakes forge output for live IOCs
    $synthetic = @()
    foreach ($ip in $result.Ips) {
        if ($ip -match '^(192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|127\.0\.0\.1$|0\.0\.0\.0$|10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)') { $synthetic += $ip }
    }
    foreach ($d in $result.Domains) {
        if ($d -match '(^|\.)example\.(com|net|org)$|\.local$|\.invalid$|\.test$') { $synthetic += $d }
    }
    $result.Synthetic = (@($synthetic | Select-Object -Unique))
    return $result
}

function ConvertTo-PlaceboDefanged {
    param([Parameter(Mandatory)]$Iocs)
    $out = @{
        Urls    = @(); Ips = @(); Domains = @(); Onions = @()
        Paths   = @($Iocs.Paths); Registry = @($Iocs.Registry); Hashes = @($Iocs.Hashes)
        Synthetic = @($Iocs.Synthetic)
    }
    foreach ($u in $Iocs.Urls) {
        $x = $u -replace '(?i)^https?://', 'hxxp://'
        $x = $x -replace '\.', '[.]'
        $out.Urls += $x
    }
    foreach ($i in $Iocs.Ips) { $out.Ips += ($i -replace '\.', '[.]') }
    foreach ($d in $Iocs.Domains) { $out.Domains += ($d -replace '\.', '[.]') }
    foreach ($o in $Iocs.Onions) { $out.Onions += ($o -replace '\.', '[.]') }
    return $out
}
