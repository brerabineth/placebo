# placebo - layered decode engine. pure string/byte transforms; never evaluates anything.

Set-StrictMode -Off

# ---------- candidate extraction ----------

$script:PlaceboB64Chars = '^[A-Za-z0-9+/=]+$'
$script:PlaceboMinBlob = 24

function Find-PlaceboCandidates {
    # returns distinct raw segments worth decoding: base64 runs, hex, charcodes, url blobs
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    $found = [System.Collections.Generic.HashSet[string]]::new()
    if ($Text.Length -eq 0) { return $found }

    # base64 runs (long, charset-clean)
    foreach ($m in [regex]::Matches($Text, '[A-Za-z0-9+/=]{24,}')) {
        [void]$found.Add($m.Value)
    }
    # \xNN hex escapes (literal backslash-x in the text)
    foreach ($m in [regex]::Matches($Text, '(?:\\x[0-9a-fA-F]{2}){6,}')) {
        [void]$found.Add($m.Value)
    }
    # plain hex blobs "41 42 43..." or "414243"
    foreach ($m in [regex]::Matches($Text, '(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}[ ,]?){16,}(?![0-9a-fA-F])')) {
        [void]$found.Add($m.Value)
    }
    # charcode lists: [char]72,[char]101 | chr(72) | String.fromCharCode(72,101)
    foreach ($m in [regex]::Matches($Text, '(?:\[char\]\s*\d{1,3}\s*,?\s*){4,}')) { [void]$found.Add($m.Value) }
    foreach ($m in [regex]::Matches($Text, '(?:chr\s*\(\s*\d{1,3}\s*\)\s*[+,.]?\s*){4,}')) { [void]$found.Add($m.Value) }
    foreach ($m in [regex]::Matches($Text, 'String\.fromCharCode\s*\(\s*\d{1,3}(?:\s*,\s*\d{1,3}){3,}\s*\)')) { [void]$found.Add($m.Value) }
    # url-encoded blobs
    foreach ($m in [regex]::Matches($Text, '(?:%[0-9a-fA-F]{2}){8,}')) { [void]$found.Add($m.Value) }
    # decimal entity lists &#72;&#101;
    foreach ($m in [regex]::Matches($Text, '(?:&#\d{2,3};){4,}')) { [void]$found.Add($m.Value) }

    return $found
}

# ---------- individual decoders ----------

function ConvertFrom-PlaceboBase64 {
    param([Parameter(Mandatory)][string]$Blob)
    if ($Blob.Length -lt $script:PlaceboMinBlob) { return $null }
    if ($Blob -notmatch $script:PlaceboB64Chars) { return $null }
    if (($Blob.Length % 4) -ne 0) { return $null }
    try { $bytes = [System.Convert]::FromBase64String($Blob) } catch { return $null }
    if ($bytes.Length -eq 0) { return $null }
    # -enc payloads are utf-16le; plain base64 usually utf-8. try utf-16le first when
    # it interleaves 0x00 bytes, else utf-8
    $nulCount = 0
    foreach ($b in $bytes) { if ($b -eq 0) { $nulCount++ } }
    $t16 = [System.Text.Encoding]::Unicode.GetString($bytes)
    if ($nulCount -gt ($bytes.Length / 8)) {
        if (Test-PlaceboReadable -Text $t16) { return @{ Kind = 'base64-utf16le'; Text = $t16; Bytes = $bytes } }
    }
    $t8 = [System.Text.Encoding]::UTF8.GetString($bytes)
    if (Test-PlaceboReadable -Text $t8) { return @{ Kind = 'base64-utf8'; Text = $t8; Bytes = $bytes } }
    if ($t16.Length -gt 0) { return @{ Kind = 'base64-utf16le'; Text = $t16; Bytes = $bytes } }  # binary inside
    return $null
}

function ConvertFrom-PlaceboHex {
    param([Parameter(Mandatory)][string]$Blob)
    $hex = $Blob -replace '\\x', '' -replace '0x', '' -replace '[ ,;]', ''
    if ($hex.Length -lt 16 -or ($hex.Length % 2) -ne 0) { return $null }
    if ($hex -notmatch '^[0-9a-fA-F]+$') { return $null }
    $bytes = [byte[]]::new($hex.Length / 2)
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $bytes[$i] = [System.Convert]::ToByte($hex.Substring($i * 2, 2), 16)
    }
    $t8 = [System.Text.Encoding]::UTF8.GetString($bytes)
    $t16 = [System.Text.Encoding]::Unicode.GetString($bytes)
    if (Test-PlaceboReadable -Text $t8) { return @{ Kind = 'hex-utf8'; Text = $t8; Bytes = $bytes } }
    if (Test-PlaceboReadable -Text $t16) { return @{ Kind = 'hex-utf16le'; Text = $t16; Bytes = $bytes } }
    return $null
}

function ConvertFrom-PlaceboCharcode {
    param([Parameter(Mandatory)][string]$Blob)
    $nums = @()
    foreach ($m in [regex]::Matches($Blob, '\d{1,3}')) { $nums += [int]$m.Value }
    if ($nums.Count -lt 4) { return $null }
    $chars = [System.Collections.Generic.List[char]]::new()
    foreach ($n in $nums) {
        if ($n -lt 0 -or $n -gt 255) { return $null }
        $chars.Add([char]$n)
    }
    $text = (-join $chars)
    if (-not (Test-PlaceboReadable -Text $text)) { return $null }
    return @{ Kind = 'charcode'; Text = $text; Bytes = $null }
}

function ConvertFrom-PlaceboUrl {
    param([Parameter(Mandatory)][string]$Blob)
    if ($Blob -notmatch '%[0-9a-fA-F]{2}') { return $null }
    try { $text = [System.Uri]::UnescapeDataString($Blob) } catch { return $null }
    if (-not (Test-PlaceboReadable -Text $text)) { return $null }
    return @{ Kind = 'url-encoding'; Text = $text; Bytes = $null }
}

function ConvertFrom-PlaceboEntities {
    param([Parameter(Mandatory)][string]$Blob)
    if ($Blob -notmatch '&#\d{2,3};') { return $null }
    $sb = [System.Text.StringBuilder]::new()
    foreach ($m in [regex]::Matches($Blob, '&#(\d{2,3});')) {
        $n = [int]$m.Groups[1].Value
        if ($n -lt 1 -or $n -gt 255) { return $null }
        [void]$sb.Append([char]$n)
    }
    $text = $sb.ToString()
    if (-not (Test-PlaceboReadable -Text $text)) { return $null }
    return @{ Kind = 'html-entities'; Text = $text; Bytes = $null }
}

function ConvertFrom-PlaceboRot13 {
    param([Parameter(Mandatory)][string]$Blob)
    if ($Blob -notmatch '^[A-Za-z\s]{8,}$') { return $null }
    $sb = [System.Text.StringBuilder]::new($Blob.Length)
    foreach ($ch in $Blob.ToCharArray()) {
        if ($ch -ge 'a' -and $ch -le 'z') { $n = (([int]$ch - [int][char]'a') + 13) % 26; [void]$sb.Append([char]([int][char]'a' + $n)) }
        elseif ($ch -ge 'A' -and $ch -le 'Z') { $n = (([int]$ch - [int][char]'A') + 13) % 26; [void]$sb.Append([char]([int][char]'A' + $n)) }
        else { [void]$sb.Append($ch) }
    }
    return @{ Kind = 'rot13'; Text = $sb.ToString(); Bytes = $null }
}

function ConvertFrom-PlaceboCompressed {
    # gzip / zlib / raw-deflate inside decoded bytes
    param([Parameter(Mandatory)][byte[]]$Bytes)
    if ($Bytes.Length -lt 8) { return $null }
    Add-Type -AssemblyName System.IO.Compression -ErrorAction SilentlyContinue
    $head = $Bytes[0]; $second = $Bytes[1]
    $plans = @()
    if ($head -eq 0x1f -and $second -eq 0x8b) {
        $plans += @{ Kind = 'gzip'; Offset = 0; Mode = 'gzip' }
    } elseif ($head -eq 0x78 -and $second -in @(0x01, 0x9c, 0xda, 0x5e)) {
        $plans += @{ Kind = 'zlib'; Offset = 2; Mode = 'deflate' }
        $plans += @{ Kind = 'zlib+gzip-hdr'; Offset = 2; Mode = 'gzip' }
    } else {
        $plans += @{ Kind = 'raw-deflate'; Offset = 0; Mode = 'deflate' }
    }
    foreach ($p in $plans) {
        try {
            $slice = [byte[]]::new($Bytes.Length - $p.Offset)
            [Array]::Copy($Bytes, $p.Offset, $slice, 0, $slice.Length)
            $in = [System.IO.MemoryStream]::new($slice)
            $ms = [System.IO.MemoryStream]::new()
            if ($p.Mode -eq 'gzip') { $ds = [System.IO.Compression.GzipStream]::new($in, [System.IO.Compression.CompressionMode]::Decompress) }
            else { $ds = [System.IO.Compression.DeflateStream]::new($in, [System.IO.Compression.CompressionMode]::Decompress) }
            try { $ds.CopyTo($ms) } finally { $ds.Dispose(); $in.Dispose() }
            $out = $ms.ToArray(); $ms.Dispose()
            if ($out.Length -lt 4) { continue }
            $t8 = [System.Text.Encoding]::UTF8.GetString($out)
            $t16 = [System.Text.Encoding]::Unicode.GetString($out)
            if (Test-PlaceboReadable -Text $t8) { return @{ Kind = $p.Kind; Text = $t8; Bytes = $out } }
            if (Test-PlaceboReadable -Text $t16) { return @{ Kind = $p.Kind; Text = $t16; Bytes = $out } }
        } catch { continue }
    }
    return $null
}

# ---------- layered pipeline ----------

function Invoke-PlaceboDecode {
    # walk candidates and their children; returns layer trace list
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Text,
        [int]$MaxDepth = 4
    )
    if ($MaxDepth -gt $script:PlaceboMaxDecodeDepth) { $MaxDepth = $script:PlaceboMaxDecodeDepth }
    $trace = [System.Collections.Generic.List[object]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new()
    $queue = [System.Collections.Generic.Queue[object]]::new()

    foreach ($c in (Find-PlaceboCandidates -Text $Text)) {
        $queue.Enqueue(@{ Blob = $c; Depth = 1; Parent = $null })
    }
    while ($queue.Count -gt 0 -and $trace.Count -lt 24) {
        $item = $queue.Dequeue()
        if ($item.Depth -gt $MaxDepth) { continue }
        $blob = $item.Blob
        if ($blob.Length -gt $script:PlaceboMaxLayerChars) { $blob = $blob.Substring(0, $script:PlaceboMaxLayerChars) }
        $key = "$($item.Depth):$($blob.Substring(0, [Math]::Min(64, $blob.Length)))"
        if (-not $seen.Add($key)) { continue }

        $res = ConvertFrom-PlaceboBase64 -Blob $blob
        if (-not $res) { $res = ConvertFrom-PlaceboHex -Blob $blob }
        if (-not $res) { $res = ConvertFrom-PlaceboCharcode -Blob $blob }
        if (-not $res) { $res = ConvertFrom-PlaceboUrl -Blob $blob }
        if (-not $res) { $res = ConvertFrom-PlaceboEntities -Blob $blob }
        if (-not $res) { $res = ConvertFrom-PlaceboRot13 -Blob $blob }
        if (-not $res) { continue }

        $trace.Add(@{
            Depth = $item.Depth
            Kind  = $res.Kind
            Input = (Get-PlaceboTruncated -Text $item.Blob -Max 96)
            Text  = $res.Text
        })
        # compressed payloads hidden inside decoded bytes
        if ($null -ne $res.Bytes) {
            $comp = ConvertFrom-PlaceboCompressed -Bytes $res.Bytes
            if ($comp) {
                $trace.Add(@{
                    Depth = $item.Depth + 1
                    Kind  = $comp.Kind
                    Input = (Get-PlaceboTruncated -Text $res.Text -Max 96)
                    Text  = $comp.Text
                })
                foreach ($c2 in (Find-PlaceboCandidates -Text $comp.Text)) {
                    if ($item.Depth + 2 -le $MaxDepth) { $queue.Enqueue(@{ Blob = $c2; Depth = $item.Depth + 2; Parent = $null }) }
                }
            }
        }
        foreach ($c2 in (Find-PlaceboCandidates -Text $res.Text)) {
            if ($item.Depth + 1 -le $MaxDepth) { $queue.Enqueue(@{ Blob = $c2; Depth = $item.Depth + 1; Parent = $null }) }
        }
    }
    return $trace
}
