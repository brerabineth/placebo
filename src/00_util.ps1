# placebo - internal helpers. static analysis only: nothing here executes user input.

Set-Variable -Name PlaceboMaxFileBytes -Option Constant -Scope Script -Value 20971520
Set-Variable -Name PlaceboMaxDecodeDepth -Option Constant -Scope Script -Value 6
Set-Variable -Name PlaceboMaxLayerChars -Option Constant -Scope Script -Value 200000

# host detection (works on pwsh 5.1 and 7+)
function Test-PlaceboWindows {
    if ($null -ne $IsWindows -and $PSVersionTable.PSVersion.Major -ge 6) { return [bool]$IsWindows }
    return ($env:OS -eq 'Windows_NT')
}

# cyrillic/greek/fullwidth lookalikes used to hide verbs from naive greps
$script:PlaceboHomoglyphs = @{
    [char]0x0430='a'; [char]0x0435='e'; [char]0x043E='o'; [char]0x0440='p'
    [char]0x0441='c'; [char]0x0445='x'; [char]0x0443='y'; [char]0x0456='i'
    [char]0x0455='s'; [char]0x04BB='h'; [char]0x043A='k'; [char]0x043C='m'
    [char]0x0391='A'; [char]0x0392='B'; [char]0x0395='E'; [char]0x039F='O'
    [char]0x03A1='P'; [char]0x03A4='T'; [char]0x03A7='X'; [char]0x03B1='a'
    [char]0x03BF='o'; [char]0x03C1='p'; [char]0x03C5='y'
    [char]0xFF21='A'; [char]0xFF22='B'; [char]0xFF25='E'; [char]0xFF30='P'
    [char]0xFF41='a'; [char]0xFF45='e'; [char]0xFF4F='o'; [char]0xFF50='p'
}

function ConvertTo-PlaceboAscii {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    if ($Text.Length -eq 0) { return $Text }
    $sb = [System.Text.StringBuilder]::new($Text.Length)
    foreach ($ch in $Text.ToCharArray()) {
        if ($script:PlaceboHomoglyphs.ContainsKey($ch)) { [void]$sb.Append($script:PlaceboHomoglyphs[$ch]) }
        else { [void]$sb.Append($ch) }
    }
    return $sb.ToString()
}

# strip control channels, keep structure; detection copy only
function Get-PlaceboNormalized {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    $t = ConvertTo-PlaceboAscii -Text $Text
    $sb = [System.Text.StringBuilder]::new($t.Length)
    foreach ($ch in $t.ToCharArray()) {
        $code = [int]$ch
        # explicit invisible channels -> space: zero-width, bidi, word joiners,
        # soft hyphen, bom, variation selectors, unicode tag block (smuggling)
        if (($code -ge 0x200B -and $code -le 0x200F) -or
            ($code -ge 0x202A -and $code -le 0x202E) -or
            ($code -ge 0x2060 -and $code -le 0x2064) -or
            $code -eq 0x00AD -or $code -eq 0xFEFF -or
            ($code -ge 0xFE00 -and $code -le 0xFE0F) -or
            ($code -ge 0xE0000 -and $code -le 0xE007F)) {
            [void]$sb.Append(' ')
        }
        elseif ($code -eq 9 -or $code -eq 10 -or $code -eq 13) { [void]$sb.Append(' ') }
        elseif ($code -ge 32 -and $code -ne 127) { [void]$sb.Append($ch) }
        else { [void]$sb.Append(' ') }
    }
    return ($sb.ToString() -replace '\s+', ' ').Trim()
}

function Get-PlaceboPrintableRatio {
    param([AllowNull()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return 0.0 }
    $good = 0; $total = 0
    foreach ($ch in $Text.ToCharArray()) {
        $total++
        $code = [int]$ch
        if (($code -ge 32 -and $code -le 126) -or $code -eq 9 -or $code -eq 10 -or $code -eq 13) { $good++ }
    }
    if ($total -eq 0) { return 0.0 }
    return [math]::Round($good / [double]$total, 4)
}

function Test-PlaceboReadable {
    param([AllowNull()][string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
    if ($Text.Length -lt 4) { return $false }
    return ((Get-PlaceboPrintableRatio -Text $Text) -ge 0.85)
}

function Get-PlaceboTruncated {
    param([AllowNull()][string]$Text, [int]$Max = 120)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $one = ($Text -replace '\s+', ' ').Trim()
    if ($one.Length -le $Max) { return $one }
    return ($one.Substring(0, $Max - 3) + '...')
}

# token-ish secrets -> first 6 chars + asterisks (morgue/familiar convention)
function Hide-PlaceboSecrets {
    param([AllowNull()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    $patterns = @(
        'gh[pousr]_[A-Za-z0-9]{20,}', 'github_pat_[A-Za-z0-9_]{20,}',
        'sk-[A-Za-z0-9_-]{16,}', 'sk-ant-[A-Za-z0-9_-]{16,}',
        'AKIA[0-9A-Z]{16}', 'AIza[0-9A-Za-z_-]{30,}',
        'xox[abprs]-[A-Za-z0-9-]{10,}', 'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}'
    )
    $joined = [string]::Join('|', $patterns)
    return ([regex]::Replace($Text, $joined, { param($m) $v = $m.Value; if ($v.Length -le 8) { '***' } else { $v.Substring(0, 6) + ('*' * 12) } }))
}

function Hide-PlaceboUrl {
    param([AllowNull()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    $t = $Text -replace '^(h)(tt)(p)', 'hxxp'
    $t = [regex]::Replace($t, '(?i)(https?://)', 'hxxp://')
    $t = $t -replace '\.', '[.]'
    return $t
}

function Hide-PlaceboText {
    param([AllowNull()][string]$Text, [switch]$Reveal)
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    if ($Reveal) { return $Text }
    return (Hide-PlaceboUrl -Text (Hide-PlaceboSecrets -Text $Text))
}

function ConvertTo-PlaceboSha256Hex {
    param([Parameter(Mandatory)][byte[]]$Bytes)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return (([System.BitConverter]::ToString($sha.ComputeHash($Bytes))) -replace '-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

# read text file with bounded size; returns $null when skipped
function Read-PlaceboTextFile {
    param([Parameter(Mandatory)][string]$Path)
    try {
        $fi = [System.IO.FileInfo]::new($Path)
        if (-not $fi.Exists) { return $null }
        if ($fi.Length -gt $script:PlaceboMaxFileBytes) { return $null }
        if ($fi.Length -eq 0) { return @() }
        return ([System.IO.File]::ReadAllLines($Path))
    } catch { return $null }
}

# utf-16le strings embedded in binary files (.lnk targets, shell link args)
function Get-PlaceboEmbeddedStrings {
    param([Parameter(Mandatory)][string]$Path, [int]$MinLen = 6)
    try {
        $fi = [System.IO.FileInfo]::new($Path)
        if (-not $fi.Exists -or $fi.Length -gt $script:PlaceboMaxFileBytes) { return @() }
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        $out = @()
        foreach ($enc in @([System.Text.Encoding]::Unicode, [System.Text.Encoding]::ASCII)) {
            $text = $enc.GetString($bytes)
            $ms = [regex]::Matches($text, '[\x20-\x7E]{6,}')
            foreach ($m in $ms) { if ($m.Value.Length -ge $MinLen) { $out += $m.Value } }
        }
        return ($out | Select-Object -Unique)
    } catch { return @() }
}

function Get-PlaceboLines {
    # history files may prefix zsh entries with ': <ts>:0;cmd' - strip it
    param([AllowNull()][object]$Lines)
    if ($null -eq $Lines) { return @() }
    $out = @()
    foreach ($l in @($Lines)) {
        if ($null -eq $l) { continue }
        $line = [string]$l
        if ($line -match '^\s*:\s*\d+:\d+;(.*)$') { $line = $Matches[1] }
        if ($line.Trim().Length -gt 0) { $out += $line }
    }
    return $out
}
