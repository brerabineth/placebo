# placebo module loader. dot-sources src in numeric order (cli dispatcher excluded).
# static analysis only: nothing here evaluates or executes analyzed content.

$srcRoot = Join-Path $PSScriptRoot 'src'
$files = Get-ChildItem -LiteralPath $srcRoot -Filter '*.ps1' | Sort-Object Name
foreach ($f in $files) {
    if ($f.Name -eq '99_cli.ps1') { continue }
    . (Join-Path $srcRoot $f.Name)
}

Export-ModuleMember -Function @(
    'Invoke-PlaceboTriage',
    'Invoke-PlaceboHunt',
    'New-PlaceboFixture',
    'Get-PlaceboRules',
    'Test-PlaceboRulesValid',
    'Get-PlaceboIocs',
    'Invoke-PlaceboDecode',
    'Find-PlaceboHistoryFiles',
    'Find-PlaceboStartupItems',
    'Get-PlaceboRegistryEvidence',
    'Get-PlaceboTaskEvidence',
    'Format-PlaceboTerminal',
    'ConvertTo-PlaceboJson',
    'ConvertTo-PlaceboJsonHunt',
    'ConvertTo-PlaceboMarkdown',
    'Hide-PlaceboText',
    'Hide-PlaceboSecrets',
    'Hide-PlaceboUrl',
    'Get-PlaceboVerdict',
    'Get-PlaceboVerdictOrder',
    'Invoke-PlaceboScore',
    'Invoke-PlaceboRuleScan',
    'Get-PlaceboNormalized',
    'ConvertTo-PlaceboAscii',
    'ConvertTo-PlaceboDefanged',
    'Get-PlaceboEmbeddedStrings',
    'Test-PlaceboWindows',
    'Test-PlaceboReadable',
    'ConvertFrom-PlaceboBase64',
    'ConvertFrom-PlaceboHex',
    'ConvertFrom-PlaceboCharcode',
    'ConvertFrom-PlaceboUrl',
    'ConvertFrom-PlaceboEntities',
    'ConvertFrom-PlaceboRot13',
    'ConvertFrom-PlaceboCompressed',
    'ConvertTo-PlaceboSha256Hex',
    'Find-PlaceboCandidates'
)
