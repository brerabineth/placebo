@{
    RootModule        = 'placebo.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = 'b7e1c3aa-9d2f-4c6e-8f41-5a7b9c0d2e33'
    Author            = 'Brerabin'
    Description       = 'the fake fix, dissected. local static triage for paste-and-run commands and the residue they leave. nothing executes, nothing leaves the machine.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
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
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{ PSData = @{ Tags = @('security','dfir','clickfix','powershell','static-analysis','triage','soc'); LicenseUri = 'https://github.com/brerabineth/placebo/blob/main/LICENSE'; ProjectUri = 'https://github.com/brerabineth/placebo' } }
}
