# placebo - scoring. distinct-rule weighted sum, capped; verdict bands; reason trail.

function Get-PlaceboVerdict {
    param([Parameter(Mandatory)][int]$Score)
    if ($Score -ge 65) { return 'critical' }
    if ($Score -ge 35) { return 'malicious' }
    if ($Score -ge 10) { return 'suspicious' }
    return 'clean'
}

function Get-PlaceboVerdictOrder {
    # rank used to compare verdicts (hunt rolls up worst hit)
    param([Parameter(Mandatory)][string]$Verdict)
    switch ($Verdict) {
        'critical'   { return 3 }
        'malicious'  { return 2 }
        'suspicious' { return 1 }
        default      { return 0 }
    }
}

function Invoke-PlaceboScore {
    # combines rule findings across ALL layers into one score + reason trail
    param([Parameter(Mandatory)]$LayerFindings)
    # LayerFindings: array of @{ Layer = int-or-null; Findings = @(finding...) }
    $merged = [System.Collections.Generic.List[object]]::new()
    $score = 0
    foreach ($lf in $LayerFindings) {
        foreach ($f in $lf.Findings) {
            $prev = $merged | Where-Object { $_.Id -eq $f.Id }
            if ($null -eq $prev) {
                $merged.Add(@{
                    Id = $f.Id; Name = $f.Name; Mitre = $f.Mitre; Weight = $f.Weight
                    Count = $f.Count; Note = $f.Note; Context = $f.Context
                    Layers = @($lf.Layer)
                })
                $score += $f.Weight
            } else {
                $prev.Count += $f.Count
                if ($prev.Layers -notcontains $lf.Layer) { $prev.Layers = @($prev.Layers) + @($lf.Layer) }
                if (-not $prev.Context) { $prev.Context = $f.Context }
            }
        }
    }
    if ($score -gt 100) { $score = 100 }
    $merged = @($merged | Sort-Object -Property Weight -Descending)
    return @{
        Score    = $score
        Verdict  = (Get-PlaceboVerdict -Score $score)
        Findings = $merged
    }
}
