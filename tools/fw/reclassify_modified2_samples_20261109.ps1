$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$sourceDir = (Resolve-Path -LiteralPath (Join-Path $projectRoot 'samples\11.9_modified3')).Path
$targetDir = (Resolve-Path -LiteralPath (Join-Path $projectRoot 'samples\11.9_modified2')).Path
$analysisSource = (Resolve-Path -LiteralPath (Join-Path $projectRoot 'analysis\modified3-nef-2026-11-09')).Path
$analysisTarget = [IO.Path]::GetFullPath((Join-Path $projectRoot 'analysis\modified2-extra-2026-11-09'))
foreach ($targetPath in @($sourceDir, $targetDir, $analysisSource, $analysisTarget)) {
    if (-not $targetPath.StartsWith($projectRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "Path outside project: $targetPath"
    }
}
if (Test-Path -LiteralPath $analysisTarget) { throw 'Archive destination already exists' }
$ids = @(4874,4875,4876,4878,4879,4880)
$audit = Get-Content -LiteralPath (Join-Path $analysisSource 'raw-audit.json') -Raw | ConvertFrom-Json
$moves = @()
foreach ($id in $ids) {
    $name = "Z61_$id.NEF"
    $from = (Resolve-Path -LiteralPath (Join-Path $sourceDir $name)).Path
    $to = [IO.Path]::GetFullPath((Join-Path $targetDir $name))
    if ([IO.Path]::GetDirectoryName($from) -ne $sourceDir -or [IO.Path]::GetDirectoryName($to) -ne $targetDir) { throw 'Unexpected file path' }
    if (Test-Path -LiteralPath $to) { throw "Destination exists: $to" }
    $digest = (Get-FileHash -LiteralPath $from -Algorithm SHA256).Hash.ToLowerInvariant()
    $old = @($audit.files | Where-Object { [IO.Path]::GetFileName($_.path) -eq $name })
    if ($old.Count -ne 1 -or $digest -ne $old[0].sha256) { throw "Source differs from audited NEF: $name" }
    $moves += [pscustomobject]@{ name=$name; from=$from; to=$to; sha256=$digest; bytes=(Get-Item -LiteralPath $from).Length }
}
foreach ($move in $moves) {
    Move-Item -LiteralPath $move.from -Destination $move.to
    if ((Test-Path -LiteralPath $move.from) -or (Get-FileHash -LiteralPath $move.to -Algorithm SHA256).Hash.ToLowerInvariant() -ne $move.sha256) { throw "Move verification failed: $($move.name)" }
}
Move-Item -LiteralPath $analysisSource -Destination $analysisTarget
$historicalScript = Join-Path $projectRoot 'tools\fw\prepare_modified3_study.py'
$scriptArchive = Join-Path $analysisTarget 'historical-scripts'
New-Item -ItemType Directory -Path $scriptArchive | Out-Null
Move-Item -LiteralPath $historicalScript -Destination (Join-Path $scriptArchive 'prepare_modified3_study.py')

# Preserve original command outputs; provide current, explicitly corrected input files.
foreach ($name in @('inputs.json','raw-audit.json','decoder-input.json')) {
    $original = Join-Path $analysisTarget $name
    $content = Get-Content -LiteralPath $original -Raw
    $content = $content.Replace($sourceDir.Replace('\','\\'), $targetDir.Replace('\','\\'))
    $content = $content.Replace($sourceDir.Replace('\','/'), $targetDir.Replace('\','/'))
    $value = $content | ConvertFrom-Json
    if ($name -eq 'inputs.json') {
        foreach ($row in $value.files) {
            $row.group = 'modified2_extra'
            $row.kind = if ($row.id -le 4876) { 'dark' } else { 'flat' }
        }
        foreach ($row in $value.flat_files) {
            if ($ids -contains $row.id) { $row.group = 'modified2_extra'; $row.kind = 'flat' }
        }
        $value.provenance = 'User corrected: forgot to flash modified3; all six files were taken on modified2. Dark/flat classification and same tablet confirmed; setup may have moved.'
    }
    $value | Add-Member -NotePropertyName reclassification -NotePropertyValue '2026-11-09: user confirmed these are modified2, not modified3. See RECLASSIFICATION.json.'
    $value | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath (Join-Path $analysisTarget ($name.Replace('.json','-corrected.json'))) -Encoding utf8
}
$record = [ordered]@{
    date='2026-11-09'; timezone='Asia/Shanghai'; recorded_utc=[DateTime]::UtcNow.ToString('o')
    reason='User explicitly corrected: forgot to install modified3; these six frames are modified2.'
    dark_ids=@(4874,4875,4876); flat_ids=@(4878,4879,4880)
    setup='Same full-brightness Tab S9+; placement/focus may have moved.'
    moves=$moves; analysis_from=$analysisSource; analysis_to=$analysisTarget
    historical_outputs='Original logs/metadata/audits retained with their original acquisition paths; use *-corrected.json for current input paths and version labels.'
    modified3_physical_evidence=$false; source_hashes_verified=$true
}
$record | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $analysisTarget 'RECLASSIFICATION.json') -Encoding utf8
@'
本批为 modified2 补充实拍，非 modified3。
用户于 2026-11-09 明确更正：忘记刷入 modified3。
4874–4876：盖镜头 5 秒暗场；4878–4880：Tab S9+ 全亮度平场。布置可能移动。
六张 NEF 已移至 samples/11.9_modified2，移动前后 SHA-256 一致。
保留已完成的解码、NEF 字段提取和命令原始日志；历史路径/版本标签不代表当前归属。
后续分析使用 inputs-corrected.json、raw-audit-corrected.json、decoder-input-corrected.json。
NEFInfo7 与 modified2 一致符合本次版本更正，不作为 modified3 补丁失效证据。
尚无 modified3 实拍结果；原 samples/11.9_modified3 目录保留供重新拍摄。
'@ | Set-Content -LiteralPath (Join-Path $analysisTarget 'README.txt') -Encoding utf8
Copy-Item -LiteralPath $PSCommandPath -Destination (Join-Path $analysisTarget 'historical-scripts\reclassify_modified2_samples_20261109.ps1')
[pscustomobject]@{ ok=$true; moved_files=$moves.Count; samples=$targetDir; evidence=$analysisTarget; modified3_remaining=@(Get-ChildItem -LiteralPath $sourceDir -File).Count } | ConvertTo-Json
