# Archived historical one-off migration script (2026-10-09); kept for provenance only.
$ErrorActionPreference = 'Stop'
$taskRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$taskOld = '<legacy-source-dir>'
$taskMappings = @(
 @('<legacy-source-dir>\Z_6_0380.bin','firmware\original\Z_6_0380.bin'),
 @("$taskOld\work\z6_decoded",'firmware\decoded'),
 @("$taskOld\work\wonder-lantern",'references\wonder-lantern'),
 @("$taskOld\work\old-nikon-tools",'references\nikon-firmware-tools'),
 @("$taskOld\work\z30-firmware-extensions",'references\z30-firmware-extensions'),
 @("$taskOld\work\FirmwareDecoder.java",'references\decoder-excerpts\FirmwareDecoder.java'),
 @("$taskOld\work\FirmwareUtils.java",'references\decoder-excerpts\FirmwareUtils.java'),
 @("$taskOld\work\analyze_z6.py",'tools\analyze_z6.py'),
 @("$taskOld\work\build_evidence.py",'tools\build_evidence.py'),
 @("$taskOld\work\z6_analysis.json",'analysis\z6_analysis.json'),
 @("$taskOld\work\z6_candidate_strings.json",'analysis\z6_candidate_strings.json'),
 @("$taskOld\work\z6_strings.txt",'analysis\z6_strings.txt'),
 @("$taskOld\outputs\Z6_0380_static_analysis.json",'outputs\Z6_0380_static_analysis.json')
)
$taskRecords = [Collections.Generic.List[object]]::new()
foreach ($taskMap in $taskMappings) {
 $taskSource = [IO.Path]::GetFullPath($taskMap[0])
 $taskDestination = [IO.Path]::GetFullPath((Join-Path $taskRoot $taskMap[1]))
 if (-not ($taskSource.StartsWith($taskOld + '\', [StringComparison]::OrdinalIgnoreCase) -or $taskSource -eq '<legacy-source-dir>\Z_6_0380.bin')) { throw "Unexpected source: $taskSource" }
 if (-not $taskDestination.StartsWith($taskRoot + '\', [StringComparison]::OrdinalIgnoreCase)) { throw "Destination outside project: $taskDestination" }
 if (Test-Path -LiteralPath $taskDestination) { throw "Destination exists: $taskDestination" }
 $taskItem = Get-Item -LiteralPath $taskSource -Force
 $taskFiles = if ($taskItem.PSIsContainer) { @(Get-ChildItem -LiteralPath $taskSource -File -Recurse -Force) } else { @($taskItem) }
 foreach ($taskFile in $taskFiles) {
  $taskTarget = if ($taskItem.PSIsContainer) { Join-Path $taskDestination $taskFile.FullName.Substring($taskSource.Length+1) } else { $taskDestination }
  $taskRecords.Add([pscustomobject]@{ original_path=$taskFile.FullName; destination_path=$taskTarget; bytes=$taskFile.Length; sha256=(Get-FileHash -LiteralPath $taskFile.FullName -Algorithm SHA256).Hash.ToLower() })
 }
}
New-Item -ItemType Directory -Path (Join-Path $taskRoot 'manifests') -Force | Out-Null
$taskRecords | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $taskRoot 'manifests\migration_files.json') -Encoding utf8
foreach ($taskMap in $taskMappings) {
 $taskSource = [IO.Path]::GetFullPath($taskMap[0])
 $taskDestination = [IO.Path]::GetFullPath((Join-Path $taskRoot $taskMap[1]))
 New-Item -ItemType Directory -Path (Split-Path $taskDestination -Parent) -Force | Out-Null
 if ((Get-Item -LiteralPath $taskSource).PSIsContainer) {
  & robocopy $taskSource $taskDestination /E /MOVE /R:1 /W:1 /NFL /NDL /NJH /NJS /NP
  if ($LASTEXITCODE -ge 8) { throw "Robocopy failure $LASTEXITCODE for $taskSource" }
 } else { Move-Item -LiteralPath $taskSource -Destination $taskDestination }
}
foreach ($taskRecord in $taskRecords) {
 if (Test-Path -LiteralPath $taskRecord.original_path) { throw "Source remains: $($taskRecord.original_path)" }
 if ((Get-FileHash -LiteralPath $taskRecord.destination_path -Algorithm SHA256).Hash.ToLower() -ne $taskRecord.sha256) { throw "Hash mismatch: $($taskRecord.destination_path)" }
}
[pscustomobject]@{date='2026-10-09';file_count=$taskRecords.Count;total_bytes=($taskRecords | Measure-Object bytes -Sum).Sum;all_hashes_match=$true;all_original_files_removed=$true;method='Move-Item for files; robocopy /E /MOVE for directories across volumes'} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $taskRoot 'manifests\migration_result.json') -Encoding utf8
Get-Content -LiteralPath (Join-Path $taskRoot 'manifests\migration_result.json')
