# Read-only PowerShell port of tools/verify_transfer.py for machines without Python.
# Same rules: manifest paths must be relative, paths containing a .git component are
# skipped (mutable Git metadata), every other file must exist with matching size and SHA-256.
# Usage (from any directory): powershell -NoProfile -ExecutionPolicy Bypass -File tools/verify_transfer.ps1
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$manifestPath = Join-Path $root 'manifests/transfer_manifest_2026-11-02.json'
$manifest = Get-Content -Raw -Encoding UTF8 $manifestPath | ConvertFrom-Json

$failures = New-Object System.Collections.ArrayList
$skippedGit = 0
$checked = 0
foreach ($row in $manifest.files) {
    $rel = [string]$row.path
    $parts = $rel -split '/'
    if ($rel.StartsWith('/') -or $rel -match '^[A-Za-z]:' -or $parts -contains '..') {
        throw "Unsafe manifest path: $rel"
    }
    if ($parts -contains '.git') { $skippedGit++; continue }
    $path = Join-Path $root ($parts -join [IO.Path]::DirectorySeparatorChar)
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        [void]$failures.Add([ordered]@{ path = $rel; reason = 'missing' })
    } else {
        $item = Get-Item -LiteralPath $path
        $ok = $item.Length -eq [int64]$row.bytes
        if ($ok) { $ok = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLower() -eq $row.sha256 }
        if (-not $ok) { [void]$failures.Add([ordered]@{ path = $rel; reason = 'size/hash mismatch' }) }
    }
    $checked++
}
[ordered]@{
    root = $root
    checked_files = $checked
    mutable_git_metadata_skipped = $skippedGit
    failures = @($failures)
    ok = ($failures.Count -eq 0)
} | ConvertTo-Json -Depth 4
if ($failures.Count) { exit 1 } else { exit 0 }
