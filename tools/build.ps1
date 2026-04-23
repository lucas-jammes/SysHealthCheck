#Requires -Version 5.0
# tools/build.ps1 — Recompress template, embed into src/SysHealthCheck.ps1, compile exe
# Usage: .\tools\build.ps1

$root     = Split-Path $PSScriptRoot
$template = Join-Path $root 'template\report.html'
$ps1      = Join-Path $root 'src\SysHealthCheck.ps1'
$exe      = Join-Path $root 'dist\SysHealthCheck.exe'

# 1. Compress template → gzip+base64
Write-Host '[1/3] Compressing template...'
$bytes = [System.IO.File]::ReadAllBytes($template)
$ms    = New-Object System.IO.MemoryStream
$gz    = New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Compress)
$gz.Write($bytes, 0, $bytes.Length); $gz.Close()
$newB64 = [Convert]::ToBase64String($ms.ToArray())
Write-Host "    $([Math]::Round($bytes.Length/1KB,1)) KB -> $([Math]::Round($ms.Length/1KB,1)) KB gzip -> $($newB64.Length) chars b64"

# 2. Embed into PS1
Write-Host '[2/3] Embedding into SysHealthCheck.ps1...'
$content  = [System.IO.File]::ReadAllText($ps1, [System.Text.Encoding]::UTF8)
$marker   = '$TEMPLATE_GZ_B64 = '''
$startIdx = $content.IndexOf($marker) + $marker.Length
$endIdx   = $content.IndexOf("'`r`n", $startIdx)
if ($endIdx -lt 0) { $endIdx = $content.IndexOf("'`n", $startIdx) }
$content  = $content.Substring(0, $startIdx) + $newB64 + $content.Substring($endIdx)
$utf8bom  = New-Object System.Text.UTF8Encoding $true
[System.IO.File]::WriteAllText($ps1, $content, $utf8bom)

# 3. Compile exe
Write-Host '[3/3] Compiling exe...'
if (Test-Path $exe) { Remove-Item $exe -Force }
Invoke-PS2EXE $ps1 $exe -requireAdmin -ErrorAction Stop

Write-Host ''
Write-Host "Build complete: $exe"
Write-Host "Size: $([Math]::Round((Get-Item $exe).Length / 1KB)) KB"
