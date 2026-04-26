#Requires -Version 5.0
# tools/build.ps1 — Recompress template, embed into src/SysHealthCheck.ps1, package dist/

$root     = Split-Path $PSScriptRoot
$template = Join-Path $root 'template\report.html'
$srcPs1   = Join-Path $root 'src\SysHealthCheck.ps1'
$distPs1  = Join-Path $root 'dist\_SysHealthCheck.ps1'
$distBat  = Join-Path $root 'dist\Lancer_SysHealthCheck.bat'

# 1. Compress template → gzip+base64
Write-Host '[1/3] Compressing template...'
$bytes = [System.IO.File]::ReadAllBytes($template)
$ms    = New-Object System.IO.MemoryStream
$gz    = New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Compress)
$gz.Write($bytes, 0, $bytes.Length); $gz.Close()
$xorKey  = [byte]42
$gzBytes = $ms.ToArray()
for ($i = 0; $i -lt $gzBytes.Length; $i++) { $gzBytes[$i] = $gzBytes[$i] -bxor $xorKey }
$newB64 = [Convert]::ToBase64String($gzBytes)
Write-Host "    $([Math]::Round($bytes.Length/1KB,1)) KB -> $([Math]::Round($ms.Length/1KB,1)) KB gzip -> $($newB64.Length) chars b64"

# 2. Embed into PS1
Write-Host '[2/3] Embedding into SysHealthCheck.ps1...'
$content  = [System.IO.File]::ReadAllText($srcPs1, [System.Text.Encoding]::UTF8)
$marker   = '$TEMPLATE_GZ_B64 = '''
$startIdx = $content.IndexOf($marker) + $marker.Length
$endIdx   = $content.IndexOf("'`r`n", $startIdx)
if ($endIdx -lt 0) { $endIdx = $content.IndexOf("'`n", $startIdx) }
$content  = $content.Substring(0, $startIdx) + $newB64 + $content.Substring($endIdx)
$utf8bom  = New-Object System.Text.UTF8Encoding $true
[System.IO.File]::WriteAllText($srcPs1, $content, $utf8bom)

# 3. Copy PS1 + generate BAT
Write-Host '[3/3] Packaging dist...'
if (-not (Test-Path (Split-Path $distPs1))) { New-Item -ItemType Directory -Path (Split-Path $distPs1) | Out-Null }
Copy-Item $srcPs1 $distPs1 -Force

$bat = "@echo off`r`ntitle SysHealthCheck `U{2014} Audit Sécurité`r`nmode con cols=110 lines=45`r`npowershell -ExecutionPolicy Bypass -NoProfile -File `"%~dp0_SysHealthCheck.ps1`"`r`necho.`r`necho  Appuyez sur une touche pour fermer...`r`npause > nul`r`n"
[System.IO.File]::WriteAllText($distBat, $bat, [System.Text.Encoding]::ASCII)

Write-Host ''
Write-Host "Build complete:"
Write-Host "  $distBat"
Write-Host "  $distPs1  ($([Math]::Round((Get-Item $distPs1).Length / 1KB)) KB)"
