#Requires -Version 5.0
param()
$srcPs1 = Join-Path (Split-Path $PSScriptRoot) 'src\SysHealthCheck.ps1'
$xorKey = [byte]42

$lines = [System.IO.File]::ReadAllLines($srcPs1, [System.Text.Encoding]::UTF8)
$out   = [System.Collections.Generic.List[string]]::new()
$inHere    = $false
$varName   = ''
$hereLines = [System.Collections.Generic.List[string]]::new()
$indent    = ''

foreach ($line in $lines) {
    if (-not $inHere -and $line -match '(\$\w+)\s*=\s*@''$') {
        $inHere  = $true
        $varName = $Matches[1].Trim()   # e.g. "$nativeSrc"
        $hereLines.Clear()
        $indent  = ($line -replace '(\s*).*','$1')
        continue
    }
    if ($inHere -and $line -eq "'@") {
        $inHere = $false
        $src   = ($hereLines -join "`n") + "`n"
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($src)
        for ($j = 0; $j -lt $bytes.Length; $j++) { $bytes[$j] = $bytes[$j] -bxor $xorKey }
        $b64 = [Convert]::ToBase64String($bytes)
        $vn  = $varName.TrimStart('$')  # e.g. "nativeSrc"
        # Build lines without tricky interpolation
        $line1 = $indent + '$' + $vn + '_xb64 = ' + "'" + $b64 + "'"
        $line2 = $indent + '$' + $vn + ' = [System.Text.Encoding]::UTF8.GetString(([byte[]](([Convert]::$xd($' + $vn + '_xb64)) | ForEach-Object { $_ -bxor $xk })))'
        $out.Add($line1)
        $out.Add($line2)
        Write-Host "Encoded $varName ($($src.Length) bytes)"
        continue
    }
    if ($inHere) { $hereLines.Add($line); continue }
    $out.Add($line)
}

$utf8bom = New-Object System.Text.UTF8Encoding $true
[System.IO.File]::WriteAllLines($srcPs1, $out.ToArray(), $utf8bom)
Write-Host "Done - $($out.Count) lines written"
