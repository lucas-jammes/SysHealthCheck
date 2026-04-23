#Requires -Version 5.0
# SysHealthCheck.ps1 — Rapport sécurité Windows autonome (support N1)
# Aucune dépendance externe. Produit rapport_securite_AAAA-MM-JJ_HHMM.html sur le Bureau.
# Clé AbuseIPDB : fichier "abuseipdb.key" dans le même dossier que l'exe, ou variable d'env ABUSEIPDB_API_KEY.

Set-StrictMode -Off
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# ── Clé AbuseIPDB ─────────────────────────────────────────────────────────────
$exeDir  = Split-Path ([System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName)
$keyFile = Join-Path $exeDir 'abuseipdb.key'
$ABUSEIPDB_KEY = ''
if (Test-Path $keyFile) {
    $ABUSEIPDB_KEY = (Get-Content $keyFile -Raw).Trim()
} elseif ($env:ABUSEIPDB_API_KEY) {
    $ABUSEIPDB_KEY = $env:ABUSEIPDB_API_KEY
} else {
    $ABUSEIPDB_KEY = Read-Host 'Clé API AbuseIPDB (laisser vide pour ignorer)'
}
$MAX_ABUSE_IPS  = 20
$HIGH_RISK_CC   = @('CN','RU','KP','IR','SY','CU','VE','BY','NG','PK','MM')
$C2_PORTS       = @(4444,1234,31337,6666,8888,9999,12345,54321,65535,1337,6667)
$DATE_STR       = Get-Date -Format 'yyyy-MM-dd HH:mm'

# ── Template embarqué (gzip+base64) ───────────────────────────────────────────
$TEMPLATE_GZ_B64 = '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'

# ── Fonctions utilitaires ─────────────────────────────────────────────────────
function Expand-Template {
    $bytes = [Convert]::FromBase64String($TEMPLATE_GZ_B64)
    $ms  = New-Object System.IO.MemoryStream(,[byte[]]$bytes)
    $gz  = New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Decompress)
    $out = New-Object System.IO.MemoryStream
    $gz.CopyTo($out); $gz.Close()
    return [System.Text.Encoding]::UTF8.GetString($out.ToArray())
}

function Test-PrivateIP($ip) {
    return ($ip -match '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|::1|0\.0\.0\.0|fe80:|::)')
}

function Invoke-AbuseIPDB($ip) {
    try {
        $uri  = "https://api.abuseipdb.com/api/v2/check?ipAddress=$ip&maxAgeInDays=90"
        $hdrs = @{ Key = $ABUSEIPDB_KEY; Accept = 'application/json' }
        $r    = Invoke-RestMethod -Uri $uri -Headers $hdrs -Method Get -TimeoutSec 6
        return $r.data
    } catch { return $null }
}

function Format-GBStr($bytes) {
    $gb = [Math]::Round($bytes / 1GB, 1)
    return ($gb.ToString('N1') -replace '\.', ',') + ' GB'
}

# ── Collecte système ──────────────────────────────────────────────────────────
Write-Host '[1/7] Informations systeme...'
$hostname    = $env:COMPUTERNAME
$os          = Get-WmiObject Win32_OperatingSystem
$osName      = $os.Caption -replace 'Microsoft ',''
$osBuild     = $os.BuildNumber
$lastBoot    = $os.ConvertToDateTime($os.LastBootUpTime)
$currentUser = "$env:USERDOMAIN\$env:USERNAME"

# ── Connexions réseau + AbuseIPDB ─────────────────────────────────────────────
Write-Host '[2/7] Connexions reseau + AbuseIPDB...'
$networkRows = @()
try {
    $tcpAll  = Get-NetTCPConnection -State Established -ErrorAction Stop
    $extConns = $tcpAll | Where-Object { -not (Test-PrivateIP $_.RemoteAddress) -and $_.RemoteAddress -notmatch ':' } |
        Group-Object RemoteAddress | ForEach-Object {
            $ip     = $_.Name
            $sample = $_.Group | Sort-Object RemotePort | Select-Object -First 1
            $proc   = Get-Process -Id $sample.OwningProcess -ErrorAction SilentlyContinue
            [PSCustomObject]@{ IP=$ip; Port=$sample.RemotePort; ProcName=if($proc){$proc.Name}else{'inconnu'} }
        } | Select-Object -First $MAX_ABUSE_IPS

    foreach ($conn in $extConns) {
        Write-Host "  AbuseIPDB: $($conn.IP)..."
        $data    = Invoke-AbuseIPDB $conn.IP
        $score   = if ($data) { $data.abuseConfidenceScore } else { 0 }
        $country = if ($data -and $data.countryCode) { $data.countryCode } else { 'N/A' }
        $isp     = if ($data -and $data.isp) { $data.isp } else { 'N/A' }

        $note = ''
        if ($score -ge 80)                          { $note = "IP signalée comme malveillante ($score% confiance AbuseIPDB)" }
        elseif ($score -ge 30)                      { $note = "IP suspecte détectée par AbuseIPDB ($score% confiance)" }
        elseif ($HIGH_RISK_CC -contains $country)   { $note = "Connexion vers pays à risque ($country)" }
        else                                        { $note = "Connexion sortante — $isp" }

        $networkRows += [PSCustomObject]@{
            IP=$conn.IP; Abuse=$score; ISP=$isp
            Country=$country; Proc=$conn.ProcName; Port=$conn.Port; Note=$note
        }
    }
    $networkRows = $networkRows | Sort-Object Abuse -Descending
} catch { Write-Host "  Erreur collecte reseau: $_" }

# ── Ports en écoute ───────────────────────────────────────────────────────────
Write-Host '[3/7] Ports en ecoute...'
$portRows = @()
try {
    Get-NetTCPConnection -State Listen -ErrorAction Stop |
        Select-Object LocalPort, OwningProcess -Unique | Sort-Object LocalPort | ForEach-Object {
        $proc    = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        $portNum = $_.LocalPort
        $procNm  = if ($proc) { $proc.Name } else { 'inconnu' }
        $note    = switch ($portNum) {
            { $C2_PORTS -contains $_ }  { "Port associé aux outils C2/malwares — à investiguer immédiatement"; break }
            3389  { "Bureau à distance (RDP) — risque si accessible depuis Internet"; break }
            23    { "Telnet — protocole non chiffré, à désactiver impérativement"; break }
            21    { "FTP — protocole non chiffré, remplacer par SFTP/FTPS"; break }
            445   { "SMB — vecteur de propagation ransomware, filtrer via pare-feu"; break }
            135   { "RPC — restreindre aux réseaux internes de confiance"; break }
            22    { "SSH — vérifier que l'authentification par mot de passe est désactivée"; break }
            80    { "Serveur HTTP local ($procNm)"; break }
            443   { "Serveur HTTPS local ($procNm)"; break }
            default { "Port $portNum en écoute — $procNm" }
        }
        $portRows += [PSCustomObject]@{ Port=$portNum; Proc=$procNm; Note=$note }
    }
} catch {}

# ── Processus suspects ────────────────────────────────────────────────────────
Write-Host '[4/7] Processus suspects...'
$suspectProcs = @()
try {
    Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path } | ForEach-Object {
        $path   = $_.Path.ToLower()
        $sev    = ''; $reason = ''
        if ($path -match '\\temp\\|\\appdata\\local\\temp\\') {
            $sev = 'critique'; $reason = "Exécutable lancé depuis répertoire temporaire ($($_.Path))"
        } elseif ($_.Name -in @('powershell','pwsh')) {
            try {
                $cl = (Get-WmiObject Win32_Process -Filter "ProcessId=$($_.Id)" -ErrorAction Stop).CommandLine
                if ($cl -match '-[Ee]nc|-[Ee]ncodedCommand') {
                    $sev = 'élevé'; $reason = "PowerShell avec commande encodée (-EncodedCommand)"
                }
            } catch {}
        } elseif ($_.Name -in @('nc','ncat','netcat')) {
            $sev = 'critique'; $reason = "Outil de tunneling réseau détecté ($($_.Name))"
        }
        if ($sev) { $suspectProcs += [PSCustomObject]@{ Sev=$sev; Name=$_.Name; Reason=$reason } }
    }
} catch {}

# ── Disques — espace + SMART ──────────────────────────────────────────────────
Write-Host '[5/7] Disques...'
$diskRows     = @()
$drivesHealth = @()
try {
    Get-PSDrive -PSProvider FileSystem -ErrorAction Stop | Where-Object { $_.Used -ne $null } | ForEach-Object {
        $total = $_.Used + $_.Free
        if ($total -gt 0) {
            $pct = [Math]::Round($_.Used / $total * 100)
            $diskRows += [PSCustomObject]@{
                Label = ($_.Root.TrimEnd('\'))
                Pct   = $pct
                Used  = Format-GBStr $_.Used
                Total = Format-GBStr $total
            }
        }
    }
} catch {}
try {
    $physDisks = Get-PhysicalDisk -ErrorAction Stop
    # Températures via Get-StorageReliabilityCounter (Windows 8+)
    $relCounters = @{}
    try {
        $physDisks | Get-StorageReliabilityCounter -ErrorAction Stop | ForEach-Object {
            $relCounters[$_.DeviceId] = $_
        }
    } catch {}
    $physDisks | ForEach-Object {
        $status = if ($_.HealthStatus -eq 'Healthy') { 'ok' } else { 'degraded' }
        $rel    = $relCounters[$_.DeviceId]
        $temp   = if ($rel -and $rel.Temperature -gt 0) { [int]$rel.Temperature } else { 0 }
        $reallocd = if ($rel -and $rel.ReadErrorsTotal -gt 0) { [int]$rel.ReadErrorsTotal } else { 0 }
        $drivesHealth += [PSCustomObject]@{
            Name=($_.FriendlyName -replace "'","\'")
            Reallocated=$reallocd; Pending=0; Uncorrectable=0; Temp=$temp; Status=$status
        }
    }
} catch {
    try {
        Get-WmiObject Win32_DiskDrive | ForEach-Object {
            $status = if ($_.Status -eq 'OK') { 'ok' } else { 'degraded' }
            $drivesHealth += [PSCustomObject]@{
                Name=(if ($_.Model) { $_.Model } else { "Disque $($_.Index)" })
                Reallocated=0; Pending=0; Uncorrectable=0; Temp=0; Status=$status
            }
        }
    } catch {}
}

# ── Mises à jour Windows ──────────────────────────────────────────────────────
Write-Host '[6/7] Mises a jour...'
$pendingUpdates = @()
try {
    $sess    = New-Object -ComObject Microsoft.Update.Session
    $results = $sess.CreateUpdateSearcher().Search("IsInstalled=0 AND IsHidden=0 AND BrowseOnly=0")
    foreach ($u in $results.Updates) {
        $sev = try { $u.MsrcSeverity } catch { '' }
        $pendingUpdates += [PSCustomObject]@{ Title=$u.Title; Severity=$sev }
    }
} catch {}

# ── Échecs de connexion ───────────────────────────────────────────────────────
Write-Host '[7/7] Evenements securite...'
$failedLogons24h = 0; $failedLogons7d = 0
try {
    $failedLogons24h = (Get-WinEvent -FilterHashtable @{
        LogName='Security'; Id=4625; StartTime=(Get-Date).AddHours(-24)
    } -ErrorAction Stop).Count
    $failedLogons7d = (Get-WinEvent -FilterHashtable @{
        LogName='Security'; Id=4625; StartTime=(Get-Date).AddDays(-7)
    } -ErrorAction Stop).Count
} catch {}
$connCount  = try { (Get-NetTCPConnection -State Established -EA Stop).Count } catch { '?' }
$procCount  = try { (Get-Process -EA Stop).Count } catch { '?' }

# ── Moteur de règles ──────────────────────────────────────────────────────────
Write-Host 'Application des regles...'
$alerts   = @()
$alertId  = 1
function Add-Alert($sev, $short, $desc, $reco) {
    $script:alerts += [PSCustomObject]@{ Id=$script:alertId++; Sev=$sev; Short=$short; Desc=$desc; Reco=$reco }
}

# IPs malveillantes
foreach ($mip in ($networkRows | Where-Object { $_.Abuse -ge 80 })) {
    Add-Alert 'critique' "IP malveillante — $($mip.IP)" `
        "Connexion active vers <code>$($mip.IP)</code> (AbuseIPDB: <strong>$($mip.Abuse)%</strong>, $($mip.Country)). Processus: <code>$($mip.Proc)</code>." `
        "Bloquer l'IP immédiatement via le pare-feu Windows. Analyser <code>$($mip.Proc)</code> avec un antivirus. Envisager l'isolation de la machine."
}
# IPs suspectes (groupées)
$suspIPs = @($networkRows | Where-Object { $_.Abuse -ge 30 -and $_.Abuse -lt 80 })
if ($suspIPs.Count -gt 0) {
    $ipList = ($suspIPs | ForEach-Object { "$($_.IP) ($($_.Abuse)%)" }) -join ', '
    Add-Alert 'moyen' "$($suspIPs.Count) IP(s) suspecte(s) détectée(s)" `
        "$($suspIPs.Count) connexion(s) avec score AbuseIPDB modéré : <code>$ipList</code>." `
        "Identifier les processus responsables et vérifier leur légitimité. Surveiller l'activité réseau."
}
# Pays à risque
foreach ($rip in ($networkRows | Where-Object { ($HIGH_RISK_CC -contains $_.Country) -and $_.Abuse -lt 80 })) {
    Add-Alert 'élevé' "Connexion vers pays à risque ($($rip.Country))" `
        "Connexion vers <code>$($rip.IP)</code> ($($rip.ISP)) en <strong>$($rip.Country)</strong> via <code>$($rip.Proc)</code>." `
        "Vérifier si cette connexion est attendue pour ce logiciel. Bloquer le pays via pare-feu si non nécessaire."
}
# Ports C2
foreach ($cp in ($portRows | Where-Object { $C2_PORTS -contains $_.Port })) {
    Add-Alert 'critique' "Port C2 en écoute — $($cp.Port)/TCP" `
        "Le port <code>$($cp.Port)/TCP</code>, associé aux frameworks C2 et malwares, est en écoute (processus: <code>$($cp.Proc)</code>)." `
        "Arrêter immédiatement le processus <code>$($cp.Proc)</code>. Scanner la machine avec un antivirus. Isoler du réseau si compromis."
}
# RDP
if ($portRows | Where-Object { $_.Port -eq 3389 }) {
    Add-Alert 'élevé' "Bureau à distance (RDP) exposé" `
        "Le port <code>3389/TCP</code> est en écoute. Si accessible depuis Internet, c'est une cible privilégiée pour les attaques par force brute." `
        "Restreindre l'accès RDP via le pare-feu aux seules IPs autorisées. Activer NLA (Network Level Authentication). Utiliser un VPN."
}
# Telnet
if ($portRows | Where-Object { $_.Port -eq 23 }) {
    Add-Alert 'moyen' "Service Telnet actif" `
        "Telnet (<code>23/TCP</code>) est en écoute. Ce protocole transmet données et mots de passe en clair." `
        "Désactiver le service Telnet et basculer sur SSH (<code>22/TCP</code>)."
}
# SMB
if ($portRows | Where-Object { $_.Port -eq 445 }) {
    Add-Alert 'élevé' "SMB exposé (port 445)" `
        "Le port <code>445/TCP</code> (SMB) est en écoute. Vecteur historique des ransomwares WannaCry et NotPetya." `
        "Bloquer le port 445 sur le pare-feu si les partages réseau ne sont pas nécessaires. Maintenir Windows à jour."
}
# Brute force
if ($failedLogons24h -gt 20) {
    Add-Alert 'élevé' "Possible brute force ($failedLogons24h échecs/24h)" `
        "<strong>$failedLogons24h</strong> échecs de connexion en 24h (<strong>$failedLogons7d</strong> sur 7 jours). Possible attaque par dictionnaire." `
        "Consulter l'Observateur d'événements (ID 4625). Bloquer les IPs source. Activer le verrouillage de compte."
} elseif ($failedLogons24h -gt 5) {
    Add-Alert 'moyen' "Échecs de connexion ($failedLogons24h en 24h)" `
        "<strong>$failedLogons24h</strong> échecs de connexion en 24h. Peut indiquer une erreur de configuration ou une tentative d'intrusion." `
        "Vérifier l'Observateur d'événements (ID 4625) pour identifier l'origine des échecs."
} elseif ($failedLogons24h -gt 0) {
    Add-Alert 'info' "Échecs de connexion ($failedLogons24h en 24h)" `
        "<strong>$failedLogons24h</strong> échec(s) de connexion enregistré(s) en 24h." `
        "Vérifier si ces échecs sont attendus (oubli de mot de passe, service mal configuré)."
}
# Processus suspects
foreach ($sp in $suspectProcs) {
    Add-Alert $sp.Sev "Processus suspect: $($sp.Name)" `
        "$($sp.Reason)." `
        "Analyser le chemin et les arguments du processus. Terminer si suspect et lancer un scan antivirus complet."
}
# Mises à jour
$critUpd = @($pendingUpdates | Where-Object { $_.Severity -eq 'Critical' })
$impUpd  = @($pendingUpdates | Where-Object { $_.Severity -eq 'Important' })
$othUpd  = @($pendingUpdates | Where-Object { $_.Severity -notin @('Critical','Important') -and $_.Title })
if ($critUpd.Count -gt 0) {
    Add-Alert 'élevé' "$($critUpd.Count) mise(s) à jour critique(s) en attente" `
        "<strong>$($critUpd.Count)</strong> correctif(s) marqué(s) <em>Critique</em> non installé(s). Ces patches corrigent souvent des failles exploitables activement." `
        "Appliquer les mises à jour via Windows Update immédiatement puis redémarrer."
} elseif ($impUpd.Count -gt 0) {
    Add-Alert 'moyen' "$($impUpd.Count) mise(s) à jour importante(s) en attente" `
        "<strong>$($impUpd.Count)</strong> mise(s) à jour marquée(s) <em>Importante</em> non installée(s)." `
        "Planifier l'installation lors de la prochaine fenêtre de maintenance."
} elseif ($othUpd.Count -gt 0) {
    Add-Alert 'info' "$($othUpd.Count) mise(s) à jour optionnelle(s)" `
        "<strong>$($othUpd.Count)</strong> mise(s) à jour optionnelle(s) disponible(s)." `
        "Appliquer lors du prochain cycle de maintenance."
}
# Disques dégradés
foreach ($dd in ($drivesHealth | Where-Object { $_.Status -ne 'ok' })) {
    Add-Alert 'élevé' "Disque défaillant: $($dd.Name)" `
        "Le disque <code>$($dd.Name)</code> présente un état de santé dégradé selon les diagnostics système." `
        "Effectuer une sauvegarde immédiate. Prévoir le remplacement du disque."
}
# Espace disque
foreach ($d in $diskRows) {
    if ($d.Pct -ge 90) {
        Add-Alert 'moyen' "Espace critique — $($d.Label) ($($d.Pct)%)" `
            "Le disque <code>$($d.Label)</code> est utilisé à <strong>$($d.Pct)%</strong> ($($d.Used) / $($d.Total)). Risque d'instabilité système." `
            "Libérer de l'espace : vider la corbeille, nettoyer les fichiers temporaires (cleanmgr), désinstaller les programmes inutilisés."
    } elseif ($d.Pct -ge 80) {
        Add-Alert 'info' "Espace faible — $($d.Label) ($($d.Pct)%)" `
            "Le disque <code>$($d.Label)</code> est utilisé à <strong>$($d.Pct)%</strong> ($($d.Used) / $($d.Total))." `
            "Prévoir un nettoyage ou une extension de stockage."
    }
}

# ── Score ─────────────────────────────────────────────────────────────────────
$score = 100
$sevW  = @{ 'critique'=-20; 'élevé'=-10; 'moyen'=-5; 'info'=-1 }
foreach ($a in $alerts) { $score += $sevW[$a.Sev] }
$score = [Math]::Max(0, $score)

# ── Construction du JS ────────────────────────────────────────────────────────
Write-Host "Generation du rapport (score: $score)..."

# ALERTS
$alertsContent = ($alerts | ForEach-Object {
    $sevU  = $_.Sev.ToUpper()
    $sh    = $_.Short -replace "'","\'"
    "{id:$($_.Id), sev:'$($_.Sev)', short:'$sh', title: <><span className=`"alert-sev-text $($_.Sev)`">$sevU</span> — $sh</>, desc: <>$($_.Desc)</>, reco: <>$($_.Reco)</>}"
}) -join ",`n"

# NETWORK
$networkContent = ($networkRows | ForEach-Object {
    $nt = $_.Note -replace "'","\'"
    $is = $_.ISP  -replace "'","\'"
    "{ip:'$($_.IP)', abuse:$($_.Abuse), isp:'$is', country:'$($_.Country)', proc:'$($_.Proc)', note:'$nt'}"
}) -join ",`n"

# PORTS
$portsContent = ($portRows | Select-Object -First 30 | ForEach-Object {
    $nt = $_.Note -replace "'","\'"
    "{port:$($_.Port), proc:'$($_.Proc)', note:'$nt'}"
}) -join ",`n"

# DISKS
$disksContent = ($diskRows | ForEach-Object {
    $lbl = $_.Label -replace '\\',''
    "{label:'$lbl', pct:$($_.Pct), used:'$($_.Used)', total:'$($_.Total)'}"
}) -join ",`n"

# DRIVES_HEALTH
$drivesContent = ($drivesHealth | ForEach-Object {
    "{name:'$($_.Name)', reallocated:$($_.Reallocated), pending:$($_.Pending), uncorrectable:$($_.Uncorrectable), temp:$($_.Temp), status:'$($_.Status)'}"
}) -join ",`n"

# PROCS_SUSPECTS
$procsContent = ($suspectProcs | ForEach-Object {
    $nm = $_.Name   -replace "'","\'"
    $rs = $_.Reason -replace "'","\'"
    "{sev:'$($_.Sev)', name:'$nm', reason:'$rs'}"
}) -join ",`n"

# SYSINFO
$sysinfoContent = @"
['OS',          '$osName'],
    ['Build',       '$osBuild'],
    ['Machine',     '$hostname'],
    ['Analyse',     '$DATE_STR'],
    ['Connexions',  '$connCount actives'],
    ['Processus',   '$procCount en cours']
"@

# ── Injection dans template ───────────────────────────────────────────────────
$html = Expand-Template

$html = $html -replace 'const SCORE = \d+',                       "const SCORE = $score"
$html = $html -replace '(?s)const ALERTS = \[.*?\];',             "const ALERTS = [`n$alertsContent`n];"
$html = $html -replace '(?s)const NETWORK = \[.*?\];',            "const NETWORK = [`n$networkContent`n];"
$html = $html -replace '(?s)const PORTS = \[.*?\];',              "const PORTS = [`n$portsContent`n];"
$html = $html -replace '(?s)const DISKS = \[.*?\];',              "const DISKS = [`n$disksContent`n];"
$html = $html -replace '(?s)const DRIVES_HEALTH = \[.*?\];',      "const DRIVES_HEALTH = [`n$drivesContent`n];"
$html = $html -replace '(?s)const PROCS_SUSPECTS = \[.*?\];',     "const PROCS_SUSPECTS = [`n$procsContent`n];"
$html = $html -replace "(?s)const sysinfo = \[.*?\];",            "const sysinfo = [`n    $sysinfoContent`n  ];"

# ── Écriture ──────────────────────────────────────────────────────────────────
$outDir  = $exeDir
$outFile = "rapport_securite_$(Get-Date -Format 'yyyy-MM-dd_HHmm').html"
$outPath = Join-Path $outDir $outFile
$utf8bom = New-Object System.Text.UTF8Encoding $true
[System.IO.File]::WriteAllText($outPath, $html, $utf8bom)

Write-Host ''
Write-Host '======================================='
Write-Host "  Fichier : $outPath"
Write-Host "  Score   : $score / 100"
Write-Host "  Alertes : $($alerts.Count) ($(@($alerts|Where-Object{$_.Sev-eq'critique'}).Count)C / $(@($alerts|Where-Object{$_.Sev-eq'élevé'}).Count)E / $(@($alerts|Where-Object{$_.Sev-eq'moyen'}).Count)M / $(@($alerts|Where-Object{$_.Sev-eq'info'}).Count)I)"
Write-Host '======================================='

Start-Process $outPath
