#Requires -Version 5.0
# SysHealthCheck.ps1 — Rapport sécurité Windows autonome (support N1)
# Aucune dépendance externe. Produit rapport_securite_AAAA-MM-JJ_HHMM.html sur le Bureau.
# Clé AbuseIPDB : fichier "abuseipdb.key" dans le même dossier que l'exe, ou variable d'env ABUSEIPDB_API_KEY.

Set-StrictMode -Off
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# ── Clé AbuseIPDB ─────────────────────────────────────────────────────────────
$keyFile = Join-Path $PSScriptRoot 'abuseipdb.key'
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
$outDir  = $PSScriptRoot
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
