#Requires -Version 5.0
# healthcheck_client.ps1 — Rapport sécurité Windows autonome (support N1)
# Aucune dépendance externe. Produit rapport_securite_AAAA-MM-JJ_HHMM.html sur le Bureau.

Set-StrictMode -Off
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# ── Configuration ─────────────────────────────────────────────────────────────
$ABUSEIPDB_KEY  = '833e79cc91c3f650b84bacf0435c6957ffd78289bb2f1267ea6486ece72a8b738571b569629aa3b1'
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
    $extConns = $tcpAll | Where-Object { -not (Test-PrivateIP $_.RemoteAddress) } |
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
        $country = if ($data -and $data.countryCode) { $data.countryCode } else { '??' }
        $isp     = if ($data -and $data.isp) { $data.isp } else { 'inconnu' }

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
$desktop = [Environment]::GetFolderPath('Desktop')
$outFile = "rapport_securite_$(Get-Date -Format 'yyyy-MM-dd_HHmm').html"
$outPath = Join-Path $desktop $outFile
$utf8bom = New-Object System.Text.UTF8Encoding $true
[System.IO.File]::WriteAllText($outPath, $html, $utf8bom)

Write-Host ''
Write-Host '======================================='
Write-Host "  Fichier : $outPath"
Write-Host "  Score   : $score / 100"
Write-Host "  Alertes : $($alerts.Count) ($(@($alerts|Where-Object{$_.Sev-eq'critique'}).Count)C / $(@($alerts|Where-Object{$_.Sev-eq'élevé'}).Count)E / $(@($alerts|Where-Object{$_.Sev-eq'moyen'}).Count)M / $(@($alerts|Where-Object{$_.Sev-eq'info'}).Count)I)"
Write-Host '======================================='

Start-Process $outPath
