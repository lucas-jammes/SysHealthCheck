$html = Get-Content "C:\Users\Lucas\Desktop\claude_security_report\Template.html" -Raw -Encoding UTF8

# ── SCORE ─────────────────────────────────────────────────────────────
$html = [regex]::Replace($html, 'const SCORE = \d+;', 'const SCORE = 23;')

# ── ALERTS ───────────────────────────────────────────────────────────
$newAlerts = @'
const ALERTS = [
{ id:1, sev:"critique", short: "Malware mimikatz actif — dump credentials LSASS",
  title: <><code>mimikatz.exe</code> renommé en <code>svchost32.exe</code></>,
  desc:  <>Détecté dans <code>%TEMP%</code> après suppression par Defender. SHA256: <code>92d4c7c4e3f3b1a2...</code>. Dump credentials LSASS possible.</>,
  reco:  <>Isoler la machine. Scanner avec MSERT. Changer tous les mots de passe depuis une machine saine.</>
},
{ id:2, sev:"critique", short: "Reverse shell actif — connexion Tor port 4444",
  title: <><code>nc.exe</code> — reverse shell vers Tor exit node port 4444</>,
  desc:  <>PID 3912 connecté à <code>185.220.101.47</code> (AbuseIPDB: 98). Clé de démarrage <code>HKLM\Run\WindowsUpdate</code> pointe vers ce binaire.</>,
  reco:  <>Tuer : <code>taskkill /F /PID 3912</code>. Supprimer la clé Run. Analyser les logs réseau des 30 derniers jours.</>
},
{ id:3, sev:"critique", short: "Backdoor — compte admin_svc créé par SYSTEM à 03h17",
  title: <>Backdoor — compte admin <code>admin_svc</code> créé par SYSTEM</>,
  desc:  <>Compte créé le 2026-04-21 à 03:17 par <code>SYSTEM</code>, ajouté aux Administrateurs. Aucune installation active à cet horaire.</>,
  reco:  <>Supprimer : <code>net user admin_svc /delete</code>. Investiguer le vecteur d'entrée.</>
},
{ id:4, sev:"critique", short: "Persistance — tâche planifiée avec payload Base64 obfusqué",
  title: <>Persistance — tâche planifiée <code>\Microsoft\Windows\Update\Svc</code> chiffrée</>,
  desc:  <>Commande : <code>powershell -enc JABjAD0ATgBlAHcALQBPAGIAagBlAGMA...</code> (4 KB). Créée le 2026-04-20 à 23:58, déclenchée toutes les 5 minutes.</>,
  reco:  <>Supprimer : <code>schtasks /delete /tn "\Microsoft\Windows\Update\Svc" /f</code>. Décoder le payload.</>
},
{ id:5, sev:"eleve", short: "MITM HTTPS possible — faux certificat DigiCert injecté",
  title: <>Faux certificat racine <code>CN=DigiCert Global Root</code> — thumbprint non officiel</>,
  desc:  <>Thumbprint <code>A8985D3A65E5E5C4B2D7D66D40C6DD2FB19C5436</code> différent du thumbprint officiel DigiCert. Ajout le 2026-04-19. Permet MITM HTTPS.</>,
  reco:  <>Supprimer via <code>certlm.msc</code>. Vérifier tous les certificats racines contre la liste Microsoft CTL.</>
},
{ id:6, sev:"eleve", short: "Fichier hosts falsifié — mises à jour sécurité bloquées",
  title: <>Fichier <code>hosts</code> falsifié — 8 redirections suspectes</>,
  desc:  <>Entrées : <code>windowsupdate.microsoft.com 127.0.0.1</code>, <code>defender.microsoft.com 127.0.0.1</code>, <code>virustotal.com 127.0.0.1</code>. Bloque les mises à jour de sécurité.</>,
  reco:  <>Restaurer le fichier hosts original. Supprimer toutes les entrées non-standard.</>
},
{ id:7, sev:"eleve", short: "Persistance WMI — script exécuté à chaque connexion",
  title: <>Persistance WMI — <code>__EventConsumer</code> au logon</>,
  desc:  <><code>FilterName: WindowsPerf</code> exécute <code>%APPDATA%\svchost.ps1</code> à chaque connexion utilisateur. Technique de persistance furtive.</>,
  reco:  <>Supprimer : <code>Get-WMIObject -Namespace root\subscription -Class __EventFilter | Remove-WMIObject</code>.</>
},
{ id:8, sev:"eleve", short: "Defender désactivé via registry — machine sans protection",
  title: <>Defender désactivé — DisableAntiSpyware=1 via registry</>,
  desc:  <>Clé <code>HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware = 1</code>. Protection temps réel inactive depuis 14h.</>,
  reco:  <><code>reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /f</code></>
},
{ id:9, sev:"eleve", short: "SMBv1 actif — surface EternalBlue / WannaCry",
  title: <>SMBv1 actif — surface EternalBlue</>,
  desc:  <><code>SMB1Protocol</code> actif. Vecteur WannaCry / NotPetya, exploitable sur réseau local.</>,
  reco:  <><code>Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol</code></>
},
{ id:10, sev:"moyen", short: "PowerShell ExecutionPolicy Bypass global",
  title: <>PowerShell ExecutionPolicy Bypass global</>,
  desc:  <>Tout script <code>.ps1</code> s'exécute sans restriction. Facilite l'exécution de payloads.</>,
  reco:  <><code>Set-ExecutionPolicy RemoteSigned -Scope LocalMachine</code></>
},
{ id:11, sev:"moyen", short: "RDP actif sans NLA — port 3389 exposé",
  title: <>RDP sans NLA — port 3389 exposé</>,
  desc:  <>Remote Desktop actif, NLA désactivée. Login Windows accessible sans pré-authentification.</>,
  reco:  <>Activer NLA via <code>sysdm.cpl</code> ou registry.</>
},
{ id:12, sev:"moyen", short: "DLL hijacking — version.dll non signé dans Downloads",
  title: <>DLL hijacking — <code>version.dll</code> non signé dans Downloads</>,
  desc:  <><code>C:\Users\Lucas\Downloads\version.dll</code> chargé par Spotify avant System32.</>,
  reco:  <>Supprimer le fichier.</>
},
{ id:13, sev:"moyen", short: "Compte admin Lucas sans mot de passe requis",
  title: <>Compte admin <code>Lucas</code> — PasswordRequired: false</>,
  desc:  <>Compte admin local sans mot de passe obligatoire. Accès physique = élévation directe.</>,
  reco:  <>Définir un mot de passe : <code>net user Lucas *</code></>
},
{ id:14, sev:"info", short: "Disque Kingston — 47 secteurs réalloués (dégradation)",
  title: <>Disque Kingston — 47 secteurs réalloués (SMART 5)</>,
  desc:  <>KINGSTON SFYRS1000G : attribut SMART 5 = 47. Signe de dégradation physique.</>,
  reco:  <>Sauvegarder immédiatement. Surveiller l'évolution. Prévoir remplacement.</>
},
{ id:15, sev:"info", short: "Disque H: à 91% — espace libre critique",
  title: <>Disque H: à 91% de capacité</>,
  desc:  <>847 GB utilisés / 931 GB total. Moins de 84 GB libres.</>,
  reco:  <>Libérer de l'espace via WinDirStat.</>
},
{ id:16, sev:"info", short: "Erreurs ACPI RTC à chaque démarrage",
  title: <>Erreurs ACPI RTC à chaque démarrage — Event ID 21</>,
  desc:  <>3 occurrences par démarrage, code <code>0xC0000001</code>.</>,
  reco:  <>Vérifier les mises à jour BIOS/UEFI.</>
}];
'@
$html = [regex]::Replace($html, '(?s)const ALERTS = \[.*?\];(?=\s*\n)', $newAlerts)

# ── NETWORK ──────────────────────────────────────────────────────────
$newNetwork = @'
const NETWORK = [
{ ip: "185.220.101.47", abuse: 98, isp: "Tor exit node",  country: "🇩🇪", proc: "nc.exe",             note: "Reverse shell actif — ordinateur compromis" },
{ ip: "194.165.16.11",  abuse: 87, isp: "Serverius BV",   country: "🇳🇱", proc: "svchost32.exe",      note: "Serveur C2 identifié — botnet actif" },
{ ip: "45.142.212.100", abuse: 65, isp: "Aeza Group",     country: "🇷🇺", proc: "svchost.exe",        note: "Hébergeur bulletproof — exfiltration suspectée" },
{ ip: "37.120.233.226", abuse: 31, isp: "M247 Europe",    country: "🇷🇴", proc: "unknown (PID 5544)", note: "Processus non résolu — origine inconnue" },
{ ip: "160.79.104.10",  abuse: 37, isp: "Anthropic",      country: "🇺🇸", proc: "claude.exe",         note: "Faux positif — IP Anthropic partagée" },
{ ip: "91.108.4.135",   abuse: 12, isp: "Telegram",       country: "🇩🇪", proc: "Telegram.exe",       note: "Messagerie Telegram — à surveiller" },
{ ip: "34.149.66.137",  abuse: 19, isp: "Google LLC",     country: "🇺🇸", proc: "claude.exe",         note: "Faux positif — CDN Google pour l'API Claude" },
{ ip: "172.64.147.231", abuse: 0,  isp: "Cloudflare",     country: "🇺🇸", proc: "LeagueClient",       note: "CDN Riot Games — normal en session League" },
{ ip: "4.208.165.242",  abuse: 0,  isp: "Microsoft",      country: "🇮🇪", proc: "MsMpEng",            note: "Télémétrie Defender — normal" },
{ ip: "155.133.248.43", abuse: 0,  isp: "Valve",          country: "🇳🇱", proc: "steam.exe",          note: "Serveur Steam — synchronisation cloud" },
{ ip: "3.74.145.219",   abuse: 0,  isp: "AWS",            country: "🇩🇪", proc: "LeagueClient",       note: "Serveur Riot Games hébergé sur AWS Frankfurt" },
{ ip: "96.17.207.142",  abuse: 2,  isp: "Akamai",         country: "🇫🇷", proc: "RiotClientServices", note: "CDN Akamai Riot — vérification de licence" }];
'@
$html = [regex]::Replace($html, '(?s)const NETWORK = \[.*?\];(?=\s*\n)', $newNetwork)

# ── PORTS ─────────────────────────────────────────────────────────────
$newPorts = @'
const PORTS = [
{ port: 4444, proc: "nc.exe",          note: "Reverse shell actif" },
{ port: 3389, proc: "TermService",     note: "RDP — NLA désactivée" },
{ port: 5000, proc: "python.exe",      note: "Flask local (dwnldr)" },
{ port: 445,  proc: "System",          note: "SMBv1 actif" },
{ port: 139,  proc: "System",          note: "NetBIOS" },
{ port: 2179, proc: "vmms.exe",        note: "Hyper-V" },
{ port: 2999, proc: "LeagueOfLegends", note: "P2P local" }];
'@
$html = [regex]::Replace($html, '(?s)const PORTS = \[.*?\];(?=\s*\n)', $newPorts)

# ── DISKS ─────────────────────────────────────────────────────────────
$newDisks = @'
const DISKS = [
{ label: "C: (Windows)",  pct: 88, used: "818 GB", total: "930 GB" },
{ label: "H: (HDD)",      pct: 91, used: "847 GB", total: "931 GB" },
{ label: "S: (Kingston)", pct: 75, used: "349 GB", total: "465 GB" }];
'@
$html = [regex]::Replace($html, '(?s)const DISKS = \[.*?\];(?=\s*\n)', $newDisks)

# ── DRIVES_HEALTH ─────────────────────────────────────────────────────
$newDrives = @'
const DRIVES_HEALTH = [
{ name: "Samsung SSD 970 EVO Plus 500GB",  reallocated: 0,  pending: 0,  uncorrectable: 0, temp: 41, status: "ok" },
{ name: "KINGSTON SFYRS1000G (SSD 932GB)", reallocated: 47, pending: 3,  uncorrectable: 0, temp: 38, status: "warn" },
{ name: "ST1000DX001 HDD 932GB",           reallocated: 0,  pending: 12, uncorrectable: 2, temp: 51, status: "warn" }];
'@
$html = [regex]::Replace($html, '(?s)const DRIVES_HEALTH = \[.*?\];(?=\s*\n)', $newDrives)

# ── PROCESSUS SUSPECTS ────────────────────────────────────────────────
$newProcs = @'
const PROCS_SUSPECTS = [
{ sev: "critique", name: "svchost32.exe", pid: 3912, reason: "Imite svchost.exe — exécuté depuis %TEMP%, hors System32, non signé Microsoft" },
{ sev: "critique", name: "nc.exe",        pid: 4401, reason: "Netcat — outil de reverse shell, connexion active vers 185.220.101.47:4444" },
{ sev: "eleve",    name: "svchost.ps1",   pid: 5102, reason: "Script PowerShell dans %APPDATA%, lancé par WMI EventConsumer à chaque logon" },
{ sev: "moyen",    name: "python.exe",    pid: 7834, reason: "Processus sans fenêtre visible, chemin inhabituel : C:\\Users\\Lucas\\Downloads\\tools\\" }];
'@
$html = [regex]::Replace($html, '(?s)const PROCS_SUSPECTS = \[.*?\];', $newProcs)

# ── MISES À JOUR ──────────────────────────────────────────────────────
$oldUpdates = @'
        <div className="update-item-sm">
          <div className="update-name-sm">Defender Antivirus</div>
          <div className="update-meta-sm">v1.449.232.0 · 1521,4 MB</div>
        </div>
        <div className="no-critical">✓ Aucune mise à jour critique</div>
'@
$newUpdates = @'
        <div className="update-item-sm" style={{borderLeft: '3px solid var(--critique)', paddingLeft: '8px'}}>
          <div className="update-name-sm" style={{color: 'var(--critique)'}}>Windows 11 KB5055523</div>
          <div className="update-meta-sm">Correctif sécurité critique · Patch Tuesday avril 2026</div>
        </div>
        <div className="update-item-sm" style={{borderLeft: '3px solid var(--critique)', paddingLeft: '8px'}}>
          <div className="update-name-sm" style={{color: 'var(--critique)'}}>Defender Antivirus</div>
          <div className="update-meta-sm">v1.449.100.0 → v1.449.232.0 · Signatures obsolètes de 4 jours</div>
        </div>
        <div className="update-item-sm" style={{borderLeft: '3px solid var(--eleve)', paddingLeft: '8px'}}>
          <div className="update-name-sm" style={{color: 'var(--eleve)'}}>Windows 11 KB5054979</div>
          <div className="update-meta-sm">Correctif élévation de privilèges · En attente depuis 12 jours</div>
        </div>
        <div className="update-item-sm">
          <div className="update-name-sm">Microsoft Edge 134.0.3124.72</div>
          <div className="update-meta-sm">Mise à jour navigateur · Non critique</div>
        </div>
'@
$html = $html.Replace($oldUpdates, $newUpdates)

# ── METADATA ──────────────────────────────────────────────────────────
$html = $html -replace "'2026-04-21 · 22:10'", "'2026-04-22 (DEMO)'"
$html = $html -replace "'Analyse', '2026-04-21 22:10'", "'Analyse', '2026-04-22 (DEMO)'"

$out = "C:\Users\Lucas\Desktop\claude_security_report\healthcheck_DEMO.html"
[System.IO.File]::WriteAllText($out, $html, [System.Text.Encoding]::UTF8)
Write-Host "OK - $out"
