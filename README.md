# SysHealthCheck

Standalone Windows security healthcheck tool for N1 support. No dependencies, no installation. Produces a self-contained HTML report on the Desktop.

![Score ring, alert cards, disk health, open ports](https://github.com/lucas-jammes/SysHealthCheck/raw/master/preview.png)

## Usage

1. Download `SysHealthCheck.exe` from the [latest release](https://github.com/lucas-jammes/SysHealthCheck/releases/latest)
2. Get a free API key at [abuseipdb.com](https://www.abuseipdb.com/register) (1000 req/day free)
3. Create a file named `abuseipdb.key` in the same folder as the exe — paste your key inside (plain text, nothing else)
4. Right-click `SysHealthCheck.exe` → **Run as administrator**
5. Wait ~2 minutes (AbuseIPDB lookups on all external IPs)
6. The HTML report opens automatically on the Desktop

> Running without `abuseipdb.key`: the exe will prompt for a key at launch. Leave empty to skip IP reputation checks.

## What it analyzes

| Category | Details |
|---|---|
| Network connections | All established external connections checked against AbuseIPDB |
| Listening ports | Flags C2 ports, RDP, Telnet, SMB, FTP |
| Suspicious processes | Executables running from %TEMP%, encoded PowerShell commands |
| Disk health | Used space + temperature via SMART (Get-StorageReliabilityCounter) |
| Windows Update | Pending critical / important updates |
| Failed logons | Brute force detection (Event ID 4625, 24h / 7d) |

## Report

- Security score 0–100 (base 100, deductions per alert severity)
- Alerts ranked: **Critical** −20 / **High** −10 / **Medium** −5 / **Info** −1
- Collapsible alert cards with description + remediation
- PDF export via browser print
- Dark mode React UI, no internet required to open

## Requirements

- Windows 8+ (Windows 10/11 recommended)
- Administrator rights (required for Security event log + Windows Update COM)
- Internet access for AbuseIPDB lookups (optional — rest of the report works offline)

## AbuseIPDB key

The key is **never embedded in the exe**. It is read at runtime from:
1. `abuseipdb.key` file next to the exe
2. `ABUSEIPDB_API_KEY` environment variable
3. Interactive prompt at launch

Keep your key file on your USB drive alongside the exe. It is gitignored and never committed.
