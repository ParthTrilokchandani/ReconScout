# ReconScout v2.1

<p align="center">
  <img src="recon-scout.png" alt="Agent P - WhatsApp Privacy Shield" width="480"/>
</p>

<p align="center">
  <b>Version 2.1</b> · Created by <b>Agent P</b><br/>
ReconScout is a professional-grade, modular Python reconnaissance framework designed for
penetration testers, security engineers, and red team operators. Inspired by Nmap,
Recon-ng, and Amass — built as a clean, extensible single-tool replacement.
</p>

```
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗███████╗ ██████╗ ██████╗ ██╗   ██╗████████╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██╔════╝██╔════╝██╔═══██╗██║   ██║╚══██╔══╝
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║███████╗██║     ██║   ██║██║   ██║   ██║
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║╚════██║██║     ██║   ██║██║   ██║   ██║
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║███████║╚██████╗╚██████╔╝╚██████╔╝   ██║
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═════╝  ╚═════╝    ╚═╝
```

<p align="center"> ⚠ <b>DISCLAIMER: This tool is for AUTHORIZED security testing and educational purposes ONLY.</b>
 Unauthorized scanning of systems you do not own or have explicit written permission to test is
 illegal. Always obtain written authorization before conducting any reconnaissance. </p>

---

**Zero required dependencies** — works out of the box with Python 3.8+ stdlib.
Optional packages unlock enhanced capabilities.

---

## Project Structure

```
reconscout/
│
├── reconscout.py                  ← Main entry point (run this)
│
├── reconscout/                    ← Core package
│   ├── __init__.py
│   ├── models.py                  ← Dataclass result models
│   ├── constants.py               ← Service maps, signatures, fingerprints
│   ├── orchestrator.py            ← Scan coordinator — wires all modules
│   │
│   ├── modules/                   ← Recon modules
│   │   ├── active_recon.py        ← TCP/SYN/UDP scan, banner grab, OS fingerprint
│   │   ├── passive_recon.py       ← WHOIS, DNS, ASN, GeoIP, reverse-IP, email harvest
│   │   ├── web_recon.py           ← HTTP headers, tech fingerprint, dir brute-force
│   │   ├── ssl_analyzer.py        ← TLS version, cipher, cert expiry, SAN extraction
│   │   ├── subdomain_enum.py      ← crt.sh + HackerTarget + OTX + wordlist BF
│   │   ├── smtp_enum.py           ← Banner, STARTTLS, open relay, user enum
│   │   └── network_recon.py       ← Traceroute, firewall detection, LB detection
│   │
│   ├── utils/
│   │   └── helpers.py             ← Logging, progress bar, HTTP client, config loader
│   │
│   └── reports/
│       └── report_generator.py    ← JSON, HTML dashboard, CLI table
│
├── config/
│   └── config.json                ← Scan intensity, DNS servers, timeouts
│
├── wordlists/
│   ├── subdomains.txt             ← Subdomain brute-force wordlist (~200 entries)
│   └── dirs.txt                   ← Directory brute-force wordlist (~100 entries)
│
├── output/                        ← Default report output directory
│   ├── demo_report.html           ← Sample HTML dashboard
│   └── demo_report.json           ← Sample JSON output
│
├── tests/                         ← Unit test stubs
├── requirements.txt
└── README.md
```

---

## Features

| Module | Capabilities |
|---|---|
| **Active Recon** | Multithreaded TCP connect scan, SYN scan (Scapy), UDP scan with protocol probes, banner grabbing, version fingerprinting, CPE tagging, OS TTL guess |
| **Passive Recon** | WHOIS + email/org extraction, DNS (A/AAAA/MX/NS/TXT/SOA/SRV/CNAME/PTR), zone transfer attempt, ASN lookup via Cymru, GeoIP, reverse-IP, OSINT email harvesting |
| **Subdomain Enum** | crt.sh CT logs, HackerTarget hostsearch, AlienVault OTX passive DNS, wordlist brute-force, wildcard detection, permutation generation |
| **Web Recon** | HTTP/HTTPS analysis, technology fingerprinting (30+ signatures), CDN/WAF detection (16+ products), security header audit, robots.txt + sitemap, form/comment/email/JS extraction, sensitive file probing, HTTP method testing, directory brute-force |
| **SSL/TLS Analysis** | Certificate inspection, version/cipher detection, SAN extraction, expiry check, self-signed detection, weak protocol testing, graded scoring (A+ → F) |
| **SMTP Enumeration** | Banner grab, STARTTLS, AUTH method discovery, open relay test, VRFY/EXPN user enumeration |
| **Network Recon** | Traceroute (OS-native + TCP fallback), firewall heuristic detection, load balancer detection |
| **Reporting** | Structured JSON, dark-theme HTML dashboard (sidebar nav, charts, full sections), colour CLI table |

---

## Installation

```bash
# Clone
git clone https://github.com/yourorg/reconscout.git
cd reconscout

# Python 3.8+ required — no external dependencies for core features
python3 --version

# Optional enhanced features
pip install dnspython python-whois pyyaml scapy
```

---

## Usage

### Basic syntax
```bash
python reconscout.py <target> [options]
```

### Scan modes

| Flag | Mode | Description |
|---|---|---|
| `-m active` | Active | Port scan, banner grab, OS fingerprint, network map, SMTP enum |
| `-m passive` | Passive | WHOIS, DNS, ASN, GeoIP, reverse-IP, subdomain OSINT (no packets sent to target) |
| `-m web` | Web | HTTP analysis, SSL/TLS, technology fingerprinting, dir brute-force |
| `-m full` | Full | All of the above combined — active + passive + web (default) |

> **Tip:** Use `-m passive` when you need zero-contact OSINT. Use `-m active` for port-scanning only. Use `-m full` for a complete assessment.

---

## Command Examples

```bash
# ── Full scan (recommended starting point) ────────────────────────
python reconscout.py example.com -m full -i normal -o output/report

# ── Passive OSINT only — zero packets sent to target ──────────────
python reconscout.py example.com -m passive -o output/osint

# ── Aggressive port scan — top 1000 ports ────────────────────────
python reconscout.py 192.168.1.1 -m active -p 1-1000 \
    -i aggressive -o output/portscan

# ── Web + SSL deep dive ───────────────────────────────────────────
python reconscout.py example.com -m web \
    --dir-wordlist wordlists/dirs.txt \
    -o output/web_report

# ── Full scan with wordlists ──────────────────────────────────────
python reconscout.py target.com -m full \
    --wordlist wordlists/subdomains.txt \
    --dir-wordlist wordlists/dirs.txt \
    --threads 100 -i normal \
    -o output/full_report

# ── SYN scan (requires root + scapy) ─────────────────────────────
sudo python reconscout.py 10.0.0.1 -m active \
    --syn -p 1-65535 -i aggressive

# ── UDP scan ─────────────────────────────────────────────────────
python reconscout.py 10.0.0.1 -m active \
    --udp-ports 53,161,500,4500,123

# ── Stealth mode ─────────────────────────────────────────────────
python reconscout.py target.com -m full \
    -i stealth --threads 5 --timeout 3

# ── JSON output + debug logging ──────────────────────────────────
python reconscout.py target.com -m full \
    --format json --log-level DEBUG \
    --log-file logs/scan.log \
    -o output/results

# ── Custom config ─────────────────────────────────────────────────
python reconscout.py target.com -m full \
    --config config/config.json \
    -o output/custom_scan
```

---

## Intensity Levels

| Level | Threads | Timeout | Delay | Use Case |
|---|---|---|---|---|
| `stealth` | 5 | 3.0s | 0.5s | Evade basic IDS/IPS rate limiting |
| `normal` | 50 | 2.0s | 0.0s | Standard authorized pentest |
| `aggressive` | 200 | 0.5s | 0.0s | Internal networks, speed priority |

---

## Output

Every scan produces:
- **`<prefix>.json`** — Full structured results, machine-readable
- **`<prefix>.html`** — Dark-theme cybersecurity dashboard with:
  - Sidebar navigation
  - Stat cards (open ports, subdomains, findings)
  - Port distribution + service breakdown charts
  - Open ports table with state badges + CPE
  - DNS records section
  - WHOIS + intelligence section
  - SSL/TLS grade card
  - Network traceroute map
  - SMTP enumeration results
  - Subdomain grid
  - Web recon (headers, technologies, CDN/WAF, misconfigs, directories)

---

## Optional Dependencies

| Package | Feature Unlocked |
|---|---|
| `dnspython` | Full DNS: zone transfer (AXFR), SRV, SOA, enhanced resolver |
| `python-whois` | Structured WHOIS parsing with org/country/date fields |
| `pyyaml` | YAML config file support |
| `scapy` | SYN (half-open) scan — requires root/admin privileges |

---

## Security & Legal

This software is provided for **authorized security testing and educational purposes only**.
The authors accept no responsibility for misuse. Before running any scan:

1. Obtain **explicit written permission** from the system owner
2. Comply with local laws and regulations (CFAA, Computer Misuse Act, etc.)
3. Follow responsible disclosure for any findings
4. Never scan production systems without a maintenance window

---

*Built by Agent P — for security engineers.*
