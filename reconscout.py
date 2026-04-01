#!/usr/bin/env python3
"""
ReconScout v2.1 — Advanced Reconnaissance & Asset Discovery Framework
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Author  : Agent P <code name>
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚠  DISCLAIMER: This tool is for AUTHORIZED security testing and
   educational purposes ONLY. Unauthorized use is illegal.
   Always obtain explicit written permission before scanning.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

import argparse
import os
import signal
import sys
from datetime import datetime
from pathlib import Path

# Allow running as `python reconscout.py` from project root
sys.path.insert(0, str(Path(__file__).parent))

from reconscout.utils.helpers import setup_logging, load_config, C
from reconscout.orchestrator import ScanOrchestrator
from reconscout.reports.report_generator import ReportManager

# ─────────────────────────────────────────────────────────────────────────────
# BANNER
# ─────────────────────────────────────────────────────────────────────────────

BANNER = (
    f"{C.CYAN}\n"
    "  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗███████╗ ██████╗ ██████╗ ██╗   ██╗████████╗\n"
    "  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██╔════╝██╔════╝██╔═══██╗██║   ██║╚══██╔══╝\n"
    "  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║███████╗██║     ██║   ██║██║   ██║   ██║   \n"
    "  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║╚════██║██║     ██║   ██║██║   ██║   ██║   \n"
    "  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║███████║╚██████╗╚██████╔╝╚██████╔╝   ██║   \n"
    "  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═════╝  ╚═════╝    ╚═╝  \n"
    f"{C.RESET}"
    f"{C.GREY}  Advanced Reconnaissance & Asset Discovery Framework  v2.1{C.RESET}\n"
    f"{C.PURPLE}  Author : Agent P{C.RESET}\n"
    f"{C.GREY}  GitHub : github.com/yourorg/reconscout{C.RESET}\n"
    f"{C.RED}  ⚠  Authorized security testing ONLY  |  Ensure written permission before use{C.RESET}\n"
    f"{C.CYAN}  {'─' * 87}{C.RESET}"
)


# ─────────────────────────────────────────────────────────────────────────────
# ARGUMENT PARSER
# ─────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="reconscout",
        description=(
            "ReconScout v2.1 — Advanced Reconnaissance & Asset Discovery Framework"
            "  |  by Agent P"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
SCAN MODES:
  active   — Port scanning, banner grabbing, OS fingerprint, network map, SMTP enum
  passive  — WHOIS, DNS, ASN, GeoIP, reverse IP, subdomain OSINT (no packets to target)
  web      — HTTP headers, SSL/TLS, tech fingerprinting, dir brute-force
  full     — Everything combined: active + passive + web  (default)

EXAMPLES:
  # Full scan — ports + DNS + WHOIS + subdomains + web + SSL + network
  python reconscout.py example.com -m full -i normal -o output/report

  # Active only — port scan, OS fingerprint, network map
  python reconscout.py 192.168.1.1 -m active -p 1-1000 -i aggressive

  # Passive only — zero packets sent to the target
  python reconscout.py example.com -m passive -o output/osint

  # Web + SSL deep dive with dir brute-force
  python reconscout.py example.com -m web --dir-wordlist wordlists/dirs.txt

  # Full scan with wordlists
  python reconscout.py target.com -m full \\
      --wordlist wordlists/subdomains.txt \\
      --dir-wordlist wordlists/dirs.txt \\
      --threads 100 -i normal -o output/full_report

  # SYN scan (needs root + scapy installed)
  sudo python reconscout.py 10.0.0.1 -m active --syn -p 1-65535

  # UDP scan
  python reconscout.py 10.0.0.1 -m active --udp-ports 53,161,500,4500

  # Stealth mode (slow, minimal noise)
  python reconscout.py target.com -m full -i stealth

  # JSON output only + debug logging to file
  python reconscout.py target.com -m full --format json \\
      --log-level DEBUG --log-file logs/scan.log

  # Force SMTP enumeration even if no SMTP port found open
  python reconscout.py mail.target.com -m active --smtp-enum

⚠  Only scan systems you own or have explicit written authorization to test.
"""
    )

    # ── Positional ──────────────────────────────────────────────────────────
    p.add_argument(
        "target",
        help="Target IP address or domain name"
    )

    # ── Scan control ────────────────────────────────────────────────────────
    scan_grp = p.add_argument_group("Scan Control")
    scan_grp.add_argument(
        "-m", "--mode",
        choices=["active", "passive", "web", "full"],
        default="full",
        help="Scan mode (default: full)"
    )
    scan_grp.add_argument(
        "-i", "--intensity",
        choices=["stealth", "normal", "aggressive"],
        default="normal",
        help="Scan intensity: stealth | normal | aggressive  (default: normal)"
    )

    # ── Port options ─────────────────────────────────────────────────────────
    port_grp = p.add_argument_group("Port Options")
    port_grp.add_argument(
        "-p", "--ports",
        default=None,
        help="Ports to scan: 80,443  or  1-1024  (default: common ports)"
    )
    port_grp.add_argument(
        "--udp-ports",
        dest="udp_ports",
        default=None,
        help="UDP ports to scan: 53,161,500"
    )
    port_grp.add_argument(
        "--syn",
        action="store_true",
        help="SYN (stealth) scan — requires scapy + root"
    )

    # ── Active module options ────────────────────────────────────────────────
    active_grp = p.add_argument_group("Active Modules")
    active_grp.add_argument(
        "--smtp-enum",
        dest="smtp_enum",
        action="store_true",
        help="Force SMTP enumeration even if port 25/465/587 not found open"
    )

    # ── Wordlists ────────────────────────────────────────────────────────────
    wl_grp = p.add_argument_group("Wordlists")
    wl_grp.add_argument(
        "--wordlist",
        default=None,
        help="Subdomain brute-force wordlist path"
    )
    wl_grp.add_argument(
        "--dir-wordlist",
        dest="dir_wordlist",
        default=None,
        help="Directory brute-force wordlist path"
    )

    # ── Performance ──────────────────────────────────────────────────────────
    perf_grp = p.add_argument_group("Performance")
    perf_grp.add_argument(
        "-t", "--threads",
        type=int, default=None,
        help="Override thread count for all threaded modules"
    )
    perf_grp.add_argument(
        "--timeout",
        type=float, default=None,
        help="Override socket/HTTP timeout in seconds"
    )

    # ── Output ───────────────────────────────────────────────────────────────
    out_grp = p.add_argument_group("Output")
    out_grp.add_argument(
        "-o", "--output",
        default="output/reconscout_report",
        help="Output file prefix  (default: output/reconscout_report)"
    )
    out_grp.add_argument(
        "--format",
        choices=["json", "html", "all"],
        default="all",
        help="Output format  (default: all)"
    )

    # ── Config / Logging ─────────────────────────────────────────────────────
    misc_grp = p.add_argument_group("Configuration")
    misc_grp.add_argument(
        "--config",
        default=None,
        help="Config file path (JSON or YAML)"
    )
    misc_grp.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        dest="log_level",
        help="Log verbosity  (default: INFO)"
    )
    misc_grp.add_argument(
        "--log-file",
        default=None,
        dest="log_file",
        help="Write logs to file in addition to stdout"
    )
    misc_grp.add_argument(
        "--no-banner",
        action="store_true",
        help="Suppress the ASCII art banner"
    )

    return p


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = build_parser()
    args   = parser.parse_args()

    # Ensure output directory exists
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)

    # Logging setup
    logger = setup_logging(args.log_level, args.log_file)

    # Config loading — explicit path → project default → built-in defaults
    cfg_path = args.config
    if not cfg_path:
        default_cfg = Path(__file__).parent / "config" / "config.json"
        if default_cfg.exists():
            cfg_path = str(default_cfg)
    config = load_config(cfg_path)

    # Apply CLI overrides to every intensity profile
    if args.threads:
        for profile in config["scan_intensity"].values():
            profile["threads"] = args.threads
    if args.timeout:
        for profile in config["scan_intensity"].values():
            profile["timeout"] = args.timeout

    if not args.no_banner:
        print(BANNER)

    # What does this mode actually run?
    mode_desc = {
        "full":    "Port Scan + DNS/WHOIS + Subdomains + Web + SSL/TLS + Network Map",
        "active":  "Port Scan + Banner Grab + OS Fingerprint + Network Map + SMTP",
        "passive": "WHOIS + DNS + ASN + GeoIP + Reverse-IP + Subdomain OSINT",
        "web":     "HTTP Headers + SSL/TLS + Tech Fingerprint + Dir Brute-Force",
    }
    logger.info(f"Mode    : {args.mode.upper()} — {mode_desc.get(args.mode, '')}")
    logger.info(f"Target  : {args.target}  |  Intensity: {args.intensity.upper()}")

    # ── Run ──────────────────────────────────────────────────────────────────
    orchestrator = ScanOrchestrator(args, config, logger)

    def _sigint_handler(sig, frame):
        """Ctrl+C — flush partial results to disk before exiting."""
        print(f"\n\n{C.YELLOW}  [!] Scan interrupted — saving partial results...{C.RESET}")
        result = orchestrator.result
        result.finished_at  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        result.duration_sec = 0.0
        result.warnings.append("Scan interrupted by user (Ctrl+C)")
        result.stats = {
            "open_ports":    sum(1 for p in result.ports if p.state == "open"),
            "closed_ports":  0,
            "filtered_ports":0,
            "total_scanned": len(result.ports),
            "subdomains":    len(result.subdomains),
            "top_service":   "",
            "findings":      0,
            "scan_duration": 0,
        }
        _finish(result, logger, args)
        sys.exit(0)

    signal.signal(signal.SIGINT, _sigint_handler)

    result = orchestrator.run()
    _finish(result, logger, args)


def _finish(result, logger, args):
    """Print CLI table and write report files."""
    reporter = ReportManager(result, logger)
    reporter.print_cli()
    fmt = args.format
    if fmt in ("json", "all"):
        reporter.save_json(f"{args.output}.json")
    if fmt in ("html", "all"):
        reporter.save_html(f"{args.output}.html")
    logger.info(f"Reports saved → {args.output}.json  /  {args.output}.html")


if __name__ == "__main__":
    main()
