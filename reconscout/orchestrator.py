"""
ReconScout — Scan Orchestrator
Routes each scan mode to the appropriate module chain and populates ScanResult.
Active vs Passive is a first-class choice — modules only run when permitted.

Author  : Agent P
Project : ReconScout v2.1
"""

import time
from datetime import datetime
from typing import Optional

from reconscout.models import ScanResult
from reconscout.utils.helpers import detect_target, parse_ports, ProgressBar, C
from reconscout.modules.active_recon   import ActiveRecon
from reconscout.modules.passive_recon  import PassiveRecon
from reconscout.modules.web_recon      import WebRecon
from reconscout.modules.ssl_analyzer   import SSLAnalyzer
from reconscout.modules.subdomain_enum import SubdomainEnum
from reconscout.modules.smtp_enum      import SMTPEnum
from reconscout.modules.network_recon  import NetworkRecon
from reconscout.constants import DEFAULT_PORTS, ACTIVE_MODES, PASSIVE_MODES, WEB_MODES


class ScanOrchestrator:
    """
    Central controller that:
      1. Detects target type (IP / domain)
      2. Routes to active / passive / web / full modules
      3. Populates a single ScanResult
      4. Calculates summary statistics
    """

    def __init__(self, args, config: dict, logger):
        self.args   = args
        self.config = config
        self.logger = logger
        self.result = ScanResult(target=args.target)

    # ──────────────────────────────────────────────────────────────────────

    def run(self) -> ScanResult:
        args = self.args
        r    = self.result
        t0   = time.time()

        r.scan_mode  = args.mode
        # scan_type is a display label only:
        # full  → "active+passive"
        # active → "active"
        # passive / web → "passive"
        r.scan_type  = (
            "active+passive" if args.mode == "full"
            else "active"    if args.mode == "active"
            else "passive"
        )
        r.started_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        self._banner_header()

        # ── Target detection ───────────────────────────────────────────
        r.target_type, r.ip_address, r.hostname = detect_target(args.target)
        self.logger.info(
            f"Target  : {r.target}  [{r.target_type.upper()}]"
        )
        self.logger.info(
            f"IP      : {r.ip_address or 'unresolved'} | Host: {r.hostname or '—'}"
        )
        self.logger.info(
            f"Mode    : {r.scan_mode.upper()} | Scan-Type: {r.scan_type.upper()} | "
            f"Intensity: {args.intensity.upper()}"
        )
        self.logger.info("─" * 60)

        if not r.ip_address and r.target_type == "domain":
            r.warnings.append(f"Could not resolve {args.target} to an IP address")
            self.logger.warning(f"DNS resolution failed for {args.target}")

        # ── ACTIVE RECON ───────────────────────────────────────────────
        if args.mode in ACTIVE_MODES:
            self._run_active(r, args)

        # ── PASSIVE RECON ──────────────────────────────────────────────
        if args.mode in PASSIVE_MODES:
            self._run_passive(r, args)

        # ── SUBDOMAIN ENUMERATION ──────────────────────────────────────
        if args.mode in PASSIVE_MODES and r.target_type == "domain":
            self._run_subdomains(r, args)

        # ── WEB RECON ──────────────────────────────────────────────────
        if args.mode in WEB_MODES:
            self._run_web(r, args)

        # ── SSL ANALYSIS ───────────────────────────────────────────────
        if args.mode in WEB_MODES:
            self._run_ssl(r, args)

        # ── NETWORK RECON — always runs in active/full mode ──────────
        if args.mode in ACTIVE_MODES:
            self._run_network(r, args)

        # ── SMTP ENUM (active + port 25 found open or forced) ──────────
        if args.mode in ACTIVE_MODES:
            smtp_open = any(
                p.state == "open" and p.port in (25, 465, 587)
                for p in r.ports
            )
            if smtp_open or getattr(args, "smtp_enum", False):
                self._run_smtp(r, args)

        # ── STATISTICS ─────────────────────────────────────────────────
        r.duration_sec = round(time.time() - t0, 2)
        r.finished_at  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        r.stats        = self._compute_stats(r)

        self.logger.info(f"{'─'*60}")
        self.logger.info(
            f"Scan complete in {r.duration_sec:.1f}s  |  "
            f"{r.stats['open_ports']} open  |  "
            f"{len(r.subdomains)} subdomains  |  "
            f"{r.stats['findings']} findings"
        )
        return r

    # ── MODULE RUNNERS ──────────────────────────────────────────────────────

    def _run_active(self, r: ScanResult, args):
        self.logger.info("◈ ACTIVE RECON — Port Scanning")
        scan_target = r.ip_address or args.target
        active = ActiveRecon(scan_target, self.config, self.logger)

        ports     = parse_ports(getattr(args, "ports", None) or DEFAULT_PORTS)
        intensity = args.intensity
        syn_scan  = getattr(args, "syn", False)
        udp_ports = parse_ports(args.udp_ports) if getattr(args, "udp_ports", None) else None

        pbar    = ProgressBar(len(ports), "TCP Port Scan")
        r.ports = active.scan_ports(
            ports, intensity,
            syn_scan=syn_scan, udp_ports=udp_ports, progress=pbar
        )
        r.intel.os_guess = active.ttl_os_guess()
        self.logger.info(f"OS fingerprint: {r.intel.os_guess}")

    def _run_passive(self, r: ScanResult, args):
        self.logger.info("◈ PASSIVE RECON — DNS / WHOIS / OSINT")
        passive = PassiveRecon(args.target, self.logger, self.config)

        # DNS
        dns_target = (args.target if r.target_type == "domain"
                      else r.hostname or args.target)
        r.dns = passive.dns_enumerate(dns_target)

        # WHOIS
        self.logger.info("  WHOIS lookup...")
        raw, emails, fields = passive.whois_lookup()
        r.intel.whois_raw     = raw
        r.intel.whois_emails  = emails
        r.intel.whois_org     = fields.get("org", "")
        r.intel.whois_country = fields.get("country", "")
        r.intel.whois_created = fields.get("created", "")
        r.intel.whois_expires = fields.get("expires", "")

        if r.ip_address:
            # ASN
            self.logger.info("  ASN lookup...")
            r.intel.asn, r.intel.ip_range, _desc = passive.asn_lookup(r.ip_address)

            # GeoIP
            self.logger.info("  GeoIP lookup...")
            r.intel.geoip = passive.geoip_lookup(r.ip_address)

            # Reverse IP
            self.logger.info("  Reverse IP lookup...")
            r.intel.reverse_ip = passive.reverse_ip_lookup(r.ip_address)

        # Email harvesting from web OSINT
        if r.target_type == "domain":
            self.logger.info("  Email harvesting (OSINT)...")
            harvested = passive.harvest_emails_from_web(args.target)
            merged = list(set(r.intel.whois_emails + harvested))
            r.intel.whois_emails = merged

    def _run_subdomains(self, r: ScanResult, args):
        self.logger.info("◈ SUBDOMAIN ENUMERATION")
        sub_enum = SubdomainEnum(args.target, self.logger, self.config)

        # Passive sources first
        r.subdomains = list(sub_enum.enumerate_passive())

        # Wordlist brute-force (optional)
        import os
        wordlist = getattr(args, "wordlist", None) or self.config.get("wordlist_default", "")
        if wordlist and os.path.exists(wordlist):
            with open(wordlist) as f:
                wc = sum(1 for _ in f)
            sbar = ProgressBar(wc, "Subdomain BF")
            bf   = sub_enum.brute_force(
                wordlist,
                threads=args.threads or 50,
                progress=sbar
            )
            r.subdomains = sorted(set(r.subdomains) | set(bf))

        # Permutation generation on top findings
        if r.subdomains:
            perm_base = r.subdomains[0].split(".")[0]
            perms     = sub_enum.generate_permutations(perm_base, args.target)
            self.logger.debug(f"  Generated {len(perms)} permutations")

        self.logger.info(f"Total subdomains discovered: {len(r.subdomains)}")

    def _run_web(self, r: ScanResult, args):
        self.logger.info("◈ WEB RECON")
        web = WebRecon(args.target, self.logger, self.config)

        # Pick HTTP port from scan results, or default
        http_ports = sorted([
            p.port for p in r.ports
            if p.state == "open" and p.port in (80, 443, 8080, 8443, 8000, 8888, 8888)
        ])
        port_n = http_ports[0] if http_ports else 80

        r.web = web.analyze(port=port_n)
        if not r.web.url:
            self.logger.warning("Web target not reachable")
            return

        base = r.web.url
        r.web.robots_txt = web.fetch_robots(base)
        r.web.sitemap    = web.fetch_sitemap(base)
        r.intel.misconfigs = r.web.misconfigs[:]

        # Sensitive files
        self.logger.info("  Checking sensitive files...")
        sensitive = web.check_sensitive_files(base)
        r.web.directories += sensitive

        # HTTP method testing
        self.logger.info("  Testing HTTP methods...")
        methods = web.test_http_methods(base)
        if methods:
            for m in methods:
                r.web.misconfigs.append(f"HTTP method allowed: {m}")

        # Directory brute-force (optional)
        import os
        dwl = getattr(args, "dir_wordlist", None)
        if dwl and os.path.exists(dwl):
            with open(dwl) as f:
                dc = sum(1 for _ in f)
            dbar = ProgressBar(dc, "Dir Brute-Force")
            dirs = web.dir_bruteforce(
                base, dwl,
                threads=args.threads or 20,
                progress=dbar
            )
            r.web.directories += dirs

    def _run_ssl(self, r: ScanResult, args):
        self.logger.info("◈ SSL/TLS ANALYSIS")

        # Resolve the hostname to use for SNI:
        # - If the target is a domain → use it directly (SNI = domain name)
        # - If the target is a raw IP  → we have no SNI hostname; use IP
        #   (cert will likely be valid only if it matches the IP SAN)
        sni_host = args.target if r.target_type == "domain" else (r.hostname or args.target)
        connect_to = r.ip_address or args.target

        # Port resolution:
        # • Prefer an open HTTPS port found during active scan
        # • Fall back to 443; SSLAnalyzer will itself try 8443/8080/8000
        ssl_candidates = [
            p.port for p in r.ports
            if p.state == "open" and p.port in (443, 8443, 8080, 8000, 8888)
        ]
        ssl_port = ssl_candidates[0] if ssl_candidates else 443

        analyzer = SSLAnalyzer(
            target_ip=connect_to,
            logger=self.logger,
            config=self.config,
            hostname=sni_host,       # ← SNI domain name, not IP
        )
        r.ssl = analyzer.analyze(port=ssl_port)

        if r.ssl.enabled:
            self.logger.info(
                f"  SSL grade: {r.ssl.grade} | "
                f"Version: {r.ssl.version} | "
                f"Cipher: {r.ssl.cipher} | "
                f"{'⚠ EXPIRED' if r.ssl.expired else 'Valid'}"
            )
            for v in r.ssl.vulnerabilities:
                self.logger.warning(f"  SSL vuln: {v}")
        else:
            self.logger.info(
                "  SSL/TLS not detected — target may not serve HTTPS "
                "or all SSL ports are filtered"
            )

    def _run_network(self, r: ScanResult, args):
        self.logger.info("◈ NETWORK MAPPING & FIREWALL DETECTION")
        net_recon = NetworkRecon(
            r.ip_address or args.target,
            self.logger,
            self.config
        )
        r.network = net_recon.analyze()
        self.logger.info(
            f"  Hops: {len(r.network.hops)} | "
            f"Firewall: {'YES ⚠' if r.network.firewall_detected else 'Not detected'} | "
            f"Load-Balancer: {'YES' if r.network.load_balancer else 'Not detected'}"
        )

    def _run_smtp(self, r: ScanResult, args):
        self.logger.info("◈ SMTP ENUMERATION")
        smtp_port = next(
            (p.port for p in r.ports if p.state == "open" and p.port in (25, 465, 587)),
            25
        )
        smtp = SMTPEnum(r.ip_address or args.target, self.logger, self.config)
        r.smtp = smtp.analyze(port=smtp_port)
        if r.smtp.open_relay:
            r.warnings.append("OPEN RELAY DETECTED — server relays external mail!")

    # ── STATISTICS ──────────────────────────────────────────────────────────

    def _compute_stats(self, r: ScanResult) -> dict:
        open_p     = [p for p in r.ports if p.state == "open"]
        closed_p   = [p for p in r.ports if p.state == "closed"]
        filt_p     = [p for p in r.ports if "filtered" in p.state]

        svc_c: dict = {}
        for p in open_p:
            s = p.service or "unknown"
            svc_c[s] = svc_c.get(s, 0) + 1
        top_svc = max(svc_c, key=svc_c.get) if svc_c else ""

        findings = (
            len(r.web.misconfigs)
            + len(r.ssl.vulnerabilities)
            + (1 if r.smtp.open_relay else 0)
            + (1 if r.dns.zone_transfer else 0)
            + len(r.intel.misconfigs)
        )

        return {
            "open_ports":    len(open_p),
            "closed_ports":  len(closed_p),
            "filtered_ports":len(filt_p),
            "total_scanned": len(r.ports),
            "subdomains":    len(r.subdomains),
            "top_service":   top_svc,
            "service_counts":svc_c,
            "findings":      findings,
            "scan_duration": r.duration_sec,
        }

    def _banner_header(self):
        self.logger.info("─" * 60)
        self.logger.info("  ReconScout v2.1 — Advanced Reconnaissance Suite")
        self.logger.info("  Author: Agent P  |  ⚠ AUTHORIZED USE ONLY")
        self.logger.info("─" * 60)
