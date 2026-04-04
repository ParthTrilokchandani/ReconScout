"""
ReconScout — Scan Orchestrator
Routes each scan mode to the appropriate module chain and populates ScanResult.

Author  : Agent P
Project : ReconScout v2.1

Module classification
─────────────────────
ACTIVE  (sends packets to target):
  • Port scanning (TCP connect / SYN / UDP)
  • Banner grabbing + version fingerprinting
  • OS TTL fingerprinting
  • Network map / traceroute / LB detection
  • SMTP enumeration (banner, relay test, user enum)

PASSIVE (no packets to target — third-party APIs only):
  • WHOIS + email extraction
  • DNS enumeration (A/AAAA/MX/NS/TXT/SOA/SRV/CNAME/PTR + zone transfer)
  • ASN lookup (Team Cymru + RIPEstat + ARIN RDAP)
  • GeoIP (ip-api.com)
  • Reverse-IP lookup (HackerTarget)
  • Subdomain enumeration (crt.sh + HackerTarget + OTX + wordlist BF)
  • Google dorking (Bing search proxy)
  • GitHub secret scanning (api.github.com)
  • Shodan lookup (api.shodan.io — requires API key)

WEB (connects to target on HTTP/HTTPS only):
  • HTTP header analysis + tech fingerprinting
  • CDN/WAF detection
  • Security header audit + misconfiguration detection
  • Robots.txt + sitemap
  • Sensitive file probing
  • HTTP method testing
  • Directory brute-force (optional wordlist)
  • SSL/TLS certificate analysis
"""

import time
from datetime import datetime

from reconscout.models import ScanResult
from reconscout.utils.helpers import detect_target, parse_ports, ProgressBar, C
from reconscout.modules.active_recon   import ActiveRecon
from reconscout.modules.passive_recon  import PassiveRecon
from reconscout.modules.web_recon      import WebRecon
from reconscout.modules.ssl_analyzer   import SSLAnalyzer
from reconscout.modules.subdomain_enum import SubdomainEnum
from reconscout.modules.smtp_enum      import SMTPEnum
from reconscout.modules.network_recon  import NetworkRecon
from reconscout.modules.osint_recon    import OSINTRecon
from reconscout.constants import DEFAULT_PORTS, ACTIVE_MODES, PASSIVE_MODES, WEB_MODES


class ScanOrchestrator:

    def __init__(self, args, config: dict, logger):
        self.args   = args
        self.config = config
        self.logger = logger
        self.result = ScanResult(target=args.target)

    # ─────────────────────────────────────────────────────────────────────────

    def run(self) -> ScanResult:
        args = self.args
        r    = self.result
        t0   = time.time()

        r.scan_mode  = args.mode
        r.scan_type  = (
            "active+passive" if args.mode == "full"
            else "active"    if args.mode == "active"
            else "passive"
        )
        r.started_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._banner_header()

        # ── Target detection ───────────────────────────────────────────
        r.target_type, r.ip_address, r.hostname = detect_target(args.target)
        self.logger.info(f"Target   : {r.target}  [{r.target_type.upper()}]")
        self.logger.info(f"IP       : {r.ip_address or 'unresolved'} | Host: {r.hostname or '—'}")
        self.logger.info(f"Mode     : {r.scan_mode.upper()} ({r.scan_type.upper()}) | Intensity: {args.intensity.upper()}")
        self.logger.info("─" * 60)

        if not r.ip_address and r.target_type == "domain":
            r.warnings.append(f"Could not resolve {args.target} to an IP address")
            self.logger.warning(f"DNS resolution failed for {args.target}")

        # ══════════════════════════════════════════════════════════════
        # ACTIVE MODULES — send packets to the target
        # ══════════════════════════════════════════════════════════════
        if args.mode in ACTIVE_MODES:
            self._run_active(r, args)
            self._run_network(r, args)
            self._maybe_run_smtp(r, args)

        # ══════════════════════════════════════════════════════════════
        # PASSIVE MODULES — no target contact, third-party APIs only
        # ══════════════════════════════════════════════════════════════
        if args.mode in PASSIVE_MODES:
            self._run_dns(r, args)
            self._run_whois(r, args)
            self._run_asn_geoip(r, args)
            if r.target_type == "domain":
                self._run_subdomains(r, args)
            self._run_osint(r, args)

        # ══════════════════════════════════════════════════════════════
        # WEB MODULES — HTTP/HTTPS to target only
        # ══════════════════════════════════════════════════════════════
        if args.mode in WEB_MODES:
            self._run_web(r, args)
            self._run_ssl(r, args)

        # ── Statistics ────────────────────────────────────────────────
        r.duration_sec = round(time.time() - t0, 2)
        r.finished_at  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        r.stats        = self._compute_stats(r)

        self.logger.info("─" * 60)
        self.logger.info(
            f"Scan complete in {r.duration_sec:.1f}s  |  "
            f"{r.stats['open_ports']} open ports  |  "
            f"{len(r.subdomains)} subdomains  |  "
            f"{r.stats['findings']} findings  |  "
            f"{len(r.dorks)} dork categories  |  "
            f"{len(r.github_leaks)} GitHub leaks"
        )
        return r

    # ═════════════════════════════════════════════════════════════════════════
    # ACTIVE MODULE RUNNERS
    # ═════════════════════════════════════════════════════════════════════════

    def _run_active(self, r: ScanResult, args):
        self.logger.info("◈ [ACTIVE] Port Scanning + Banner Grabbing + OS Fingerprint")
        target    = r.ip_address or args.target
        active    = ActiveRecon(target, self.config, self.logger)
        ports     = parse_ports(getattr(args, "ports", None) or DEFAULT_PORTS)
        syn_scan  = getattr(args, "syn", False)
        udp_ports = parse_ports(args.udp_ports) if getattr(args, "udp_ports", None) else None

        pbar    = ProgressBar(len(ports), "TCP Port Scan")
        r.ports = active.scan_ports(ports, args.intensity,
                                    syn_scan=syn_scan, udp_ports=udp_ports, progress=pbar)
        r.intel.os_guess = active.ttl_os_guess()
        self.logger.info(f"  OS guess: {r.intel.os_guess}")

    def _run_network(self, r: ScanResult, args):
        self.logger.info("◈ [ACTIVE] Network Map + Firewall + Load Balancer Detection")
        net = NetworkRecon(r.ip_address or args.target, self.logger, self.config)
        r.network = net.analyze()
        self.logger.info(
            f"  Hops: {len(r.network.hops)} | "
            f"Firewall: {'YES ⚠' if r.network.firewall_detected else 'no'} | "
            f"LB: {'YES' if r.network.load_balancer else 'no'}"
        )

    def _maybe_run_smtp(self, r: ScanResult, args):
        smtp_open = any(p.state == "open" and p.port in (25, 465, 587) for p in r.ports)
        if smtp_open or getattr(args, "smtp_enum", False):
            self.logger.info("◈ [ACTIVE] SMTP Enumeration")
            port = next((p.port for p in r.ports
                         if p.state == "open" and p.port in (25, 465, 587)), 25)
            smtp = SMTPEnum(r.ip_address or args.target, self.logger, self.config)
            r.smtp = smtp.analyze(port=port)
            if r.smtp.open_relay:
                r.warnings.append("OPEN RELAY DETECTED — server relays external mail!")

    # ═════════════════════════════════════════════════════════════════════════
    # PASSIVE MODULE RUNNERS
    # ═════════════════════════════════════════════════════════════════════════

    def _run_dns(self, r: ScanResult, args):
        self.logger.info("◈ [PASSIVE] DNS Enumeration")
        passive    = PassiveRecon(args.target, self.logger, self.config)
        dns_target = args.target if r.target_type == "domain" else (r.hostname or args.target)
        r.dns      = passive.dns_enumerate(dns_target)
        if r.dns.zone_transfer:
            r.warnings.append(f"ZONE TRANSFER SUCCEEDED — {len(r.dns.zone_transfer)} records exposed!")

    def _run_whois(self, r: ScanResult, args):
        self.logger.info("◈ [PASSIVE] WHOIS + Email Extraction")
        passive = PassiveRecon(args.target, self.logger, self.config)
        raw, emails, fields = passive.whois_lookup()
        r.intel.whois_raw      = raw
        r.intel.whois_emails   = emails
        r.intel.whois_org      = fields.get("org", "")
        r.intel.whois_country  = fields.get("country", "")
        r.intel.whois_created  = fields.get("created", "")
        r.intel.whois_expires  = fields.get("expires", "")
        r.intel.whois_registrar= fields.get("registrar", "")
        if r.target_type == "domain":
            harvested = passive.harvest_emails_from_web(args.target)
            r.intel.whois_emails = sorted(set(emails + harvested))

    def _run_asn_geoip(self, r: ScanResult, args):
        if not r.ip_address:
            return
        self.logger.info("◈ [PASSIVE] ASN + GeoIP + Reverse-IP")
        passive      = PassiveRecon(args.target, self.logger, self.config)
        r.asn        = passive.asn_lookup(r.ip_address)
        r.geoip      = passive.geoip_lookup(r.ip_address)
        r.intel.reverse_ip = passive.reverse_ip_lookup(r.ip_address)
        self.logger.info(
            f"  ASN: {r.asn.asn} | Org: {r.asn.org} | "
            f"Range: {r.asn.ip_range} | RIR: {r.asn.rir}"
        )
        self.logger.info(
            f"  GeoIP: {r.geoip.city}, {r.geoip.country} | "
            f"ISP: {r.geoip.isp}"
        )

    def _run_subdomains(self, r: ScanResult, args):
        self.logger.info("◈ [PASSIVE] Subdomain Enumeration (crt.sh + HackerTarget + OTX)")
        import os
        sub      = SubdomainEnum(args.target, self.logger, self.config)
        r.subdomains = list(sub.enumerate_passive())
        wordlist = getattr(args, "wordlist", None) or self.config.get("wordlist_default", "")
        if wordlist and os.path.exists(wordlist):
            with open(wordlist) as f:
                wc = sum(1 for _ in f)
            sbar = ProgressBar(wc, "Subdomain BF")
            bf   = sub.brute_force(wordlist, threads=args.threads or 50, progress=sbar)
            r.subdomains = sorted(set(r.subdomains) | set(bf))
        self.logger.info(f"  Total subdomains: {len(r.subdomains)}")

    def _run_osint(self, r: ScanResult, args):
        osint  = OSINTRecon(args.target, self.logger, self.config)
        # Determine the domain to search — prefer the actual domain name
        domain = args.target if r.target_type == "domain" else (r.hostname or args.target)
        # Strip any leading wildcard / dot from the domain
        domain = domain.lstrip("*.").strip()

        # ── Google Dorking (always runs for domain targets) ────────────
        if domain:
            self.logger.info(f"◈ [PASSIVE] Google Dorking → {domain}")
            r.dorks = osint.google_dork(domain)
            total_urls = sum(d.total_found for d in r.dorks)
            self.logger.info(
                f"  Dork results: {len(r.dorks)} categories searched, "
                f"{total_urls} URLs captured"
            )
        else:
            self.logger.warning("  Google dorking skipped — could not determine domain")

        # ── GitHub Secret Scanning (always runs for domain targets) ────
        if domain:
            self.logger.info(f"◈ [PASSIVE] GitHub Secret Scanning → {domain}")
            r.github_leaks = osint.github_leak_scan(domain)
            self.logger.info(
                f"  GitHub: {len(r.github_leaks)} potential secrets found"
            )
        else:
            self.logger.warning("  GitHub scanning skipped — could not determine domain")

        # ── Shodan (requires API key + resolved IP) ────────────────────
        if r.ip_address:
            self.logger.info(f"◈ [PASSIVE] Shodan Lookup → {r.ip_address}")
            r.shodan = osint.shodan_lookup(r.ip_address)
            if r.shodan.error:
                self.logger.info(f"  Shodan: {r.shodan.error}")
            elif r.shodan.ip:
                self.logger.info(
                    f"  Shodan: {len(r.shodan.ports)} ports | "
                    f"{len(r.shodan.vulns)} CVEs | OS: {r.shodan.os or 'unknown'}"
                )
                if r.shodan.vulns:
                    r.warnings.append(
                        f"Shodan found {len(r.shodan.vulns)} CVEs: "
                        f"{', '.join(r.shodan.vulns[:5])}"
                    )
        else:
            self.logger.info("  Shodan skipped — no resolved IP address")

    # ═════════════════════════════════════════════════════════════════════════
    # WEB MODULE RUNNERS
    # ═════════════════════════════════════════════════════════════════════════

    def _run_web(self, r: ScanResult, args):
        import os
        self.logger.info("◈ [WEB] HTTP Analysis + Tech Fingerprint + Security Audit")
        web = WebRecon(args.target, self.logger, self.config)
        http_ports = sorted([
            p.port for p in r.ports
            if p.state == "open" and p.port in (80, 443, 8080, 8443, 8000, 8888)
        ])
        r.web = web.analyze(port=http_ports[0] if http_ports else 80)
        if not r.web.url:
            self.logger.warning("  Web target not reachable")
            return
        base = r.web.url
        r.web.robots_txt  = web.fetch_robots(base)
        r.web.sitemap     = web.fetch_sitemap(base)
        r.intel.misconfigs = r.web.misconfigs[:]
        self.logger.info("  Checking sensitive files...")
        r.web.directories += web.check_sensitive_files(base)
        self.logger.info("  Testing HTTP methods...")
        methods = web.test_http_methods(base)
        for m in methods:
            r.web.misconfigs.append(f"HTTP method allowed: {m}")
        dwl = getattr(args, "dir_wordlist", None)
        if dwl and os.path.exists(dwl):
            with open(dwl) as f:
                dc = sum(1 for _ in f)
            dbar = ProgressBar(dc, "Dir Brute-Force")
            r.web.directories += web.dir_bruteforce(base, dwl, threads=args.threads or 20, progress=dbar)

    def _run_ssl(self, r: ScanResult, args):
        self.logger.info("◈ [WEB] SSL/TLS Certificate Analysis")
        sni_host   = args.target if r.target_type == "domain" else (r.hostname or args.target)
        connect_to = r.ip_address or args.target
        ssl_port   = next(
            (p.port for p in r.ports if p.state == "open" and p.port in (443, 8443, 8080, 8000)),
            443
        )
        analyzer = SSLAnalyzer(target_ip=connect_to, logger=self.logger,
                               config=self.config, hostname=sni_host)
        r.ssl = analyzer.analyze(port=ssl_port)
        if r.ssl.enabled:
            self.logger.info(f"  Grade: {r.ssl.grade} | {r.ssl.version} | {'⚠ EXPIRED' if r.ssl.expired else 'Valid'}")
            for v in r.ssl.vulnerabilities:
                self.logger.warning(f"  SSL vuln: {v}")
        else:
            self.logger.info("  SSL not detected or port filtered")

    # ═════════════════════════════════════════════════════════════════════════
    # STATISTICS
    # ═════════════════════════════════════════════════════════════════════════

    def _compute_stats(self, r: ScanResult) -> dict:
        open_p   = [p for p in r.ports if p.state == "open"]
        closed_p = [p for p in r.ports if p.state == "closed"]
        filt_p   = [p for p in r.ports if "filtered" in p.state]
        svc_c: dict = {}
        for p in open_p:
            s = p.service or "unknown"
            svc_c[s] = svc_c.get(s, 0) + 1
        high_leaks = sum(1 for l in r.github_leaks if l.severity == "HIGH")
        findings = (
            len(r.web.misconfigs) + len(r.ssl.vulnerabilities)
            + (1 if r.smtp.open_relay else 0)
            + (1 if r.dns.zone_transfer else 0)
            + len(r.intel.misconfigs)
            + len(r.shodan.vulns)
            + high_leaks
        )
        return {
            "open_ports":     len(open_p),
            "closed_ports":   len(closed_p),
            "filtered_ports": len(filt_p),
            "total_scanned":  len(r.ports),
            "subdomains":     len(r.subdomains),
            "top_service":    max(svc_c, key=svc_c.get) if svc_c else "",
            "service_counts": svc_c,
            "findings":       findings,
            "github_leaks":   len(r.github_leaks),
            "shodan_cves":    len(r.shodan.vulns),
            "dork_categories":len(r.dorks),
            "scan_duration":  r.duration_sec,
        }

    def _banner_header(self):
        self.logger.info("─" * 60)
        self.logger.info("  ReconScout v2.1 — Advanced Reconnaissance Suite")
        self.logger.info("  Author: Agent P  |  ⚠ AUTHORIZED USE ONLY")
        self.logger.info("─" * 60)
