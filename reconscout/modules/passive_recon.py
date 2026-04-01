"""
ReconScout — Passive Recon Module
WHOIS lookup + email extraction, DNS enumeration (A/AAAA/MX/NS/TXT/SRV/SOA/CNAME/PTR),
zone transfer attempt, ASN lookup, GeoIP, reverse IP, OSINT feeds.

Author  : Agent P
Project : ReconScout v2.1

All techniques are passive — no direct connection to the target system.
"""

import json
import re
import socket
import subprocess
from typing import Dict, List, Optional, Tuple

from reconscout.models import DNSResult, IntelResult
from reconscout.utils.helpers import http_request

try:
    import dns.resolver
    import dns.reversename
    import dns.zone
    import dns.query
    import dns.exception
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

try:
    import whois as _whois_lib
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False


class PassiveRecon:
    """
    Passive intelligence gathering — no packets sent to the target.
    """

    def __init__(self, target: str, logger, config: dict):
        self.target = target
        self.logger = logger
        self.config = config
        self._ua    = config.get("user_agent", "ReconScout/2.1")

    # ── WHOIS ───────────────────────────────────────────────────────────────

    def whois_lookup(self) -> Tuple[str, List[str], Dict[str, str]]:
        """
        Returns (raw_text, email_list, parsed_fields_dict).
        parsed_fields: org, country, created, expires, registrar
        """
        raw    = ""
        fields: Dict[str, str] = {}

        if HAS_WHOIS:
            try:
                w = _whois_lib.whois(self.target)
                raw = str(w)
                fields = {
                    "org":       str(w.get("org", "") or ""),
                    "country":   str(w.get("country", "") or ""),
                    "created":   str(w.get("creation_date", "") or "")[:30],
                    "expires":   str(w.get("expiration_date", "") or "")[:30],
                    "registrar": str(w.get("registrar", "") or ""),
                }
                self.logger.debug("WHOIS via python-whois library")
            except Exception as e:
                self.logger.debug(f"python-whois error: {e}")

        if not raw:
            try:
                r = subprocess.run(
                    ["whois", self.target], capture_output=True, text=True, timeout=20
                )
                raw = r.stdout
                self.logger.debug("WHOIS via system binary")
            except Exception as e:
                self.logger.warning(f"WHOIS lookup failed: {e}")

        emails = []
        if raw:
            emails = list(set(re.findall(
                r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", raw
            )))
            # Extract org/country from raw if library failed
            if not fields.get("org"):
                m = re.search(r"(?:org(?:anization)?|org-name)[:\s]+(.+)", raw, re.IGNORECASE)
                if m: fields["org"] = m.group(1).strip()[:80]
            if not fields.get("country"):
                m = re.search(r"country[:\s]+([A-Z]{2})", raw, re.IGNORECASE)
                if m: fields["country"] = m.group(1).strip()

        return raw, emails, fields

    # ── DNS Enumeration ─────────────────────────────────────────────────────

    def dns_enumerate(self, domain: str) -> DNSResult:
        result = DNSResult()

        if not HAS_DNSPYTHON:
            self.logger.warning("dnspython not installed — using socket fallback (limited)")
            try:
                result.a = list(set(socket.gethostbyname_ex(domain)[2]))
            except Exception:
                pass
            return result

        resolver = dns.resolver.Resolver()
        resolver.nameservers = self.config.get("dns_servers", ["8.8.8.8", "1.1.1.1"])
        resolver.timeout  = 5
        resolver.lifetime = 12

        type_map = {
            "A":     result.a,
            "AAAA":  result.aaaa,
            "MX":    result.mx,
            "NS":    result.ns,
            "TXT":   result.txt,
            "CNAME": result.cname,
            "SOA":   result.soa,
        }

        for rtype, store in type_map.items():
            try:
                answers = resolver.resolve(domain, rtype)
                for ans in answers:
                    store.append(str(ans).strip('"').rstrip("."))
                self.logger.debug(f"DNS {rtype}: {len(store)} records")
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                    dns.exception.Timeout, dns.resolver.NoNameservers):
                pass
            except Exception as e:
                self.logger.debug(f"DNS {rtype} error: {e}")

        # SRV records — common service locations
        srv_queries = [
            f"_http._tcp.{domain}",
            f"_https._tcp.{domain}",
            f"_smtp._tcp.{domain}",
            f"_imap._tcp.{domain}",
            f"_xmpp-client._tcp.{domain}",
        ]
        for srv_q in srv_queries:
            try:
                for ans in resolver.resolve(srv_q, "SRV"):
                    result.srv.append(str(ans))
            except Exception:
                pass

        # Reverse DNS for A records
        for ip in result.a[:5]:
            try:
                result.reverse.append(socket.gethostbyaddr(ip)[0])
            except Exception:
                pass

        # Zone transfer attempt
        result.zone_transfer = self._attempt_zone_transfer(domain, result.ns)

        return result

    def _attempt_zone_transfer(self, domain: str, nameservers: List[str]) -> List[str]:
        """Try AXFR zone transfer against each NS."""
        records = []
        if not HAS_DNSPYTHON:
            return records

        for ns_str in nameservers:
            ns_host = ns_str.rstrip(".")
            try:
                ns_ip = socket.gethostbyname(ns_host)
                z = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=5))
                for name, node in z.nodes.items():
                    for rdataset in node.rdatasets:
                        for rdata in rdataset:
                            records.append(f"{name}.{domain} {rdataset.rdtype} {rdata}")
                if records:
                    self.logger.warning(
                        f"ZONE TRANSFER SUCCEEDED on {ns_host} — {len(records)} records"
                    )
                    return records
            except Exception:
                pass
        return records

    # ── ASN Lookup ──────────────────────────────────────────────────────────

    def asn_lookup(self, ip: str) -> Tuple[str, str, str]:
        """
        Returns (asn, ip_range, description) via Team Cymru whois.
        """
        asn, ip_range, desc = "", "", ""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(8)
                s.connect(("whois.cymru.com", 43))
                s.sendall(f"begin\nverbose\n{ip}\nend\n".encode())
                buf = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
            text  = buf.decode("utf-8", errors="replace")
            lines = [l.strip() for l in text.splitlines()
                     if l.strip() and not l.startswith("#")]
            if lines:
                parts = [p.strip() for p in lines[0].split("|")]
                if len(parts) >= 4:
                    asn      = f"AS{parts[0].strip()}" if parts[0].strip() else ""
                    ip_range = parts[2].strip()
                    desc     = parts[3].strip()[:80]
            self.logger.debug(f"ASN: {asn} | Range: {ip_range}")
        except Exception as e:
            self.logger.debug(f"ASN lookup error: {e}")
        return asn, ip_range, desc

    # ── GeoIP ───────────────────────────────────────────────────────────────

    def geoip_lookup(self, ip: str) -> Dict[str, str]:
        """GeoIP via ip-api.com free endpoint."""
        try:
            resp = http_request(
                f"http://ip-api.com/json/{ip}?fields=country,regionName,city,isp,org,as,timezone",
                user_agent=self._ua, timeout=8
            )
            if resp:
                data = json.loads(resp[2])
                if data.get("status") != "fail":
                    return {
                        "country":  data.get("country", ""),
                        "region":   data.get("regionName", ""),
                        "city":     data.get("city", ""),
                        "isp":      data.get("isp", ""),
                        "org":      data.get("org", ""),
                        "asn":      data.get("as", ""),
                        "timezone": data.get("timezone", ""),
                    }
        except Exception as e:
            self.logger.debug(f"GeoIP error: {e}")
        return {}

    # ── Reverse IP Lookup ───────────────────────────────────────────────────

    def reverse_ip_lookup(self, ip: str) -> List[str]:
        """Find co-hosted domains via HackerTarget free API."""
        try:
            resp = http_request(
                f"https://api.hackertarget.com/reverseiplookup/?q={ip}",
                user_agent=self._ua, timeout=10
            )
            if resp and resp[0] == 200:
                body = resp[2]
                if "error" not in body.lower() and "API count exceeded" not in body:
                    return [d.strip() for d in body.splitlines() if d.strip()][:30]
        except Exception as e:
            self.logger.debug(f"Reverse-IP error: {e}")
        return []

    # ── Certificate Transparency ─────────────────────────────────────────────

    def crtsh_lookup(self, domain: str) -> List[str]:
        """Passive subdomain discovery via crt.sh certificate transparency logs."""
        found = set()
        try:
            resp = http_request(
                f"https://crt.sh/?q=%.{domain}&output=json",
                user_agent=self._ua, timeout=20
            )
            if resp and resp[0] == 200:
                data = json.loads(resp[2])
                for entry in data:
                    for name in entry.get("name_value", "").splitlines():
                        name = name.strip().lstrip("*.")
                        if domain in name and name != domain:
                            found.add(name.lower())
                self.logger.info(f"crt.sh → {len(found)} certificate entries")
        except Exception as e:
            self.logger.debug(f"crt.sh error: {e}")
        return sorted(found)

    # ── DNSDumpster ──────────────────────────────────────────────────────────

    def dnsdumpster_lookup(self, domain: str) -> List[str]:
        """Passive recon using HackerTarget DNS lookup."""
        found = []
        try:
            resp = http_request(
                f"https://api.hackertarget.com/hostsearch/?q={domain}",
                user_agent=self._ua, timeout=15
            )
            if resp and resp[0] == 200:
                for line in resp[2].splitlines():
                    parts = line.split(",")
                    if parts:
                        hostname = parts[0].strip()
                        if domain in hostname:
                            found.append(hostname)
                self.logger.debug(f"HackerTarget → {len(found)} hosts")
        except Exception as e:
            self.logger.debug(f"HackerTarget error: {e}")
        return found

    # ── Email Harvesting (OSINT) ─────────────────────────────────────────────

    def harvest_emails_from_web(self, domain: str) -> List[str]:
        """
        Passive email harvesting from public OSINT sources.
        Uses HackerTarget email lookup (rate-limited, free tier).
        """
        emails = set()
        try:
            resp = http_request(
                f"https://api.hackertarget.com/emailhunter/?q={domain}",
                user_agent=self._ua, timeout=10
            )
            if resp and resp[0] == 200:
                for line in resp[2].splitlines():
                    line = line.strip()
                    if "@" in line and domain in line:
                        emails.add(line.lower())
        except Exception as e:
            self.logger.debug(f"Email harvest error: {e}")
        return sorted(emails)
