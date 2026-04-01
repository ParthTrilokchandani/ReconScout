"""
ReconScout — Subdomain Enumeration Module
Passive discovery (crt.sh, HackerTarget, DNSDumpster),
wordlist brute-force with wildcard detection,
and permutation/alteration generation.

Author  : Agent P
Project : ReconScout v2.1
"""

import concurrent.futures
import itertools
import re
import socket
from typing import List, Optional, Set

from reconscout.utils.helpers import ProgressBar, http_request
import json


class SubdomainEnum:
    """
    Multi-technique subdomain enumeration.
    """

    def __init__(self, domain: str, logger, config: dict):
        self.domain = domain
        self.logger = logger
        self.config = config
        self._ua    = config.get("user_agent", "ReconScout/2.1")
        self._wildcard_ip: Optional[str] = None

    # ── Wildcard Detection ──────────────────────────────────────────────────

    def detect_wildcard(self) -> bool:
        """Check if domain uses wildcard DNS — returns True if wildcard."""
        test_fqdn = f"xznotreal777abc.{self.domain}"
        try:
            ip = socket.gethostbyname(test_fqdn)
            self._wildcard_ip = ip
            self.logger.warning(
                f"Wildcard DNS detected → *.{self.domain} → {ip} "
                f"(brute-force results may contain false positives)"
            )
            return True
        except socket.gaierror:
            return False

    # ── Single Resolution ────────────────────────────────────────────────────

    def _resolve(self, subdomain: str) -> Optional[str]:
        fqdn = f"{subdomain}.{self.domain}"
        try:
            ip = socket.gethostbyname(fqdn)
            # Skip wildcard hits
            if self._wildcard_ip and ip == self._wildcard_ip:
                return None
            return fqdn
        except socket.gaierror:
            return None

    # ── Passive: crt.sh ─────────────────────────────────────────────────────

    def passive_crtsh(self) -> Set[str]:
        found: Set[str] = set()
        try:
            resp = http_request(
                f"https://crt.sh/?q=%.{self.domain}&output=json",
                user_agent=self._ua, timeout=20
            )
            if resp and resp[0] == 200:
                data = json.loads(resp[2])
                for entry in data:
                    for name in entry.get("name_value", "").splitlines():
                        name = name.strip().lstrip("*.").lower()
                        if self.domain in name and name != self.domain:
                            found.add(name)
                self.logger.info(f"crt.sh → {len(found)} subdomains")
        except Exception as e:
            self.logger.debug(f"crt.sh error: {e}")
        return found

    # ── Passive: HackerTarget ────────────────────────────────────────────────

    def passive_hackertarget(self) -> Set[str]:
        found: Set[str] = set()
        try:
            resp = http_request(
                f"https://api.hackertarget.com/hostsearch/?q={self.domain}",
                user_agent=self._ua, timeout=15
            )
            if resp and resp[0] == 200:
                for line in resp[2].splitlines():
                    parts = line.split(",")
                    if parts and self.domain in parts[0]:
                        found.add(parts[0].strip().lower())
                self.logger.info(f"HackerTarget → {len(found)} subdomains")
        except Exception as e:
            self.logger.debug(f"HackerTarget error: {e}")
        return found

    # ── Passive: AlienVault OTX ──────────────────────────────────────────────

    def passive_otx(self) -> Set[str]:
        """AlienVault OTX passive DNS (no API key needed for basic lookup)."""
        found: Set[str] = set()
        try:
            resp = http_request(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns",
                user_agent=self._ua, timeout=15
            )
            if resp and resp[0] == 200:
                data = json.loads(resp[2])
                for entry in data.get("passive_dns", []):
                    hostname = entry.get("hostname", "").lower()
                    if self.domain in hostname:
                        found.add(hostname.lstrip("*."))
                self.logger.info(f"OTX → {len(found)} passive DNS entries")
        except Exception as e:
            self.logger.debug(f"OTX error: {e}")
        return found

    # ── Permutation Generation ───────────────────────────────────────────────

    @staticmethod
    def generate_permutations(base_subdomain: str, domain: str) -> List[str]:
        """
        Generate common permutations of a discovered subdomain.
        e.g. 'api' → ['api1', 'api2', 'api-dev', 'api-staging', 'new-api', ...]
        """
        prefixes = ["dev", "staging", "test", "uat", "qa", "prod", "new", "old", "beta", "v2"]
        suffixes = ["1", "2", "3", "-dev", "-test", "-staging", "-old", "-new", "-prod"]
        results  = set()
        for p in prefixes:
            results.add(f"{p}-{base_subdomain}")
            results.add(f"{p}.{base_subdomain}")
        for s in suffixes:
            results.add(f"{base_subdomain}{s}")
        return [f"{r}.{domain}" for r in results]

    # ── Brute-Force ─────────────────────────────────────────────────────────

    def brute_force(
        self,
        wordlist:  str,
        threads:   int = 50,
        progress:  Optional[ProgressBar] = None,
    ) -> List[str]:
        import os
        if not os.path.exists(wordlist):
            self.logger.warning(f"Wordlist not found: {wordlist}")
            return []

        with open(wordlist) as f:
            words = [w.strip() for w in f if w.strip() and not w.startswith("#")]

        is_wildcard = self.detect_wildcard()
        self.logger.info(
            f"Brute-forcing {len(words)} subdomains "
            f"({'wildcard detected' if is_wildcard else 'no wildcard'})"
        )

        found: List[str] = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {pool.submit(self._resolve, w): w for w in words}
            for fut in concurrent.futures.as_completed(futures):
                if progress:
                    progress.update()
                try:
                    result = fut.result()
                    if result:
                        found.append(result)
                        self.logger.info(f"  [+] {result}")
                except Exception:
                    pass

        return sorted(set(found))

    # ── Combined Passive Enumeration ─────────────────────────────────────────

    def enumerate_passive(self) -> List[str]:
        """Run all passive sources and merge results."""
        all_found: Set[str] = set()

        self.logger.info("Passive subdomain enumeration (crt.sh + HackerTarget + OTX)...")
        all_found |= self.passive_crtsh()
        all_found |= self.passive_hackertarget()
        all_found |= self.passive_otx()

        # Verify each passively found subdomain resolves
        self.logger.info(f"Verifying {len(all_found)} passive hits...")
        verified: List[str] = []
        for fqdn in sorted(all_found):
            try:
                socket.gethostbyname(fqdn)
                verified.append(fqdn)
            except socket.gaierror:
                pass  # domain in cert but not resolving — still interesting

        self.logger.info(f"Passive subdomains: {len(all_found)} discovered, {len(verified)} resolve")
        return sorted(all_found)  # return all discovered, verified or not
