"""
ReconScout — OSINT Intelligence Module
Google dorking, GitHub repository secret scanning, Shodan IP lookup.

Author  : Agent P
Project : ReconScout v2.1

Module classification: PASSIVE (no direct packets to the target)
  - Google dorking   : queries go to google.com / bing.com, NOT the target
  - GitHub scanning  : queries go to api.github.com, NOT the target
  - Shodan lookup    : queries go to api.shodan.io, NOT the target

All three are pure OSINT — safe to run in passive mode.
"""

import json
import re
import time
import urllib.parse
import urllib.request
import urllib.error
from typing import List, Optional

from reconscout.models import GoogleDorkResult, GitHubLeakResult, ShodanResult
from reconscout.utils.helpers import http_request


# ── Google Dork templates ────────────────────────────────────────────────────
# Each template uses {domain} — filled at runtime.
# All queries are real Google/DDG dork syntax.
DORK_TEMPLATES = {
    "login_panels": [
        'site:{domain} inurl:login',
        'site:{domain} inurl:admin',
        'site:{domain} inurl:signin',
        'site:{domain} inurl:dashboard',
    ],
    "admin_panels": [
        'site:{domain} inurl:wp-admin',
        'site:{domain} inurl:administrator',
        'site:{domain} inurl:cpanel',
        'site:{domain} inurl:controlpanel',
    ],
    "config_files": [
        'site:{domain} ext:env "DB_PASSWORD"',
        'site:{domain} ext:xml | ext:conf | ext:cnf | ext:reg',
        'site:{domain} ext:sql | ext:dbf | ext:mdb',
        'site:{domain} "index of" "config"',
    ],
    "sensitive_docs": [
        'site:{domain} ext:pdf | ext:docx | ext:xlsx confidential',
        'site:{domain} filetype:pdf "internal use only"',
        'site:{domain} ext:log | ext:txt "password"',
    ],
    "exposed_dirs": [
        'site:{domain} intitle:"index of"',
        'site:{domain} intitle:"Index of /" ".git"',
        'site:{domain} intitle:"Directory Listing"',
    ],
    "api_endpoints": [
        'site:{domain} inurl:/api/',
        'site:{domain} inurl:/v1/ | inurl:/v2/ | inurl:/v3/',
        'site:{domain} inurl:/graphql | inurl:/swagger',
        'site:api.{domain}',          # catches api.domain.com subdomains
    ],
    "subdomains": [
        'site:{domain} -www',
        'site:{domain} -inurl:www',
    ],
    "error_pages": [
        'site:{domain} "SQL syntax" | "mysql_fetch" | "ORA-"',
        'site:{domain} "stack trace" | "Traceback" | "Internal Server Error"',
        'site:{domain} "Warning: include" | "fatal error"',
    ],
}

# ── GitHub sensitive file / secret patterns ──────────────────────────────────
GITHUB_SECRET_PATTERNS = [
    # AWS
    (r'AKIA[0-9A-Z]{16}',                          "AWS Access Key ID",      "HIGH"),
    (r'(?i)aws.{0,20}secret.{0,20}["\'][0-9a-zA-Z/+]{40}', "AWS Secret Key", "HIGH"),
    # Generic API keys
    (r'(?i)api[_-]?key["\'\s:=]+["\'][a-zA-Z0-9_\-]{20,}', "API Key",       "HIGH"),
    (r'(?i)secret[_-]?key["\'\s:=]+["\'][a-zA-Z0-9_\-]{20,}', "Secret Key", "HIGH"),
    # Tokens
    (r'(?i)token["\'\s:=]+["\'][a-zA-Z0-9_\-\.]{20,}',    "Token",          "MEDIUM"),
    (r'ghp_[a-zA-Z0-9]{36}',                              "GitHub PAT",       "HIGH"),
    (r'gho_[a-zA-Z0-9]{36}',                              "GitHub OAuth",     "HIGH"),
    # Passwords
    (r'(?i)password["\'\s:=]+["\'][^\s"\']{8,}',          "Password",         "MEDIUM"),
    (r'(?i)passwd["\'\s:=]+["\'][^\s"\']{8,}',            "Password",         "MEDIUM"),
    # Private keys
    (r'-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----', "Private Key",      "HIGH"),
    # DB connection strings
    (r'(?i)mongodb(\+srv)?://[^\s"\'<>]+',                "MongoDB URI",      "HIGH"),
    (r'(?i)postgres://[^\s"\'<>]+',                       "Postgres URI",     "HIGH"),
    (r'(?i)mysql://[^\s"\'<>]+',                          "MySQL URI",        "HIGH"),
    # Slack / Stripe / Twilio
    (r'xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}',  "Slack Token",      "HIGH"),
    (r'sk_(live|test)_[a-zA-Z0-9]{24,}',                  "Stripe Secret",    "HIGH"),
    (r'AC[a-z0-9]{32}',                                   "Twilio SID",       "MEDIUM"),
]

GITHUB_SENSITIVE_FILENAMES = [
    ".env", ".env.local", ".env.production", "config.yml", "config.yaml",
    "secrets.yml", "credentials.yml", "database.yml", "settings.py",
    "local_settings.py", "wp-config.php", "web.config", "appsettings.json",
    ".aws/credentials", "id_rsa", "id_ed25519", "*.pem", "*.key",
]


class OSINTRecon:
    """
    Passive OSINT intelligence gathering.
    No packets are sent to the target — all queries go to third-party APIs.
    """

    def __init__(self, target: str, logger, config: dict):
        self.target  = target
        self.logger  = logger
        self.config  = config
        self._ua     = config.get("user_agent", "ReconScout/2.1")
        self._to     = config.get("http_timeout", 8)

    # ── Google Dorking ───────────────────────────────────────────────────────

    # ── Google Dorking ───────────────────────────────────────────────────────

    def google_dork(self, domain: str) -> List[GoogleDorkResult]:
        """
        Perform dork searches across multiple public search engines.
        Always records every category attempted so the report shows what
        was searched even when results are empty (bot-blocked).
        """
        if not self.config.get("enable_google_dorks", True):
            self.logger.info("  Google dorking disabled in config")
            return []

        results: List[GoogleDorkResult] = []
        delay = float(self.config.get("dork_delay_sec", 2.0))

        for category, templates in DORK_TEMPLATES.items():
            cat_urls: List[str] = []
            queries_tried: List[str] = []

            for template in templates:
                query = template.format(domain=domain)
                queries_tried.append(query)
                urls  = self._web_search(query, max_results=5)
                cat_urls.extend(urls)
                if delay > 0:
                    time.sleep(delay)

            # Always record the category — even with 0 results
            dork_result = GoogleDorkResult(
                query       = " | ".join(queries_tried[:2]),
                category    = category,
                results     = list(dict.fromkeys(cat_urls))[:20],  # dedup, preserve order
                total_found = len(cat_urls),
                note        = "" if cat_urls else "No results returned (search engine may have blocked automated queries)",
            )
            results.append(dork_result)
            self.logger.info(
                f"  Dork [{category}]: {len(cat_urls)} results"
                + (" (blocked/empty)" if not cat_urls else "")
            )

        return results

    def _web_search(self, query: str, max_results: int = 5) -> List[str]:
        """
        Try multiple search engines to extract result URLs.
        Rotates between DuckDuckGo HTML, Bing, and a fallback grep approach.
        """
        # Try DuckDuckGo first (more bot-friendly for HTML scraping)
        urls = self._ddg_search(query, max_results)
        if urls:
            return urls

        # Fallback to Bing
        urls = self._bing_search(query, max_results)
        return urls

    def _ddg_search(self, query: str, max_results: int = 5) -> List[str]:
        """DuckDuckGo HTML search — no JS, simpler to scrape."""
        urls: List[str] = []
        SKIP = [
            "duckduckgo.com", "duck.com", "ddg.gg",
            "ad.doubleclick.net", "googleadservices.com",
        ]
        try:
            q   = urllib.parse.quote_plus(query)
            url = f"https://html.duckduckgo.com/html/?q={q}"
            resp = http_request(
                url,
                user_agent=(
                    "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) "
                    "Gecko/20100101 Firefox/120.0"
                ),
                timeout=self._to,
                retry_count=2,
                extra_headers={"Accept-Language": "en-US,en;q=0.9"},
            )
            if not resp or resp[0] != 200:
                return urls
            body = resp[2]
            # DuckDuckGo HTML result links are in <a class="result__url"> or result__a
            # Try both patterns
            patterns = [
                r'class="result__a"[^>]*href="([^"]+)"',
                r'class="result__url"[^>]*>([^<]+)<',
                r'href="//duckduckgo\.com/l/\?uddg=([^"&]+)',
                r'<a[^>]+class="[^"]*result[^"]*"[^>]+href="(https?://[^"]+)"',
            ]
            for pat in patterns:
                for m in re.finditer(pat, body):
                    href = m.group(1)
                    # Decode URL encoding
                    try:
                        href = urllib.parse.unquote(href)
                    except Exception:
                        pass
                    if not href.startswith("http"):
                        continue
                    if any(skip in href for skip in SKIP):
                        continue
                    if href not in urls:
                        urls.append(href)
                if urls:
                    break  # stop if we found results with this pattern

            # If still empty, try extracting from uddg= encoded links
            if not urls:
                for m in re.finditer(r'uddg=(https?[^&"]+)', body):
                    href = urllib.parse.unquote(m.group(1))
                    if not any(skip in href for skip in SKIP):
                        urls.append(href)

        except Exception as e:
            self.logger.debug(f"  DDG search error ({query[:40]}): {e}")
        return list(dict.fromkeys(urls))[:max_results]  # dedup

    def _bing_search(self, query: str, max_results: int = 5) -> List[str]:
        """Bing HTML fallback search."""
        urls: List[str] = []
        SKIP = [
            "bing.com", "microsoft.com", "go.microsoft.com",
            "msn.com", "live.com", "bing.net", "microsoftonline.com",
        ]
        try:
            q   = urllib.parse.quote_plus(query)
            url = f"https://www.bing.com/search?q={q}&count={max_results}&setlang=en"
            resp = http_request(
                url,
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
                timeout=self._to,
                retry_count=1,
                extra_headers={"Accept-Language": "en-US,en;q=0.9"},
            )
            if not resp or resp[0] != 200:
                return urls
            body = resp[2]
            # Bing wraps results in <li class="b_algo"> with <a href="...">
            for m in re.finditer(r'<h2[^>]*><a[^>]+href="(https?://[^"]+)"', body):
                href = m.group(1)
                if any(skip in href for skip in SKIP):
                    continue
                if href not in urls:
                    urls.append(href)
            # Fallback: any href that looks external
            if not urls:
                for m in re.finditer(r'href="(https?://[^"&]{10,})"', body):
                    href = m.group(1)
                    if any(skip in href for skip in SKIP):
                        continue
                    if href not in urls:
                        urls.append(href)
        except Exception as e:
            self.logger.debug(f"  Bing search error ({query[:40]}): {e}")
        return urls[:max_results]

    # ── GitHub Leak Scanning ─────────────────────────────────────────────────

    def github_leak_scan(self, domain: str) -> List[GitHubLeakResult]:
        """
        Search GitHub code search for sensitive data related to the domain.
        Uses the public GitHub search API (rate-limited: 10 req/min unauthenticated,
        30 req/min with token).
        """
        if not self.config.get("enable_github_leak_scan", True):
            self.logger.info("  GitHub leak scanning disabled in config")
            return []

        leaks:  List[GitHubLeakResult] = []
        token   = self.config.get("github_token", "")
        headers = {"Accept": "application/vnd.github.v3+json"}
        if token:
            headers["Authorization"] = f"token {token}"

        # Search terms — combine domain with each sensitive filename
        search_terms = [
            f'"{domain}" password',
            f'"{domain}" api_key',
            f'"{domain}" secret',
            f'"{domain}" DB_PASSWORD',
            f'"{domain}" aws_access_key',
        ]

        for term in search_terms:
            try:
                q   = urllib.parse.quote_plus(term)
                url = f"https://api.github.com/search/code?q={q}&per_page=10"
                req = urllib.request.Request(url, headers={
                    "User-Agent": self._ua, **headers
                })
                resp = urllib.request.urlopen(req, timeout=self._to)
                data = json.loads(resp.read().decode())

                for item in data.get("items", []):
                    repo_url  = item.get("repository", {}).get("html_url", "")
                    file_path = item.get("path", "")
                    raw_url   = item.get("html_url", "")

                    # Try to fetch the raw file and scan for secrets
                    raw_content_url = raw_url.replace(
                        "github.com", "raw.githubusercontent.com"
                    ).replace("/blob/", "/")
                    content = self._fetch_raw_github(raw_content_url, headers)

                    found_leaks = self._scan_content(content, file_path)
                    for leak_type, match, severity in found_leaks:
                        leaks.append(GitHubLeakResult(
                            repo_url  = repo_url,
                            file_path = file_path,
                            leak_type = leak_type,
                            match     = self._redact(match),
                            severity  = severity,
                            raw_url   = raw_url,
                        ))
                        self.logger.warning(
                            f"  ⚠ GitHub leak [{severity}] {leak_type} in {repo_url}/{file_path}"
                        )

                time.sleep(1.5)   # respect rate limit

            except urllib.error.HTTPError as e:
                if e.code == 403:
                    self.logger.warning("  GitHub API rate limit reached — add github_token to config")
                    break
                self.logger.debug(f"  GitHub search error ({term[:30]}): {e}")
            except Exception as e:
                self.logger.debug(f"  GitHub search error ({term[:30]}): {e}")

        return leaks

    def _fetch_raw_github(self, url: str, extra_headers: dict) -> str:
        try:
            req  = urllib.request.Request(url, headers={
                "User-Agent": self._ua, **extra_headers
            })
            resp = urllib.request.urlopen(req, timeout=6)
            return resp.read(32768).decode("utf-8", errors="replace")
        except Exception:
            return ""

    def _scan_content(self, content: str, filename: str):
        """Scan file content against all secret patterns."""
        hits = []
        if not content:
            return hits
        for pattern, label, severity in GITHUB_SECRET_PATTERNS:
            try:
                m = re.search(pattern, content)
                if m:
                    hits.append((label, m.group(0), severity))
            except Exception:
                pass
        return hits

    @staticmethod
    def _redact(value: str) -> str:
        """Show first 6 chars + asterisks to avoid exposing real secrets."""
        if len(value) <= 6:
            return "***"
        return value[:6] + "*" * min(len(value) - 6, 20)

    # ── Shodan Lookup ────────────────────────────────────────────────────────

    def shodan_lookup(self, ip: str) -> ShodanResult:
        """
        Lookup an IP on Shodan using the REST API.
        Requires shodan_api_key in config. Returns empty result if not configured.
        """
        result = ShodanResult(ip=ip)
        api_key = self.config.get("shodan_api_key", "").strip()

        if not api_key:
            self.logger.info(
                "  Shodan: no API key in config — skipping "
                "(add shodan_api_key to config/config.json)"
            )
            result.error = "No API key configured. Add shodan_api_key to config/config.json"
            return result

        if not self.config.get("enable_shodan", True):
            self.logger.info("  Shodan disabled in config")
            result.error = "Shodan disabled in config"
            return result

        try:
            url  = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
            req  = urllib.request.Request(
                url, headers={"User-Agent": self._ua}
            )
            resp = urllib.request.urlopen(req, timeout=12)
            data = json.loads(resp.read().decode())

            result.org          = data.get("org", "")
            result.isp          = data.get("isp", "")
            result.asn          = data.get("asn", "")
            result.country      = data.get("country_name", "")
            result.city         = data.get("city", "")
            result.os           = data.get("os", "")
            result.last_update  = data.get("last_update", "")
            result.hostnames    = data.get("hostnames", [])
            result.ports        = data.get("ports", [])
            result.tags         = data.get("tags", [])
            result.vulns        = list(data.get("vulns", {}).keys())

            # Banners — top 10
            for svc in data.get("data", [])[:10]:
                result.banners.append({
                    "port":    svc.get("port", 0),
                    "product": svc.get("product", ""),
                    "version": svc.get("version", ""),
                    "banner":  svc.get("data", "")[:200].replace("\n", " "),
                })

            self.logger.info(
                f"  Shodan: {len(result.ports)} ports | "
                f"{len(result.vulns)} CVEs | OS: {result.os or 'unknown'}"
            )
            if result.vulns:
                for cve in result.vulns[:5]:
                    self.logger.warning(f"  Shodan CVE: {cve}")

        except urllib.error.HTTPError as e:
            if e.code == 401:
                result.error = "Invalid Shodan API key"
                self.logger.warning("  Shodan: invalid API key")
            elif e.code == 404:
                result.error = "IP not found in Shodan database"
                self.logger.info("  Shodan: IP not indexed")
            else:
                result.error = f"HTTP {e.code}"
                self.logger.debug(f"  Shodan HTTP error: {e.code}")
        except Exception as e:
            result.error = str(e)[:80]
            self.logger.debug(f"  Shodan lookup error: {e}")

        return result
