"""
ReconScout — Web Recon Module
HTTP/HTTPS header analysis, technology fingerprinting, CDN/WAF detection,
security misconfiguration audit, robots.txt + sitemap, directory brute-force,
form extraction, comment scraping, JS file enumeration, HTTP method testing.

Author  : Agent P
Project : ReconScout v2.1
"""

import concurrent.futures
import re
import time
from typing import Dict, List, Optional, Tuple
from html import unescape

from reconscout.models import WebResult
from reconscout.constants import (
    CDN_WAF_SIGNATURES, TECH_SIGNATURES, SECURITY_HEADERS,
    INTERESTING_HTTP_METHODS, SENSITIVE_FILES,
)
from reconscout.utils.helpers import http_request, ProgressBar


class WebRecon:
    """
    Comprehensive HTTP/HTTPS reconnaissance without active exploitation.
    """

    def __init__(self, target: str, logger, config: dict):
        self.target = target
        self.logger = logger
        self.config = config
        self._ua    = config.get("user_agent", "ReconScout/2.1")
        self._to    = config.get("http_timeout", 8)

    # ── Core Analysis ───────────────────────────────────────────────────────

    def analyze(self, port: int = 80) -> WebResult:
        result = WebResult()

        # Determine base URLs to try
        if port in (443, 8443):
            urls = [f"https://{self.target}:{port}" if port != 443
                    else f"https://{self.target}"]
        elif port in (80, 8080, 8000, 8888):
            base = f"http://{self.target}" + (f":{port}" if port != 80 else "")
            urls = [f"https://{self.target}", base]
        else:
            urls = [f"https://{self.target}:{port}", f"http://{self.target}:{port}"]

        resp = None
        used_url = ""
        for url in urls:
            resp = http_request(
                url, user_agent=self._ua, timeout=self._to,
                retry_count=self.config.get("retry_count", 2)
            )
            if resp:
                used_url = url
                break

        if not resp:
            self.logger.warning(f"Web target unreachable on port {port}")
            return result

        status, headers, body, elapsed = resp
        result.url            = used_url
        result.status_code    = status
        result.response_time  = round(elapsed, 3)
        result.content_length = len(body)
        result.headers        = {k.lower(): v for k, v in headers.items()}
        result.server         = headers.get("Server", headers.get("server", ""))

        # Page title
        m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
        result.title = unescape(m.group(1).strip()[:200]) if m else ""

        # HSTS
        result.hsts = "strict-transport-security" in result.headers

        # HTTP→HTTPS redirect check
        result.https_redirect = self._check_https_redirect()

        # Technology fingerprinting
        full_text = str(headers) + body
        for tech, sigs in TECH_SIGNATURES.items():
            if any(s.lower() in full_text.lower() for s in sigs):
                result.technologies.append(tech)

        # CDN / WAF detection
        header_blob = json_safe_str(headers)
        for product, sigs in CDN_WAF_SIGNATURES.items():
            if any(s.lower() in header_blob.lower() for s in sigs):
                result.cdn_waf.append(product)

        # Cookies
        for k, v in headers.items():
            if "set-cookie" in k.lower():
                result.cookies.append(v[:300])

        # Security misconfiguration audit
        result.misconfigs = self._audit_security(result, body)

        # Scrape emails, forms, comments, JS files, links
        result.emails   = self._extract_emails(body)
        result.forms    = self._extract_forms(body)
        result.comments = self._extract_html_comments(body)
        result.js_files = self._extract_js_files(body, used_url)
        result.links    = self._extract_links(body, used_url)

        return result

    # ── HTTPS Redirect ──────────────────────────────────────────────────────

    def _check_https_redirect(self) -> bool:
        resp = http_request(
            f"http://{self.target}",
            user_agent=self._ua, timeout=self._to, follow_redirects=False
        )
        if resp and resp[0] in (301, 302, 307, 308):
            loc = resp[1].get("location", "").lower()
            return loc.startswith("https://")
        return False

    # ── Security Header Audit ───────────────────────────────────────────────

    def _audit_security(self, result: WebResult, body: str) -> List[str]:
        mc = []
        h  = result.headers

        for hdr in SECURITY_HEADERS:
            if hdr not in h:
                mc.append(f"Missing header: {hdr}")

        # Server version disclosure
        srv = result.server
        if srv and re.search(r"\d+\.\d+", srv):
            mc.append(f"Server version disclosure: {srv}")

        # X-Powered-By disclosure
        xpb = h.get("x-powered-by", "")
        if xpb:
            mc.append(f"X-Powered-By disclosure: {xpb}")

        # Insecure cookies
        for cookie in result.cookies:
            clow = cookie.lower()
            if "httponly" not in clow:
                mc.append(f"Cookie missing HttpOnly flag")
                break
        for cookie in result.cookies:
            clow = cookie.lower()
            if result.url.startswith("https") and "secure" not in clow:
                mc.append("Cookie missing Secure flag on HTTPS")
                break

        # CORS wildcard
        if h.get("access-control-allow-origin", "") == "*":
            mc.append("Permissive CORS: Access-Control-Allow-Origin: *")

        # Directory listing indicators
        if "index of" in body.lower() or "parent directory" in body.lower():
            mc.append("Possible directory listing enabled")

        # Debug/error mode
        if re.search(r"(stack trace|traceback|fatal error|syntax error)", body, re.IGNORECASE):
            mc.append("Debug / error output visible in response body")

        return mc

    # ── Robots.txt + Sitemap ────────────────────────────────────────────────

    def fetch_robots(self, base_url: str) -> str:
        resp = http_request(
            f"{base_url.rstrip('/')}/robots.txt",
            user_agent=self._ua, timeout=self._to
        )
        return resp[2][:3000] if resp and resp[0] == 200 else ""

    def fetch_sitemap(self, base_url: str) -> str:
        for path in ["/sitemap.xml", "/sitemap_index.xml", "/sitemap.txt"]:
            resp = http_request(
                f"{base_url.rstrip('/')}{path}",
                user_agent=self._ua, timeout=self._to
            )
            if resp and resp[0] == 200:
                return resp[2][:3000]
        return ""

    # ── HTTP Method Testing ─────────────────────────────────────────────────

    def test_http_methods(self, base_url: str) -> List[str]:
        """Check for enabled dangerous HTTP methods."""
        allowed = []
        for method in INTERESTING_HTTP_METHODS:
            resp = http_request(
                base_url, method=method, user_agent=self._ua,
                timeout=self._to, follow_redirects=False
            )
            if resp and resp[0] not in (405, 501, 400):
                allowed.append(f"{method} → {resp[0]}")
                self.logger.info(f"  [!] HTTP method {method} allowed ({resp[0]})")
        return allowed

    # ── Sensitive File Check ────────────────────────────────────────────────

    def check_sensitive_files(self, base_url: str) -> List[str]:
        """Probe common sensitive files/paths."""
        found = []
        for path in SENSITIVE_FILES:
            url  = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
            resp = http_request(
                url, user_agent=self._ua, timeout=self._to, follow_redirects=False
            )
            if resp and resp[0] in (200, 403, 401):
                found.append(f"{url} [{resp[0]}]")
                self.logger.info(f"  [!] Sensitive file: {url} [{resp[0]}]")
        return found

    # ── Directory Brute-Force ───────────────────────────────────────────────

    def dir_bruteforce(
        self,
        base_url:  str,
        wordlist:  str,
        threads:   int = 20,
        progress:  Optional[ProgressBar] = None,
    ) -> List[str]:
        import os
        if not os.path.exists(wordlist):
            self.logger.warning(f"Dir wordlist not found: {wordlist}")
            return []

        with open(wordlist) as f:
            paths = [p.strip().lstrip("/") for p in f
                     if p.strip() and not p.startswith("#")]

        found = []

        def check(path: str) -> Optional[str]:
            url  = f"{base_url.rstrip('/')}/{path}"
            resp = http_request(
                url, user_agent=self._ua, timeout=self._to,
                follow_redirects=False
            )
            if progress:
                progress.update()
            if resp and resp[0] in (200, 201, 301, 302, 401, 403):
                return f"{url} [{resp[0]}]"
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
            futures = [pool.submit(check, p) for p in paths]
            for fut in concurrent.futures.as_completed(futures):
                try:
                    res = fut.result()
                    if res:
                        found.append(res)
                        self.logger.info(f"  [+] Dir: {res}")
                except Exception:
                    pass

        return sorted(found)

    # ── Content Extraction ──────────────────────────────────────────────────

    def _extract_emails(self, body: str) -> List[str]:
        return list(set(re.findall(
            r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", body
        )))[:30]

    def _extract_forms(self, body: str) -> List[str]:
        """Extract form actions and methods."""
        forms = []
        for m in re.finditer(r"<form[^>]*>", body, re.IGNORECASE):
            tag = m.group(0)
            action = re.search(r'action=["\']([^"\']+)', tag, re.IGNORECASE)
            method = re.search(r'method=["\']([^"\']+)', tag, re.IGNORECASE)
            action_v = action.group(1) if action else "(none)"
            method_v = method.group(1).upper() if method else "GET"
            forms.append(f"{method_v} → {action_v}")
        return forms[:20]

    def _extract_html_comments(self, body: str) -> List[str]:
        comments = re.findall(r"<!--(.*?)-->", body, re.DOTALL)
        # Filter out empty / whitespace-only / IE conditionals
        return [
            c.strip()[:200] for c in comments
            if c.strip() and not c.strip().startswith("[if")
            and len(c.strip()) > 5
        ][:15]

    def _extract_js_files(self, body: str, base_url: str) -> List[str]:
        srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', body, re.IGNORECASE)
        js   = []
        for src in srcs:
            if not src.startswith("http"):
                src = base_url.rstrip("/") + "/" + src.lstrip("/")
            js.append(src)
        return js[:30]

    def _extract_links(self, body: str, base_url: str) -> List[str]:
        hrefs = re.findall(r'href=["\']([^"\'#\s]+)["\']', body, re.IGNORECASE)
        links = set()
        for h in hrefs:
            if h.startswith("http"):
                links.add(h)
            elif h.startswith("/"):
                links.add(base_url.rstrip("/") + h)
        return sorted(links)[:50]


def json_safe_str(d: dict) -> str:
    import json
    try:
        return json.dumps(d)
    except Exception:
        return str(d)
