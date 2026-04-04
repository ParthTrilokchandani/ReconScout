"""
ReconScout — SSL/TLS Analysis Module
Certificate inspection, cipher suite analysis, protocol version detection,
expiry checking, SAN extraction, self-signed detection, weak cipher flagging.

Author  : Agent P
Project : ReconScout v2.1
"""

import socket
import ssl
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from reconscout.models import SSLResult
from reconscout.constants import WEAK_CIPHERS, WEAK_PROTOCOLS


class SSLAnalyzer:
    """
    Deep SSL/TLS inspection using Python stdlib only.

    Key design decisions
    ────────────────────
    • SNI server_hostname is always the *domain name*, never the raw IP —
      connecting to an IP with a domain SNI is how browsers resolve certs
      for shared-hosting / CDN targets.
    • Multi-port probe: tries every candidate SSL port in order so the
      module produces results even when no active port scan was run first
      (e.g. in web-only or passive+web modes).
    • Deprecated-protocol test uses the *actual scan port*, not hardcoded 443,
      so it works for targets on 8443 or custom ports.
    """

    # Candidate ports tried in order when no port is specified
    SSL_PORTS = (443, 8443, 8080, 8000)

    def __init__(self, target_ip: str, logger, config: dict,
                 hostname: str = ""):
        self.target   = target_ip     # IP or hostname to *connect* to
        self.hostname = hostname or target_ip   # SNI / cert hostname
        self.logger   = logger
        self.config   = config
        self._timeout = config.get("http_timeout", 8)

    # ── Public entry point ──────────────────────────────────────────────────

    def analyze(self, port: int = 443) -> SSLResult:
        """
        Probe SSL on the given port.  If that fails, try the full
        SSL_PORTS list before giving up so we never return empty due to
        a missed port.
        """
        result = SSLResult()

        # Primary attempt
        ok = self._probe(port, result)

        # Fallback: try other common SSL ports if primary failed
        if not ok:
            for fallback_port in self.SSL_PORTS:
                if fallback_port == port:
                    continue
                self.logger.debug(f"SSL fallback probe → port {fallback_port}")
                ok = self._probe(fallback_port, result)
                if ok:
                    break

        if not result.enabled:
            self.logger.debug(
                f"SSL not detected on {self.target} "
                f"(tried port {port} + fallbacks)"
            )
            return result

        result.vulnerabilities = self._check_vulnerabilities(result, port)
        result.grade           = self._grade(result)
        self.logger.info(
            f"  SSL/TLS: grade={result.grade}  version={result.version}  "
            f"issuer={result.issuer[:40]}  "
            f"expired={'YES' if result.expired else 'no'}"
        )
        return result

    # ── Internal probe ──────────────────────────────────────────────────────

    def _make_ctx(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        return ctx

    def _probe(self, port: int, result: SSLResult) -> bool:
        """
        Attempt TLS handshake on (target, port).
        Populate *result* in-place.  Return True on success.
        """
        ctx = self._make_ctx()
        try:
            with socket.create_connection(
                (self.target, port), timeout=self._timeout
            ) as raw:
                # Use domain hostname for SNI so CDN/shared-host certs resolve
                with ctx.wrap_socket(raw, server_hostname=self.hostname) as tls:
                    result.enabled = True
                    result.version = tls.version() or ""
                    cipher_info    = tls.cipher()
                    result.cipher  = cipher_info[0] if cipher_info else ""

                    # getpeercert() returns {} (not None) when CERT_NONE is set
                    # and the cert is valid; returns a populated dict for DER certs.
                    cert = tls.getpeercert(binary_form=False)
                    if not cert:
                        # Try binary + manual parse as last resort
                        raw_cert = tls.getpeercert(binary_form=True)
                        self._parse_cert_binary_fallback(raw_cert, result)
                    else:
                        self._parse_cert(cert, result)
            return True

        except ssl.SSLError as e:
            self.logger.debug(f"SSL handshake failed {self.target}:{port} — {e}")
        except (ConnectionRefusedError, OSError):
            pass   # Port closed / filtered — not an SSL error
        except socket.timeout:
            self.logger.debug(f"SSL probe timed out {self.target}:{port}")
        except Exception as e:
            self.logger.debug(f"SSL probe error {self.target}:{port} — {e}")

        return False

    # ── Certificate parsing ─────────────────────────────────────────────────

    def _parse_cert(self, cert: dict, result: SSLResult):
        """Parse the structured cert dict returned by getpeercert()."""
        if not cert:
            # cert dict empty → likely self-signed + CERT_NONE context
            result.self_signed = True
            return

        # Subject CN
        subject_tuples = cert.get("subject", [])
        subject = {}
        for pair in subject_tuples:
            if pair:
                subject[pair[0][0]] = pair[0][1]
        result.subject = subject.get("commonName", "")

        # Issuer
        issuer_tuples = cert.get("issuer", [])
        issuer = {}
        for pair in issuer_tuples:
            if pair:
                issuer[pair[0][0]] = pair[0][1]
        result.issuer = (
            issuer.get("organizationName")
            or issuer.get("commonName")
            or ""
        )

        # Self-signed: subject == issuer
        result.self_signed = (
            cert.get("subject") == cert.get("issuer")
            or (result.issuer and "self" in result.issuer.lower())
        )

        # Validity window
        not_before = cert.get("notBefore", "")
        not_after  = cert.get("notAfter",  "")
        result.valid_from = not_before
        result.valid_to   = not_after

        # Expiry — handle both space-padded and zero-padded day formats
        if not_after:
            for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
                try:
                    exp = datetime.strptime(not_after.strip(), fmt)
                    result.expired = exp.replace(tzinfo=None) < datetime.utcnow()
                    break
                except ValueError:
                    continue

        # SANs
        for entry in cert.get("subjectAltName", []):
            if entry[0] == "DNS":
                result.san.append(entry[1])

    def _parse_cert_binary_fallback(self, raw_cert: Optional[bytes],
                                    result: SSLResult):
        """Minimal fallback when getpeercert(False) returns empty dict."""
        if not raw_cert:
            result.self_signed = True
            return
        # We cannot fully parse DER without cryptography/pyOpenSSL,
        # but we can at least flag that a cert was received.
        result.self_signed = False   # unknown — don't assume worst case

    # ── Vulnerability checks ────────────────────────────────────────────────

    def _check_vulnerabilities(self, result: SSLResult, port: int) -> List[str]:
        vulns: List[str] = []

        if result.expired:
            vulns.append("Certificate EXPIRED")
        if result.self_signed:
            vulns.append("Self-signed certificate (untrusted)")

        # Negotiated protocol weak? — use exact match to avoid "TLSv1" matching "TLSv1.3"
        version = result.version or ""
        for weak_proto in WEAK_PROTOCOLS:
            # Exact match only — "TLSv1" must NOT match "TLSv1.2" or "TLSv1.3"
            if version.strip() == weak_proto:
                vulns.append(f"Weak protocol negotiated: {weak_proto}")

        # Negotiated cipher weak?
        cipher = result.cipher or ""
        for weak_cipher in WEAK_CIPHERS:
            if weak_cipher.upper() in cipher.upper():
                vulns.append(f"Weak cipher suite: {cipher}")
                break

        # Actively test whether deprecated protocol versions are *accepted*
        # Use the same port we successfully connected on (not hardcoded 443)
        deprecated_tests: List[Tuple[str, object]] = []
        if hasattr(ssl, "TLSVersion"):
            if hasattr(ssl.TLSVersion, "TLSv1"):
                deprecated_tests.append(("TLSv1.0", ssl.TLSVersion.TLSv1))
            if hasattr(ssl.TLSVersion, "TLSv1_1"):
                deprecated_tests.append(("TLSv1.1", ssl.TLSVersion.TLSv1_1))

        for proto_name, ssl_ver in deprecated_tests:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname  = False
                ctx.verify_mode     = ssl.CERT_NONE
                ctx.minimum_version = ssl_ver   # type: ignore[assignment]
                ctx.maximum_version = ssl_ver   # type: ignore[assignment]
                with socket.create_connection(
                    (self.target, port), timeout=3
                ) as s:
                    with ctx.wrap_socket(s, server_hostname=self.hostname):
                        vulns.append(f"Deprecated protocol accepted: {proto_name}")
            except Exception:
                pass   # Either not accepted or OS doesn't support it — fine

        return vulns

    # ── Grading ────────────────────────────────────────────────────────────

    def _grade(self, result: SSLResult) -> str:
        if not result.enabled:
            return "N/A"
        score = 100
        if result.expired:     score -= 40
        if result.self_signed: score -= 30
        # Each distinct vulnerability type −10 (cap at 3 for fairness)
        score -= min(len(result.vulnerabilities), 3) * 10
        if score >= 90: return "A+"
        if score >= 80: return "A"
        if score >= 70: return "B"
        if score >= 50: return "C"
        if score >= 30: return "D"
        return "F"
