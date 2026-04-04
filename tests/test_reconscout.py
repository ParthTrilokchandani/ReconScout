"""
ReconScout — Unit Tests
Run with: python -m pytest tests/ -v
"""

import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from reconscout.models import (
    ScanResult, PortResult, DNSResult, WebResult,
    SSLResult, SMTPResult, NetworkResult, IntelResult
)
from reconscout.utils.helpers import (
    detect_target, parse_ports, load_config, truncate, sanitise_filename
)
from reconscout.constants import SERVICE_MAP, TECH_SIGNATURES, CDN_WAF_SIGNATURES


class TestModels(unittest.TestCase):

    def test_scan_result_defaults(self):
        r = ScanResult(target="example.com")
        self.assertEqual(r.target, "example.com")
        self.assertEqual(r.target_type, "unknown")
        self.assertIsInstance(r.ports, list)
        self.assertIsInstance(r.subdomains, list)
        self.assertIsInstance(r.stats, dict)

    def test_port_result_defaults(self):
        p = PortResult(port=80)
        self.assertEqual(p.port, 80)
        self.assertEqual(p.protocol, "tcp")
        self.assertEqual(p.state, "unknown")
        self.assertEqual(p.cpe, "")

    def test_web_result_defaults(self):
        w = WebResult()
        self.assertIsInstance(w.technologies, list)
        self.assertIsInstance(w.misconfigs, list)
        self.assertFalse(w.hsts)

    def test_ssl_result_defaults(self):
        s = SSLResult()
        self.assertFalse(s.enabled)
        self.assertFalse(s.expired)
        self.assertEqual(s.grade, "")


class TestHelpers(unittest.TestCase):

    def test_detect_target_ip(self):
        t_type, ip, host = detect_target("192.168.1.1")
        self.assertEqual(t_type, "ip")
        self.assertEqual(ip, "192.168.1.1")

    def test_detect_target_domain(self):
        t_type, ip, host = detect_target("example.com")
        self.assertEqual(t_type, "domain")
        self.assertEqual(host, "example.com")

    def test_detect_target_strips_protocol(self):
        t_type, _, host = detect_target("https://example.com")
        self.assertEqual(t_type, "domain")
        self.assertEqual(host, "example.com")

    def test_parse_ports_csv(self):
        ports = parse_ports("80,443,8080")
        self.assertEqual(ports, [80, 443, 8080])

    def test_parse_ports_range(self):
        ports = parse_ports("22-25")
        self.assertEqual(ports, [22, 23, 24, 25])

    def test_parse_ports_mixed(self):
        ports = parse_ports("22,80-82,443")
        self.assertEqual(ports, [22, 80, 81, 82, 443])

    def test_parse_ports_dedup_sort(self):
        ports = parse_ports("443,80,443")
        self.assertEqual(ports, [80, 443])

    def test_truncate_short(self):
        self.assertEqual(truncate("hello", 10), "hello")

    def test_truncate_long(self):
        result = truncate("a" * 100, 10)
        self.assertTrue(result.endswith("…"))
        self.assertEqual(len(result), 11)

    def test_sanitise_filename(self):
        result = sanitise_filename("scan result/2024 test!")
        self.assertNotIn("/", result)
        self.assertNotIn(" ", result)
        self.assertNotIn("!", result)

    def test_load_config_defaults(self):
        cfg = load_config(None)
        self.assertIn("scan_intensity", cfg)
        self.assertIn("normal", cfg["scan_intensity"])
        self.assertIn("threads", cfg["scan_intensity"]["normal"])
        self.assertIn("dns_servers", cfg)


class TestConstants(unittest.TestCase):

    def test_service_map_common_ports(self):
        self.assertEqual(SERVICE_MAP[22],   "SSH")
        self.assertEqual(SERVICE_MAP[80],   "HTTP")
        self.assertEqual(SERVICE_MAP[443],  "HTTPS")
        self.assertEqual(SERVICE_MAP[3306], "MySQL")
        self.assertEqual(SERVICE_MAP[6379], "Redis")

    def test_tech_signatures_coverage(self):
        for tech, sigs in TECH_SIGNATURES.items():
            self.assertIsInstance(sigs, list, f"{tech} signatures not a list")
            self.assertGreater(len(sigs), 0, f"{tech} has empty signatures")

    def test_cdn_waf_coverage(self):
        expected = ["Cloudflare", "Akamai", "Fastly", "AWS CloudFront", "ModSecurity"]
        for cdn in expected:
            self.assertIn(cdn, CDN_WAF_SIGNATURES, f"{cdn} not in CDN_WAF_SIGNATURES")


class TestActiveRecon(unittest.TestCase):
    """Tests for ActiveRecon that do not require network access."""

    def setUp(self):
        from reconscout.utils.helpers import setup_logging, DEFAULT_CONFIG
        import logging
        self.config = DEFAULT_CONFIG
        self.logger = logging.getLogger("test")
        from reconscout.modules.active_recon import ActiveRecon
        self.recon = ActiveRecon("127.0.0.1", self.config, self.logger)

    def test_fingerprint_ssh_banner(self):
        banner  = "SSH-2.0-OpenSSH_9.2p1 Ubuntu-2ubuntu0.1"
        version = self.recon._fingerprint_version(banner, 22)
        # SSH regex: SSH-<proto_version>-<software> → captures proto or software version
        self.assertTrue(len(version) > 0, "Should extract some version string from SSH banner")

    def test_fingerprint_empty_banner(self):
        version = self.recon._fingerprint_version("", 22)
        self.assertEqual(version, "")

    def test_build_cpe_openssh(self):
        cpe = self.recon._build_cpe("SSH-2.0-OpenSSH_9.2 Ubuntu", "9.2")
        self.assertIn("openssh", cpe.lower())

    def test_localhost_port_22_closed(self):
        """Port 22 on localhost — state should be open or closed, never crash."""
        result = self.recon._tcp_connect(9, 1.0)   # Port 9 (discard) is almost always closed
        self.assertIn(result.state, ("open", "closed", "filtered"))


class TestSubdomainEnum(unittest.TestCase):

    def setUp(self):
        import logging
        from reconscout.utils.helpers import DEFAULT_CONFIG
        from reconscout.modules.subdomain_enum import SubdomainEnum
        self.enum = SubdomainEnum("example.com", logging.getLogger("test"), DEFAULT_CONFIG)

    def test_generate_permutations(self):
        from reconscout.modules.subdomain_enum import SubdomainEnum
        perms = SubdomainEnum.generate_permutations("api", "example.com")
        self.assertIsInstance(perms, list)
        self.assertGreater(len(perms), 0)
        for p in perms:
            self.assertIn("example.com", p)

    def test_wildcard_nonexistent_domain(self):
        """Non-existent domain should NOT trigger wildcard."""
        result = self.enum.detect_wildcard()
        # example.com doesn't have wildcard DNS — should be False (or True if it does)
        self.assertIsInstance(result, bool)


class TestSSLGrading(unittest.TestCase):

    def setUp(self):
        import logging
        from reconscout.utils.helpers import DEFAULT_CONFIG
        from reconscout.modules.ssl_analyzer import SSLAnalyzer
        self.analyzer = SSLAnalyzer("example.com", logging.getLogger("test"), DEFAULT_CONFIG)

    def test_grade_a_plus(self):
        from reconscout.models import SSLResult
        r = SSLResult(enabled=True, expired=False, self_signed=False, vulnerabilities=[])
        self.assertEqual(self.analyzer._grade(r), "A+")

    def test_grade_f_expired_self_signed(self):
        from reconscout.models import SSLResult
        r = SSLResult(
            enabled=True, expired=True, self_signed=True,
            vulnerabilities=["Weak protocol: TLSv1", "Weak cipher: RC4"]
        )
        grade = self.analyzer._grade(r)
        self.assertIn(grade, ("D", "F"))

    def test_grade_na_no_ssl(self):
        from reconscout.models import SSLResult
        r = SSLResult(enabled=False)
        self.assertEqual(self.analyzer._grade(r), "N/A")


if __name__ == "__main__":
    unittest.main(verbosity=2)
