"""
ReconScout — Active Recon Module
TCP connect scan, SYN scan (Scapy), UDP scan, banner grabbing,
service version fingerprinting, OS TTL guess.

Author  : Agent P
Project : ReconScout v2.1

REQUIRES AUTHORIZATION — only scan systems you own or have permission to test.
"""

import concurrent.futures
import re
import socket
import subprocess
import time
from typing import List, Optional

from reconscout.models import PortResult
from reconscout.constants import SERVICE_MAP, BANNER_SIGNATURES, CPE_MAP
from reconscout.utils.helpers import ProgressBar

try:
    from scapy.all import IP, TCP, UDP, ICMP, sr1, conf as _scapy_conf
    _scapy_conf.verb = 0
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


class ActiveRecon:
    """
    Thread-pooled TCP/UDP port scanner with banner grabbing and fingerprinting.
    All methods are stateless and safe for concurrent use.
    """

    def __init__(self, target_ip: str, config: dict, logger):
        self.target = target_ip
        self.config = config
        self.logger = logger

    # ── TCP Connect Scan ────────────────────────────────────────────────────

    def _tcp_connect(self, port: int, timeout: float) -> PortResult:
        result = PortResult(port=port, protocol="tcp")
        retries = self.config.get("retry_count", 2)

        for attempt in range(retries):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    code = s.connect_ex((self.target, port))

                    if code == 0:
                        result.state   = "open"
                        result.service = SERVICE_MAP.get(port, "unknown")
                        result.banner  = self._grab_banner(s, port, timeout)
                        result.version = self._fingerprint_version(result.banner, port)
                        result.cpe     = self._build_cpe(result.banner, result.version)
                        return result

                    # Connection refused → definitively closed
                    if code in (111, 61, 10061):
                        result.state = "closed"
                        return result

                    result.state = "filtered"
                    return result

            except socket.timeout:
                result.state = "filtered"
            except OSError:
                result.state = "filtered"
                return result

            if attempt < retries - 1:
                time.sleep(self.config.get("retry_delay", 0.5))

        return result

    # ── Banner Grabbing ─────────────────────────────────────────────────────

    def _grab_banner(self, sock: socket.socket, port: int, timeout: float) -> str:
        """Send protocol-appropriate probe and read banner."""
        probes = {
            21:  b"",
            22:  b"",
            25:  b"EHLO reconscout.local\r\n",
            80:  b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
            110: b"",
            143: b"",
            6379: b"INFO server\r\n",
            9200: b"GET / HTTP/1.0\r\n\r\n",
            27017: b"\x3a\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00"
                   b"\x00\x00\x00\x00test.$cmd\x00\x00\x00\x00\x00\xff\xff\xff\xff"
                   b"\x13\x00\x00\x00\x10serverStatus\x00\x01\x00\x00\x00\x00",
        }
        try:
            probe = probes.get(port, b"")
            if probe:
                sock.sendall(probe)
            sock.settimeout(min(timeout, 2.0))
            return sock.recv(2048).decode("utf-8", errors="replace").strip()[:400]
        except Exception:
            return ""

    # ── Version Fingerprinting ──────────────────────────────────────────────

    def _fingerprint_version(self, banner: str, port: int) -> str:
        if not banner:
            return ""
        svc = SERVICE_MAP.get(port, "")
        patterns = BANNER_SIGNATURES.get(svc, [])
        for pat in patterns:
            m = re.search(pat, banner, re.IGNORECASE)
            if m:
                return m.group(1).strip()[:80]
        # Generic: extract first version-like string
        m = re.search(r"(\d+\.\d+[\.\d\-\w]*)", banner)
        return m.group(1)[:40] if m else ""

    def _build_cpe(self, banner: str, version: str) -> str:
        for product, cpe_base in CPE_MAP.items():
            if product.lower() in banner.lower():
                return f"{cpe_base}{version}" if version else cpe_base
        return ""

    # ── SYN Scan (Scapy / root) ─────────────────────────────────────────────

    def _syn_scan(self, port: int, timeout: float) -> PortResult:
        if not HAS_SCAPY:
            return self._tcp_connect(port, timeout)
        result = PortResult(port=port, protocol="tcp")
        try:
            pkt  = IP(dst=self.target) / TCP(dport=port, flags="S")
            resp = sr1(pkt, timeout=timeout, verbose=0)
            if resp is None:
                result.state = "filtered"
            elif resp.haslayer(TCP):
                flags = resp.getlayer(TCP).flags
                if flags == 0x12:            # SYN-ACK
                    result.state   = "open"
                    result.service = SERVICE_MAP.get(port, "unknown")
                    # Send RST to cleanly close
                    sr1(IP(dst=self.target) / TCP(dport=port, flags="R"),
                        timeout=1, verbose=0)
                elif flags == 0x14:          # RST-ACK
                    result.state = "closed"
                else:
                    result.state = "filtered"
            elif resp.haslayer(ICMP):
                result.state = "filtered"
        except Exception as e:
            self.logger.debug(f"SYN scan port {port}: {e}")
            return self._tcp_connect(port, timeout)
        return result

    # ── UDP Scan ────────────────────────────────────────────────────────────

    def _udp_scan(self, port: int, timeout: float) -> PortResult:
        result = PortResult(port=port, protocol="udp")
        udp_probes = {
            53:  b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                 b"\x07version\x04bind\x00\x00\x10\x00\x03",  # DNS version
            161: b"\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x04"
                 b"\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00\x30\x0b"
                 b"\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",  # SNMP v1
            123: b"\x1b" + b"\x00" * 47,   # NTP client request
            500: b"\x00" * 28,              # IKE
        }
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                probe = udp_probes.get(port, b"\x00" * 8)
                s.sendto(probe, (self.target, port))
                try:
                    data, _ = s.recvfrom(1024)
                    result.state   = "open"
                    result.service = SERVICE_MAP.get(port, "unknown")
                    result.banner  = data[:200].decode("utf-8", errors="replace").strip()
                except socket.timeout:
                    result.state = "open|filtered"   # no ICMP unreachable = possibly open
        except Exception:
            result.state = "filtered"
        return result

    # ── OS Fingerprinting (TTL-based) ───────────────────────────────────────

    def ttl_os_guess(self) -> str:
        """Infer OS from ping TTL value."""
        for cmd in (
            ["ping", "-c", "1", "-W", "2", self.target],          # Linux/macOS
            ["ping", "-n", "1", "-w", "2000", self.target],        # Windows
        ):
            try:
                out = subprocess.check_output(
                    cmd, stderr=subprocess.DEVNULL, timeout=6
                ).decode(errors="replace")
                m = re.search(r"[Tt][Tt][Ll]=(\d+)", out)
                if m:
                    ttl = int(m.group(1))
                    if   ttl <= 64:  return f"Linux / Unix (TTL={ttl})"
                    elif ttl <= 128: return f"Windows (TTL={ttl})"
                    else:            return f"Cisco / Network Device (TTL={ttl})"
            except Exception:
                continue
        return "Unknown"

    # ── Public: Port Scan Orchestration ────────────────────────────────────

    def scan_ports(
        self,
        ports:      List[int],
        intensity:  str  = "normal",
        syn_scan:   bool = False,
        udp_ports:  Optional[List[int]] = None,
        progress:   Optional[ProgressBar] = None,
    ) -> List[PortResult]:
        """
        Run TCP (and optionally UDP) scan across provided ports.
        Returns sorted list of PortResult objects.
        """
        cfg     = self.config["scan_intensity"][intensity]
        threads = cfg["threads"]
        timeout = cfg["timeout"]
        delay   = cfg.get("delay", 0.0)

        self.logger.info(
            f"TCP scan → {len(ports)} ports | mode={intensity} "
            f"| threads={threads} | timeout={timeout}s"
        )

        results: List[PortResult] = []

        def worker(port: int) -> PortResult:
            if delay:
                time.sleep(delay)
            if syn_scan and HAS_SCAPY:
                return self._syn_scan(port, timeout)
            return self._tcp_connect(port, timeout)

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {pool.submit(worker, p): p for p in ports}
            for fut in concurrent.futures.as_completed(futures):
                if progress:
                    progress.update()
                try:
                    results.append(fut.result())
                except Exception as e:
                    self.logger.debug(f"Port worker error: {e}")

        # UDP
        if udp_ports:
            self.logger.info(f"UDP scan → {len(udp_ports)} ports")
            u_bar = ProgressBar(len(udp_ports), "UDP Scan")
            udp_threads = min(threads, 30)
            with concurrent.futures.ThreadPoolExecutor(max_workers=udp_threads) as pool:
                futures = {pool.submit(self._udp_scan, p, timeout): p for p in udp_ports}
                for fut in concurrent.futures.as_completed(futures):
                    u_bar.update()
                    try:
                        results.append(fut.result())
                    except Exception as e:
                        self.logger.debug(f"UDP worker error: {e}")

        open_count = sum(1 for r in results if r.state == "open")
        self.logger.info(f"Scan complete → {open_count} open / {len(results)} probed")
        return sorted(results, key=lambda r: (r.protocol, r.port))
