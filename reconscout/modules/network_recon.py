"""
ReconScout — Network Recon Module
Traceroute (OS-native → TCP-TTL fallback), firewall heuristic detection,
load balancer detection via header variance, basic network topology mapping.

Author  : Agent P
Project : ReconScout v2.1

Design notes
────────────
• OS-native traceroute is tried first (Linux/macOS `traceroute`, Windows
  `tracert`).  If neither binary exists a pure-Python TCP-TTL probe loop
  is used — this works without root on most Linux kernels.
• TCP-TTL fallback no longer imports `struct` (unused, was masking the
  real PermissionError on some kernels).  It catches PermissionError
  explicitly and logs a helpful message.
• Load-balancer detection now has a hard timeout per request and swallows
  all network errors so it never returns an empty NetworkResult.
• `analyze()` always returns a populated NetworkResult — fields may be
  empty/False, but the object is never None.
"""

import re
import socket
import subprocess
import time
from typing import Dict, List

from reconscout.models import NetworkResult
from reconscout.constants import TRACEROUTE_MAX_HOPS


class NetworkRecon:
    """
    Network topology and firewall reconnaissance.
    Always produces a valid NetworkResult — never raises to the caller.
    """

    def __init__(self, target: str, logger, config: dict):
        self.target  = target
        self.logger  = logger
        self.config  = config
        self._ua     = config.get("user_agent", "ReconScout/2.1")
        self._timeout = min(config.get("http_timeout", 8), 4)

    # ── Public entry point ──────────────────────────────────────────────────

    def analyze(self) -> NetworkResult:
        """Run all network recon tasks; always return a populated result."""
        result = NetworkResult()
        try:
            result.hops = self.traceroute()
        except Exception as e:
            self.logger.debug(f"Traceroute outer error: {e}")
            result.hops = []

        if result.hops:
            fw = self.detect_firewall(result.hops)
            result.firewall_detected = fw.get("detected", False)
            result.firewall_type     = fw.get("type", "")

        try:
            result.load_balancer = self.detect_load_balancer()
        except Exception as e:
            self.logger.debug(f"LB detection error: {e}")
            result.load_balancer = False

        return result

    # ── Traceroute ──────────────────────────────────────────────────────────

    def traceroute(self, max_hops: int = TRACEROUTE_MAX_HOPS) -> List[Dict]:
        """
        Try OS-native tool first; fall back to TCP-TTL loop.
        Returns list of hop dicts: {hop, ip, hostname, rtt_ms}.
        """
        self.logger.info(f"  Traceroute → {self.target} (max {max_hops} hops)")

        # ── 1. OS-native binary ─────────────────────────────────────────
        for cmd in [
            ["traceroute", "-n", "-m", str(max_hops), "-w", "2", self.target],
            ["tracert",    "-d", "-h", str(max_hops), "-w", "2000", self.target],
        ]:
            try:
                out = subprocess.check_output(
                    cmd, stderr=subprocess.DEVNULL, timeout=60
                ).decode(errors="replace")
                hops = [h for h in (self._parse_line(l) for l in out.splitlines()) if h]
                if hops:
                    self.logger.debug(f"  Traceroute: {len(hops)} hops via {cmd[0]}")
                    return hops
            except FileNotFoundError:
                continue          # binary not installed
            except subprocess.TimeoutExpired:
                self.logger.warning("  Traceroute timed out")
                return []
            except Exception as e:
                self.logger.debug(f"  Traceroute ({cmd[0]}) error: {e}")

        # ── 2. TCP-TTL pure-Python fallback ─────────────────────────────
        self.logger.debug("  Falling back to TCP-TTL traceroute")
        return self._tcp_ttl_trace(max_hops)

    def _parse_line(self, line: str) -> Dict:
        """Parse one line of traceroute/tracert output."""
        # Handles both:
        #   " 1  192.168.1.1  1.234 ms"
        #   " 1  * * *"
        ip_pat  = r'(\d{1,3}(?:\.\d{1,3}){3})'
        rtt_pat = r'(\d+\.?\d*)\s*ms'
        hop_pat = r'^\s*(\d+)'

        m_hop = re.match(hop_pat, line)
        if not m_hop:
            return {}

        hop_n   = int(m_hop.group(1))
        m_ip    = re.search(ip_pat, line)
        m_rtt   = re.search(rtt_pat, line)
        ip      = m_ip.group(1) if m_ip else ""
        rtt     = float(m_rtt.group(1)) if m_rtt else 0.0
        host    = ""
        if ip:
            try:
                host = socket.gethostbyaddr(ip)[0]
            except Exception:
                pass
        return {"hop": hop_n, "ip": ip, "hostname": host, "rtt_ms": rtt}

    def _tcp_ttl_trace(self, max_hops: int) -> List[Dict]:
        """
        Pure-Python TCP SYN traceroute via IP_TTL socket option.
        Does NOT require raw sockets — uses SOCK_STREAM.
        May return empty on some restricted environments.
        """
        hops: List[Dict] = []
        try:
            import socket as _sock  # local alias for clarity
            for ttl in range(1, max_hops + 1):
                try:
                    with _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM) as s:
                        s.setsockopt(_sock.IPPROTO_IP, _sock.IP_TTL, ttl)
                        s.settimeout(2)
                        t0 = time.time()
                        try:
                            s.connect((self.target, 80))
                            rtt = (time.time() - t0) * 1000
                            hops.append({
                                "hop": ttl, "ip": self.target,
                                "hostname": "", "rtt_ms": round(rtt, 2)
                            })
                            break  # reached the target
                        except _sock.timeout:
                            hops.append({"hop": ttl, "ip": "", "hostname": "", "rtt_ms": 0.0})
                        except OSError as e:
                            import errno
                            if e.errno in (errno.ECONNREFUSED, 111):
                                # Destination port closed but target reached
                                rtt = (time.time() - t0) * 1000
                                hops.append({
                                    "hop": ttl, "ip": self.target,
                                    "hostname": "", "rtt_ms": round(rtt, 2)
                                })
                                break
                            hops.append({"hop": ttl, "ip": "", "hostname": "", "rtt_ms": 0.0})
                except PermissionError:
                    self.logger.debug(
                        "  TCP-TTL traceroute: PermissionError — "
                        "IP_TTL manipulation may require elevated privileges"
                    )
                    break
                except Exception as e:
                    self.logger.debug(f"  TCP-TTL hop {ttl}: {e}")
                    hops.append({"hop": ttl, "ip": "", "hostname": "", "rtt_ms": 0.0})

        except Exception as e:
            self.logger.debug(f"  TCP-TTL trace outer: {e}")

        return hops

    # ── Firewall detection ──────────────────────────────────────────────────

    def detect_firewall(self, hops: List[Dict]) -> Dict:
        """
        Heuristic firewall detection from traceroute hop patterns.
        Returns {detected: bool, type: str, evidence: list}.
        """
        result = {"detected": False, "type": "", "evidence": []}
        if not hops:
            return result

        # Consecutive unreachable hops (IP = "") → stateful firewall / ICMP block
        max_gap = 0
        cur_gap = 0
        for h in hops:
            if not h.get("ip"):
                cur_gap += 1
                max_gap = max(max_gap, cur_gap)
            else:
                cur_gap = 0

        if max_gap >= 3:
            result["detected"] = True
            result["type"]     = "Stateful Firewall / ICMP-filtered hops"
            result["evidence"].append(
                f"{max_gap} consecutive unreachable hops (ICMP TTL-exceeded blocked)"
            )

        # Large RTT jump (>150 ms) between adjacent *reachable* hops
        reachable = [h for h in hops if h.get("ip") and h.get("rtt_ms", 0) > 0]
        for i in range(1, len(reachable)):
            delta = reachable[i]["rtt_ms"] - reachable[i-1]["rtt_ms"]
            if delta > 150:
                result["detected"] = True
                result["evidence"].append(
                    f"RTT jump +{delta:.0f}ms between hops "
                    f"{reachable[i-1]['hop']} → {reachable[i]['hop']} "
                    f"(possible transparent proxy or WAF)"
                )

        # Route asymmetry: fewer than 3 reachable hops with destination reached
        if len(reachable) < 3 and any(h.get("ip") == self.target for h in hops):
            result["evidence"].append(
                "Very few hops visible — possible ICMP rate-limiting or transparent proxy"
            )

        return result

    # ── Load balancer detection ─────────────────────────────────────────────

    def detect_load_balancer(self) -> bool:
        """
        Send 4 quick HTTP HEAD requests and check whether *any* server-identity
        header changes across responses.  Returns True if variance detected.
        Never raises — all errors are caught.
        """
        from reconscout.utils.helpers import http_request
        server_ids: List[str] = []
        identity_headers = (
            "Server", "server",
            "Via", "via",
            "X-Served-By", "x-served-by",
            "X-Cache", "x-cache",
            "X-Backend-Server", "x-backend-server",
            "X-Server-Name", "x-server-name",
        )

        for attempt in range(4):
            try:
                resp = http_request(
                    f"http://{self.target}",
                    method="HEAD",
                    user_agent=self._ua,
                    timeout=self._timeout,
                    follow_redirects=False,
                    retry_count=1,
                )
                if resp:
                    _, hdrs, _, _ = resp
                    sid = "|".join(
                        hdrs.get(h, "") for h in identity_headers if hdrs.get(h)
                    )
                    if sid:
                        server_ids.append(sid)
            except Exception as e:
                self.logger.debug(f"  LB probe {attempt+1}: {e}")
            time.sleep(0.2)

        if len(set(server_ids)) > 1:
            self.logger.info("  Load balancer likely detected (server header variance)")
            return True

        # Also check for explicit LB/proxy headers in a single GET
        try:
            resp = http_request(
                f"http://{self.target}",
                user_agent=self._ua,
                timeout=self._timeout,
                retry_count=1,
            )
            if resp:
                _, hdrs, _, _ = resp
                lb_indicators = [
                    "x-forwarded-for", "x-real-ip", "x-lb",
                    "x-envoy-upstream", "x-amzn-trace-id",
                    "x-request-id", "x-proxy-id",
                ]
                for ind in lb_indicators:
                    if any(ind in k.lower() for k in hdrs):
                        self.logger.info(f"  LB/proxy indicator header found: {ind}")
                        return True
        except Exception as e:
            self.logger.debug(f"  LB header check: {e}")

        return False
