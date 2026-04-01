"""
ReconScout — SMTP Enumeration Module
Banner analysis, STARTTLS detection, AUTH method enumeration,
open relay testing, VRFY/EXPN user enumeration.

Author  : Agent P
Project : ReconScout v2.1

Only run against targets you own or have written authorization to test.
"""

import re
import socket
from typing import List

from reconscout.models import SMTPResult
from reconscout.constants import SMTP_TEST_USERS


class SMTPEnum:
    """
    SMTP service interrogation — does not send actual mail.
    """

    def __init__(self, target: str, logger, config: dict):
        self.target = target
        self.logger = logger
        self.config = config

    def _connect(self, port: int, timeout: float):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((self.target, port))
        return s

    def _recv(self, s: socket.socket) -> str:
        data = b""
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
                if b"\r\n" in chunk or b"\n" in chunk:
                    if not chunk.rstrip().endswith(b"-"):  # multi-line response continues
                        break
        except socket.timeout:
            pass
        return data.decode("utf-8", errors="replace")

    def _send(self, s: socket.socket, cmd: str) -> str:
        s.sendall((cmd + "\r\n").encode())
        return self._recv(s)

    def analyze(self, port: int = 25) -> SMTPResult:
        result = SMTPResult()
        timeout = self.config["scan_intensity"]["normal"]["timeout"]

        try:
            s = self._connect(port, timeout)
            result.open   = True
            result.banner = self._recv(s).strip()[:200]
            self.logger.debug(f"SMTP banner: {result.banner}")

            # EHLO — discover capabilities
            ehlo_resp = self._send(s, f"EHLO reconscout.local")
            capabilities = ehlo_resp.upper()

            result.starttls = "STARTTLS" in capabilities

            # Extract AUTH methods
            for m in re.finditer(r"AUTH\s+([\w\s]+)", ehlo_resp, re.IGNORECASE):
                for method in m.group(1).split():
                    result.auth_methods.append(method.strip())

            # VRFY — user verification
            vrfy_resp = self._send(s, "VRFY root")
            if vrfy_resp.startswith(("250", "252", "550", "551")):
                result.vrfy_enabled = not vrfy_resp.startswith(("502", "500"))

            # EXPN — mailing list expansion
            expn_resp = self._send(s, "EXPN postmaster")
            result.expn_enabled = not expn_resp.startswith(("502", "500", "252"))

            # User enumeration (RCPT TO method — most reliable)
            if result.vrfy_enabled:
                found_users = self._enum_users_vrfy(s)
            else:
                found_users = self._enum_users_rcpt(s)
            result.users_found = found_users

            # Open relay test
            result.open_relay = self._test_open_relay(s)

            self._send(s, "QUIT")
            s.close()

        except ConnectionRefusedError:
            result.open = False
        except Exception as e:
            self.logger.debug(f"SMTP analysis error on port {port}: {e}")

        return result

    def _enum_users_vrfy(self, s: socket.socket) -> List[str]:
        found = []
        for user in SMTP_TEST_USERS[:8]:
            try:
                resp = self._send(s, f"VRFY {user}")
                if resp.startswith("250"):
                    found.append(user)
                    self.logger.info(f"  [+] SMTP user exists (VRFY): {user}")
            except Exception:
                break
        return found

    def _enum_users_rcpt(self, s: socket.socket) -> List[str]:
        found = []
        try:
            self._send(s, "MAIL FROM:<reconscout@test.local>")
            for user in SMTP_TEST_USERS[:8]:
                resp = self._send(s, f"RCPT TO:<{user}@{self.target}>")
                if resp.startswith("250"):
                    found.append(user)
                    self.logger.info(f"  [+] SMTP user exists (RCPT): {user}")
            self._send(s, "RSET")
        except Exception:
            pass
        return found

    def _test_open_relay(self, s: socket.socket) -> bool:
        """Test if server relays mail for external addresses."""
        try:
            self._send(s, "MAIL FROM:<test@gmail.com>")
            resp = self._send(s, "RCPT TO:<test@yahoo.com>")
            self._send(s, "RSET")
            if resp.startswith("250"):
                self.logger.warning("OPEN RELAY DETECTED — server will relay external mail!")
                return True
        except Exception:
            pass
        return False
