"""
ReconScout — Utility Functions
Logging setup, progress bars, HTTP helpers, target detection, config loading.

Author  : Agent P
Project : ReconScout v2.1
"""

import ipaddress
import json
import logging
import os
import re
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


# ── Colour codes ─────────────────────────────────────────────────────────────
class C:
    CYAN   = '\033[36m'; GREEN  = '\033[32m'; YELLOW = '\033[33m'
    RED    = '\033[31m'; PURPLE = '\033[35m'; BLUE   = '\033[34m'
    WHITE  = '\033[97m'; GREY   = '\033[90m'; BOLD   = '\033[1m'
    DIM    = '\033[2m';  RESET  = '\033[0m'


# ══════════════════════════════════════════════════════════════════════════════
# LOGGING
# ══════════════════════════════════════════════════════════════════════════════

class ColorFormatter(logging.Formatter):
    LEVEL_COLORS = {
        'DEBUG':    C.CYAN,
        'INFO':     C.GREEN,
        'WARNING':  C.YELLOW,
        'ERROR':    C.RED,
        'CRITICAL': C.PURPLE,
    }

    def format(self, record):
        color = self.LEVEL_COLORS.get(record.levelname, C.RESET)
        ts    = datetime.fromtimestamp(record.created).strftime('%H:%M:%S')
        lvl   = f"{color}{C.BOLD}{record.levelname:<8}{C.RESET}"
        msg   = f"{color}{record.getMessage()}{C.RESET}"
        return f"  [{C.GREY}{ts}{C.RESET}] {lvl} {msg}"


def setup_logging(level: str = "INFO", log_file: Optional[str] = None) -> logging.Logger:
    logger = logging.getLogger("reconscout")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.handlers.clear()

    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(ColorFormatter())
    logger.addHandler(ch)

    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_file)
        fh.setFormatter(logging.Formatter(
            '%(asctime)s [%(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S'
        ))
        logger.addHandler(fh)

    return logger


# ══════════════════════════════════════════════════════════════════════════════
# PROGRESS BAR
# ══════════════════════════════════════════════════════════════════════════════

class ProgressBar:
    """Thread-safe CLI progress bar with ETA and rate display."""

    def __init__(self, total: int, label: str = "", width: int = 36):
        self.total   = max(total, 1)
        self.label   = label
        self.width   = width
        self.current = 0
        self._lock   = threading.Lock()
        self._start  = time.time()

    def update(self, n: int = 1):
        with self._lock:
            self.current = min(self.current + n, self.total)
            self._draw()

    def _draw(self):
        pct     = self.current / self.total
        filled  = int(self.width * pct)
        bar     = f"{C.CYAN}{'█' * filled}{C.DIM}{'░' * (self.width - filled)}{C.RESET}"
        elapsed = time.time() - self._start
        rate    = self.current / elapsed if elapsed > 0 else 0
        eta     = (self.total - self.current) / rate if rate > 0 else 0

        sys.stdout.write(
            f"\r  {C.CYAN}{self.label:<22}{C.RESET} [{bar}] "
            f"{C.YELLOW}{pct*100:5.1f}%{C.RESET} "
            f"({self.current}/{self.total}) "
            f"{C.GREY}ETA:{eta:.0f}s  rate:{rate:.0f}/s{C.RESET}  "
        )
        sys.stdout.flush()
        if self.current >= self.total:
            sys.stdout.write("\n")
            sys.stdout.flush()

    def finish(self, msg: str = ""):
        with self._lock:
            self.current = self.total
            self._draw()
            if msg:
                print(f"  {C.GREEN}✓{C.RESET} {msg}")


# ══════════════════════════════════════════════════════════════════════════════
# TARGET DETECTION
# ══════════════════════════════════════════════════════════════════════════════

def detect_target(target: str) -> Tuple[str, str, str]:
    """
    Returns (target_type, ip_address, hostname).
    target_type: 'ip' | 'domain'
    """
    target = target.strip().lower().rstrip("/")
    # Strip protocol if accidentally included
    target = re.sub(r'^https?://', '', target)

    try:
        ipaddress.ip_address(target)
        hostname = ""
        try:
            hostname = socket.gethostbyaddr(target)[0]
        except Exception:
            pass
        return "ip", target, hostname
    except ValueError:
        pass

    # Domain — resolve to IP
    ip = ""
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        pass
    return "domain", ip, target


def parse_ports(port_str: str) -> List[int]:
    """Parse port string like '80,443,1-1024' into sorted list."""
    ports: set = set()
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            try:
                lo, hi = part.split("-", 1)
                ports.update(range(int(lo), min(int(hi) + 1, 65536)))
            except ValueError:
                pass
        elif part.isdigit():
            ports.add(int(part))
    return sorted(ports)


# ══════════════════════════════════════════════════════════════════════════════
# HTTP CLIENT
# ══════════════════════════════════════════════════════════════════════════════

class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def make_ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    return ctx


def http_request(
    url:              str,
    method:           str  = "GET",
    user_agent:       str  = "ReconScout/2.1",
    timeout:          int  = 8,
    follow_redirects: bool = True,
    extra_headers:    Optional[Dict] = None,
    retry_count:      int  = 2,
    retry_delay:      float = 0.5,
) -> Optional[Tuple[int, Dict[str, str], str, float]]:
    """
    Returns (status_code, headers_dict, body_str, response_time_sec) or None on failure.
    """
    ctx = make_ssl_context()
    for attempt in range(retry_count):
        try:
            headers = {"User-Agent": user_agent, "Accept": "*/*", "Connection": "close"}
            if extra_headers:
                headers.update(extra_headers)

            req = urllib.request.Request(url, method=method, headers=headers)
            handlers = [urllib.request.HTTPSHandler(context=ctx)]
            if not follow_redirects:
                handlers.append(_NoRedirectHandler())
            opener = urllib.request.build_opener(*handlers)

            t0 = time.time()
            with opener.open(req, timeout=timeout) as resp:
                body    = resp.read(131072).decode("utf-8", errors="replace")
                elapsed = time.time() - t0
                return resp.status, dict(resp.headers), body, elapsed

        except urllib.error.HTTPError as e:
            t1 = time.time() - (t0 if 'resp' not in dir() else 0)
            return e.code, dict(e.headers), "", 0.0
        except Exception:
            if attempt < retry_count - 1:
                time.sleep(retry_delay)
    return None


# ══════════════════════════════════════════════════════════════════════════════
# CONFIG LOADER
# ══════════════════════════════════════════════════════════════════════════════

DEFAULT_CONFIG: Dict = {
    "scan_intensity": {
        "stealth":    {"threads": 5,   "timeout": 3.0, "delay": 0.5},
        "normal":     {"threads": 50,  "timeout": 2.0, "delay": 0.0},
        "aggressive": {"threads": 200, "timeout": 0.5, "delay": 0.0},
    },
    "user_agent":    "ReconScout/2.1 (Security Research; +github.com/yourorg/reconscout)",
    "dns_servers":   ["8.8.8.8", "1.1.1.1", "9.9.9.9"],
    "http_timeout":  8,
    "retry_count":   2,
    "retry_delay":   0.5,
    "wordlist_default": "",
}


def load_config(path: Optional[str] = None) -> Dict:
    cfg = dict(DEFAULT_CONFIG)
    if not path:
        return cfg
    try:
        with open(path) as f:
            if HAS_YAML and path.endswith((".yaml", ".yml")):
                user = yaml.safe_load(f)
            else:
                user = json.load(f)
        # Deep-merge intensity block
        if "scan_intensity" in user:
            for k, v in user["scan_intensity"].items():
                if k in cfg["scan_intensity"]:
                    cfg["scan_intensity"][k].update(v)
                else:
                    cfg["scan_intensity"][k] = v
        for k, v in user.items():
            if k != "scan_intensity":
                cfg[k] = v
    except Exception as e:
        print(f"{C.RED}[!] Config load error: {e}{C.RESET}")
        sys.exit(1)
    return cfg


# ══════════════════════════════════════════════════════════════════════════════
# MISC HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def section_header(title: str, icon: str = "◈"):
    """Print a styled section header to the terminal."""
    line = f"  {icon} {title}"
    print(f"\n{C.CYAN}{C.BOLD}{line}{C.RESET}")
    print(f"  {C.CYAN}{'─' * (len(title) + 4)}{C.RESET}")


def print_kv(key: str, value: str, indent: int = 4, color: str = C.RESET):
    if value:
        pad = " " * indent
        print(f"{pad}{C.GREY}{key:<22}{C.RESET} {color}{value}{C.RESET}")


def truncate(s: str, n: int = 80) -> str:
    return s[:n] + "…" if len(s) > n else s


def sanitise_filename(name: str) -> str:
    return re.sub(r'[^\w\-.]', '_', name)
