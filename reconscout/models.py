"""
ReconScout — Core Data Models
Shared dataclasses for all scan results and module outputs.

Author  : Agent P
Project : ReconScout v2.1
"""

from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional


@dataclass
class PortResult:
    port:     int
    protocol: str = "tcp"
    state:    str = "unknown"   # open | closed | filtered | open|filtered
    service:  str = ""
    banner:   str = ""
    version:  str = ""
    cpe:      str = ""


@dataclass
class DNSResult:
    a:       List[str] = field(default_factory=list)
    aaaa:    List[str] = field(default_factory=list)
    mx:      List[str] = field(default_factory=list)
    ns:      List[str] = field(default_factory=list)
    txt:     List[str] = field(default_factory=list)
    cname:   List[str] = field(default_factory=list)
    soa:     List[str] = field(default_factory=list)
    srv:     List[str] = field(default_factory=list)
    reverse: List[str] = field(default_factory=list)
    zone_transfer: List[str] = field(default_factory=list)


@dataclass
class ASNResult:
    """Dedicated ASN / BGP / IP-range intelligence."""
    asn:          str = ""        # e.g. AS15133
    org:          str = ""        # e.g. "Edgecast Inc."
    isp:          str = ""
    ip_range:     str = ""        # CIDR block, e.g. 93.184.216.0/24
    country:      str = ""
    rir:          str = ""        # ARIN / RIPE / APNIC / LACNIC / AFRINIC
    abuse_email:  str = ""
    peers:        List[str] = field(default_factory=list)   # upstream ASNs
    prefixes:     List[str] = field(default_factory=list)   # announced prefixes


@dataclass
class GeoIPResult:
    """Geographic and network location data."""
    ip:       str = ""
    country:  str = ""
    region:   str = ""
    city:     str = ""
    lat:      float = 0.0
    lon:      float = 0.0
    timezone: str = ""
    isp:      str = ""
    org:      str = ""
    asn:      str = ""


@dataclass
class WebResult:
    url:            str   = ""
    status_code:    int   = 0
    server:         str   = ""
    title:          str   = ""
    technologies:   List[str]      = field(default_factory=list)
    headers:        Dict[str, str] = field(default_factory=dict)
    cookies:        List[str]      = field(default_factory=list)
    robots_txt:     str   = ""
    sitemap:        str   = ""
    https_redirect: bool  = False
    hsts:           bool  = False
    cdn_waf:        List[str]  = field(default_factory=list)
    directories:    List[str]  = field(default_factory=list)
    misconfigs:     List[str]  = field(default_factory=list)
    forms:          List[str]  = field(default_factory=list)
    emails:         List[str]  = field(default_factory=list)
    comments:       List[str]  = field(default_factory=list)
    js_files:       List[str]  = field(default_factory=list)
    links:          List[str]  = field(default_factory=list)
    screenshot_b64: str   = ""
    content_length: int   = 0
    response_time:  float = 0.0


@dataclass
class SSLResult:
    enabled:         bool = False
    version:         str  = ""
    cipher:          str  = ""
    issuer:          str  = ""
    subject:         str  = ""
    valid_from:      str  = ""
    valid_to:        str  = ""
    expired:         bool = False
    self_signed:     bool = False
    san:             List[str] = field(default_factory=list)
    vulnerabilities: List[str] = field(default_factory=list)
    grade:           str  = ""


@dataclass
class SMTPResult:
    open:         bool = False
    banner:       str  = ""
    starttls:     bool = False
    auth_methods: List[str] = field(default_factory=list)
    open_relay:   bool = False
    vrfy_enabled: bool = False
    expn_enabled: bool = False
    users_found:  List[str] = field(default_factory=list)


@dataclass
class NetworkResult:
    hops:              List[Dict] = field(default_factory=list)
    firewall_detected: bool       = False
    firewall_type:     str        = ""
    load_balancer:     bool       = False
    isp:               str        = ""


@dataclass
class GoogleDorkResult:
    """Results from Google dorking queries."""
    query:       str        = ""
    category:    str        = ""   # login_pages | admin_panels | config_files | etc.
    results:     List[str]  = field(default_factory=list)   # list of URLs found
    total_found: int        = 0
    note:        str        = ""


@dataclass
class GitHubLeakResult:
    """Results from GitHub repository secret scanning."""
    repo_url:    str        = ""
    file_path:   str        = ""
    leak_type:   str        = ""   # api_key | aws_key | password | token | etc.
    match:       str        = ""   # the matched string (redacted)
    severity:    str        = ""   # HIGH | MEDIUM | LOW
    raw_url:     str        = ""


@dataclass
class ShodanResult:
    """Data returned from Shodan IP lookup."""
    ip:           str        = ""
    org:          str        = ""
    isp:          str        = ""
    asn:          str        = ""
    country:      str        = ""
    city:         str        = ""
    hostnames:    List[str]  = field(default_factory=list)
    ports:        List[int]  = field(default_factory=list)
    vulns:        List[str]  = field(default_factory=list)   # CVE IDs
    tags:         List[str]  = field(default_factory=list)
    os:           str        = ""
    last_update:  str        = ""
    banners:      List[Dict] = field(default_factory=list)   # {port, banner, product}
    error:        str        = ""


@dataclass
class IntelResult:
    """WHOIS + OSINT intelligence — passive, no target contact."""
    # WHOIS fields
    whois_raw:    str  = ""
    whois_emails: List[str] = field(default_factory=list)
    whois_org:    str  = ""
    whois_country:str  = ""
    whois_created:str  = ""
    whois_expires:str  = ""
    whois_registrar: str = ""
    # Misconfigs propagated from web/SSL
    misconfigs:   List[str] = field(default_factory=list)
    # OS guess from TTL
    os_guess:     str  = ""
    # Reverse IP co-hosted domains
    reverse_ip:   List[str] = field(default_factory=list)


@dataclass
class ScanResult:
    target:       str
    target_type:  str   = "unknown"      # ip | domain
    ip_address:   str   = ""
    hostname:     str   = ""
    scan_mode:    str   = ""             # active | passive | web | full
    scan_type:    str   = ""             # display label
    started_at:   str   = ""
    finished_at:  str   = ""
    duration_sec: float = 0.0

    # ── Active modules ─────────────────────────────────────────────────────
    ports:      List[PortResult]  = field(default_factory=list)
    smtp:       SMTPResult        = field(default_factory=SMTPResult)
    network:    NetworkResult     = field(default_factory=NetworkResult)

    # ── Passive modules ────────────────────────────────────────────────────
    dns:        DNSResult         = field(default_factory=DNSResult)
    asn:        ASNResult         = field(default_factory=ASNResult)
    geoip:      GeoIPResult       = field(default_factory=GeoIPResult)
    intel:      IntelResult       = field(default_factory=IntelResult)
    subdomains: List[str]         = field(default_factory=list)
    dorks:      List[GoogleDorkResult] = field(default_factory=list)
    github_leaks: List[GitHubLeakResult] = field(default_factory=list)

    # ── Web modules ────────────────────────────────────────────────────────
    web:        WebResult         = field(default_factory=WebResult)
    ssl:        SSLResult         = field(default_factory=SSLResult)

    # ── API-key gated modules ──────────────────────────────────────────────
    shodan:     ShodanResult      = field(default_factory=ShodanResult)

    # ── Meta ───────────────────────────────────────────────────────────────
    stats:      Dict[str, Any]    = field(default_factory=dict)
    warnings:   List[str]         = field(default_factory=list)
