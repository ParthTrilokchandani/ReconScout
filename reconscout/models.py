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
    cpe:      str = ""          # Common Platform Enumeration string


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
class WebResult:
    url:            str  = ""
    status_code:    int  = 0
    server:         str  = ""
    title:          str  = ""
    technologies:   List[str]       = field(default_factory=list)
    headers:        Dict[str, str]  = field(default_factory=dict)
    cookies:        List[str]       = field(default_factory=list)
    robots_txt:     str  = ""
    sitemap:        str  = ""
    https_redirect: bool = False
    hsts:           bool = False
    cdn_waf:        List[str] = field(default_factory=list)
    directories:    List[str] = field(default_factory=list)
    misconfigs:     List[str] = field(default_factory=list)
    forms:          List[str] = field(default_factory=list)
    emails:         List[str] = field(default_factory=list)
    comments:       List[str] = field(default_factory=list)
    js_files:       List[str] = field(default_factory=list)
    links:          List[str] = field(default_factory=list)
    screenshot_b64: str  = ""
    content_length: int  = 0
    response_time:  float = 0.0


@dataclass
class SSLResult:
    enabled:        bool = False
    version:        str  = ""
    cipher:         str  = ""
    issuer:         str  = ""
    subject:        str  = ""
    valid_from:     str  = ""
    valid_to:       str  = ""
    expired:        bool = False
    self_signed:    bool = False
    san:            List[str] = field(default_factory=list)
    vulnerabilities: List[str] = field(default_factory=list)
    grade:          str  = ""


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
    """Results from network-level recon: traceroute, firewall detection."""
    hops:          List[Dict] = field(default_factory=list)   # [{hop, ip, rtt_ms}]
    firewall_detected: bool   = False
    firewall_type: str        = ""
    load_balancer: bool       = False
    isp:           str        = ""


@dataclass
class IntelResult:
    whois_raw:    str  = ""
    whois_emails: List[str]      = field(default_factory=list)
    whois_org:    str  = ""
    whois_country:str  = ""
    whois_created:str  = ""
    whois_expires:str  = ""
    asn:          str  = ""
    ip_range:     str  = ""
    geoip:        Dict[str, str] = field(default_factory=dict)
    reverse_ip:   List[str]      = field(default_factory=list)
    os_guess:     str  = ""
    misconfigs:   List[str]      = field(default_factory=list)
    shodan_data:  Dict           = field(default_factory=dict)
    cve_list:     List[str]      = field(default_factory=list)
    leaked_creds: List[str]      = field(default_factory=list)


@dataclass
class ScanResult:
    target:       str
    target_type:  str  = "unknown"   # ip | domain
    ip_address:   str  = ""
    hostname:     str  = ""
    scan_mode:    str  = ""          # active | passive | web | full | custom
    scan_type:    str  = ""          # active | passive (top-level category)
    started_at:   str  = ""
    finished_at:  str  = ""
    duration_sec: float = 0.0

    ports:      List[PortResult]  = field(default_factory=list)
    dns:        DNSResult         = field(default_factory=DNSResult)
    web:        WebResult         = field(default_factory=WebResult)
    ssl:        SSLResult         = field(default_factory=SSLResult)
    smtp:       SMTPResult        = field(default_factory=SMTPResult)
    network:    NetworkResult     = field(default_factory=NetworkResult)
    intel:      IntelResult       = field(default_factory=IntelResult)
    subdomains: List[str]         = field(default_factory=list)
    stats:      Dict[str, Any]    = field(default_factory=dict)
    warnings:   List[str]         = field(default_factory=list)
