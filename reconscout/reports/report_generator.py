"""
ReconScout — Report Generator
Produces: structured JSON, cybersecurity dark-theme HTML dashboard, CLI table.

Author  : Agent P
Project : ReconScout v2.1
"""

import json
from dataclasses import asdict
from datetime import datetime
from html import escape as he
from pathlib import Path
from typing import Any, Dict, List

from reconscout.models import ScanResult
from reconscout.utils.helpers import C


# ══════════════════════════════════════════════════════════════════════════════
# JSON
# ══════════════════════════════════════════════════════════════════════════════

class JSONReport:
    def __init__(self, result: ScanResult, logger):
        self.result = result
        self.logger = logger

    def save(self, path: str):
        def _ser(obj: Any) -> Any:
            if hasattr(obj, "__dataclass_fields__"):
                return {k: _ser(v) for k, v in asdict(obj).items()}
            if isinstance(obj, (list, tuple)):
                return [_ser(i) for i in obj]
            if isinstance(obj, dict):
                return {k: _ser(v) for k, v in obj.items()}
            return obj

        data = {
            "meta": {
                "tool":        "ReconScout v2.1",
                "author":      "Agent P",
                "generated":   datetime.now().isoformat(),
                "disclaimer":  "For authorized security testing only",
                "github":      "github.com/yourorg/reconscout",
            },
            "result": _ser(self.result),
        }
        Path(path).write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        self.logger.info(f"JSON report saved → {path}")


# ══════════════════════════════════════════════════════════════════════════════
# HTML
# ══════════════════════════════════════════════════════════════════════════════

class HTMLReport:
    def __init__(self, result: ScanResult, logger):
        self.result = result
        self.logger = logger

    # ── Helper renderers ───────────────────────────────────────────────────

    def _badge(self, text: str, style: str) -> str:
        classes = {"open":"badge-open","closed":"badge-closed",
                   "filtered":"badge-filtered","open|filtered":"badge-filtered"}
        return f'<span class="badge {classes.get(style,"badge-info")}">{he(text)}</span>'

    def _tag(self, text: str, cls: str) -> str:
        return f'<span class="{cls}">{he(text)}</span>'

    def _info_row(self, key: str, value: str, mono: bool = True) -> str:
        if not value:
            return ""
        cls = "info-val mono" if mono else "info-val"
        return (f'<div class="info-row">'
                f'<span class="info-key">{he(key)}</span>'
                f'<span class="{cls}">{he(str(value))}</span>'
                f'</div>')

    def _section(self, icon: str, title: str, body: str, full: bool = False) -> str:
        extra = ' full' if full else ''
        return f"""
<div class="section{extra}">
  <div class="section-header">
    <span class="s-icon">{icon}</span>
    <span class="s-title">{he(title)}</span>
  </div>
  <div class="section-body">{body}</div>
</div>"""

    # ── Chart data ─────────────────────────────────────────────────────────

    def _chart_data(self):
        r = self.result
        open_ports  = [p for p in r.ports if p.state == "open"]
        port_labels = json.dumps([str(p.port) for p in open_ports[:20]])
        port_vals   = json.dumps([1] * len(open_ports[:20]))

        svc: Dict[str, int] = {}
        for p in open_ports:
            s = p.service or "unknown"
            svc[s] = svc.get(s, 0) + 1
        svc_labels = json.dumps(list(svc.keys()))
        svc_vals   = json.dumps(list(svc.values()))

        # Port state distribution
        states = {"Open": len(open_ports),
                  "Closed": len([p for p in r.ports if p.state=="closed"]),
                  "Filtered": len([p for p in r.ports if "filtered" in p.state])}
        state_labels = json.dumps(list(states.keys()))
        state_vals   = json.dumps(list(states.values()))

        return port_labels, port_vals, svc_labels, svc_vals, state_labels, state_vals

    # ── Section builders ───────────────────────────────────────────────────

    def _target_summary(self) -> str:
        r   = self.result
        geo = r.intel.geoip
        left = "".join([
            self._info_row("Target",        r.target),
            self._info_row("Type",          r.target_type.upper()),
            self._info_row("IP Address",    r.ip_address),
            self._info_row("Hostname",      r.hostname),
            self._info_row("Scan Mode",     r.scan_mode.upper()),
            self._info_row("Scan Type",     r.scan_type.upper()),
            self._info_row("OS Fingerprint",r.intel.os_guess),
            self._info_row("ASN",           r.intel.asn),
            self._info_row("IP Range",      r.intel.ip_range),
        ])
        right = "".join([
            self._info_row("Country",  geo.get("country", "")),
            self._info_row("Region",   geo.get("region", "")),
            self._info_row("City",     geo.get("city", "")),
            self._info_row("ISP",      geo.get("isp", "")),
            self._info_row("Org",      geo.get("org", "")),
            self._info_row("Timezone", geo.get("timezone", "")),
            self._info_row("Started",  r.started_at),
            self._info_row("Finished", r.finished_at),
            self._info_row("Duration", f"{r.duration_sec:.1f}s"),
            self._info_row("Top Service", r.stats.get("top_service","")),
        ])
        return f'<div class="two-col">{left}{right}</div>'

    def _ports_table(self) -> str:
        open_ports = [p for p in self.result.ports if p.state == "open"]
        if not open_ports:
            return '<div class="empty">No open ports detected</div>'
        rows = ""
        for p in open_ports:
            banner = he(p.banner[:90].replace('\n',' ')) if p.banner else ""
            cpe    = f'<span class="cpe-tag">{he(p.cpe)}</span>' if p.cpe else ""
            rows += (
                f"<tr>"
                f"<td class='mono bold'>{p.port}</td>"
                f"<td>{p.protocol.upper()}</td>"
                f"<td>{self._badge(p.state, p.state)}</td>"
                f"<td class='mono'>{he(p.service)}</td>"
                f"<td class='mono dim'>{he(p.version)}</td>"
                f"<td class='banner'>{banner}</td>"
                f"<td>{cpe}</td>"
                f"</tr>"
            )
        return (
            '<table><thead><tr>'
            '<th>Port</th><th>Proto</th><th>State</th>'
            '<th>Service</th><th>Version</th><th>Banner</th><th>CPE</th>'
            '</tr></thead>'
            f'<tbody>{rows}</tbody></table>'
        )

    def _all_ports_table(self) -> str:
        if not self.result.ports:
            return '<div class="empty">No ports scanned</div>'
        rows = ""
        for p in self.result.ports:
            if p.state == "open":
                continue   # already in open ports section
            rows += (
                f"<tr class='dim-row'>"
                f"<td class='mono'>{p.port}</td>"
                f"<td>{p.protocol.upper()}</td>"
                f"<td>{self._badge(p.state, p.state)}</td>"
                f"<td class='mono dim'>{he(p.service)}</td>"
                f"</tr>"
            )
        if not rows:
            return '<div class="empty">All scanned ports were open or no data</div>'
        return (
            '<table><thead><tr><th>Port</th><th>Proto</th><th>State</th><th>Service</th></tr></thead>'
            f'<tbody>{rows}</tbody></table>'
        )

    def _dns_section(self) -> str:
        dns = self.result.dns
        rows = ""
        type_map = [("A",dns.a),("AAAA",dns.aaaa),("MX",dns.mx),("NS",dns.ns),
                    ("TXT",dns.txt),("CNAME",dns.cname),("SOA",dns.soa),
                    ("SRV",dns.srv),("PTR",dns.reverse)]
        for rtype, records in type_map:
            for rec in records:
                rows += f"<tr><td>{self._tag(rtype,'rtag')}</td><td class='mono'>{he(rec)}</td></tr>"
        if not rows:
            return '<div class="empty">No DNS records</div>'
        zt_warn = ""
        if dns.zone_transfer:
            zt_warn = (
                '<div class="alert alert-crit">'
                f'⚠ ZONE TRANSFER SUCCEEDED — {len(dns.zone_transfer)} records exposed!</div>'
            )
        return zt_warn + f'<table><thead><tr><th>Type</th><th>Value</th></tr></thead><tbody>{rows}</tbody></table>'

    def _ssl_section(self) -> str:
        ssl = self.result.ssl
        if not ssl.enabled:
            return '<div class="empty">SSL/TLS not detected or not scanned</div>'
        grade_color = {"A+":"#00e676","A":"#00e676","B":"#ffd740","C":"#ffd740","D":"#ff5252","F":"#ff5252"}.get(ssl.grade,"#64748b")
        grade_html  = f'<div class="ssl-grade" style="color:{grade_color}">{he(ssl.grade)}</div>'
        rows = "".join([
            self._info_row("Enabled",     "Yes ✓"),
            self._info_row("Version",     ssl.version),
            self._info_row("Cipher",      ssl.cipher),
            self._info_row("Issuer",      ssl.issuer),
            self._info_row("Subject",     ssl.subject),
            self._info_row("Valid From",  ssl.valid_from),
            self._info_row("Valid To",    ssl.valid_to),
            self._info_row("Expired",     "⚠ YES" if ssl.expired else "No"),
            self._info_row("Self-Signed", "⚠ YES" if ssl.self_signed else "No"),
        ])
        sans = "".join(f'{self._tag(s,"subdomain-tag")} ' for s in ssl.san[:20])
        vulns = "".join(
            f'<div class="finding"><span class="warn-icon">⚠</span> {he(v)}</div>'
            for v in ssl.vulnerabilities
        ) or '<div class="ok">No SSL vulnerabilities detected</div>'
        return f'{grade_html}{rows}<div class="label">SANs</div>{sans or "<div class=\'empty\'>None</div>"}<div class="label mt">Vulnerabilities</div>{vulns}'

    def _web_section(self) -> str:
        w = self.result.web
        if not w.url:
            return '<div class="empty">Web recon not performed</div>'

        basic = "".join([
            self._info_row("URL",           w.url),
            self._info_row("Status",        str(w.status_code)),
            self._info_row("Response Time", f"{w.response_time}s"),
            self._info_row("Content Length",f"{w.content_length:,} bytes"),
            self._info_row("Server",        w.server),
            self._info_row("Title",         w.title),
            self._info_row("HTTPS Redirect","Yes ✓" if w.https_redirect else "No ✗"),
            self._info_row("HSTS",          "Yes ✓" if w.hsts else "No ✗"),
        ])
        techs = "".join(self._tag(t,"tech-badge") for t in w.technologies) or '<span class="dim">None detected</span>'
        cdns  = "".join(self._tag(c,"cdn-badge") for c in w.cdn_waf) or '<span class="dim">None detected</span>'
        mc    = "".join(
            f'<div class="finding"><span class="warn-icon">⚠</span> {he(m)}</div>'
            for m in w.misconfigs
        ) or '<div class="ok">No misconfigurations detected</div>'

        hdrs = "".join(
            f"<tr><td class='mono dim'>{he(k)}</td><td class='mono small'>{he(v[:150])}</td></tr>"
            for k, v in w.headers.items()
        )
        hdr_table = f'<table class="compact"><thead><tr><th>Header</th><th>Value</th></tr></thead><tbody>{hdrs}</tbody></table>' if hdrs else ""

        emails_html  = " ".join(self._tag(e,"subdomain-tag") for e in w.emails) or ""
        forms_html   = "".join(f'<div class="item-row">▶ {he(f)}</div>' for f in w.forms) or ""
        comments_html= "".join(f'<div class="comment-block">{he(c)}</div>' for c in w.comments) or ""
        dirs_html    = "".join(
            f'<div class="finding"><span style="color:var(--green)">▶</span> {he(d)}</div>'
            for d in w.directories
        ) or ""
        js_html = " ".join(f'<span class="js-tag">{he(j)}</span>' for j in w.js_files[:15]) or ""

        robots_html = f'<details><summary class="expand-toggle">robots.txt (click to expand)</summary><pre>{he(w.robots_txt)}</pre></details>' if w.robots_txt else ""

        return f"""
<div class="two-col">
  <div>{basic}<div class="label">Technologies</div>{techs}<div class="label mt">CDN / WAF</div>{cdns}</div>
  <div><div class="label">Security Misconfigurations</div>{mc}</div>
</div>
{hdr_table}
{('<div class="label mt">Emails Found</div>' + emails_html) if w.emails else ""}
{('<div class="label mt">Forms</div>' + forms_html) if w.forms else ""}
{('<div class="label mt">HTML Comments</div>' + comments_html) if w.comments else ""}
{('<div class="label mt">JS Files</div>' + js_html) if w.js_files else ""}
{('<div class="label mt">Directories Found</div>' + dirs_html) if w.directories else ""}
{('<div class="label mt">HTTP Methods</div>' + "".join(f'<span class="method-tag">{he(m)}</span>' for m in w.misconfigs if "method" in m.lower())) if any("method" in m.lower() for m in w.misconfigs) else ""}
{robots_html}
"""

    def _smtp_section(self) -> str:
        s = self.result.smtp
        if not s.open:
            return '<div class="empty">SMTP not open or not scanned</div>'
        rows = "".join([
            self._info_row("Open",         "Yes ✓"),
            self._info_row("Banner",       s.banner),
            self._info_row("STARTTLS",     "Yes ✓" if s.starttls else "No ✗"),
            self._info_row("AUTH Methods", ", ".join(s.auth_methods) if s.auth_methods else "None"),
            self._info_row("Open Relay",   "⚠ YES — CRITICAL!" if s.open_relay else "No"),
            self._info_row("VRFY Enabled", "Yes (user enum possible)" if s.vrfy_enabled else "No"),
            self._info_row("EXPN Enabled", "Yes" if s.expn_enabled else "No"),
            self._info_row("Users Found",  ", ".join(s.users_found) if s.users_found else "None"),
        ])
        if s.open_relay:
            rows = '<div class="alert alert-crit">⚠ OPEN RELAY DETECTED — can be used for spam!</div>' + rows
        return rows

    def _network_section(self) -> str:
        n = self.result.network
        if not n.hops:
            return '<div class="empty">Network recon not performed</div>'
        rows = ""
        for h in n.hops:
            ip   = h.get("ip", "") or "* * *"
            host = h.get("hostname", "")
            rtt  = f"{h.get('rtt_ms', 0):.1f}ms"
            rows += f"<tr><td class='mono dim'>{h.get('hop','')}</td><td class='mono'>{he(ip)}</td><td class='mono small dim'>{he(host)}</td><td class='mono'>{rtt}</td></tr>"
        table = f'<table class="compact"><thead><tr><th>Hop</th><th>IP</th><th>Hostname</th><th>RTT</th></tr></thead><tbody>{rows}</tbody></table>'
        fw = f'<div class="finding"><span class="warn-icon">🔥</span> Firewall detected: {he(n.firewall_type)}</div>' if n.firewall_detected else '<div class="ok">No firewall filtering detected</div>'
        lb = '<div class="finding"><span class="warn-icon">⚖</span> Load balancer detected</div>' if n.load_balancer else ""
        return f"{fw}{lb}{table}"

    def _whois_section(self) -> str:
        intel = self.result.intel
        rows = "".join([
            self._info_row("Org",       intel.whois_org),
            self._info_row("Country",   intel.whois_country),
            self._info_row("Created",   intel.whois_created),
            self._info_row("Expires",   intel.whois_expires),
            self._info_row("ASN",       intel.asn),
            self._info_row("IP Range",  intel.ip_range),
        ])
        emails = "".join(self._tag(e,"subdomain-tag") for e in intel.whois_emails) or '<span class="dim">None</span>'
        rev_ip = "".join(f'<div class="item-row">{he(d)}</div>' for d in intel.reverse_ip[:10]) or ""
        raw_block = (
            f'<details><summary class="expand-toggle">Raw WHOIS (click to expand)</summary>'
            f'<pre>{he(intel.whois_raw[:4000])}</pre></details>'
            if intel.whois_raw else ""
        )
        return f'{rows}<div class="label mt">WHOIS Emails</div>{emails}{("<div class=\'label mt\'>Reverse IP Hosts</div>" + rev_ip) if rev_ip else ""}{raw_block}'

    def _subdomains_section(self) -> str:
        subs = self.result.subdomains
        if not subs:
            return '<div class="empty">No subdomains discovered</div>'
        tags = "".join(self._tag(s, "subdomain-tag") for s in subs)
        return f'<div class="subdomain-grid">{tags}</div>'

    # ── Main render ────────────────────────────────────────────────────────

    def save(self, path: str):
        r  = self.result
        s  = r.stats
        pl, pv, sl, sv, stl, stv = self._chart_data()
        dur = f"{r.duration_sec:.1f}s"

        open_c     = s.get("open_ports", 0)
        closed_c   = s.get("closed_ports", 0)
        filtered_c = s.get("filtered_ports", 0)
        sub_c      = len(r.subdomains)
        vuln_c     = len(r.web.misconfigs) + len(r.ssl.vulnerabilities)

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ReconScout :: {he(r.target)}</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:ital,wght@0,300;0,400;0,700;1,400&family=Space+Grotesk:wght@400;500;600;700&display=swap');

:root {{
  --bg:      #060911;
  --surface: #0b1120;
  --card:    #0f1929;
  --card2:   #131f30;
  --border:  #1b2d45;
  --border2: #243550;
  --accent:  #00e5ff;
  --accent2: #7c3aed;
  --green:   #00e676;
  --yellow:  #ffd740;
  --red:     #ff5252;
  --orange:  #ff9800;
  --text:    #c8d6e8;
  --muted:   #4a6080;
  --dim:     #2d4060;
  --mono:    'JetBrains Mono', monospace;
  --sans:    'Space Grotesk', sans-serif;
}}

*, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
html {{ scroll-behavior: smooth; }}
body {{
  background: var(--bg); color: var(--text);
  font-family: var(--sans); font-size: 14px; line-height: 1.6;
  min-height: 100vh;
}}

/* SCROLLBAR */
::-webkit-scrollbar {{ width: 5px; height: 5px; }}
::-webkit-scrollbar-track {{ background: var(--surface); }}
::-webkit-scrollbar-thumb {{ background: var(--border2); border-radius: 2px; }}
::selection {{ background: rgba(0,229,255,0.15); }}

/* ── SIDEBAR NAV ─────────────────────────────────────────── */
.sidebar {{
  position: fixed; left: 0; top: 0; bottom: 0;
  width: 220px; background: var(--surface);
  border-right: 1px solid var(--border);
  display: flex; flex-direction: column;
  z-index: 100; overflow-y: auto;
}}
.sidebar-logo {{
  padding: 20px 20px 16px;
  border-bottom: 1px solid var(--border);
}}
.sidebar-logo .tool-name {{
  font-size: 15px; font-weight: 700; color: var(--accent);
  letter-spacing: 3px; text-transform: uppercase;
}}
.sidebar-logo .tool-ver {{ font-size: 10px; color: var(--muted); font-family: var(--mono); }}
.sidebar-logo .tool-author {{ font-size: 10px; color: var(--accent2); font-family: var(--mono); margin-top: 2px; letter-spacing: 0.5px; }}
.sidebar-logo .target-name {{ font-size: 11px; color: var(--text); margin-top: 8px; font-family: var(--mono); word-break: break-all; }}
.nav-section {{ padding: 12px 0; border-bottom: 1px solid var(--border); }}
.nav-label {{ padding: 4px 20px 2px; font-size: 9px; color: var(--muted); text-transform: uppercase; letter-spacing: 2px; }}
.nav-item {{
  display: flex; align-items: center; gap: 10px;
  padding: 8px 20px; font-size: 12px; color: var(--muted);
  cursor: pointer; transition: all .15s;
  text-decoration: none;
}}
.nav-item:hover {{ color: var(--accent); background: rgba(0,229,255,0.04); }}
.nav-item .nav-icon {{ font-size: 14px; width: 18px; text-align: center; }}
.sidebar-stats {{ padding: 16px 20px; margin-top: auto; border-top: 1px solid var(--border); }}
.sidebar-stat {{ display: flex; justify-content: space-between; padding: 3px 0; font-size: 11px; font-family: var(--mono); }}
.sidebar-stat-key {{ color: var(--muted); }}
.sidebar-stat-val {{ color: var(--accent); font-weight: 700; }}

/* ── MAIN LAYOUT ─────────────────────────────────────────── */
.main {{ margin-left: 220px; min-height: 100vh; }}
.topbar {{
  background: var(--surface); border-bottom: 1px solid var(--border);
  padding: 16px 32px; display: flex; align-items: center; justify-content: space-between;
  position: sticky; top: 0; z-index: 50;
}}
.topbar-left h1 {{ font-size: 16px; font-weight: 600; color: var(--text); }}
.topbar-left p  {{ font-size: 11px; color: var(--muted); font-family: var(--mono); }}
.topbar-right   {{ display: flex; gap: 8px; }}
.pill {{
  padding: 4px 12px; font-size: 10px; font-family: var(--mono);
  border: 1px solid; letter-spacing: 1px; text-transform: uppercase;
}}
.pill-active   {{ color: var(--green);  border-color: rgba(0,230,118,0.4); background: rgba(0,230,118,0.06); }}
.pill-passive  {{ color: var(--accent); border-color: rgba(0,229,255,0.4); background: rgba(0,229,255,0.06); }}
.pill-duration {{ color: var(--yellow); border-color: rgba(255,215,64,0.4); background: rgba(255,215,64,0.06); }}
.pill-author   {{ color: var(--accent2); border-color: rgba(124,58,237,0.4); background: rgba(124,58,237,0.07); letter-spacing: 0.5px; }}

.disclaimer-bar {{
  background: rgba(255,82,82,0.07); border-bottom: 1px solid rgba(255,82,82,0.2);
  padding: 7px 32px; font-family: var(--mono); font-size: 10px;
  color: #ff8a80; letter-spacing: 1px; text-align: center;
}}

.content {{ padding: 24px 32px 48px; }}

/* ── STAT CARDS ──────────────────────────────────────────── */
.stats-row {{ display: grid; grid-template-columns: repeat(5,1fr); gap: 14px; margin-bottom: 20px; }}
.stat-card {{
  background: var(--card); border: 1px solid var(--border);
  padding: 18px 20px; position: relative; overflow: hidden;
  transition: border-color .2s, transform .1s;
}}
.stat-card:hover {{ border-color: var(--border2); transform: translateY(-1px); }}
.stat-card::before {{
  content: ''; position: absolute; top: 0; left: 0;
  width: 2px; height: 100%;
}}
.stat-card.c::before {{ background: var(--accent);  }}
.stat-card.g::before {{ background: var(--green);   }}
.stat-card.r::before {{ background: var(--red);     }}
.stat-card.y::before {{ background: var(--yellow);  }}
.stat-card.p::before {{ background: var(--accent2); }}
.stat-val   {{ font-size: 34px; font-weight: 700; font-family: var(--mono); line-height: 1; }}
.stat-card.c .stat-val {{ color: var(--accent);  }}
.stat-card.g .stat-val {{ color: var(--green);   }}
.stat-card.r .stat-val {{ color: var(--red);     }}
.stat-card.y .stat-val {{ color: var(--yellow);  }}
.stat-card.p .stat-val {{ color: #a78bfa;        }}
.stat-label {{ font-size: 9px; color: var(--muted); text-transform: uppercase; letter-spacing: 2px; margin-top: 6px; }}

/* ── SECTIONS ────────────────────────────────────────────── */
.grid-2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 16px; }}
.section {{ background: var(--card); border: 1px solid var(--border); margin-bottom: 16px; }}
.section.full {{ }}
.section-header {{
  padding: 12px 20px; border-bottom: 1px solid var(--border);
  display: flex; align-items: center; gap: 10px;
  background: rgba(255,255,255,0.01);
}}
.s-icon  {{ font-size: 15px; }}
.s-title {{ font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 2.5px; color: var(--accent); font-family: var(--mono); }}
.section-body {{ padding: 18px 20px; }}
.section-body.pad0 {{ padding: 0; }}

/* ── TWO-COL ─────────────────────────────────────────────── */
.two-col {{ display: grid; grid-template-columns: 1fr 1fr; gap: 24px; }}

/* ── INFO ROWS ───────────────────────────────────────────── */
.info-row {{ display: flex; padding: 6px 0; border-bottom: 1px solid rgba(27,45,69,0.5); }}
.info-row:last-child {{ border-bottom: none; }}
.info-key {{ width: 140px; flex-shrink: 0; color: var(--muted); font-size: 11px; font-family: var(--mono); padding-top: 1px; }}
.info-val {{ font-size: 12px; font-family: var(--sans); color: var(--text); word-break: break-all; }}
.info-val.mono {{ font-family: var(--mono); font-size: 11px; }}

/* ── TABLES ──────────────────────────────────────────────── */
table {{ width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 11px; }}
table.compact {{ font-size: 11px; }}
th {{
  text-align: left; padding: 8px 12px; color: var(--muted); font-size: 10px;
  text-transform: uppercase; letter-spacing: 1.5px;
  border-bottom: 1px solid var(--border); background: rgba(255,255,255,0.01);
  font-family: var(--sans); font-weight: 600;
}}
td {{ padding: 8px 12px; border-bottom: 1px solid rgba(27,45,69,0.4); vertical-align: top; }}
tr:hover td {{ background: rgba(0,229,255,0.02); }}
tr:last-child td {{ border-bottom: none; }}
td.banner {{ color: var(--muted); font-size: 10px; max-width: 250px; word-break: break-all; }}
tr.dim-row td {{ opacity: 0.55; }}

/* ── BADGES ──────────────────────────────────────────────── */
.badge {{ display: inline-block; padding: 2px 8px; font-size: 9px; font-weight: 700; font-family: var(--mono); letter-spacing: 1px; text-transform: uppercase; }}
.badge-open     {{ background: rgba(0,230,118,0.1); border: 1px solid rgba(0,230,118,0.35); color: var(--green); }}
.badge-closed   {{ background: rgba(255,82,82,0.08); border: 1px solid rgba(255,82,82,0.3); color: var(--red); }}
.badge-filtered {{ background: rgba(255,215,64,0.07); border: 1px solid rgba(255,215,64,0.3); color: var(--yellow); }}
.badge-info     {{ background: rgba(0,229,255,0.07); border: 1px solid rgba(0,229,255,0.3); color: var(--accent); }}

.tech-badge, .cdn-badge, .subdomain-tag, .js-tag, .method-tag, .cpe-tag {{
  display: inline-block; margin: 3px; padding: 3px 10px; font-size: 10px; font-family: var(--mono);
}}
.tech-badge  {{ background: rgba(124,58,237,0.1); border: 1px solid rgba(124,58,237,0.3); color: #c4b5fd; }}
.cdn-badge   {{ background: rgba(255,215,64,0.07); border: 1px solid rgba(255,215,64,0.3); color: var(--yellow); }}
.subdomain-tag {{ background: rgba(0,229,255,0.05); border: 1px solid rgba(0,229,255,0.2); color: var(--accent); }}
.js-tag      {{ background: rgba(255,152,0,0.07); border: 1px solid rgba(255,152,0,0.25); color: var(--orange); font-size: 9px; word-break: break-all; }}
.method-tag  {{ background: rgba(255,82,82,0.1); border: 1px solid rgba(255,82,82,0.3); color: var(--red); }}
.cpe-tag     {{ background: rgba(100,116,139,0.1); border: 1px solid rgba(100,116,139,0.2); color: var(--muted); font-size: 9px; }}
.rtag        {{ display: inline-block; padding: 1px 7px; font-size: 9px; background: rgba(0,229,255,0.07); border: 1px solid rgba(0,229,255,0.2); color: var(--accent); letter-spacing: 1px; }}
.bold        {{ font-weight: 700; }}
.mono        {{ font-family: var(--mono); }}
.dim         {{ color: var(--muted); }}
.small       {{ font-size: 10px; }}

/* ── FINDINGS / ALERTS ───────────────────────────────────── */
.finding     {{ padding: 8px 14px; margin: 4px 0; background: rgba(255,82,82,0.05); border-left: 2px solid rgba(255,82,82,0.5); font-family: var(--mono); font-size: 11px; }}
.warn-icon   {{ color: var(--red); margin-right: 8px; }}
.ok          {{ color: var(--green); font-family: var(--mono); font-size: 11px; padding: 8px 0; }}
.empty       {{ color: var(--muted); font-family: var(--mono); font-size: 11px; padding: 12px 0; font-style: italic; }}
.alert       {{ padding: 10px 16px; margin-bottom: 12px; font-family: var(--mono); font-size: 11px; border-left: 3px solid; }}
.alert-crit  {{ background: rgba(255,82,82,0.1); border-color: var(--red); color: #fca5a5; }}
.item-row    {{ padding: 4px 0; font-family: var(--mono); font-size: 11px; color: var(--text); border-bottom: 1px solid rgba(27,45,69,0.3); }}
.comment-block {{ background: rgba(255,215,64,0.04); border: 1px solid rgba(255,215,64,0.15); padding: 8px 12px; margin: 4px 0; font-family: var(--mono); font-size: 10px; color: var(--muted); word-break: break-all; }}
.subdomain-grid {{ display: flex; flex-wrap: wrap; gap: 4px; }}

/* ── SSL ─────────────────────────────────────────────────── */
.ssl-grade {{ font-size: 48px; font-weight: 700; font-family: var(--mono); margin-bottom: 12px; }}

/* ── LABELS ──────────────────────────────────────────────── */
.label {{ font-size: 9px; color: var(--muted); text-transform: uppercase; letter-spacing: 2px; font-family: var(--mono); margin-top: 14px; margin-bottom: 6px; }}
.label.mt {{ margin-top: 18px; }}

/* ── CHARTS ──────────────────────────────────────────────── */
.chart-wrap {{ position: relative; height: 200px; }}

/* ── PRE / CODE ──────────────────────────────────────────── */
pre {{
  background: rgba(0,0,0,0.5); border: 1px solid var(--border);
  padding: 12px; font-family: var(--mono); font-size: 10px; color: var(--muted);
  overflow: auto; max-height: 280px; white-space: pre-wrap; line-height: 1.5; margin-top: 8px;
}}
details .expand-toggle {{
  cursor: pointer; color: var(--muted); font-size: 10px; font-family: var(--mono);
  padding: 6px 0; user-select: none; list-style: none;
}}
details .expand-toggle:hover {{ color: var(--accent); }}
details[open] .expand-toggle {{ color: var(--accent); }}

/* ── FOOTER ──────────────────────────────────────────────── */
.footer {{
  text-align: center; padding: 20px 32px;
  font-family: var(--mono); font-size: 10px; color: var(--muted);
  border-top: 1px solid var(--border); letter-spacing: 1px;
  margin-left: 220px;
}}

/* ── RESPONSIVE ──────────────────────────────────────────── */
@media (max-width:1100px) {{
  .sidebar {{ display:none; }}
  .main,.footer {{ margin-left:0; }}
  .stats-row {{ grid-template-columns: repeat(3,1fr); }}
  .two-col {{ grid-template-columns: 1fr; }}
  .grid-2  {{ grid-template-columns: 1fr; }}
}}
@media (max-width:600px) {{
  .stats-row {{ grid-template-columns: 1fr 1fr; }}
  .content {{ padding: 16px; }}
}}
</style>
</head>
<body>

<!-- SIDEBAR -->
<aside class="sidebar">
  <div class="sidebar-logo">
    <div class="tool-name">ReconScout</div>
    <div class="tool-ver">v2.1 — Advanced Recon Suite</div>
    <div class="tool-author">by Agent P</div>
    <div class="target-name">⬡ {he(r.target)}</div>
  </div>
  <nav>
    <div class="nav-section">
      <div class="nav-label">Overview</div>
      <a href="#summary"    class="nav-item"><span class="nav-icon">🎯</span> Target Summary</a>
      <a href="#charts"     class="nav-item"><span class="nav-icon">📊</span> Charts</a>
    </div>
    <div class="nav-section">
      <div class="nav-label">Active Recon</div>
      <a href="#ports"      class="nav-item"><span class="nav-icon">🔓</span> Open Ports</a>
      <a href="#allports"   class="nav-item"><span class="nav-icon">🔒</span> All Ports</a>
      <a href="#network"    class="nav-item"><span class="nav-icon">🌐</span> Network Map</a>
      <a href="#smtp"       class="nav-item"><span class="nav-icon">📧</span> SMTP</a>
    </div>
    <div class="nav-section">
      <div class="nav-label">Passive Recon</div>
      <a href="#dns"        class="nav-item"><span class="nav-icon">📡</span> DNS Records</a>
      <a href="#whois"      class="nav-item"><span class="nav-icon">📋</span> WHOIS / Intel</a>
      <a href="#subdomains" class="nav-item"><span class="nav-icon">🔍</span> Subdomains</a>
    </div>
    <div class="nav-section">
      <div class="nav-label">Web</div>
      <a href="#ssl"        class="nav-item"><span class="nav-icon">🔐</span> SSL/TLS</a>
      <a href="#web"        class="nav-item"><span class="nav-icon">🌍</span> Web Recon</a>
    </div>
  </nav>
  <div class="sidebar-stats">
    <div class="sidebar-stat"><span class="sidebar-stat-key">Open Ports</span><span class="sidebar-stat-val">{open_c}</span></div>
    <div class="sidebar-stat"><span class="sidebar-stat-key">Subdomains</span><span class="sidebar-stat-val">{sub_c}</span></div>
    <div class="sidebar-stat"><span class="sidebar-stat-key">Findings</span><span class="sidebar-stat-val">{vuln_c}</span></div>
    <div class="sidebar-stat"><span class="sidebar-stat-key">Duration</span><span class="sidebar-stat-val">{dur}</span></div>
  </div>
</aside>

<!-- MAIN -->
<div class="main">

<div class="topbar">
  <div class="topbar-left">
    <h1>⬡ {he(r.target)}</h1>
    <p>{r.started_at} · {r.target_type.upper()} · {r.ip_address}</p>
  </div>
  <div class="topbar-right">
    <span class="pill pill-author">by Agent P</span>
    <span class="pill {'pill-active' if r.scan_type in ('active','active+passive') else 'pill-passive'}">{r.scan_mode.upper()}</span>
    <span class="pill pill-duration">⏱ {dur}</span>
  </div>
</div>

<div class="disclaimer-bar">
  ⚠ FOR AUTHORIZED SECURITY TESTING AND EDUCATIONAL PURPOSES ONLY ·
  UNAUTHORIZED SCANNING IS ILLEGAL · ENSURE WRITTEN PERMISSION BEFORE TESTING
</div>

<div class="content">

<!-- STAT CARDS -->
<div class="stats-row">
  <div class="stat-card g"><div class="stat-val">{open_c}</div><div class="stat-label">Open Ports</div></div>
  <div class="stat-card r"><div class="stat-val">{closed_c}</div><div class="stat-label">Closed</div></div>
  <div class="stat-card y"><div class="stat-val">{filtered_c}</div><div class="stat-label">Filtered</div></div>
  <div class="stat-card p"><div class="stat-val">{sub_c}</div><div class="stat-label">Subdomains</div></div>
  <div class="stat-card c"><div class="stat-val">{vuln_c}</div><div class="stat-label">Findings</div></div>
</div>

<!-- TARGET SUMMARY -->
<div id="summary">
{self._section("🎯","Target Summary", self._target_summary(), full=True)}
</div>

<!-- CHARTS -->
<div id="charts" class="grid-2">
  <div class="section">
    <div class="section-header"><span class="s-icon">📊</span><span class="s-title">Open Port Distribution</span></div>
    <div class="section-body"><div class="chart-wrap"><canvas id="portChart"></canvas></div></div>
  </div>
  <div class="section">
    <div class="section-header"><span class="s-icon">🔧</span><span class="s-title">Service Breakdown</span></div>
    <div class="section-body"><div class="chart-wrap"><canvas id="svcChart"></canvas></div></div>
  </div>
</div>

<!-- OPEN PORTS -->
<div id="ports">
{self._section("🔓","Open Ports & Services", '<div class="pad0">' + self._ports_table() + '</div>', full=True)}
</div>

<!-- ALL PORTS -->
<div id="allports">
{self._section("🔒","All Scanned Ports (Closed/Filtered)", '<div class="pad0">' + self._all_ports_table() + '</div>', full=True)}
</div>

<!-- DNS + WHOIS -->
<div class="grid-2">
  <div id="dns">{self._section("📡","DNS Records", self._dns_section())}</div>
  <div id="whois">{self._section("📋","WHOIS & Intelligence", self._whois_section())}</div>
</div>

<!-- SUBDOMAINS -->
<div id="subdomains">
{self._section("🔍", f"Subdomains Discovered ({sub_c})", self._subdomains_section(), full=True)}
</div>

<!-- SSL + NETWORK -->
<div class="grid-2">
  <div id="ssl">{self._section("🔐","SSL/TLS Analysis", self._ssl_section())}</div>
  <div id="network">{self._section("🌐","Network Map & Firewall", self._network_section())}</div>
</div>

<!-- SMTP -->
<div id="smtp">
{self._section("📧","SMTP Enumeration", self._smtp_section(), full=True)}
</div>

<!-- WEB RECON -->
<div id="web">
{self._section("🌍","Web Reconnaissance", self._web_section(), full=True)}
</div>

</div><!-- /content -->
</div><!-- /main -->

<footer class="footer">
  ReconScout v2.1 &nbsp;·&nbsp; by <span style="color:var(--accent2);font-weight:600">Agent P</span>
  &nbsp;·&nbsp; Generated {r.finished_at} &nbsp;·&nbsp; Duration: {dur}
  &nbsp;·&nbsp; FOR AUTHORIZED USE ONLY
</footer>

<script>
const MONO = "'JetBrains Mono',monospace";
const MUTED  = "#4a6080";
const BORDER = "#1b2d45";
const PAL = ["#00e5ff","#00e676","#7c3aed","#ffd740","#ff5252",
             "#ff9800","#40c4ff","#b39ddb","#69f0ae","#ffca28","#ff6e40","#26c6da"];

const baseOpts = {{
  responsive: true, maintainAspectRatio: false,
  plugins: {{ legend: {{ labels: {{ color: MUTED, font: {{ family: MONO, size: 10 }} }} }} }},
  scales: {{
    x: {{ ticks: {{ color: MUTED, font: {{ family: MONO, size: 9 }} }}, grid: {{ color: BORDER }} }},
    y: {{ ticks: {{ color: MUTED, font: {{ family: MONO, size: 9 }} }}, grid: {{ color: BORDER }}, beginAtZero: true }},
  }}
}};

new Chart(document.getElementById('portChart'), {{
  type: 'bar',
  data: {{
    labels: {pl},
    datasets: [{{ label: 'Port', data: {pv},
      backgroundColor: 'rgba(0,229,255,0.3)',
      borderColor: '#00e5ff', borderWidth: 1, borderRadius: 3
    }}]
  }},
  options: {{ ...baseOpts }}
}});

new Chart(document.getElementById('svcChart'), {{
  type: 'doughnut',
  data: {{
    labels: {sl},
    datasets: [{{ data: {sv},
      backgroundColor: PAL, borderColor: '#0f1929', borderWidth: 2
    }}]
  }},
  options: {{
    responsive: true, maintainAspectRatio: false,
    plugins: {{ legend: {{
      position: 'right',
      labels: {{ color: MUTED, font: {{ family: MONO, size: 10 }}, padding: 10, boxWidth: 10 }}
    }} }}
  }}
}});
</script>
</body>
</html>"""
        Path(path).write_text(html, encoding="utf-8")
        self.logger.info(f"HTML report saved → {path}")


# ══════════════════════════════════════════════════════════════════════════════
# CLI TABLE
# ══════════════════════════════════════════════════════════════════════════════

class CLIReport:
    def __init__(self, result: ScanResult, logger):
        self.result = result
        self.logger = logger

    def _hdr(self, title: str, icon: str = "◈"):
        W = 70
        print(f"\n{C.CYAN}{C.BOLD}  {icon} {title}{C.RESET}")
        print(f"  {C.CYAN}{'─' * (W - 2)}{C.RESET}")

    def _kv(self, key: str, val: str, color: str = C.RESET):
        if val:
            print(f"    {C.GREY}{key:<22}{C.RESET} {color}{val}{C.RESET}")

    def print(self):
        r  = self.result
        s  = r.stats
        W  = 70

        print()
        print(f"  {C.CYAN}{'═' * W}{C.RESET}")
        print(f"  {C.BOLD}{C.CYAN}  RECONSCOUT v2.1 — RESULTS  {C.RESET}")
        print(f"  {C.CYAN}{'═' * W}{C.RESET}")

        self._hdr("Target Overview", "🎯")
        self._kv("Target",       r.target)
        self._kv("Type",         r.target_type.upper())
        self._kv("IP Address",   r.ip_address)
        self._kv("Hostname",     r.hostname)
        self._kv("Scan Mode",    r.scan_mode.upper())
        self._kv("Scan Type",    r.scan_type.upper())
        self._kv("OS Guess",     r.intel.os_guess,   C.YELLOW)
        self._kv("ASN",          r.intel.asn)
        geo = r.intel.geoip
        if geo.get("country"):
            loc = ", ".join(filter(None, [geo.get("city",""), geo.get("country","")]))
            self._kv("Location",  loc)
        self._kv("Duration",     f"{r.duration_sec:.1f}s", C.YELLOW)

        print()
        print(f"    {C.GREEN}Open:{C.BOLD}{s.get('open_ports',0)}{C.RESET}  "
              f"{C.RED}Closed:{C.BOLD}{s.get('closed_ports',0)}{C.RESET}  "
              f"{C.YELLOW}Filtered:{C.BOLD}{s.get('filtered_ports',0)}{C.RESET}  "
              f"{C.CYAN}Subdomains:{C.BOLD}{len(r.subdomains)}{C.RESET}")

        # Open Ports
        open_ports = [p for p in r.ports if p.state == "open"]
        if open_ports:
            self._hdr("Open Ports & Services", "🔓")
            fmt = f"    {{:<8}} {{:<6}} {{:<16}} {{:<18}} {{}}"
            print(f"{C.GREY}{fmt.format('PORT','PROTO','SERVICE','VERSION','BANNER')}{C.RESET}")
            print(f"    {'─'*66}")
            for p in open_ports:
                bn = (p.banner[:38]+"…" if len(p.banner)>38 else p.banner).replace('\n',' ')
                print(f"    {C.GREEN}{str(p.port):<8}{C.RESET}"
                      f"{p.protocol:<6}"
                      f"{p.service:<16}"
                      f"{p.version:<18}"
                      f"{C.CYAN}{bn}{C.RESET}")

        # DNS
        if any([r.dns.a, r.dns.mx, r.dns.ns]):
            self._hdr("DNS Records", "📡")
            for t, recs in [("A",r.dns.a),("AAAA",r.dns.aaaa),("MX",r.dns.mx),
                             ("NS",r.dns.ns),("TXT",r.dns.txt[:3])]:
                for rec in recs:
                    print(f"    {C.YELLOW}{t:<6}{C.RESET} {rec}")
            if r.dns.zone_transfer:
                print(f"    {C.RED}{C.BOLD}⚠ ZONE TRANSFER SUCCEEDED — {len(r.dns.zone_transfer)} records!{C.RESET}")

        # SSL
        if r.ssl.enabled:
            self._hdr("SSL/TLS", "🔐")
            self._kv("Grade",    r.ssl.grade,   C.GREEN if r.ssl.grade in ("A+","A") else C.YELLOW)
            self._kv("Version",  r.ssl.version)
            self._kv("Issuer",   r.ssl.issuer)
            self._kv("Expires",  r.ssl.valid_to)
            for v in r.ssl.vulnerabilities:
                print(f"    {C.RED}⚠ {v}{C.RESET}")

        # SMTP
        if r.smtp.open:
            self._hdr("SMTP", "📧")
            self._kv("Banner",      r.smtp.banner)
            self._kv("STARTTLS",    "Yes" if r.smtp.starttls else "No")
            self._kv("Open Relay",  "⚠ YES" if r.smtp.open_relay else "No",
                     C.RED if r.smtp.open_relay else C.RESET)
            if r.smtp.users_found:
                self._kv("Users Found", ", ".join(r.smtp.users_found), C.YELLOW)

        # Subdomains
        if r.subdomains:
            self._hdr(f"Subdomains ({len(r.subdomains)})", "🔍")
            for sd in r.subdomains[:30]:
                print(f"    {C.GREEN}[+]{C.RESET} {sd}")
            if len(r.subdomains) > 30:
                print(f"    {C.GREY}... {len(r.subdomains)-30} more in report{C.RESET}")

        # Web
        if r.web.url:
            self._hdr("Web Recon", "🌍")
            self._kv("URL",        r.web.url)
            self._kv("Status",     str(r.web.status_code))
            self._kv("Server",     r.web.server)
            self._kv("Title",      r.web.title)
            self._kv("Technologies",", ".join(r.web.technologies) or "None")
            self._kv("CDN/WAF",   ", ".join(r.web.cdn_waf) or "None")
            self._kv("HTTPS Redir","Yes" if r.web.https_redirect else "No")
            self._kv("HSTS",      "Yes" if r.web.hsts else "No")
            if r.web.misconfigs:
                print()
                print(f"    {C.RED}{C.BOLD}Misconfigurations:{C.RESET}")
                for m in r.web.misconfigs[:10]:
                    print(f"    {C.YELLOW}  ⚠{C.RESET} {m}")

        # Warnings
        if r.warnings:
            self._hdr("Scan Warnings", "⚠")
            for w in r.warnings:
                print(f"    {C.YELLOW}⚠ {w}{C.RESET}")

        print()
        print(f"  {C.CYAN}{'═' * W}{C.RESET}\n")


# ══════════════════════════════════════════════════════════════════════════════
# FACADE
# ══════════════════════════════════════════════════════════════════════════════

class ReportManager:
    def __init__(self, result: ScanResult, logger):
        self.result   = result
        self.logger   = logger
        self._json    = JSONReport(result, logger)
        self._html    = HTMLReport(result, logger)
        self._cli     = CLIReport(result, logger)

    def print_cli(self):
        self._cli.print()

    def save_json(self, path: str):
        self._json.save(path)

    def save_html(self, path: str):
        self._html.save(path)

    def save_all(self, prefix: str):
        self.save_json(f"{prefix}.json")
        self.save_html(f"{prefix}.html")
