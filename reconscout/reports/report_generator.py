"""
ReconScout — Report Generator
JSON export, dark-theme HTML dashboard, CLI table.

Author  : Agent P
Project : ReconScout v2.1

HTML report sections (each is its own card):
  Overview      — stat cards + charts
  Target Summary— IP, OS, type
  Active Recon  — open ports table (scrollable), all-ports table (scrollable)
  Network Map   — traceroute hops, firewall/LB
  SMTP          — banner, relay, users
  DNS Records   — all record types + zone transfer alert
  WHOIS         — org, registrar, dates, emails
  ASN / BGP     — dedicated: ASN, range, org, RIR, prefixes, peers, abuse
  GeoIP         — country, region, city, lat/lon, ISP
  Subdomains    — grid of all discovered subdomains
  SSL/TLS       — grade card, cert details, SANs, vulns
  Web Recon     — headers, tech, CDN/WAF, misconfigs, forms, dirs
  Google Dorks  — dork results by category
  GitHub Leaks  — secret findings with severity badges
  Shodan        — open ports, CVEs, banners (API key required)
  Warnings      — scan-level alerts
"""

import json
from dataclasses import asdict
from datetime import datetime
from html import escape as he
from pathlib import Path
from typing import Any, Dict, List

from reconscout.models import ScanResult
from reconscout.utils.helpers import C


# ─────────────────────────────────────────────────────────────────────────────
# JSON
# ─────────────────────────────────────────────────────────────────────────────

class JSONReport:
    def __init__(self, result: ScanResult, logger):
        self.result = result
        self.logger = logger

    def save(self, path: str):
        def _s(o):
            if hasattr(o, "__dataclass_fields__"): return {k: _s(v) for k, v in asdict(o).items()}
            if isinstance(o, (list, tuple)): return [_s(i) for i in o]
            if isinstance(o, dict): return {k: _s(v) for k, v in o.items()}
            return o
        data = {
            "meta": {
                "tool":       "ReconScout v2.1",
                "author":     "Agent P",
                "generated":  datetime.now().isoformat(),
                "disclaimer": "For authorized security testing only",
            },
            "result": _s(self.result),
        }
        Path(path).write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        self.logger.info(f"JSON saved → {path}")


# ─────────────────────────────────────────────────────────────────────────────
# HTML
# ─────────────────────────────────────────────────────────────────────────────

class HTMLReport:
    def __init__(self, result: ScanResult, logger):
        self.result = result
        self.logger = logger

    # ── tiny helpers ─────────────────────────────────────────────────────────

    def _b(self, text, style):
        classes = {"open":"badge-open","closed":"badge-closed","filtered":"badge-filtered","open|filtered":"badge-filtered"}
        return f'<span class="badge {classes.get(style,"badge-info")}">{he(text)}</span>'

    def _tag(self, text, cls):
        return f'<span class="{cls}">{he(text)}</span>'

    def _ir(self, key, value, mono=True):
        if not value: return ""
        cls = "info-val mono" if mono else "info-val"
        return f'<div class="info-row"><span class="info-key">{he(key)}</span><span class="{cls}">{he(str(value))}</span></div>'

    def _section(self, anchor, icon, title, body, badge=""):
        b = f' <span class="s-badge">{he(str(badge))}</span>' if badge else ""
        return f"""
<div class="section" id="{anchor}">
  <div class="section-header">
    <span class="s-icon">{icon}</span>
    <span class="s-title">{he(title)}{b}</span>
  </div>
  <div class="section-body">{body}</div>
</div>"""

    def _two(self, left, right):
        return f'<div class="two-col"><div>{left}</div><div>{right}</div></div>'

    def _alert(self, text, kind="warn"):
        icon = "⚠" if kind == "warn" else "✓" if kind == "ok" else "🔴"
        cls  = f"alert alert-{kind}"
        return f'<div class="{cls}"><span>{icon}</span> {he(text)}</div>'

    def _empty(self, msg="No data available"):
        return f'<div class="empty">{he(msg)}</div>'

    # ── section builders ─────────────────────────────────────────────────────

    def _sec_target(self):
        r = self.result
        left = (
            self._ir("Target",        r.target) +
            self._ir("Type",          r.target_type.upper()) +
            self._ir("IP Address",    r.ip_address) +
            self._ir("Hostname",      r.hostname) +
            self._ir("Scan Mode",     r.scan_mode.upper()) +
            self._ir("Scan Type",     r.scan_type.upper()) +
            self._ir("OS Fingerprint",r.intel.os_guess) +
            self._ir("Started",       r.started_at) +
            self._ir("Finished",      r.finished_at) +
            self._ir("Duration",      f"{r.duration_sec:.1f}s")
        )
        right = (
            self._ir("Country",   r.geoip.country) +
            self._ir("Region",    r.geoip.region) +
            self._ir("City",      r.geoip.city) +
            self._ir("Lat/Lon",   f"{r.geoip.lat},{r.geoip.lon}" if r.geoip.lat else "") +
            self._ir("Timezone",  r.geoip.timezone) +
            self._ir("ISP",       r.geoip.isp) +
            self._ir("Org",       r.geoip.org) +
            self._ir("Findings",  str(r.stats.get("findings", 0))) +
            self._ir("Top Svc",   r.stats.get("top_service", ""))
        )
        return self._two(left, right)

    def _sec_ports_open(self):
        open_ports = [p for p in self.result.ports if p.state == "open"]
        if not open_ports:
            return self._empty("No open ports detected")
        rows = "".join(
            f"<tr>"
            f"<td class='mono bold green'>{p.port}</td>"
            f"<td>{p.protocol.upper()}</td>"
            f"<td>{self._b(p.state, p.state)}</td>"
            f"<td class='mono'>{he(p.service)}</td>"
            f"<td class='mono dim'>{he(p.version)}</td>"
            f"<td class='banner'>{he(p.banner[:80].replace(chr(10),' '))}</td>"
            f"<td><span class='cpe-tag'>{he(p.cpe)}</span></td>"
            f"</tr>"
            for p in open_ports
        )
        return (
            '<div class="scroll-table">'
            '<table><thead><tr><th>Port</th><th>Proto</th><th>State</th>'
            '<th>Service</th><th>Version</th><th>Banner</th><th>CPE</th></tr></thead>'
            f'<tbody>{rows}</tbody></table></div>'
        )

    def _sec_ports_all(self):
        non_open = [p for p in self.result.ports if p.state != "open"]
        if not non_open:
            return self._empty("No closed/filtered ports")
        rows = "".join(
            f"<tr class='dim-row'>"
            f"<td class='mono'>{p.port}</td>"
            f"<td>{p.protocol.upper()}</td>"
            f"<td>{self._b(p.state, p.state)}</td>"
            f"<td class='mono dim'>{he(p.service)}</td>"
            f"</tr>"
            for p in non_open
        )
        return (
            '<div class="scroll-table">'
            '<table><thead><tr><th>Port</th><th>Proto</th><th>State</th><th>Service</th></tr></thead>'
            f'<tbody>{rows}</tbody></table></div>'
        )

    def _sec_network(self):
        n = self.result.network
        if not n.hops:
            return self._empty("Network recon not performed or no route data")
        rows = "".join(
            f"<tr><td class='mono dim'>{h.get('hop','')}</td>"
            f"<td class='mono'>{he(h.get('ip','') or '* * *')}</td>"
            f"<td class='mono dim'>{he(h.get('hostname',''))}</td>"
            f"<td class='mono'>{h.get('rtt_ms',0):.1f}ms</td></tr>"
            for h in n.hops
        )
        table = (
            '<table class="compact"><thead><tr><th>Hop</th><th>IP</th>'
            f'<th>Hostname</th><th>RTT</th></tr></thead><tbody>{rows}</tbody></table>'
        )
        fw = self._alert(f"Firewall detected: {n.firewall_type}", "warn") if n.firewall_detected \
             else '<div class="ok">No firewall filtering detected</div>'
        lb = self._alert("Load balancer detected (server header variance)", "warn") if n.load_balancer else ""
        return f"{fw}{lb}<div style='margin-top:14px'>{table}</div>"

    def _sec_smtp(self):
        s = self.result.smtp
        if not s.open:
            return self._empty("SMTP not detected or not scanned (port 25/465/587 not open)")
        relay = self._alert("OPEN RELAY — server will relay external mail!", "crit") if s.open_relay else ""
        body = (
            relay +
            self._ir("Banner",       s.banner) +
            self._ir("STARTTLS",     "Yes ✓" if s.starttls else "No ✗") +
            self._ir("AUTH Methods", ", ".join(s.auth_methods) or "None") +
            self._ir("Open Relay",   "⚠ YES — CRITICAL" if s.open_relay else "No") +
            self._ir("VRFY Enabled", "Yes (user enum possible)" if s.vrfy_enabled else "No") +
            self._ir("EXPN Enabled", "Yes" if s.expn_enabled else "No") +
            self._ir("Users Found",  ", ".join(s.users_found) if s.users_found else "None")
        )
        return body

    def _sec_dns(self):
        dns = self.result.dns
        zt  = ""
        if dns.zone_transfer:
            zt = self._alert(f"ZONE TRANSFER SUCCEEDED — {len(dns.zone_transfer)} records exposed!", "crit")
        rows = ""
        for rtype, records in [("A",dns.a),("AAAA",dns.aaaa),("MX",dns.mx),("NS",dns.ns),
                                ("TXT",dns.txt),("CNAME",dns.cname),("SOA",dns.soa),
                                ("SRV",dns.srv),("PTR",dns.reverse)]:
            for rec in records:
                rows += f"<tr><td>{self._tag(rtype,'rtag')}</td><td class='mono'>{he(rec)}</td></tr>"
        if not rows:
            return zt + self._empty("No DNS records resolved")
        return zt + f'<table><thead><tr><th>Type</th><th>Value</th></tr></thead><tbody>{rows}</tbody></table>'

    def _sec_whois(self):
        i  = self.result.intel
        body = (
            self._ir("Org",        i.whois_org) +
            self._ir("Registrar",  i.whois_registrar) +
            self._ir("Country",    i.whois_country) +
            self._ir("Created",    i.whois_created) +
            self._ir("Expires",    i.whois_expires)
        )
        emails_html = (
            "".join(self._tag(e, "subdomain-tag") for e in i.whois_emails)
            or '<span class="dim">None found</span>'
        )
        # Reverse IP — only show if we actually have entries
        rev_entries = [d for d in i.reverse_ip if d.strip()]
        if rev_entries:
            rev_html = (
                f'<div class="label mt">Reverse IP — Co-hosted Domains ({len(rev_entries)})</div>'
                + "".join(f'<div class="item-row">▶ {he(d)}</div>' for d in rev_entries[:20])
            )
        else:
            rev_html = (
                '<div class="label mt">Reverse IP (Co-hosted Domains)</div>'
                '<div class="empty">No co-hosted domains found (HackerTarget returned no results '
                'or this IP hosts only this domain)</div>'
            )
        raw_block = (
            f'<details style="margin-top:12px"><summary class="expand-toggle">'
            f'Raw WHOIS (click to expand)</summary><pre>{he(i.whois_raw[:4000])}</pre></details>'
        ) if i.whois_raw else ""
        return (
            body
            + f'<div class="label mt">Emails (WHOIS + OSINT harvest)</div>{emails_html}'
            + rev_html
            + raw_block
        )

    def _sec_asn(self):
        a = self.result.asn
        # Show section if ANY primary field was populated
        has_data = any([a.asn, a.org, a.isp, a.ip_range])
        if not has_data:
            return (
                '<div class="alert alert-warn" style="margin-bottom:10px">'
                '<span>ℹ</span> ASN data unavailable. This can happen when: '
                '(1) target IP did not resolve, '
                '(2) ip-api.com / Team Cymru were unreachable, or '
                '(3) scan ran in active-only mode without passive lookup.</div>'
                + self._empty("Run with -m passive or -m full to populate ASN data")
            )
        left = (
            self._ir("ASN",         a.asn or "—") +
            self._ir("Org",         a.org or "—") +
            self._ir("ISP",         a.isp) +
            self._ir("IP Range",    a.ip_range or "—") +
            self._ir("Country",     a.country) +
            self._ir("RIR",         a.rir) +
            self._ir("Abuse Email", a.abuse_email)
        )
        prefixes_html = (
            "".join(self._tag(p, "cpe-tag") for p in a.prefixes)
            or '<span class="dim">Not available (RIPEstat may be slow or not indexed this ASN)</span>'
        )
        peers_html = (
            "".join(self._tag(p, "subdomain-tag") for p in a.peers)
            or '<span class="dim">Not available (RIPEstat may be slow)</span>'
        )
        right = (
            f'<div class="label">Announced Prefixes ({len(a.prefixes)})</div>{prefixes_html}'
            f'<div class="label mt">BGP Peers ({len(a.peers)})</div>{peers_html}'
        )
        return self._two(left, right)

    def _sec_geoip(self):
        g = self.result.geoip
        if not g.country:
            return self._empty("GeoIP data not available — passive scan required")
        body = (
            self._ir("IP",       g.ip) +
            self._ir("Country",  g.country) +
            self._ir("Region",   g.region) +
            self._ir("City",     g.city) +
            self._ir("Lat / Lon",f"{g.lat:.4f}, {g.lon:.4f}" if g.lat else "") +
            self._ir("Timezone", g.timezone) +
            self._ir("ISP",      g.isp) +
            self._ir("Org",      g.org) +
            self._ir("ASN",      g.asn)
        )
        # Embed OpenStreetMap iframe if we have coordinates
        map_html = ""
        if g.lat and g.lon:
            map_html = (
                f'<div style="margin-top:16px">'
                f'<iframe src="https://www.openstreetmap.org/export/embed.html'
                f'?bbox={g.lon-0.05:.4f},{g.lat-0.05:.4f},{g.lon+0.05:.4f},{g.lat+0.05:.4f}'
                f'&amp;layer=mapnik&amp;marker={g.lat:.4f},{g.lon:.4f}" '
                f'style="width:100%;height:200px;border:1px solid var(--border);filter:invert(0.9) hue-rotate(180deg)"'
                f' loading="lazy" title="Location map"></iframe></div>'
            )
        return body + map_html

    def _sec_subdomains(self):
        subs = self.result.subdomains
        if not subs:
            return self._empty("No subdomains discovered")
        return '<div class="subdomain-grid">' + \
               "".join(self._tag(s,"subdomain-tag") for s in subs) + \
               '</div>'

    def _sec_ssl(self):
        s = self.result.ssl
        if not s.enabled:
            return self._empty("SSL/TLS not detected or target port filtered")
        grade_color = {"A+":"#00e676","A":"#00e676","B":"#ffd740","C":"#ffd740","D":"#ff5252","F":"#ff5252"}.get(s.grade,"#64748b")
        grade = f'<div class="ssl-grade" style="color:{grade_color}">{he(s.grade)}</div>'
        body  = (
            self._ir("Enabled",      "Yes ✓") +
            self._ir("Version",      s.version) +
            self._ir("Cipher",       s.cipher) +
            self._ir("Issuer",       s.issuer) +
            self._ir("Subject",      s.subject) +
            self._ir("Valid From",   s.valid_from) +
            self._ir("Valid To",     s.valid_to) +
            self._ir("Expired",      "⚠ YES" if s.expired else "No") +
            self._ir("Self-Signed",  "⚠ YES" if s.self_signed else "No")
        )
        sans   = "".join(self._tag(x,"subdomain-tag") for x in s.san[:30]) or '<span class="dim">None</span>'
        vulns  = "".join(f'<div class="finding"><span class="warn-icon">⚠</span> {he(v)}</div>' for v in s.vulnerabilities) \
                 or '<div class="ok">No SSL vulnerabilities detected</div>'
        return (
            grade + body +
            f'<div class="label mt">Subject Alternative Names ({len(s.san)})</div>{sans}' +
            f'<div class="label mt">Vulnerabilities</div>{vulns}'
        )

    def _sec_web(self):
        w = self.result.web
        if not w.url:
            return self._empty("Web recon not performed")
        basic = (
            self._ir("URL",           w.url) +
            self._ir("Status",        str(w.status_code)) +
            self._ir("Response Time", f"{w.response_time:.3f}s") +
            self._ir("Content Length",f"{w.content_length:,} bytes") +
            self._ir("Server",        w.server) +
            self._ir("Title",         w.title) +
            self._ir("HTTPS Redirect","Yes ✓" if w.https_redirect else "No ✗") +
            self._ir("HSTS",          "Yes ✓" if w.hsts else "No ✗")
        )
        tech  = "".join(self._tag(t,"tech-badge") for t in w.technologies) or '<span class="dim">None detected</span>'
        cdns  = "".join(self._tag(c,"cdn-badge")  for c in w.cdn_waf)       or '<span class="dim">None detected</span>'

        # Separate security misconfigs from HTTP-method findings
        http_methods = [m for m in w.misconfigs if m.startswith("HTTP method")]
        sec_misconfigs = [m for m in w.misconfigs if not m.startswith("HTTP method")]

        mc = "".join(
            f'<div class="finding"><span class="warn-icon">⚠</span> {he(m)}</div>'
            for m in sec_misconfigs
        ) or '<div class="ok">No misconfigurations detected</div>'

        hdrs = "".join(
            f"<tr><td class='mono dim'>{he(k)}</td><td class='mono small'>{he(v[:150])}</td></tr>"
            for k, v in w.headers.items()
        )
        hdr_t = (
            f'<table class="compact"><thead><tr><th>Header</th><th>Value</th></tr></thead>'
            f'<tbody>{hdrs}</tbody></table>'
        ) if hdrs else ""

        emails_html   = " ".join(self._tag(e, "subdomain-tag") for e in w.emails)
        forms_html    = "".join(f'<div class="item-row">▶ {he(f)}</div>' for f in w.forms)
        comments_html = "".join(f'<div class="comment-block">{he(c)}</div>' for c in w.comments)
        dirs_html     = "".join(
            f'<div class="finding"><span style="color:var(--green)">▶</span> {he(d)}</div>'
            for d in w.directories
        )

        # JS files — styled clickable cards matching theme
        if w.js_files:
            js_items = "".join(
                f'<a href="{he(j)}" target="_blank" class="js-file-card">'
                f'<span class="js-icon">⟨/⟩</span>'
                f'<span class="js-url">{he(j)}</span>'
                f'</a>'
                for j in w.js_files[:30]
            )
            js_html = f'<div class="js-file-grid">{js_items}</div>'
        else:
            js_html = ""

        # HTTP methods as method-tag badges
        methods_html = "".join(self._tag(m, "method-tag") for m in http_methods)

        robots = (
            f'<details><summary class="expand-toggle">robots.txt</summary>'
            f'<pre>{he(w.robots_txt)}</pre></details>'
        ) if w.robots_txt else ""

        return f"""
<div class="two-col">
  <div>{basic}<div class="label">Technologies</div>{tech}<div class="label mt">CDN / WAF</div>{cdns}</div>
  <div><div class="label">Security Misconfigurations</div>{mc}</div>
</div>
{hdr_t}
{('<div class="label mt">Emails on Page</div>' + emails_html) if w.emails else ""}
{('<div class="label mt">Forms</div>' + forms_html) if w.forms else ""}
{('<div class="label mt">JS Files (' + str(len(w.js_files)) + ')</div>' + js_html) if w.js_files else ""}
{('<div class="label mt">HTTP Methods Accepted</div>' + methods_html) if http_methods else ""}
{('<div class="label mt">HTML Comments</div>' + comments_html) if w.comments else ""}
{('<div class="label mt">Directories / Sensitive Files</div>' + dirs_html) if w.directories else ""}
{robots}"""

    def _sec_dorks(self):
        dorks = self.result.dorks
        if not dorks:
            return (
                '<div class="alert alert-warn" style="margin-bottom:12px">'
                '<span>⚠</span> Google dorking returned no results. '
                'Search engines may block automated queries. '
                'Tip: increase <code style="font-family:var(--mono)">dork_delay_sec</code> '
                'in config.json or search manually: '
                '<code style="font-family:var(--mono)">site:TARGET -www</code></div>'
                + self._empty("No dork results captured in this scan")
            )
        total_urls = sum(d.total_found for d in dorks)
        has_results = any(d.total_found > 0 for d in dorks)
        out = (
            f'<div style="font-size:10px;color:var(--muted);font-family:var(--mono);margin-bottom:14px">'
            f'{len(dorks)} categories searched &nbsp;·&nbsp; {total_urls} total URLs found'
            f'&nbsp;·&nbsp; Engines: DuckDuckGo → Bing (fallback) &nbsp;·&nbsp; No API key required'
            f'</div>'
        )
        for d in dorks:
            cat_label = d.category.replace("_", " ").title()
            badge_color = "var(--green)" if d.total_found > 0 else "var(--muted)"
            count_badge = (
                f'<span style="font-size:10px;color:{badge_color};font-family:var(--mono);'
                f'background:rgba(0,0,0,.3);padding:1px 8px;border:1px solid {badge_color};margin-left:6px">'
                f'{d.total_found} result{"s" if d.total_found != 1 else ""}</span>'
            )
            if d.results:
                urls_html = "".join(
                    f'<div class="item-row">'
                    f'<a href="{he(u)}" target="_blank" class="dork-link">{he(u[:130])}</a>'
                    f'</div>'
                    for u in d.results[:15]
                )
            else:
                note_msg = d.note if d.note else "No results found for this category"
                urls_html = (
                    f'<div class="empty" style="padding:5px 0;font-size:10px">'
                    f'⚠ {he(note_msg)}</div>'
                )
            out += (
                f'<div class="dork-category">'
                f'<div class="dork-cat-title">'
                f'<span class="rtag">{he(cat_label)}</span>{count_badge}'
                f'<div class="mono dim" style="font-size:9px;margin-top:4px;color:var(--muted)">'
                f'Query: {he(d.query[:120])}</div>'
                f'</div>'
                f'<div class="dork-urls">{urls_html}</div>'
                f'</div>'
            )
        return out

    def _sec_github(self):
        leaks = self.result.github_leaks
        if not leaks:
            return (
                '<div class="alert alert-warn" style="margin-bottom:12px">'
                '<span>ℹ</span> No secrets found in public GitHub repositories. '
                'This may mean: (1) no public repos reference this domain, '
                '(2) GitHub API rate limit reached (add <code style="font-family:var(--mono)">github_token</code> '
                'to config.json for 5,000 req/hr instead of 60), or '
                '(3) secrets were not in the scanned files.</div>'
                + self._empty("No GitHub secret leaks detected")
            )
        high_c   = sum(1 for l in leaks if l.severity == "HIGH")
        medium_c = sum(1 for l in leaks if l.severity == "MEDIUM")
        summary  = (
            f'<div style="margin-bottom:10px;font-family:var(--mono);font-size:11px">'
            f'<span style="color:var(--red)">{high_c} HIGH</span> · '
            f'<span style="color:var(--yellow)">{medium_c} MEDIUM</span> · '
            f'{len(leaks)} total findings</div>'
        )
        SEV = {"HIGH": "var(--red)", "MEDIUM": "var(--yellow)", "LOW": "var(--muted)"}
        def _row(l):
            c = SEV.get(l.severity, "var(--muted)")
            repo_short = l.repo_url.replace("https://github.com/", "")
            return (
                f"<tr>"
                f"<td><span class='badge' style='color:{c};border-color:{c}'>{he(l.severity)}</span></td>"
                f"<td class='mono'>{he(l.leak_type)}</td>"
                f"<td class='mono dim'>{he(l.match)}</td>"
                f"<td class='mono small'><a href='{he(l.repo_url)}' target='_blank' "
                f"class='dork-link'>{he(repo_short)}</a></td>"
                f"<td class='mono dim'>{he(l.file_path)}</td>"
                f"</tr>"
            )
        rows = "".join(_row(l) for l in leaks)
        return (
            summary +
            '<div class="scroll-table">'
            '<table><thead><tr><th>Severity</th><th>Type</th><th>Match (redacted)</th>'
            '<th>Repository</th><th>File</th></tr></thead>'
            f'<tbody>{rows}</tbody></table></div>'
        )

    def _sec_shodan(self):
        s = self.result.shodan
        # No API key configured
        if not s.ip and not s.error:
            return (
                '<div class="alert alert-warn" style="margin-bottom:12px">'
                '<span>🔑</span> Shodan API key not configured. '
                'Add your key to <code style="font-family:var(--mono)">config/config.json</code>:'
                '<pre style="margin-top:8px;font-size:11px">"shodan_api_key": "your-key-here"</pre>'
                'Get a free key at <a href="https://account.shodan.io" target="_blank" '
                'class="dork-link">account.shodan.io</a> '
                '(free tier includes IP lookups).</div>'
                + self._empty("Shodan lookup not performed — API key required")
            )
        if s.error:
            err_advice = ""
            if "No API key" in s.error:
                err_advice = (
                    ' Add <code style="font-family:var(--mono)">shodan_api_key</code> '
                    'to <code style="font-family:var(--mono)">config/config.json</code>.'
                )
            elif "Invalid" in s.error:
                err_advice = " Check that your Shodan API key is correct."
            elif "not found" in s.error:
                err_advice = " This IP has not been scanned by Shodan yet."
            return (
                f'<div class="alert alert-warn">'
                f'<span>⚠</span> Shodan error: {he(s.error)}{err_advice}</div>'
            )
        # We have real data
        left = (
            self._ir("IP",          s.ip) +
            self._ir("Org",         s.org) +
            self._ir("ISP",         s.isp) +
            self._ir("ASN",         s.asn) +
            self._ir("Country",     s.country) +
            self._ir("City",        s.city) +
            self._ir("OS",          s.os or "Unknown") +
            self._ir("Last Update", s.last_update)
        )
        ports_html = "".join(self._tag(str(p), "cpe-tag") for p in s.ports) \
                     or '<span class="dim">None</span>'
        tags_html  = "".join(self._tag(t, "tech-badge") for t in s.tags) \
                     or '<span class="dim">None</span>'
        cves_html  = "".join(
            f'<div class="finding"><span class="warn-icon">⚠</span> {he(c)}</div>'
            for c in s.vulns
        ) or '<div class="ok">No CVEs found by Shodan</div>'
        right = (
            f'<div class="label">Open Ports (Shodan history)</div>{ports_html}'
            f'<div class="label mt">Tags</div>{tags_html}'
            f'<div class="label mt">CVEs ({len(s.vulns)})</div>{cves_html}'
        )
        banners_html = ""
        if s.banners:
            rows = "".join(
                f"<tr><td class='mono'>{b.get('port','')}</td>"
                f"<td class='mono dim'>{he(b.get('product',''))}</td>"
                f"<td class='mono dim'>{he(b.get('version',''))}</td>"
                f"<td class='banner'>{he(b.get('banner','')[:120])}</td></tr>"
                for b in s.banners
            )
            banners_html = (
                '<div class="label mt">Service Banners</div>'
                '<table class="compact"><thead><tr><th>Port</th><th>Product</th>'
                f'<th>Version</th><th>Banner</th></tr></thead><tbody>{rows}</tbody></table>'
            )
        return self._two(left, right) + banners_html

    def _sec_warnings(self):
        w = self.result.warnings
        if not w:
            return '<div class="ok">✓ No scan-level warnings</div>'
        return "".join(self._alert(x, "warn") for x in w)

    # ── chart data ────────────────────────────────────────────────────────────

    def _chart_data(self):
        r = self.result
        op = [p for p in r.ports if p.state == "open"]
        pl = json.dumps([str(p.port) for p in op[:20]])
        pv = json.dumps([1] * len(op[:20]))
        svc: Dict[str,int] = {}
        for p in op:
            s = p.service or "unknown"
            svc[s] = svc.get(s,0)+1
        sl = json.dumps(list(svc.keys()))
        sv = json.dumps(list(svc.values()))
        return pl, pv, sl, sv

    # ── main render ───────────────────────────────────────────────────────────

    def save(self, path: str):
        r   = self.result
        s   = r.stats
        pl, pv, sl, sv = self._chart_data()
        dur = f"{r.duration_sec:.1f}s"
        open_c   = s.get("open_ports", 0)
        closed_c = s.get("closed_ports", 0)
        filt_c   = s.get("filtered_ports", 0)
        sub_c    = len(r.subdomains)
        find_c   = s.get("findings", 0)
        leak_c   = len(r.github_leaks)
        cve_c    = len(r.shodan.vulns)

        CSS = """
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:ital,wght@0,300;0,400;0,700;1,400&family=Space+Grotesk:wght@400;500;600;700&display=swap');
:root{
  --bg:#060911;--surface:#0b1120;--card:#0f1929;--border:#1b2d45;--border2:#243550;
  --accent:#00e5ff;--accent2:#7c3aed;--green:#00e676;--yellow:#ffd740;--red:#ff5252;
  --orange:#ff9800;--text:#c8d6e8;--muted:#4a6080;--dim:#2d4060;
  --mono:'JetBrains Mono',monospace;--sans:'Space Grotesk',sans-serif;
}
*{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{background:var(--bg);color:var(--text);font-family:var(--sans);font-size:14px;line-height:1.6;min-height:100vh}
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-track{background:var(--surface)}
::-webkit-scrollbar-thumb{background:var(--border2)}
::selection{background:rgba(0,229,255,0.15)}
/* SIDEBAR */
.sidebar{position:fixed;left:0;top:0;bottom:0;width:220px;background:var(--surface);border-right:1px solid var(--border);display:flex;flex-direction:column;z-index:100;overflow-y:auto}
.sidebar-logo{padding:18px 18px 14px;border-bottom:1px solid var(--border)}
.logo-name{font-size:15px;font-weight:700;color:var(--accent);letter-spacing:3px;text-transform:uppercase}
.logo-ver{font-size:10px;color:var(--muted);font-family:var(--mono)}
.logo-author{font-size:10px;color:var(--accent2);font-family:var(--mono);margin-top:1px}
.logo-target{font-size:11px;color:var(--text);margin-top:8px;font-family:var(--mono);word-break:break-all}
.nav-group{padding:10px 0;border-bottom:1px solid var(--border)}
.nav-label{padding:3px 18px 1px;font-size:9px;color:var(--muted);text-transform:uppercase;letter-spacing:2px}
.nav-item{display:flex;align-items:center;gap:9px;padding:7px 18px;font-size:12px;color:var(--muted);text-decoration:none;transition:all .15s}
.nav-item:hover{color:var(--accent);background:rgba(0,229,255,0.04)}
.nav-icon{font-size:13px;width:16px;text-align:center}
.sidebar-stats{padding:14px 18px;margin-top:auto;border-top:1px solid var(--border)}
.ss{display:flex;justify-content:space-between;padding:2px 0;font-size:11px;font-family:var(--mono)}
.ss-k{color:var(--muted)}.ss-v{color:var(--accent);font-weight:700}
/* MAIN */
.main{margin-left:220px;min-height:100vh}
.topbar{background:var(--surface);border-bottom:1px solid var(--border);padding:14px 28px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:50}
.topbar-left h1{font-size:15px;font-weight:600;color:var(--text)}
.topbar-left p{font-size:10px;color:var(--muted);font-family:var(--mono)}
.topbar-right{display:flex;gap:7px}
.pill{padding:3px 10px;font-size:10px;font-family:var(--mono);border:1px solid;letter-spacing:1px;text-transform:uppercase}
.pill-active{color:var(--green);border-color:rgba(0,230,118,.4);background:rgba(0,230,118,.06)}
.pill-passive{color:var(--accent);border-color:rgba(0,229,255,.4);background:rgba(0,229,255,.06)}
.pill-duration{color:var(--yellow);border-color:rgba(255,215,64,.4);background:rgba(255,215,64,.06)}
.pill-author{color:var(--accent2);border-color:rgba(124,58,237,.4);background:rgba(124,58,237,.07)}
.disclaimer-bar{background:rgba(255,82,82,.07);border-bottom:1px solid rgba(255,82,82,.2);padding:6px 28px;font-family:var(--mono);font-size:10px;color:#ff8a80;letter-spacing:1px;text-align:center}
.content{padding:22px 28px 48px}
/* STAT CARDS */
.stats-row{display:grid;grid-template-columns:repeat(7,1fr);gap:12px;margin-bottom:18px}
.stat-card{background:var(--card);border:1px solid var(--border);padding:16px 18px;position:relative;overflow:hidden;transition:border-color .2s}
.stat-card:hover{border-color:var(--border2)}
.stat-card::before{content:'';position:absolute;top:0;left:0;width:2px;height:100%}
.sc{color:var(--accent)}.sc::before{background:var(--accent)}
.sg{color:var(--green)}.sg::before{background:var(--green)}
.sr{color:var(--red)}.sr::before{background:var(--red)}
.sy{color:var(--yellow)}.sy::before{background:var(--yellow)}
.sp{color:#a78bfa}.sp::before{background:var(--accent2)}
.so{color:var(--orange)}.so::before{background:var(--orange)}
.stat-val{font-size:28px;font-weight:700;font-family:var(--mono);line-height:1}
.stat-label{font-size:9px;color:var(--muted);text-transform:uppercase;letter-spacing:2px;margin-top:5px}
/* SECTIONS */
.section{background:var(--card);border:1px solid var(--border);margin-bottom:14px}
.section-header{padding:11px 18px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:9px;background:rgba(255,255,255,.01)}
.s-icon{font-size:14px}.s-title{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:2px;color:var(--accent);font-family:var(--mono)}
.s-badge{font-size:10px;padding:1px 7px;background:rgba(0,229,255,.08);border:1px solid rgba(0,229,255,.2);color:var(--accent);font-family:var(--mono)}
.section-body{padding:16px 18px}
.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px}
.two-col{display:grid;grid-template-columns:1fr 1fr;gap:22px}
/* INFO ROWS */
.info-row{display:flex;padding:5px 0;border-bottom:1px solid rgba(27,45,69,.5)}
.info-row:last-child{border-bottom:none}
.info-key{width:130px;flex-shrink:0;color:var(--muted);font-size:11px;font-family:var(--mono);padding-top:1px}
.info-val{font-size:12px;color:var(--text);word-break:break-all}.info-val.mono{font-family:var(--mono);font-size:11px}
/* SCROLLABLE TABLES */
.scroll-table{max-height:320px;overflow-y:auto;border:1px solid var(--border);position:relative}
.scroll-table table{margin:0;border-collapse:separate;border-spacing:0}
/* TABLES */
table{width:100%;border-collapse:collapse;font-family:var(--mono);font-size:11px}
th{text-align:left;padding:7px 11px;color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:1.5px;border-bottom:2px solid var(--border2);background:var(--surface);position:sticky;top:0;z-index:10;font-family:var(--sans);font-weight:600;box-shadow:0 1px 0 var(--border2)}
.scroll-table th{position:sticky;top:0;z-index:10;background:var(--surface)}
td{padding:7px 11px;border-bottom:1px solid rgba(27,45,69,.4);vertical-align:top}
tr:hover td{background:rgba(0,229,255,.02)}
tr:last-child td{border-bottom:none}
.banner{color:var(--muted);font-size:10px;max-width:220px;word-break:break-all}
tr.dim-row td{opacity:.55}
/* BADGES */
.badge{display:inline-block;padding:2px 8px;font-size:9px;font-weight:700;font-family:var(--mono);letter-spacing:1px;text-transform:uppercase;border:1px solid}
.badge-open{background:rgba(0,230,118,.1);border-color:rgba(0,230,118,.35);color:var(--green)}
.badge-closed{background:rgba(255,82,82,.08);border-color:rgba(255,82,82,.3);color:var(--red)}
.badge-filtered{background:rgba(255,215,64,.07);border-color:rgba(255,215,64,.3);color:var(--yellow)}
.badge-info{background:rgba(0,229,255,.07);border-color:rgba(0,229,255,.3);color:var(--accent)}
.tech-badge,.cdn-badge,.subdomain-tag,.cpe-tag{display:inline-block;margin:3px;padding:3px 9px;font-size:10px;font-family:var(--mono)}
.tech-badge{background:rgba(124,58,237,.1);border:1px solid rgba(124,58,237,.3);color:#c4b5fd}
.cdn-badge{background:rgba(255,215,64,.07);border:1px solid rgba(255,215,64,.3);color:var(--yellow)}
.subdomain-tag{background:rgba(0,229,255,.05);border:1px solid rgba(0,229,255,.2);color:var(--accent)}
.cpe-tag{background:rgba(100,116,139,.1);border:1px solid rgba(100,116,139,.2);color:var(--muted);font-size:9px}
.rtag{display:inline-block;padding:1px 7px;font-size:9px;background:rgba(0,229,255,.07);border:1px solid rgba(0,229,255,.2);color:var(--accent);letter-spacing:1px}
.bold{font-weight:700}.mono{font-family:var(--mono)}.dim{color:var(--muted)}.small{font-size:10px}
.green{color:var(--green)}
/* MISC */
.subdomain-grid{display:flex;flex-wrap:wrap;gap:4px}
.finding{padding:7px 12px;margin:3px 0;background:rgba(255,82,82,.05);border-left:2px solid rgba(255,82,82,.5);font-family:var(--mono);font-size:11px}
.warn-icon{color:var(--red);margin-right:7px}
.ok{color:var(--green);font-family:var(--mono);font-size:11px;padding:7px 0}
.empty{color:var(--muted);font-family:var(--mono);font-size:11px;padding:10px 0;font-style:italic}
.item-row{padding:3px 0;font-family:var(--mono);font-size:11px;color:var(--text);border-bottom:1px solid rgba(27,45,69,.3)}
.comment-block{background:rgba(255,215,64,.04);border:1px solid rgba(255,215,64,.15);padding:7px 11px;margin:3px 0;font-family:var(--mono);font-size:10px;color:var(--muted);word-break:break-all}
.alert{padding:9px 13px;margin:4px 0;font-family:var(--mono);font-size:11px;border-left:3px solid}
.alert-warn{background:rgba(255,215,64,.07);border-color:var(--yellow);color:var(--yellow)}
.alert-crit{background:rgba(255,82,82,.1);border-color:var(--red);color:#fca5a5}
.alert-ok{background:rgba(0,230,118,.07);border-color:var(--green);color:var(--green)}
.ssl-grade{font-size:44px;font-weight:700;font-family:var(--mono);margin-bottom:10px}
.label{font-size:9px;color:var(--muted);text-transform:uppercase;letter-spacing:2px;font-family:var(--mono);margin-top:12px;margin-bottom:5px}
.label.mt{margin-top:16px}
.chart-wrap{position:relative;height:200px}
.dork-category{margin-bottom:12px;background:rgba(0,0,0,.2);border:1px solid var(--border);padding:10px 14px}
.dork-cat-title{margin-bottom:8px}
.dork-link{color:var(--accent);font-size:10px;word-break:break-all;text-decoration:none}
.dork-link:hover{text-decoration:underline}
/* JS file cards */
.js-file-grid{display:flex;flex-direction:column;gap:6px;margin-top:4px}
.js-file-card{display:flex;align-items:flex-start;gap:8px;padding:7px 12px;
  background:rgba(255,152,0,.05);border:1px solid rgba(255,152,0,.2);
  text-decoration:none;transition:border-color .15s;border-left:3px solid var(--orange)}
.js-file-card:hover{border-color:rgba(255,152,0,.5);background:rgba(255,152,0,.09)}
.js-icon{color:var(--orange);font-family:var(--mono);font-size:11px;
  flex-shrink:0;font-weight:700;padding-top:1px}
.js-url{color:var(--text);font-family:var(--mono);font-size:11px;
  word-break:break-all;line-height:1.4}
pre{background:rgba(0,0,0,.5);border:1px solid var(--border);padding:11px;font-family:var(--mono);font-size:10px;color:var(--muted);overflow:auto;max-height:260px;white-space:pre-wrap;margin-top:7px}
details summary{cursor:pointer;color:var(--muted);font-size:10px;font-family:var(--mono);padding:5px 0;user-select:none}
details summary:hover{color:var(--accent)}
.expand-toggle{cursor:pointer;color:var(--muted);font-size:10px;font-family:var(--mono)}
.footer{text-align:center;padding:18px 28px;font-family:var(--mono);font-size:10px;color:var(--muted);border-top:1px solid var(--border);margin-left:220px;letter-spacing:1px}
@media(max-width:1100px){.sidebar{display:none}.main,.footer{margin-left:0}.stats-row{grid-template-columns:repeat(4,1fr)}.two-col{grid-template-columns:1fr}.grid-2{grid-template-columns:1fr}}
@media(max-width:600px){.stats-row{grid-template-columns:1fr 1fr}.content{padding:14px}}"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ReconScout :: {he(r.target)}</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>{CSS}</style>
</head>
<body>

<aside class="sidebar">
  <div class="sidebar-logo">
    <div class="logo-name">ReconScout</div>
    <div class="logo-ver">v2.1 — Advanced Recon Suite</div>
    <div class="logo-author">by Agent P</div>
    <div class="logo-target">⬡ {he(r.target)}</div>
  </div>
  <nav>
    <div class="nav-group">
      <div class="nav-label">Overview</div>
      <a href="#summary"   class="nav-item"><span class="nav-icon">🎯</span> Target Summary</a>
      <a href="#charts"    class="nav-item"><span class="nav-icon">📊</span> Charts</a>
    </div>
    <div class="nav-group">
      <div class="nav-label">Active Recon</div>
      <a href="#ports"     class="nav-item"><span class="nav-icon">🔓</span> Open Ports</a>
      <a href="#allports"  class="nav-item"><span class="nav-icon">🔒</span> All Ports</a>
      <a href="#network"   class="nav-item"><span class="nav-icon">🌐</span> Network Map</a>
      <a href="#smtp"      class="nav-item"><span class="nav-icon">📧</span> SMTP</a>
    </div>
    <div class="nav-group">
      <div class="nav-label">Passive Recon</div>
      <a href="#dns"       class="nav-item"><span class="nav-icon">📡</span> DNS Records</a>
      <a href="#whois"     class="nav-item"><span class="nav-icon">📋</span> WHOIS</a>
      <a href="#asn"       class="nav-item"><span class="nav-icon">🔢</span> ASN / BGP</a>
      <a href="#geoip"     class="nav-item"><span class="nav-icon">🌍</span> GeoIP</a>
      <a href="#subdomains"class="nav-item"><span class="nav-icon">🔍</span> Subdomains</a>
    </div>
    <div class="nav-group">
      <div class="nav-label">OSINT</div>
      <a href="#dorks"     class="nav-item"><span class="nav-icon">🔎</span> Google Dorks</a>
      <a href="#github"    class="nav-item"><span class="nav-icon">🐙</span> GitHub Leaks</a>
      <a href="#shodan"    class="nav-item"><span class="nav-icon">🕵️</span> Shodan</a>
    </div>
    <div class="nav-group">
      <div class="nav-label">Web</div>
      <a href="#ssl"       class="nav-item"><span class="nav-icon">🔐</span> SSL/TLS</a>
      <a href="#web"       class="nav-item"><span class="nav-icon">🌏</span> Web Recon</a>
    </div>
    <div class="nav-group">
      <div class="nav-label">Alerts</div>
      <a href="#warnings"  class="nav-item"><span class="nav-icon">⚠</span> Warnings</a>
    </div>
  </nav>
  <div class="sidebar-stats">
    <div class="ss"><span class="ss-k">Open Ports</span><span class="ss-v">{open_c}</span></div>
    <div class="ss"><span class="ss-k">Subdomains</span><span class="ss-v">{sub_c}</span></div>
    <div class="ss"><span class="ss-k">Findings</span><span class="ss-v">{find_c}</span></div>
    <div class="ss"><span class="ss-k">GH Leaks</span><span class="ss-v">{leak_c}</span></div>
    <div class="ss"><span class="ss-k">Shodan CVEs</span><span class="ss-v">{cve_c}</span></div>
    <div class="ss"><span class="ss-k">Duration</span><span class="ss-v">{dur}</span></div>
  </div>
</aside>

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

<div class="stats-row">
  <div class="stat-card sg"><div class="stat-val" style="color:var(--green)">{open_c}</div><div class="stat-label">Open Ports</div></div>
  <div class="stat-card sr"><div class="stat-val" style="color:var(--red)">{closed_c}</div><div class="stat-label">Closed</div></div>
  <div class="stat-card sy"><div class="stat-val" style="color:var(--yellow)">{filt_c}</div><div class="stat-label">Filtered</div></div>
  <div class="stat-card sp"><div class="stat-val" style="color:#a78bfa">{sub_c}</div><div class="stat-label">Subdomains</div></div>
  <div class="stat-card sc"><div class="stat-val" style="color:var(--accent)">{find_c}</div><div class="stat-label">Findings</div></div>
  <div class="stat-card so"><div class="stat-val" style="color:var(--orange)">{leak_c}</div><div class="stat-label">GH Leaks</div></div>
  <div class="stat-card sr"><div class="stat-val" style="color:var(--red)">{cve_c}</div><div class="stat-label">CVEs</div></div>
</div>

{self._section("summary","🎯","Target Summary",self._sec_target())}

<div class="grid-2" id="charts">
  <div class="section"><div class="section-header"><span class="s-icon">📊</span><span class="s-title">Port Distribution</span></div>
  <div class="section-body"><div class="chart-wrap"><canvas id="portChart"></canvas></div></div></div>
  <div class="section"><div class="section-header"><span class="s-icon">🔧</span><span class="s-title">Service Breakdown</span></div>
  <div class="section-body"><div class="chart-wrap"><canvas id="svcChart"></canvas></div></div></div>
</div>

{self._section("ports","🔓",f"Open Ports & Services",self._sec_ports_open(),badge=open_c)}
{self._section("allports","🔒",f"All Scanned Ports (Closed / Filtered)",self._sec_ports_all(),badge=f"{closed_c+filt_c}")}
{self._section("network","🌐","Network Map & Firewall Detection",self._sec_network())}
{self._section("smtp","📧","SMTP Enumeration",self._sec_smtp())}
{self._section("dns","📡","DNS Records",self._sec_dns())}
{self._section("whois","📋","WHOIS & Intelligence",self._sec_whois())}
{self._section("asn","🔢","ASN / BGP Intelligence",self._sec_asn())}
{self._section("geoip","🌍","GeoIP Location",self._sec_geoip())}
{self._section("subdomains","🔍",f"Subdomains Discovered",self._sec_subdomains(),badge=sub_c)}
{self._section("dorks","🔎","Google Dorking Results",self._sec_dorks())}
{self._section("github","🐙","GitHub Secret Leaks",self._sec_github(),badge=leak_c)}
{self._section("shodan","🕵️","Shodan Intelligence",self._sec_shodan(),badge=cve_c if cve_c else "")}
{self._section("ssl","🔐","SSL/TLS Analysis",self._sec_ssl())}
{self._section("web","🌏","Web Reconnaissance",self._sec_web())}
{self._section("warnings","⚠","Scan Warnings & Alerts",self._sec_warnings())}

</div>
</div>

<footer class="footer">
  ReconScout v2.1 &nbsp;·&nbsp;
  by <span style="color:var(--accent2);font-weight:600">Agent P</span>
  &nbsp;·&nbsp; {r.finished_at} &nbsp;·&nbsp; Duration: {dur} &nbsp;·&nbsp;
  FOR AUTHORIZED USE ONLY
</footer>

<script>
const MONO='"JetBrains Mono",monospace',MT="#4a6080",BR="#1b2d45";
const PAL=["#00e5ff","#00e676","#7c3aed","#ffd740","#ff5252","#ff9800","#40c4ff","#b39ddb","#69f0ae","#ffca28","#ff6e40"];
const base={{responsive:true,maintainAspectRatio:false,
  plugins:{{legend:{{labels:{{color:MT,font:{{family:MONO,size:10}}}}}}}},
  scales:{{x:{{ticks:{{color:MT,font:{{family:MONO,size:9}}}},grid:{{color:BR}}}},
           y:{{ticks:{{color:MT,font:{{family:MONO,size:9}}}},grid:{{color:BR}},beginAtZero:true}}}}}};
new Chart(document.getElementById('portChart'),{{type:'bar',
  data:{{labels:{pl},datasets:[{{label:'Port',data:{pv},backgroundColor:'rgba(0,229,255,.3)',borderColor:'#00e5ff',borderWidth:1,borderRadius:3}}]}},
  options:{{...base}}}});
new Chart(document.getElementById('svcChart'),{{type:'doughnut',
  data:{{labels:{sl},datasets:[{{data:{sv},backgroundColor:PAL,borderColor:'#0f1929',borderWidth:2}}]}},
  options:{{responsive:true,maintainAspectRatio:false,
    plugins:{{legend:{{position:'right',labels:{{color:MT,font:{{family:MONO,size:10}},padding:9,boxWidth:9}}}}}}}}}});
</script>
</body></html>"""

        Path(path).write_text(html, encoding="utf-8")
        self.logger.info(f"HTML saved → {path}")


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

class CLIReport:
    def __init__(self, result: ScanResult, logger):
        self.r = result
        self.logger = logger

    def _h(self, title, icon="◈"):
        print(f"\n{C.CYAN}{C.BOLD}  {icon} {title}{C.RESET}")
        print(f"  {C.CYAN}{'─'*68}{C.RESET}")

    def _kv(self, k, v, col=C.RESET):
        if v: print(f"    {C.GREY}{k:<22}{C.RESET} {col}{v}{C.RESET}")

    def print(self):
        r = self.r; s = r.stats
        print(f"\n  {C.CYAN}{'═'*70}{C.RESET}")
        print(f"  {C.BOLD}{C.CYAN}  RECONSCOUT v2.1 — by Agent P  {C.RESET}")
        print(f"  {C.CYAN}{'═'*70}{C.RESET}")

        self._h("Target Overview","🎯")
        self._kv("Target",    r.target); self._kv("Type",r.target_type.upper())
        self._kv("IP",        r.ip_address); self._kv("Hostname",r.hostname)
        self._kv("Mode",      r.scan_mode.upper()); self._kv("OS Guess",r.intel.os_guess,C.YELLOW)
        self._kv("ASN",       r.asn.asn); self._kv("Org",r.asn.org)
        geo = r.geoip
        if geo.country: self._kv("Location",f"{geo.city}, {geo.country}")
        self._kv("Duration",  f"{r.duration_sec:.1f}s",C.YELLOW)
        print(f"\n    {C.GREEN}Open:{C.BOLD}{s.get('open_ports',0)}{C.RESET}  "
              f"{C.RED}Closed:{C.BOLD}{s.get('closed_ports',0)}{C.RESET}  "
              f"{C.YELLOW}Filtered:{C.BOLD}{s.get('filtered_ports',0)}{C.RESET}  "
              f"{C.CYAN}Subs:{C.BOLD}{len(r.subdomains)}{C.RESET}  "
              f"{C.PURPLE}Findings:{C.BOLD}{s.get('findings',0)}{C.RESET}")

        # Ports
        open_p = [p for p in r.ports if p.state=="open"]
        if open_p:
            self._h("Open Ports","🔓")
            print(f"{C.GREY}    {'PORT':<8}{'PROTO':<7}{'SERVICE':<16}{'VERSION':<18}{'BANNER'}{C.RESET}")
            print(f"    {'─'*66}")
            for p in open_p:
                bn=(p.banner[:36]+"…" if len(p.banner)>36 else p.banner).replace('\n',' ')
                print(f"    {C.GREEN}{str(p.port):<8}{C.RESET}{p.protocol:<7}{p.service:<16}{p.version:<18}{C.CYAN}{bn}{C.RESET}")

        # ASN
        if r.asn.asn:
            self._h("ASN / BGP","🔢")
            self._kv("ASN",      r.asn.asn); self._kv("Org",r.asn.org)
            self._kv("IP Range", r.asn.ip_range); self._kv("RIR",r.asn.rir)
            self._kv("Abuse",    r.asn.abuse_email)
            if r.asn.prefixes: self._kv("Prefixes",str(len(r.asn.prefixes)))
            if r.asn.peers:    self._kv("Peers",   str(len(r.asn.peers)))

        # DNS
        if any([r.dns.a,r.dns.mx,r.dns.ns]):
            self._h("DNS Records","📡")
            for t,recs in [("A",r.dns.a),("AAAA",r.dns.aaaa),("MX",r.dns.mx),("NS",r.dns.ns),("TXT",r.dns.txt[:3])]:
                for rec in recs: print(f"    {C.YELLOW}{t:<6}{C.RESET} {rec}")
            if r.dns.zone_transfer: print(f"    {C.RED}{C.BOLD}⚠ ZONE TRANSFER! {len(r.dns.zone_transfer)} records{C.RESET}")

        # SSL
        if r.ssl.enabled:
            self._h("SSL/TLS","🔐")
            self._kv("Grade",   r.ssl.grade, C.GREEN if r.ssl.grade in ("A+","A") else C.YELLOW)
            self._kv("Version", r.ssl.version); self._kv("Issuer",r.ssl.issuer)
            for v in r.ssl.vulnerabilities: print(f"    {C.RED}⚠ {v}{C.RESET}")

        # Subdomains
        if r.subdomains:
            self._h(f"Subdomains ({len(r.subdomains)})","🔍")
            for sd in r.subdomains[:25]: print(f"    {C.GREEN}[+]{C.RESET} {sd}")
            if len(r.subdomains)>25: print(f"    {C.GREY}... {len(r.subdomains)-25} more in report{C.RESET}")

        # GitHub leaks
        if r.github_leaks:
            self._h(f"GitHub Leaks ({len(r.github_leaks)})","🐙")
            for l in r.github_leaks[:10]:
                col = C.RED if l.severity=="HIGH" else C.YELLOW
                print(f"    {col}[{l.severity}]{C.RESET} {l.leak_type} — {l.repo_url}")

        # Shodan CVEs
        if r.shodan.vulns:
            self._h("Shodan CVEs","🕵️")
            for cve in r.shodan.vulns[:10]: print(f"    {C.RED}⚠ {cve}{C.RESET}")

        # Web
        if r.web.url:
            self._h("Web Recon","🌏")
            self._kv("URL",r.web.url); self._kv("Status",str(r.web.status_code))
            self._kv("Server",r.web.server); self._kv("Technologies",", ".join(r.web.technologies) or "None")
            self._kv("CDN/WAF",", ".join(r.web.cdn_waf) or "None")
            if r.web.misconfigs:
                print(f"\n    {C.RED}{C.BOLD}Misconfigurations:{C.RESET}")
                for m in r.web.misconfigs[:8]: print(f"    {C.YELLOW}  ⚠{C.RESET} {m}")

        # Warnings
        if r.warnings:
            self._h("Warnings","⚠")
            for w in r.warnings: print(f"    {C.YELLOW}⚠ {w}{C.RESET}")

        print(f"\n  {C.CYAN}{'═'*70}{C.RESET}\n")


# ─────────────────────────────────────────────────────────────────────────────
# FACADE
# ─────────────────────────────────────────────────────────────────────────────

class ReportManager:
    def __init__(self, result: ScanResult, logger):
        self.result = result; self.logger = logger
        self._json = JSONReport(result, logger)
        self._html = HTMLReport(result, logger)
        self._cli  = CLIReport(result, logger)

    def print_cli(self):   self._cli.print()
    def save_json(self, p): self._json.save(p)
    def save_html(self, p): self._html.save(p)
    def save_all(self, prefix):
        self.save_json(f"{prefix}.json"); self.save_html(f"{prefix}.html")
