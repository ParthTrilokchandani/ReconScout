"""
ReconScout — Constants & Fingerprint Databases
Central registry for service maps, banner signatures, tech fingerprints.

Author  : Agent P
Project : ReconScout v2.1
"""

# ── Service port → name map ─────────────────────────────────────────────────
SERVICE_MAP = {
    21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP", 53:"DNS",
    67:"DHCP", 68:"DHCP", 69:"TFTP", 80:"HTTP", 88:"Kerberos",
    110:"POP3", 111:"RPC", 119:"NNTP", 123:"NTP", 135:"MSRPC",
    139:"NetBIOS", 143:"IMAP", 161:"SNMP", 162:"SNMP-Trap", 179:"BGP",
    194:"IRC", 389:"LDAP", 443:"HTTPS", 445:"SMB", 465:"SMTPS",
    514:"Syslog", 515:"LPD", 587:"SMTP-Sub", 631:"IPP", 636:"LDAPS",
    873:"rsync", 902:"VMware", 993:"IMAPS", 995:"POP3S", 1080:"SOCKS",
    1194:"OpenVPN", 1433:"MSSQL", 1521:"Oracle-DB", 1723:"PPTP",
    2049:"NFS", 2181:"Zookeeper", 2375:"Docker-API", 2376:"Docker-TLS",
    3000:"HTTP-Dev", 3268:"LDAP-GC", 3306:"MySQL", 3389:"RDP",
    4369:"Erlang-EPM", 4444:"Metasploit", 5000:"HTTP-Alt",
    5432:"PostgreSQL", 5601:"Kibana", 5672:"AMQP", 5900:"VNC",
    5985:"WinRM-HTTP", 5986:"WinRM-HTTPS", 6379:"Redis",
    6443:"K8s-API", 7001:"WebLogic", 7180:"Cloudera", 8000:"HTTP-Alt",
    8080:"HTTP-Proxy", 8443:"HTTPS-Alt", 8888:"HTTP-Alt",
    9000:"PHP-FPM", 9090:"Prometheus", 9200:"Elasticsearch",
    9300:"Elasticsearch-T", 9418:"Git", 10250:"Kubelet",
    11211:"Memcached", 15672:"RabbitMQ-Mgmt", 15692:"RabbitMQ-Prom",
    27017:"MongoDB", 27018:"MongoDB-Shard", 50000:"DB2",
    50070:"HDFS-NameNode", 61616:"ActiveMQ",
}

# ── Banner regex patterns for version extraction ────────────────────────────
BANNER_SIGNATURES = {
    "SSH":   [r"SSH-(\d+\.\d+)-(.+)"],
    "FTP":   [r"^220[- ](.+)"],
    "SMTP":  [r"^220[- ](.+?)\s"],
    "HTTP":  [r"[Ss]erver:\s*(.+)"],
    "MySQL": [r"(\d+\.\d+\.\d+)[-\w]*"],
    "Redis": [r"redis_version:(.+)"],
    "SSH-OS":[r"OpenSSH[_-](\S+)\s+(Ubuntu|Debian|CentOS|RedHat|FreeBSD)"],
}

# CPE templates for common services
CPE_MAP = {
    "OpenSSH": "cpe:/a:openbsd:openssh:",
    "Apache":  "cpe:/a:apache:http_server:",
    "nginx":   "cpe:/a:nginx:nginx:",
    "MySQL":   "cpe:/a:mysql:mysql:",
    "vsftpd":  "cpe:/a:beasts:vsftpd:",
    "ProFTPD": "cpe:/a:proftpd:proftpd:",
    "Postfix": "cpe:/a:postfix:postfix:",
}

# ── CDN / WAF detection signatures ─────────────────────────────────────────
CDN_WAF_SIGNATURES = {
    "Cloudflare":     ["cloudflare","cf-ray","cf-cache-status","__cfduid","cf-connecting-ip"],
    "Akamai":         ["akamai","x-akamai-transformed","akamaighost"],
    "Fastly":         ["fastly","x-fastly-request-id","x-served-by"],
    "AWS CloudFront": ["cloudfront","x-amz-cf-id","x-amz-cf-pop"],
    "AWS Shield":     ["x-amzn-requestid","x-amz-rid"],
    "Azure CDN":      ["x-azure-ref","x-ms-request-id","x-cache: tcp_hit"],
    "Sucuri WAF":     ["sucuri","x-sucuri-id","x-sucuri-cache"],
    "Incapsula":      ["incapsula","visid_incap","incap_ses","x-cdn: Imperva"],
    "F5 BIG-IP":      ["bigip","x-wa-info","x-cnection"],
    "ModSecurity":    ["mod_security","modsecurity","x-waf-status"],
    "Imperva":        ["x-cdn: Imperva","x-iinfo"],
    "StackPath":      ["x-sp-url","stackpath"],
    "Varnish":        ["x-varnish","via: varnish","age:"],
    "Nginx WAF":      ["naxsi","x-naxsi"],
    "Barracuda":      ["barra_counter_session","barracuda"],
    "Citrix NetScaler":["citrix_ns_id","ns_af"],
    "Reblaze":        ["x-reblaze-protection"],
    "Radware":        ["x-sl-compstate"],
}

# ── Technology fingerprinting signatures ────────────────────────────────────
TECH_SIGNATURES = {
    # Web Servers
    "Apache":        ["Apache/", "apache"],
    "Nginx":         ["nginx/", "nginx"],
    "IIS":           ["Microsoft-IIS", "ASP.NET"],
    "LiteSpeed":     ["LiteSpeed", "X-Powered-By: LiteSpeed"],
    "Caddy":         ["Caddy", "caddy"],
    "Gunicorn":      ["gunicorn"],
    "uWSGI":         ["uWSGI"],
    "Tomcat":        ["Apache-Coyote", "Tomcat"],
    "WebLogic":      ["WebLogic", "X-Powered-By: Servlet"],
    "JBoss":         ["JBoss", "jboss"],
    "WildFly":       ["WildFly", "wildfly"],
    # Languages / Runtimes
    "PHP":           ["X-Powered-By: PHP", ".php"],
    "Node.js":       ["X-Powered-By: Express", "node.js", "nodejs"],
    "Python":        ["python", "werkzeug", "django", "flask"],
    "Ruby/Rails":    ["Phusion Passenger", "rails", "x-rack"],
    "Go":            ["Go-http-client", "gorilla"],
    "Java":          ["Java/", "javax.servlet"],
    # CMS
    "WordPress":     ["wp-content", "wp-includes", "WordPress"],
    "Drupal":        ["Drupal", "X-Generator: Drupal"],
    "Joomla":        ["Joomla", "/media/jui/"],
    "Magento":       ["Magento", "mage-cache"],
    "Shopify":       ["shopify", "cdn.shopify.com"],
    "Ghost":         ["ghost", "Ghost"],
    "Strapi":        ["strapi"],
    # Frameworks
    "Django":        ["csrfmiddlewaretoken", "django"],
    "Laravel":       ["laravel_session", "X-Powered-By: PHP", "laravel"],
    "Spring":        ["X-Application-Context", "spring"],
    "ASP.NET MVC":   ["__RequestVerificationToken", "asp.net"],
    "React":         ["_next/", "__NEXT_DATA__", "react"],
    "Vue.js":        ["__vue__", "vue.js"],
    "Angular":       ["ng-version", "angular"],
    # Databases (exposed)
    "MySQL":         ["mysql", "phpmyadmin"],
    "MongoDB":       ["mongodb", "mongo"],
    "Elasticsearch": ["elasticsearch"],
    # Analytics / Marketing
    "Google Analytics": ["google-analytics.com", "gtag(", "UA-"],
    "Google Tag Manager":["googletagmanager.com", "GTM-"],
    "Hotjar":        ["hotjar"],
    "Mixpanel":      ["mixpanel"],
    # Security
    "reCAPTCHA":     ["recaptcha", "g-recaptcha"],
    "Cloudflare Turnstile": ["challenges.cloudflare.com"],
}

# ── Common HTTP security headers ────────────────────────────────────────────
SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "x-xss-protection",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-embedder-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
]

# ── Interesting ports for default active scans ──────────────────────────────
DEFAULT_PORTS = (
    "21,22,23,25,53,80,88,110,111,135,139,143,161,389,443,445,"
    "465,587,636,873,993,995,1080,1433,1521,1723,2049,2181,2375,"
    "3000,3268,3306,3389,4369,5432,5601,5672,5900,5985,6379,6443,"
    "7001,8000,8080,8443,8888,9000,9090,9200,10250,11211,15672,"
    "27017,50000,61616"
)

# ── SSL/TLS weak ciphers & protocols ───────────────────────────────────────
WEAK_CIPHERS = [
    "RC4", "DES", "3DES", "NULL", "EXPORT", "MD5", "anon"
]
WEAK_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]

# ── Common SMTP test users for enumeration ──────────────────────────────────
SMTP_TEST_USERS = [
    "admin", "administrator", "root", "postmaster", "info",
    "webmaster", "support", "contact", "mail", "noreply",
]

# ── Default traceroute max hops ─────────────────────────────────────────────
TRACEROUTE_MAX_HOPS = 20

# ── HTTP methods to test ────────────────────────────────────────────────────
INTERESTING_HTTP_METHODS = ["OPTIONS", "PUT", "DELETE", "TRACE", "CONNECT", "PATCH"]

# ── Sensitive file patterns for web recon ──────────────────────────────────
SENSITIVE_FILES = [
    ".env", ".git/config", ".svn/entries", "wp-config.php",
    "config.php", "database.yml", "settings.py", "application.properties",
    "web.config", "phpinfo.php", "info.php", "server-status",
    "crossdomain.xml", "clientaccesspolicy.xml",
    "/.well-known/security.txt", "/security.txt",
]

# ── Top-level scan modes ─────────────────────────────────────────────────────
ACTIVE_MODES  = ("active", "full")
PASSIVE_MODES = ("passive", "full")
WEB_MODES     = ("web", "full")
