import os
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field

from config import CONFIG
from constants import C
from logging_utils import log


@dataclass
class DiscoveredTool:
    binary: str
    path: str
    category: str
    description: str
    install_hint: str


# Maps tool binary → install instructions per OS
INSTALL_MAP: Dict[str, Dict[str, str]] = {
    "nmap":        {"apt": "apt install nmap", "brew": "brew install nmap", "pip": "pip install python-nmap"},
    "masscan":     {"apt": "apt install masscan", "brew": "brew install masscan"},
    "rustscan":    {"cargo": "cargo install rustscan", "docker": "docker run -it --rm --name rustscan rustscan/rustscan:latest"},
    "gobuster":    {"apt": "apt install gobuster", "brew": "brew install gobuster", "go": "go install github.com/OJ/gobuster/v3@latest"},
    "ffuf":        {"apt": "apt install ffuf", "brew": "brew install ffuf", "go": "go install github.com/ffuf/ffuf/v2@latest"},
    "dirsearch":   {"pip": "pip install dirsearch"},
    "whatweb":     {"apt": "apt install whatweb", "brew": "brew install whatweb"},
    "nuclei":      {"go": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", "brew": "brew install nuclei"},
    "subfinder":   {"go": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"},
    "httpx":       {"go": "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"},
    "dnsx":        {"go": "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest"},
    "amass":       {"go": "go install github.com/owasp-amass/amass/v4/...@master"},
    "assetfinder": {"go": "go install github.com/tomnomnom/assetfinder@latest"},
    "sqlmap":      {"pip": "pip install sqlmap"},
    "searchsploit":{"apt": "apt install exploitdb"},
    "hydra":       {"apt": "apt install hydra", "brew": "brew install hydra"},
    "john":        {"apt": "apt install john", "brew": "brew install john"},
    "enum4linux":  {"apt": "apt install enum4linux"},
    "smbclient":   {"apt": "apt install smbclient"},
    "smbmap":      {"pip": "pip install smbmap"},
    "netexec":     {"pip": "pip install netexec"},
    "impacket-secretsdump": {"pip": "pip install impacket"},
    "impacket-GetNPUsers":  {"pip": "pip install impacket"},
    "impacket-GetUserSPNs": {"pip": "pip install impacket"},
    "impacket-smbexec":     {"pip": "pip install impacket"},
    "impacket-wmiexec":     {"pip": "pip install impacket"},
    "impacket-psexec":      {"pip": "pip install impacket"},
    "kerbrute":    {"go": "go install github.com/ropnop/kerbrute@latest"},
    "certipy":     {"pip": "pip install certipy-ad"},
    "bloodhound-python": {"pip": "pip install bloodhound"},
    "ldapsearch":  {"apt": "apt install ldap-utils"},
    "gospider":    {"go": "go install github.com/jaeles-project/gospider@latest"},
    "katana":      {"go": "go install github.com/projectdiscovery/katana/cmd/katana@latest"},
    "kiterunner":  {"go": "go install github.com/assetnote/kiterunner@latest"},
    "arjun":       {"pip": "pip install arjun"},
    "dalfox":      {"go": "go install github.com/hahwul/dalfox/v2@latest"},
    "wpscan":      {"gem": "gem install wpscan"},
    "joomscan":    {"apt": "apt install joomscan"},
    "droopescan":  {"pip": "pip install droopescan"},
    "theHarvester":{"pip": "pip install theHarvester"},
    "trufflehog":  {"go": "go install github.com/trufflesecurity/trufflehog/v3@latest"},
    "gitleaks":    {"go": "go install github.com/gitleaks/gitleaks/v8@latest"},
    "git-dumper":  {"pip": "pip install git-dumper"},
    "apktool":     {"apt": "apt install apktool"},
    "jadx":        {"apt": "apt install jadx"},
    "linpeas":     {"curl": "curl -sL https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh"},
    "winpeas":     {"curl": "curl -sL https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEAS.exe"},
    "trivy":       {"apt": "apt install trivy", "brew": "brew install trivy"},
    "kube-hunter": {"pip": "pip install kube-hunter"},
    "testssl":     {"apt": "apt install testssl.sh", "brew": "brew install testssl"},
    "sslscan":     {"apt": "apt install sslscan"},
    "snmpwalk":    {"apt": "apt install snmp"},
    "redis-cli":   {"apt": "apt install redis-tools"},
    "mongosh":     {"apt": "apt install mongodb-mongosh"},
    "psql":        {"apt": "apt install postgresql-client"},
    "mysql":       {"apt": "apt install mysql-client"},
    "msfconsole":  {"apt": "apt install metasploit-framework", "brew": "brew install metasploit"},
    "msfvenom":    {"apt": "apt install metasploit-framework", "brew": "brew install metasploit"},
}


CATEGORY_MAP: Dict[str, str] = {
    "nmap": "port_scan", "masscan": "port_scan", "rustscan": "port_scan",
    "gobuster": "web_dirbust", "ffuf": "web_dirbust", "dirsearch": "web_dirbust", "dirb": "web_dirbust",
    "whatweb": "fingerprint", "wappalyzer": "fingerprint",
    "nuclei": "web_scanner", "jaeles": "web_scanner",
    "subfinder": "subdomain", "amass": "subdomain", "assetfinder": "subdomain", "findomain": "subdomain",
    "sqlmap": "web_exploit", "dalfox": "web_exploit", "xsstrike": "web_exploit", "xsser": "web_exploit",
    "gospider": "web_spider", "katana": "web_spider", "kiterunner": "web_spider",
    "arjun": "web_param", "paramspider": "web_param",
    "wpscan": "cms", "joomscan": "cms", "droopescan": "cms",
    "enum4linux": "smb", "smbclient": "smb", "smbmap": "smb", "netexec": "smb",
    "crackmapexec": "smb", "cme": "smb",
    "hydra": "auth", "john": "auth", "hashcat": "auth",
    "searchsploit": "exploit_search",
    "ldapsearch": "ad", "bloodhound-python": "ad", "certipy": "ad",
    "impacket-secretsdump": "ad", "impacket-GetNPUsers": "ad", "impacket-GetUserSPNs": "ad",
    "impacket-smbexec": "ad", "impacket-wmiexec": "ad", "impacket-psexec": "ad",
    "kerbrute": "ad",
    "theHarvester": "osint", "sherlock": "osint",
    "apktool": "mobile", "jadx": "mobile", "apkleaks": "mobile",
    "trivy": "container", "kube-hunter": "container", "kubectl": "container",
    "airodump-ng": "wireless", "aircrack-ng": "wireless", "reaver": "wireless", "bully": "wireless",
    "git-dumper": "git", "trufflehog": "git", "gitleaks": "git",
    "testssl": "ssl", "sslscan": "ssl",
    "snmpwalk": "snmp", "snmpcheck": "snmp",
    "dnsrecon": "dns", "dnsx": "dns", "dig": "dns", "nslookup": "dns",
    "curl": "web", "wget": "web",
    "msfconsole": "exploit_framework", "msfvenom": "exploit_framework",
    "linpeas": "privesc", "winpeas": "privesc",
}


def scan_available_tools() -> Dict[str, DiscoveredTool]:
    found: Dict[str, DiscoveredTool] = {}
    seen = set()

    for binary_name, cat in CATEGORY_MAP.items():
        if binary_name in seen:
            continue
        seen.add(binary_name)

        fp = shutil.which(binary_name)
        if fp:
            install_hint = ""
            found[binary_name] = DiscoveredTool(
                binary=binary_name,
                path=fp,
                category=cat,
                description=_describe_tool(binary_name, cat),
                install_hint=install_hint,
            )

    return found


def scan_missing_critical() -> Dict[str, DiscoveredTool]:
    missing: Dict[str, DiscoveredTool] = {}
    seen = set()

    for binary_name, cat in CATEGORY_MAP.items():
        if binary_name in seen:
            continue
        seen.add(binary_name)

        if not shutil.which(binary_name):
            install_cmds = _install_command(binary_name)
            missing[binary_name] = DiscoveredTool(
                binary=binary_name,
                path="",
                category=cat,
                description=_describe_tool(binary_name, cat),
                install_hint=install_cmds,
            )

    return missing


def _describe_tool(binary: str, category: str) -> str:
    descs = {
        "nmap": "Port scanning, service detection, OS fingerprinting, NSE vuln scripts",
        "masscan": "Fast full-port TCP scanner (10x faster than nmap)",
        "rustscan": "Rust-based port scanner with automatic nmap integration",
        "gobuster": "Directory/file brute force for web servers",
        "ffuf": "Fast web fuzzer for directory/parameter discovery",
        "dirsearch": "Advanced HTTP directory brute forcer",
        "whatweb": "Web technology and CMS fingerprinting",
        "nuclei": "Template-based vulnerability scanner (CVEs, misconfigs, exposures)",
        "sqlmap": "Automated SQL injection detection and exploitation",
        "hydra": "Online password brute forcing (SSH, FTP, HTTP, SMB, etc.)",
        "searchsploit": "Local ExploitDB search for known exploits by service/version",
        "subfinder": "Passive subdomain discovery using multiple OSINT sources",
        "amass": "Deep subdomain enumeration (passive + active)",
        "assetfinder": "Asset/subdomain discovery from various sources",
        "enum4linux": "SMB/NetBIOS/AD enumeration (Linux equivalent of enum.exe)",
        "smbclient": "SMB/CIFS share access and file listing",
        "smbmap": "SMB share enumeration with recursive listing",
        "netexec": "Post-exploitation AD/SMB enumeration (CME successor)",
        "impacket-secretsdump": "DCSync attack — dump domain hashes from DC",
        "impacket-GetNPUsers": "AS-REP roasting — find Kerberos pre-auth disabled accounts",
        "impacket-GetUserSPNs": "Kerberoasting — request TGS tickets for service accounts",
        "impacket-smbexec": "SMB-based remote command execution",
        "impacket-wmiexec": "WMI-based remote command execution (more stealthy)",
        "impacket-psexec": "PsExec-style remote execution",
        "bloodhound-python": "Active Directory reconnaissance ingestor for BloodHound",
        "certipy": "AD CS certificate service abuse (ESC1-8, ESC13)",
        "kerbrute": "Kerberos user enumeration and password spraying",
        "ldapsearch": "LDAP directory query and AD object enumeration",
        "gospider": "Fast web spider for asset/endpoint discovery",
        "katana": "Next-gen web crawler with JS parsing and form extraction",
        "kiterunner": "API route/endpoint discovery using wordlists",
        "arjun": "HTTP parameter discovery for web endpoints",
        "dalfox": "Advanced XSS scanner with DOM and parameter analysis",
        "wpscan": "WordPress vulnerability scanner (theme, plugin, user enum)",
        "theHarvester": "OSINT email, subdomain, and employee name harvesting",
        "trufflehog": "High-entropy secret scanning in git repos and filesystems",
        "gitleaks": "Git repository secret leak detection",
        "git-dumper": "Dump exposed .git repositories from web servers",
        "msfconsole": "Metasploit Framework — exploit development and execution",
        "msfvenom": "Metasploit payload generator (reverse shells, stagers)",
        "trivy": "Container image and filesystem vulnerability scanner",
        "testssl": "SSL/TLS security testing (Heartbleed, Poodle, etc.)",
        "apktool": "APK decompilation to smali (Android reverse engineering)",
        "jadx": "APK/DEX decompilation to readable Java source",
        "linpeas": "Linux privilege escalation enumeration (PEASS-ng)",
        "winpeas": "Windows privilege escalation enumeration (PEASS-ng)",
    }
    return descs.get(binary, f"{category.replace('_', ' ').title()} tool")


def _install_command(binary: str) -> str:
    installs = INSTALL_MAP.get(binary, {})
    if not installs:
        return ""

    os_type = "windows" if os.name == "nt" else "linux"
    # Prefer OS-native package manager
    if os_type == "linux":
        for pm in ("apt", "apt-get", "yum", "dnf", "pacman"):
            if pm in installs:
                return installs[pm]
    elif os_type == "windows":
        if "pip" in installs:
            return installs["pip"]
        # Chocolatey fallback
        return f"choco install {binary}"

    # Fallback: return first available
    for pm, cmd in installs.items():
        which_pm = shutil.which(pm) or shutil.which(pm.replace("install", "").strip())
        if which_pm:
            return cmd

    # Last resort: return any install instruction
    return next(iter(installs.values()), f"Install {binary} via your package manager")


def build_tool_context(available: Dict[str, DiscoveredTool],
                       missing: Dict[str, DiscoveredTool],
                       phase: str = "") -> str:
    lines = []

    if available:
        lines.append("AVAILABLE TOOLS:")
        for name, tool in sorted(available.items(), key=lambda x: x[1].category + x[0]):
            lines.append(f"  {name:<25} [{tool.category}] {tool.description}")

    if missing:
        lines.append("")
        lines.append("MISSING TOOLS (install for more capabilities):")
        for name, tool in sorted(missing.items(), key=lambda x: x[1].category + x[0]):
            hint = tool.install_hint
            lines.append(f"  {name:<25} [{tool.category}] install: {hint}")

    return "\n".join(lines)


if __name__ == "__main__":
    avail = scan_available_tools()
    miss = scan_missing_critical()
    print(f"Available: {len(avail)} tools")
    print(f"Missing: {len(miss)} tools")
    print()
    print(build_tool_context(avail, miss))
