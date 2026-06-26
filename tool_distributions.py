import random
from typing import Dict, List, Optional

TOOLSETS = {
    "recon": {
        "description": "Reconnaissance tools — port scanning, subdomain enum, tech fingerprinting",
        "tools": ["nmap_quick", "nmap_full", "nmap_vuln", "nmap_os", "masscan", "rustscan",
                  "gobuster", "ffuf", "whatweb", "waf_detect", "dirsearch",
                  "amass", "subfinder", "assetfinder", "findomain",
                  "dns_enum", "dnsrecon", "dnsx",
                  "httpx", "gospider", "katana",
                  "cloud_metadata"]
    },
    "vuln_scan": {
        "description": "Vulnerability scanning — CVE scanning, web app scanners",
        "tools": ["nuclei", "nuclei_templates", "jaeles", "searchsploit", "sploitus",
                  "wpscan", "joomscan", "droopescan",
                  "ssl_scan", "testssl",
                  "burp"]
    },
    "enumeration": {
        "description": "Service enumeration — SMB, SSH, FTP, SNMP, LDAP, database",
        "tools": ["enum4linux", "smb_enum", "smbmap", "crackmapexec",
                  "ssh_scan", "ssh_audit",
                  "ftp_enum", "ftp_anon",
                  "snmp_walk", "snmpcheck",
                  "ldap_enum", "ad_enum",
                  "mysql_enum", "mongo_enum",
                  "rdp_scan"]
    },
    "exploit": {
        "description": "Exploitation — SQL injection, XSS, command injection, API testing",
        "tools": ["sqlmap", "xsser", "xsstrike", "commix", "dalfox",
                  "arjun", "kiterunner",
                  "searchsploit", "sploitus"]
    },
    "webapp": {
        "description": "Web application testing — focused web assessment",
        "tools": ["gobuster", "ffuf", "whatweb", "waf_detect", "dirsearch",
                  "nuclei", "sqlmap", "xsser", "xsstrike", "dalfox",
                  "arjun", "kiterunner", "gospider", "katana",
                  "wpscan", "joomscan", "droopescan",
                  "httpx"]
    },
    "cloud": {
        "description": "Cloud infrastructure testing",
        "tools": ["cloud_metadata", "nmap_quick", "whatweb", "curl", "http"]
    }
}

PHASE_DISTRIBUTIONS = {
    "initial": {
        "description": "Initial recon phase — port scanning and fingerprinting",
        "toolsets": {
            "recon": 95,
            "enumeration": 30,
            "vuln_scan": 20,
        }
    },
    "recon": {
        "description": "Deep reconnaissance — subdomain, directory, service enumeration",
        "toolsets": {
            "recon": 90,
            "enumeration": 70,
            "vuln_scan": 40,
            "webapp": 50,
        }
    },
    "vuln_assessment": {
        "description": "Vulnerability assessment — scanning for known CVEs and misconfigs",
        "toolsets": {
            "vuln_scan": 95,
            "recon": 30,
            "enumeration": 30,
            "webapp": 60,
        }
    },
    "exploitation": {
        "description": "Active exploitation — attempting to exploit discovered vulns",
        "toolsets": {
            "exploit": 95,
            "webapp": 60,
            "vuln_scan": 40,
        }
    },
    "post_exploit": {
        "description": "Post-exploitation — deeper access and lateral movement",
        "toolsets": {
            "enumeration": 80,
            "exploit": 60,
            "cloud": 40,
        }
    },
    "default": {
        "description": "Balanced distribution for general pentesting",
        "toolsets": {
            "recon": 70,
            "vuln_scan": 60,
            "enumeration": 50,
            "exploit": 40,
            "webapp": 50,
            "cloud": 20,
        }
    }
}


def get_distribution(name: str) -> Optional[Dict]:
    return PHASE_DISTRIBUTIONS.get(name)


def list_distributions() -> Dict[str, Dict]:
    return PHASE_DISTRIBUTIONS.copy()


def sample_tools_from_distribution(distribution_name: str) -> List[str]:
    dist = get_distribution(distribution_name)
    if not dist:
        dist = get_distribution("default")

    selected = []
    for toolset_name, probability in dist["toolsets"].items():
        if random.random() * 100 < probability:
            toolset = TOOLSETS.get(toolset_name)
            if toolset:
                selected.extend(toolset["tools"])

    return list(set(selected))


def get_tools_for_phase(target_type: str = "", phase: str = "") -> List[str]:
    if phase and phase in PHASE_DISTRIBUTIONS:
        return sample_tools_from_distribution(phase)
    return sample_tools_from_distribution("default")
