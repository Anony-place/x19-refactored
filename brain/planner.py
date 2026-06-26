from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Any
import time
import re

from config import CONFIG
from constants import C, ICO


# ============================================================
# Tool I/O Schema — what each tool needs and produces
# ============================================================

@dataclass
class ToolIO:
    name: str
    inputs: List[str]           # data this tool needs (target, url, port, domain, etc.)
    outputs: List[str]          # data this tool can discover
    prerequisites: List[str]    # conditions like "port_80", "tech_wordpress", "domain_known"
    unlocks: List[str]          # tools that become relevant after this one
    category: str = "general"
    phase: str = "recon"        # recon, web_enum, vuln_scan, exploit
    description: str = ""


# Map: tool_name → ToolIO
TOOL_IO: Dict[str, ToolIO] = {
    # ---- RECON ----
    "nmap": ToolIO("nmap",
        inputs=["target"],
        outputs=["ports", "services", "os_info", "tech_stack", "host_status"],
        prerequisites=[],
        unlocks=["whatweb", "gobuster", "nuclei", "enum4linux", "searchsploit", "testssl"],
        category="port_scan", phase="recon",
        description="Discover open ports, running services, OS fingerprint"),
    "masscan": ToolIO("masscan",
        inputs=["target"],
        outputs=["ports"],
        prerequisites=[],
        unlocks=["nmap"],
        category="port_scan", phase="recon",
        description="Fast full-port TCP scan (faster but less detail than nmap)"),
    "whatweb": ToolIO("whatweb",
        inputs=["url"],
        outputs=["tech_stack", "cms", "version", "framework"],
        prerequisites=["port_80", "port_443", "port_8080", "port_8443"],
        unlocks=["wpscan", "joomscan", "droopescan", "sqlmap", "nuclei"],
        category="fingerprint", phase="recon",
        description="Identify web tech stack, CMS, framework, server versions"),
    "subfinder": ToolIO("subfinder",
        inputs=["domain"],
        outputs=["subdomains"],
        prerequisites=["domain_known"],
        unlocks=["httpx", "gospider"],
        category="subdomain", phase="recon",
        description="Passive subdomain discovery via multiple OSINT sources"),
    "amass": ToolIO("amass",
        inputs=["domain"],
        outputs=["subdomains"],
        prerequisites=["domain_known"],
        unlocks=["httpx"],
        category="subdomain", phase="recon",
        description="Deep subdomain enumeration (passive + active)"),

    # ---- WEB ENUM ----
    "gobuster": ToolIO("gobuster",
        inputs=["url"],
        outputs=["endpoints", "directories", "files"],
        prerequisites=["port_80", "port_443", "port_8080", "port_8443"],
        unlocks=["nuclei", "curl"],
        category="dirbust", phase="web_enum",
        description="Directory/file brute force on web servers"),
    "ffuf": ToolIO("ffuf",
        inputs=["url"],
        outputs=["endpoints", "parameters", "vhosts"],
        prerequisites=["port_80", "port_443", "port_8080", "port_8443"],
        unlocks=["nuclei", "arjun"],
        category="dirbust", phase="web_enum",
        description="Fast web fuzzer for directories, parameters, vhosts"),
    "gospider": ToolIO("gospider",
        inputs=["url"],
        outputs=["endpoints", "forms", "links", "js_files"],
        prerequisites=["port_80", "port_443"],
        unlocks=["dalfox", "arjun"],
        category="crawl", phase="web_enum",
        description="Web crawler to discover endpoints, forms, JS files"),
    "katana": ToolIO("katana",
        inputs=["url"],
        outputs=["endpoints", "js_files", "api_routes"],
        prerequisites=["port_80", "port_443"],
        unlocks=["dalfox", "kiterunner"],
        category="crawl", phase="web_enum",
        description="JS-aware web crawler with form extraction"),
    "arjun": ToolIO("arjun",
        inputs=["url"],
        outputs=["parameters"],
        prerequisites=["port_80", "port_443"],
        unlocks=["sqlmap", "dalfox"],
        category="param", phase="web_enum",
        description="HTTP parameter discovery for web endpoints"),

    # ---- VULN SCAN ----
    "nuclei": ToolIO("nuclei",
        inputs=["url"],
        outputs=["cves", "misconfigs", "exposures", "vulnerabilities"],
        prerequisites=["port_80", "port_443"],
        unlocks=["searchsploit", "sqlmap"],
        category="scanner", phase="vuln_scan",
        description="Template-based vulnerability scanner (CVEs, misconfigs)"),
    "searchsploit": ToolIO("searchsploit",
        inputs=["service_version", "cve_id", "keyword"],
        outputs=["exploit_code", "exploit_path", "cve_matches"],
        prerequisites=["ports", "tech_stack"],
        unlocks=["msfconsole", "sqlmap"],
        category="exploit_search", phase="vuln_scan",
        description="Search ExploitDB for known exploits by service/version"),
    "sqlmap": ToolIO("sqlmap",
        inputs=["url", "parameter"],
        outputs=["sql_injection", "database_dump", "credentials"],
        prerequisites=["port_80", "port_443", "web_param_detected"],
        unlocks=[],
        category="web_exploit", phase="vuln_scan",
        description="Automated SQL injection detection & exploitation"),
    "dalfox": ToolIO("dalfox",
        inputs=["url", "parameter"],
        outputs=["xss", "dom_xss"],
        prerequisites=["port_80", "port_443"],
        unlocks=[],
        category="web_exploit", phase="vuln_scan",
        description="Advanced XSS scanner with DOM verification"),
    "testssl": ToolIO("testssl",
        inputs=["host", "port"],
        outputs=["ssl_vulns", "ciphers", "cert_info"],
        prerequisites=["port_443", "port_8443"],
        unlocks=[],
        category="crypto", phase="vuln_scan",
        description="SSL/TLS security testing (Heartbleed, Poodle, etc.)"),

    # ---- SMB / AD / AUTH ----
    "enum4linux": ToolIO("enum4linux",
        inputs=["target"],
        outputs=["smb_shares", "users", "os_info", "policies"],
        prerequisites=["port_445", "port_139"],
        unlocks=["smbmap", "netexec", "crackmapexec"],
        category="smb", phase="web_enum",
        description="SMB/NetBIOS/AD enumeration"),
    "smbmap": ToolIO("smbmap",
        inputs=["target"],
        outputs=["smb_shares", "files", "permissions"],
        prerequisites=["port_445"],
        unlocks=[],
        category="smb", phase="web_enum",
        description="SMB share enumeration with recursive file listing"),
    "netexec": ToolIO("netexec",
        inputs=["target", "user", "password"],
        outputs=["smb_shares", "credentials", "ad_info"],
        prerequisites=["port_445"],
        unlocks=["impacket-secretsdump"],
        category="smb", phase="vuln_scan",
        description="SMB/AD post-exploitation enumeration"),
    "ldapsearch": ToolIO("ldapsearch",
        inputs=["target", "domain"],
        outputs=["ad_objects", "users", "groups", "dns_entries"],
        prerequisites=["port_389"],
        unlocks=["bloodhound-python", "certipy"],
        category="ad", phase="web_enum",
        description="LDAP directory query and AD object enumeration"),
    "bloodhound-python": ToolIO("bloodhound-python",
        inputs=["target", "domain", "user", "password"],
        outputs=["ad_relationships", "attack_paths", "privileged_users"],
        prerequisites=["port_389", "domain_known"],
        unlocks=["certipy", "impacket-secretsdump"],
        category="ad", phase="vuln_scan",
        description="BloodHound AD collector for attack path mapping"),
    "impacket-secretsdump": ToolIO("impacket-secretsdump",
        inputs=["target", "domain", "user", "password"],
        outputs=["password_hashes", "kerberos_tickets", "domain_sids"],
        prerequisites=["port_445", "credentials_known"],
        unlocks=[],
        category="ad", phase="exploit",
        description="DCSync — dump domain password hashes from DC"),
    "impacket-GetNPUsers": ToolIO("impacket-GetNPUsers",
        inputs=["target", "domain"],
        outputs=["asrep_hashes", "no_preauth_users"],
        prerequisites=["port_389"],
        unlocks=["john", "hashcat"],
        category="ad", phase="vuln_scan",
        description="AS-REP roasting — find Kerberos pre-auth disabled accounts"),
    "impacket-GetUserSPNs": ToolIO("impacket-GetUserSPNs",
        inputs=["target", "domain", "user", "password"],
        outputs=["tgs_hashes", "service_accounts"],
        prerequisites=["port_389", "credentials_known"],
        unlocks=["john", "hashcat"],
        category="ad", phase="vuln_scan",
        description="Kerberoasting — crack service account TGS tickets"),
    "certipy": ToolIO("certipy",
        inputs=["target", "domain", "user", "password"],
        outputs=["ad_cs_vulns", "certificates", "esc_misconfigs"],
        prerequisites=["port_389", "credentials_known"],
        unlocks=["impacket-secretsdump"],
        category="ad", phase="vuln_scan",
        description="AD CS certificate service abuse (ESC1-8)"),
    "hydra": ToolIO("hydra",
        inputs=["target", "service", "user", "password_list"],
        outputs=["valid_credentials"],
        prerequisites=["port_22", "port_21", "port_3389", "port_445"],
        unlocks=[],
        category="auth", phase="vuln_scan",
        description="Online password brute forcing (SSH, FTP, RDP, SMB)"),
    "kerbrute": ToolIO("kerbrute",
        inputs=["target", "domain", "user_list"],
        outputs=["valid_users"],
        prerequisites=["port_88"],
        unlocks=["impacket-GetNPUsers"],
        category="ad", phase="vuln_scan",
        description="Kerberos user enumeration and password spraying"),

    # ---- EXPLOIT ----
    "msfconsole": ToolIO("msfconsole",
        inputs=["exploit", "target", "port", "payload", "lhost"],
        outputs=["exploit_session", "shell"],
        prerequisites=["vuln_confirmed"],
        unlocks=[],
        category="exploit_framework", phase="exploit",
        description="Metasploit Framework exploit execution"),
    "msfvenom": ToolIO("msfvenom",
        inputs=["payload", "lhost", "lport"],
        outputs=["payload_binary"],
        prerequisites=["lhost_configured"],
        unlocks=[],
        category="exploit_framework", phase="exploit",
        description="Payload generation for reverse shells and stagers"),

    # ---- PRIVESC ----
    "linpeas": ToolIO("linpeas",
        inputs=["target"],
        outputs=["privesc_vectors", "suid_binaries", "cron_jobs", "vuln_services"],
        prerequisites=["os_linux"],
        unlocks=[],
        category="privesc", phase="exploit",
        description="Linux privilege escalation enumeration (PEASS-ng)"),
    "winpeas": ToolIO("winpeas",
        inputs=["target"],
        outputs=["privesc_vectors", "service_perms", "registry_issues"],
        prerequisites=["os_windows"],
        unlocks=[],
        category="privesc", phase="exploit",
        description="Windows privilege escalation enumeration (PEASS-ng)"),

    # ---- CLOUD ----
    "cloud_metadata": ToolIO("cloud_metadata",
        inputs=["target"],
        outputs=["cloud_provider", "instance_metadata", "iam_credentials"],
        prerequisites=["port_80"],
        unlocks=["s3scanner"],
        category="cloud", phase="vuln_scan",
        description="Check for cloud metadata service SSRF"),

    # ---- MOBILE ----
    "apktool": ToolIO("apktool",
        inputs=["apk_path"],
        outputs=["smali_code", "manifest", "resources"],
        prerequisites=["file_apk"],
        unlocks=["jadx"],
        category="mobile", phase="web_enum",
        description="APK decompilation to smali code"),
    "jadx": ToolIO("jadx",
        inputs=["apk_path"],
        outputs=["java_source"],
        prerequisites=["file_apk"],
        unlocks=[],
        category="mobile", phase="web_enum",
        description="APK/DEX decompilation to readable Java source"),
}


# ============================================================
# Methodology templates — REFERENCE KNOWLEDGE ONLY
# These are NEVER executed directly. They serve as documentation
# that the LLM may consider during genuine reasoning.
# ============================================================

METHODOLOGIES_REFERENCE = {
    "web": [
        {
            "phase": "recon",
            "description": "Discover ports, web tech stack, and surface area",
            "tools": ["nmap", "masscan"],
            "branch": [
                {"if": "port_80|443|8080|8443", "tools": ["whatweb", "gobuster", "ffuf"]},
                {"if": "domain_known", "tools": ["subfinder", "amass"]},
            ],
            "unlock": ["nuclei", "searchsploit"],
        },
        {
            "phase": "web_enum",
            "description": "Crawl, fuzz, and discover endpoints/params",
            "tools": ["gospider", "katana", "arjun"],
            "branch": [
                {"if": "tech_wordpress", "tools": ["wpscan"]},
                {"if": "tech_joomla", "tools": ["joomscan"]},
                {"if": "tech_drupal", "tools": ["droopescan"]},
            ],
            "unlock": ["nuclei", "sqlmap", "dalfox"],
        },
        {
            "phase": "vuln_scan",
            "description": "Scan for vulnerabilities matching the tech stack",
            "tools": ["nuclei", "searchsploit", "testssl"],
            "branch": [
                {"if": "endpoint_sql", "tools": ["sqlmap"]},
                {"if": "endpoint_xss", "tools": ["dalfox"]},
                {"if": "port_443", "tools": ["testssl"]},
            ],
            "unlock": ["msfconsole"],
        },
        {
            "phase": "exploit",
            "description": "Confirm and exploit confirmed vulnerabilities",
            "tools": ["sqlmap", "msfconsole", "searchsploit"],
            "unlock": [],
        },
    ],
    "ad": [
        {
            "phase": "recon",
            "description": "Discover AD ports, domain info, and surface",
            "tools": ["nmap"],
            "branch": [
                {"if": "port_389", "tools": ["ldapsearch"]},
                {"if": "port_445", "tools": ["enum4linux", "smbmap"]},
                {"if": "port_88", "tools": ["kerbrute"]},
            ],
            "unlock": ["bloodhound-python", "impacket-GetNPUsers"],
        },
        {
            "phase": "vuln_scan",
            "description": "Enumerate AD objects and find privilege escalation paths",
            "tools": ["bloodhound-python", "certipy", "impacket-GetNPUsers"],
            "branch": [
                {"if": "credentials_known", "tools": ["impacket-GetUserSPNs", "impacket-secretsdump"]},
            ],
            "unlock": ["impacket-secretsdump"],
        },
        {
            "phase": "exploit",
            "description": "Exploit AD weaknesses for domain dominance",
            "tools": ["impacket-secretsdump", "impacket-smbexec", "impacket-wmiexec"],
            "unlock": [],
        },
    ],
    "ctf": [
        {
            "phase": "recon",
            "description": "Quick port scan and web surface discovery",
            "tools": ["nmap", "whatweb"],
            "branch": [
                {"if": "port_80|443", "tools": ["gobuster", "ffuf"]},
                {"if": "port_22", "tools": ["ssh_scan"]},
            ],
            "unlock": ["searchsploit", "nuclei"],
        },
        {
            "phase": "vuln_scan",
            "description": "Check for known CVEs and misconfigs",
            "tools": ["nuclei", "searchsploit"],
            "branch": [
                {"if": "cve_found", "tools": ["searchsploit"]},
            ],
            "unlock": ["msfconsole"],
        },
        {
            "phase": "exploit",
            "description": "Run exploit and capture flag",
            "tools": ["sqlmap", "msfconsole", "curl"],
            "unlock": [],
        },
    ],
    "cloud": [
        {
            "phase": "recon",
            "description": "Check metadata endpoints and bucket discovery",
            "tools": ["cloud_metadata", "curl"],
            "unlock": [],
        },
    ],
    "network": [
        {
            "phase": "recon",
            "description": "Full port scan and service fingerprint",
            "tools": ["nmap", "masscan"],
            "branch": [
                {"if": "port_80|443", "tools": ["whatweb", "gobuster"]},
                {"if": "port_445|139", "tools": ["enum4linux", "smbmap"]},
                {"if": "port_22", "tools": ["ssh_scan"]},
                {"if": "port_389", "tools": ["ldapsearch"]},
                {"if": "port_3389", "tools": ["rdp_scan"]},
                {"if": "port_21", "tools": ["ftp_enum"]},
            ],
            "unlock": ["searchsploit", "nuclei"],
        },
        {
            "phase": "vuln_scan",
            "description": "Check services for known vulnerabilities",
            "tools": ["searchsploit", "nuclei"],
            "branch": [
                {"if": "port_443", "tools": ["testssl"]},
                {"if": "credentials_known", "tools": ["hydra"]},
            ],
            "unlock": [],
        },
    ],
}


DEFAULT_PHASE_ORDER = ["recon", "web_enum", "vuln_scan", "exploit"]


def detect_target_type(model_ports: List[Dict],
                       model_tech: Dict[str, str],
                       subdomains: List[str],
                       user_target_type: str = "auto") -> str:
    """Auto-detect the methodology to use based on target model state."""
    if user_target_type in ("ctf", "lab"):
        return "ctf"
    if user_target_type == "authorized":
        ad_ports = {389, 445, 88, 464, 636, 3268, 3269}
        ports = {p.get("port") for p in model_ports if isinstance(p, dict)}
        if ports & ad_ports:
            return "ad"
        cloud_tech = any(k in (model_tech or {}) for k in ("aws", "azure", "gcp", "cloud"))
        if cloud_tech:
            return "cloud"
        if any(p in (80, 443, 8080, 8443) for p in ports):
            return "web"
        if ports:
            return "network"
        return "web"
    return "web"


def generate_structured_hypotheses(
    model: Any,
    target: str,
    service_attacks: Dict[Any, List[Any]],
) -> List[Any]:
    """DEPRECATED: This function generated hypotheses from hardcoded templates.
    
    Hypothesis generation is now done by the LLM through genuine reasoning.
    The LLM examines the World Model state and generates testable hypotheses
    based on discovered services, technologies, and information gaps.
    
    SERVICE_ATTACKS and known_tests remain as REFERENCE KNOWLEDGE that can be
    mentioned in context to the LLM, but they NEVER directly generate hypotheses.
    
    Returns empty list - hypotheses come from LLM reasoning instead.
    """
    # All hypothesis generation now flows through the LLM decision pipeline:
    # 1. World Model contains discovered ports, services, technologies
    # 2. Planner builds context showing what's known and potential attack surfaces
    # 3. LLM reasons about which hypotheses are worth testing
    # 4. LLM generates specific, testable hypotheses with commands
    #
    # The SERVICE_ATTACKS dict (constants.py:236-309) and known_tests templates
    # are retained as reference knowledge that the Planner can mention in context,
    # but they NEVER directly generate executable hypotheses or commands.
    #
    # No template-based hypotheses here - that would defeat autonomy.
    return []

@dataclass
class ChainStep:
    tool: str
    rationale: str
    phase: str
    prerequisites: List[str] = field(default_factory=list)
    depends_on: List[str] = field(default_factory=list)
    completed: bool = False
    result_summary: str = ""


@dataclass
class ToolChain:
    methodology: str
    target_type: str
    steps: List[ChainStep] = field(default_factory=list)
    current_index: int = 0

    @property
    def current_step(self) -> Optional[ChainStep]:
        if 0 <= self.current_index < len(self.steps):
            return self.steps[self.current_index]
        return None

    @property
    def pending_steps(self) -> List[ChainStep]:
        return [s for s in self.steps if not s.completed]

    @property
    def completed_steps(self) -> List[ChainStep]:
        return [s for s in self.steps if s.completed]


class Planner:
    """Generates and tracks attack chains based on tool I/O models and target state."""

    def __init__(self):
        self.chain: Optional[ToolChain] = None
        self._used_tools: Set[str] = set()
        self._completed_checks: Set[str] = set()
        self._findings: Dict[str, str] = {}  # key -> value from tool outputs
        
        # Evidence caching to avoid duplicate tool runs
        self._evidence_cache: Dict[str, Tuple[Any, float]] = {}  # tool_name -> (result, timestamp)
        self._cache_ttl: float = 300.0  # 5 minutes default TTL
        
        # Hypothesis-weighted tool selection for smarter planning
        self._hypothesis_weights: Dict[str, float] = {}  # hypothesis -> weight (0.0-1.0)
        self._tool_hypothesis_map: Dict[str, List[str]] = {}  # tool -> [hypotheses it supports]
        
        # Timestamp tracking to prevent duplicate actions
        self._tool_timestamps: Dict[str, float] = {}  # tool_name -> last_run_timestamp
        self._min_tool_interval: float = 60.0  # Minimum seconds between tool runs

    def build_chain(self, model, target_type: str = "auto") -> ToolChain:
        """DEPRECATED: This method built deterministic attack chains from METHODOLOGIES.
        
        Attack chain generation is now done by the LLM through genuine reasoning.
        The LLM examines the World Model state and decides which tools to use
        based on discovered services, technologies, and information gaps.
        
        METHODOLOGIES_REFERENCE remains as REFERENCE KNOWLEDGE that can be
        mentioned in context to the LLM, but it NEVER directly generates
        executable tool chains or command sequences.
        
        Returns an empty ToolChain - actual planning flows through LLM reasoning.
        """
        # All attack planning now flows through the LLM decision pipeline:
        # 1. World Model contains discovered ports, services, technologies
        # 2. Planner builds context showing what's known and potential attack surfaces
        # 3. LLM reasons about which tools and approaches are most appropriate
        # 4. LLM generates specific commands with rationale
        #
        # The METHODOLOGIES_REFERENCE dict is retained as reference knowledge
        # that the Planner can mention in context, but it NEVER directly
        # generates executable tool chains or command sequences.
        #
        # No template-based chain building here - that would defeat autonomy.
        
        # Return empty chain - real planning happens via LLM reasoning
        self.chain = ToolChain(
            methodology="llm_reasoned",
            target_type=target_type,
            steps=[],
        )
        return self.chain

    def mark_step_complete(self, tool: str, summary: str = ""):
        self._used_tools.add(tool)
        if self.chain:
            for step in self.chain.steps:
                if step.tool == tool and not step.completed:
                    step.completed = True
                    step.result_summary = summary
                    break
            while (self.chain.current_index < len(self.chain.steps) and
                   self.chain.steps[self.chain.current_index].completed):
                self.chain.current_index += 1

    def suggest_next_tools(self, model, limit: int = 5) -> List[ChainStep]:
        """DEPRECATED: This method suggested tools from the deterministic chain.
        
        Tool suggestion is now done by the LLM through genuine reasoning.
        The LLM examines the World Model state and decides which tools to use
        based on discovered services, technologies, and information gaps.
        
        Returns empty list - tool selection flows through LLM reasoning instead.
        """
        # All tool selection now flows through the LLM decision pipeline:
        # 1. World Model contains discovered ports, services, technologies
        # 2. Planner builds context showing what's known and potential attack surfaces
        # 3. LLM reasons about which tools are most appropriate
        # 4. LLM generates specific commands with rationale
        #
        # No template-based tool suggestions here - that would defeat autonomy.
        
        # Return empty list - real tool selection happens via LLM reasoning
        return []

    def _prerequisites_met(self, step: ChainStep, model) -> bool:
        if not step.prerequisites:
            return True
        ports = {p.get("port") for p in getattr(model, "ports", []) if isinstance(p, dict)}
        tech = set((getattr(model, "tech_stack", {}) or {}).keys())
        subdomains = bool(getattr(model, "subdomains", []))
        credentials = bool(getattr(model, "credentials", []))
        endpoints = bool(getattr(model, "endpoints", []))
        os_info = (getattr(model, "os_info", "") or "").lower()

        for prereq in step.prerequisites:
            if prereq.startswith("port_"):
                port_nums = prereq.replace("port_", "").split("|")
                if port_nums:
                    port_ints = {int(p) for p in port_nums if p.isdigit()}
                    if port_ints and not (ports & port_ints):
                        return False
            elif prereq.startswith("tech_"):
                tech_name = prereq.replace("tech_", "").lower()
                if tech_name not in {t.lower() for t in tech}:
                    return False
            elif prereq == "domain_known":
                if not subdomains and not getattr(model, "hostname", ""):
                    return False
            elif prereq == "credentials_known":
                if not credentials:
                    return False
            elif prereq == "vuln_confirmed":
                if not any(f.severity in ("high", "critical") for f in getattr(model, "findings", [])):
                     return False
            elif prereq == "os_linux":
                if "linux" not in os_info:
                    return False
            elif prereq == "os_windows":
                if "windows" not in os_info:
                    return False
            elif prereq.startswith("endpoint_"):
                if not endpoints:
                    return False
                ep_type = prereq.replace("endpoint_", "").lower()
                ep_list = [e.lower() for e in (getattr(model, "endpoints", []) or [])]
                if not any(ep_type in e for e in ep_list):
                    return False

        return True

    def chain_context(self, model) -> str:
        """DEPRECATED: This method displayed the deterministic attack chain.
        
        Attack chain context is now generated dynamically by examining the
        World Model state and LLM reasoning history.
        
        Returns a message indicating that planning is LLM-driven.
        """
        # All attack planning now flows through the LLM decision pipeline.
        # The chain_context method previously displayed predefined steps from
        # METHODOLOGIES, but this would bias the LLM toward scripted behavior.
        #
        # Instead, we return a simple message indicating that the LLM will
        # reason about next steps based on the current World Model state.
        
        parts = ["PLANNING MODE: LLM-REASONED"]
        parts.append("  The Planner examines the World Model state and")
        parts.append("  generates hypotheses through genuine AI reasoning.")
        parts.append("  No predefined attack chains are used.")
        parts.append(f"  Target type: {getattr(model, 'target_type', 'auto')}")
        parts.append(f"  Known ports: {len(getattr(model, 'ports', []) or [])}")
        parts.append(f"  Known technologies: {len(getattr(model, 'tech_stack', {}) or {})}")
        parts.append(f"  Known findings: {len(getattr(model, 'findings', []) or [])}")
        parts.append("")
        parts.append("  Next action will be determined by LLM reasoning")
        parts.append("  based on information gaps and hypothesis testing.")
        
        return "\n".join(parts)
