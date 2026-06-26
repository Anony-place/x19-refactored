import ast
import difflib
import hashlib
import json
import os
import re
import sys
import time
import traceback
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, List, Tuple, Any, TYPE_CHECKING

if TYPE_CHECKING:
    from agent import X19
from dataclasses import dataclass, field

from constants import C, ICO
from config import CONFIG, CONFIG_DIR, load_config
from reporting import Finding
from logging_utils import log, swallow as _swallow

TOOLS_SOURCE_PATH = Path(__file__).resolve().parent / "tools.py"


@dataclass
class CodePatch:
    id: str = ""
    description: str = ""
    target_file: str = "agent.py"
    target_function: str = ""
    patch_type: str = "modify"
    original_code: str = ""
    new_code: str = ""
    validation_hint: str = ""
    expected_impact: str = ""
    risk: str = "low"


@dataclass
class PatchResult:
    success: bool = False
    patch_id: str = ""
    error: str = ""
    diff: str = ""
    backup_path: str = ""
    needs_restart: bool = False
    validated: bool = False


@dataclass
class ImprovementSuggestion:
    area: str = ""
    metric: str = ""
    current_value: float = 0.0
    observation: str = ""
    suggested_patch: Optional[CodePatch] = None


@dataclass
class Bottleneck:
    area: str = ""
    metric: str = ""
    current_value: float = 0.0
    target_value: float = 0.0
    observation: str = ""
    severity: str = "medium"


class SelfAwareness:
    """Read-only introspection into X19's own source code."""

    def __init__(self):
        self.source_path = Path(__file__).resolve()

    def read_source(self) -> str:
        return self.source_path.read_text(encoding="utf-8")

    def get_ast(self) -> ast.Module:
        return ast.parse(self.read_source())

    def get_function_source(self, func_name: str) -> Optional[str]:
        tree = self.get_ast()
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == func_name:
                lines = self.source_path.read_text(encoding="utf-8").splitlines()
                return "\n".join(lines[node.lineno - 1: node.end_lineno])
        return None

    def get_method_source(self, class_name: str, method_name: str) -> Optional[str]:
        tree = self.get_ast()
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name == class_name:
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name == method_name:
                        lines = self.source_path.read_text(encoding="utf-8").splitlines()
                        return "\n".join(lines[item.lineno - 1: item.end_lineno])
        return None

    def get_class_signatures(self) -> Dict[str, list]:
        tree = self.get_ast()
        result = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                methods = []
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        methods.append(item.name)
                result[node.name] = methods
        return result

    def get_tool_registry(self) -> Dict[str, str]:
        return dict(TOOLS)

    def get_config_fields(self) -> List[str]:
        fields = []
        for node in ast.walk(self.get_ast()):
            if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                if node.target.id:
                    fields.append(node.target.id)
        return fields

    def count_lines(self) -> int:
        return len(self.read_source().splitlines())

    def count_classes(self) -> int:
        return len([n for n in ast.walk(self.get_ast()) if isinstance(n, ast.ClassDef)])

    def count_functions(self) -> int:
        return len([n for n in ast.walk(self.get_ast()) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))])

    def summary(self) -> str:
        return (f"Source: {self.count_lines()} lines, {self.count_classes()} classes, "
                f"{self.count_functions()} functions")

    def inspect_command_template(self, tool_name: str) -> Optional[Dict[str, str]]:
        """Read the TOOLS dict in tools.py and return the template entry for a tool."""
        tools_path = TOOLS_SOURCE_PATH
        if not tools_path.exists():
            return None
        src = tools_path.read_text(encoding="utf-8")
        m = re.search(
            rf'"{re.escape(tool_name)}":\s*"(.*?)"',
            src, re.DOTALL
        )
        if not m:
            return None
        raw = m.group(1)
        parts = raw.rsplit(" | ", 2)
        return {
            "tool_name": tool_name,
            "template": parts[0].strip() if parts else raw,
            "description": parts[1].strip() if len(parts) > 1 else "",
            "timeout": parts[2].strip() if len(parts) > 2 else "120",
        }

    def diagnose_tool_failure(self, tool_name: str, error_type: str,
                              stderr_snippet: str) -> Optional[CodePatch]:
        """Given a tool name and the error, inspect its template and propose a fix.
        Returns None if no fix is identifiable."""
        entry = self.inspect_command_template(tool_name)
        if not entry:
            return None
        template = entry["template"]
        patch = None
        # Case 1: timeout -> suggest longer timeout or simpler flags
        if error_type == "timeout":
            old_timeout = entry.get("timeout", "120")
            new_timeout = str(min(int(old_timeout) * 2, 600))
            old_line = f'"{tool_name}": "{template} | {entry["description"]} | {old_timeout}"'
            new_line = f'"{tool_name}": "{template} | {entry["description"]} | {new_timeout}"'
            patch = CodePatch(
                id=f"fix_timeout_{tool_name}_{datetime.now().strftime('%H%M%S')}",
                description=f"Increase {tool_name} timeout from {old_timeout}s to {new_timeout}s",
                target_file="tools.py",
                target_function=tool_name,
                patch_type="modify",
                original_code=old_line,
                new_code=new_line,
                validation_hint=f"Run {tool_name} with new timeout to verify",
                expected_impact=f"Tool will have {new_timeout}s instead of {old_timeout}s",
                risk="low",
            )
        # Case 2: non-zero exit with "invalid option" or "unrecognized argument"
        elif error_type == "bad_flag" or ("invalid option" in stderr_snippet.lower()
                                          or "unrecognized" in stderr_snippet.lower()):
            return None  # Cannot auto-fix flags without LLM analysis
        # Case 3: empty output -> tool may not be suited for target
        elif error_type == "empty_output":
            return None  # Cannot auto-fix empty output without understanding target
        return patch


class PerformanceAnalyzer:
    """Records and analyzes session performance to find improvement opportunities."""

    def __init__(self):
        self._session_log: List[Dict] = []
        self._analysis_cache: Optional[List[ImprovementSuggestion]] = None

    def record_session(self, model: "TargetModel", session_data: dict, agent_state: dict):
        findings = model.findings
        cmd_hist = session_data.get("commands", [])
        cat_counter: Dict[str, int] = {}
        cat_fail: Dict[str, int] = {}
        cat_success: Dict[str, int] = {}

        for c in cmd_hist:
            cat = c.get("cmd", "")[:10]
            result = c.get("result", "")
            if "error" in result.lower() or "failed" in result.lower() or "timeout" in result.lower():
                cat_fail[cat] = cat_fail.get(cat, 0) + 1
            else:
                cat_success[cat] = cat_success.get(cat, 0) + 1
            cat_counter[cat] = cat_counter.get(cat, 0) + 1

        high_findings = sum(
            1 for f in findings
            if (f.severity if isinstance(f, Finding) else f.get("severity", "info"))
            in ("critical", "high", "medium")
        )
        total_iters = len(cmd_hist)
        stuck_count = len(agent_state.get("stuck_warnings", []))
        auth_blocks = agent_state.get("auth_attack_blocked", 0)
        recon_total = agent_state.get("recon_total", 0)
        forced_exploit = agent_state.get("forced_exploit", False)

        record = {
            "timestamp": datetime.now().isoformat(),
            "target": session_data.get("target", ""),
            "target_type": session_data.get("type", ""),
            "total_iterations": total_iters,
            "total_commands": len(cmd_hist),
            "findings_total": len(findings),
            "findings_high": high_findings,
            "stuck_count": stuck_count,
            "auth_blocks": auth_blocks,
            "recon_total": recon_total,
            "forced_exploit": forced_exploit,
            "categories": dict(cat_counter),
            "cat_success": dict(cat_success),
            "cat_fail": dict(cat_fail),
        }
        self._session_log.append(record)
        self._analysis_cache = None

    def analyze(self, min_sessions: int = 2) -> List[ImprovementSuggestion]:
        if len(self._session_log) < min_sessions:
            return []
        if self._analysis_cache is not None:
            return self._analysis_cache

        suggestions: List[ImprovementSuggestion] = []
        recent = self._session_log[-10:]

        # Analyze stuck frequency
        recent_len = len(recent)
        if recent_len > 0:
            avg_stuck = sum(s["stuck_count"] for s in recent) / recent_len
            if avg_stuck > 3:
                suggestions.append(ImprovementSuggestion(
                    area="loop_detection",
                    metric="stuck_count_per_session",
                    current_value=avg_stuck,
                    observation=f"Average {avg_stuck:.1f} stuck events per session — loop detection may be too sensitive",
                ))

        # Analyze recon efficiency
        for s in recent:
            if s["recon_total"] > 0 and s["findings_high"] == 0:
                suggestions.append(ImprovementSuggestion(
                    area="tool_selection",
                    metric="recon_to_finding_ratio",
                    current_value=float(s["recon_total"]),
                    observation=f"{s['recon_total']} recon commands with 0 high findings — recon strategy may need adjustment",
                ))
                break

        # Analyze forced exploit triggers
        forced_count = sum(1 for s in recent if s.get("forced_exploit", False))
        recent_len = len(recent)
        if recent_len > 0 and forced_count > recent_len * 0.5:
            suggestions.append(ImprovementSuggestion(
                area="goal_planning",
                metric="forced_exploit_rate",
                current_value=float(forced_count) / float(recent_len),
                observation="Forced exploit triggered in >50% of sessions — goal tree may need better early exploit bias",
            ))

        # Analyze category failure rates
        all_cat_fail: Dict[str, int] = {}
        all_cat_total: Dict[str, int] = {}
        for s in recent:
            for cat, cnt in s.get("cat_fail", {}).items():
                all_cat_fail[cat] = all_cat_fail.get(cat, 0) + cnt
            for cat, cnt in s.get("categories", {}).items():
                all_cat_total[cat] = all_cat_total.get(cat, 0) + cnt
        for cat in all_cat_total:
            total = all_cat_total.get(cat, 0)
            if total >= 5:
                fail_rate = all_cat_fail.get(cat, 0) / total
                if fail_rate > 0.7:
                    suggestions.append(ImprovementSuggestion(
                        area="tool_selection",
                        metric=f"fail_rate_{cat}",
                        current_value=fail_rate,
                        observation=f"Category '{cat}' has {fail_rate:.0%} failure rate ({total} attempts)",
                    ))

        self._analysis_cache = suggestions
        return suggestions

    def get_bottlenecks(self, n: int = 5) -> List[Bottleneck]:
        suggestions = self.analyze()
        bottlenecks = []
        for s in suggestions[:n]:
            sev = "high" if s.current_value > 0.8 else "medium"
            bottlenecks.append(Bottleneck(
                area=s.area, metric=s.metric, current_value=s.current_value,
                target_value=max(0.0, s.current_value * 0.5),
                observation=s.observation, severity=sev,
            ))
        return bottlenecks

    def effectiveness_report(self) -> str:
        if not self._session_log:
            return "No session data yet."
        recent = self._session_log[-5:]
        recent_len = len(recent)
        if recent_len > 0:
            avg_findings = sum(s["findings_high"] for s in recent) / recent_len
            avg_iters = sum(s["total_iterations"] for s in recent) / recent_len
            avg_stuck = sum(s["stuck_count"] for s in recent) / recent_len
            return (f"Performance: {avg_findings:.1f} findings/session, "
                    f"{avg_iters:.0f} iters/session, {avg_stuck:.1f} stuck events/session")
        else:
            return "No recent session data."

    def summary(self) -> str:
        return f"PerformanceAnalyzer: {len(self._session_log)} sessions recorded"


class CodeSurgeon:
    """Applies validated code patches to x19/agent.py with safety checks and rollback."""

    IMMUTABLE_PATTERNS = [
        "BLOCKED = [",
        "AUTH_ATTACK_PATTERNS = [",
        "EXPLOIT_SUCCESS_PATTERNS = [",
        "COMMON_TOOLS = {",
        "IMMUTABLE_PATTERNS",
        "def safety_check",
        "def _validate_command",
    ]

    def __init__(self):
        self.source_path = Path(__file__).resolve().parent / "agent.py"
        self.backup_dir = CONFIG_DIR / "backups"
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.patch_log: List[PatchResult] = []
        self._load_integrity_config()

    def _load_integrity_config(self):
        integrity_file = CONFIG_DIR / "integrity.json"
        self.immutable_patterns = list(self.IMMUTABLE_PATTERNS)
        self.max_patches_per_session = 3
        self.require_human_approval = ["high"]
        if integrity_file.exists():
            try:
                data = json.loads(integrity_file.read_text())
                self.immutable_patterns = data.get("immutable_patterns", self.immutable_patterns)
                self.max_patches_per_session = data.get("max_patches_per_session", 3)
                self.require_human_approval = data.get("require_human_approval_for", ["high"])
            except Exception as e:
                _swallow(e)
        # Integrity config itself is loaded but the agent cannot write to it
        self._integrity_file = integrity_file

    def validate_patch_strict(self, patch: CodePatch) -> Tuple[bool, str]:
        """Strict pre-apply validation: ast.parse() + isolation test.
        Returns (ok, reason). Never applies the patch - just validates."""
        # Step A: ast.parse() syntax check
        try:
            ast.parse(patch.new_code)
        except SyntaxError as e:
            return False, f"SYNTAX ERROR at line {e.lineno}: {e.msg}"

        # Step B: Check the new code compiles as a Python module fragment
        try:
            compile(patch.new_code, "<patch>", "exec")
        except SyntaxError as e:
            return False, f"COMPILE ERROR: {e.msg}"

        # Step C: Isolated execution test - run the new code in a sandbox
        if patch.patch_type == "modify" and patch.original_code:
            try:
                import textwrap
                sandbox_globals = {"__builtins__": __builtins__}
                sandbox_locals = {}
                exec(textwrap.dedent(patch.new_code), sandbox_globals, sandbox_locals)
            except Exception as e:
                return False, f"ISOLATION TEST FAILED: {type(e).__name__}: {e}"

        # Step D: Check the patch doesn't break critical sentinels
        lowered = patch.new_code.lower()
        banned_inline = [
            "os.system(", "subprocess.run(", "subprocess.popen(",
            "__import__('os')", "__import__('subprocess')",
        ]
        for b in banned_inline:
            if b in lowered:
                return False, f"BANNED API in new code: {b}"

        return True, "All validation checks passed"

    def try_mid_session_patch(self, patch: CodePatch, tools_source: str) -> PatchResult:
        """Attempt a patch with full validation + backup + transparent logging.
        Returns PatchResult with diff and validation info.
        Never silently applies - always prints diagnostics."""
        result = PatchResult(patch_id=patch.id)

        print(f"{C.M}[SELF-IMPROVE] Diagnosed issue: {patch.description}{C.N}")
        print(f"{C.B}  Target: {patch.target_file} / {patch.target_function}{C.N}")
        print(f"{C.B}  Type: {patch.patch_type} | Risk: {patch.risk}{C.N}")

        # 1) Safety check
        verdict = self.safety_check(patch)
        if verdict != "APPROVED":
            print(f"{C.R}  SAFETY BLOCKED: {verdict}{C.N}")
            result.error = verdict
            return result

        # 2) Strict validation
        valid, reason = self.validate_patch_strict(patch)
        if not valid:
            print(f"{C.R}  VALIDATION FAILED: {reason}{C.N}")
            result.error = f"Validation failed: {reason}"
            return result
        print(f"{C.G}  Validation passed: {reason}{C.N}")

        # 3) Show diff before applying
        old_source = tools_source
        new_source = old_source.replace(patch.original_code, patch.new_code, 1)
        diff_lines = list(difflib.unified_diff(
            old_source.splitlines(keepends=True),
            new_source.splitlines(keepends=True),
            fromfile=f"{patch.target_file} (before)",
            tofile=f"{patch.target_file} (after)",
            lineterm="",
        ))
        diff_text = "".join(diff_lines)
        print(f"{C.C}  Proposed diff:{C.N}")
        for line in diff_lines:
            if line.startswith("+"):
                print(f"{C.G}{line}{C.N}", end="")
            elif line.startswith("-"):
                print(f"{C.R}{line}{C.N}", end="")
            else:
                print(f"{C.D}{line}{C.N}", end="")

        # 4) Write backup to disk
        backup_path = self.backup_dir / f"{patch.target_file}_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.py"
        backup_path.write_text(old_source, encoding="utf-8")
        result.backup_path = str(backup_path)
        print(f"{C.B}  Backup saved: {backup_path}{C.N}")

        # 5) Apply
        try:
            TOOLS_SOURCE_PATH.write_text(new_source, encoding="utf-8")
            result.success = True
            result.diff = diff_text
            result.validated = True
            print(f"{C.G}  Patch applied successfully{C.N}")
        except Exception as e:
            result.error = f"Write failed: {e}"
            print(f"{C.R}  Apply failed: {e}{C.N}")

        self.patch_log.append(result)
        return result

    def safety_check(self, patch: CodePatch) -> str:
        """Returns 'APPROVED', 'BLOCKED', or 'NEEDS_REVIEW'."""
        # Block patches targeting immutable patterns
        for pattern in self.immutable_patterns:
            if patch.original_code and pattern in patch.original_code:
                return f"BLOCKED: patch targets immutable pattern '{pattern}'"
            if patch.new_code and pattern in patch.new_code:
                return f"BLOCKED: patch contains immutable pattern '{pattern}'"

        # Block patches trying to modify safety functions
        safety_funcs = {"safety_check", "_validate_command", "_load_integrity_config"}
        if patch.target_function in safety_funcs:
            return f"BLOCKED: cannot modify safety function '{patch.target_function}'"

        # Block destructive operations in new code
        destructive = ["os.system(", "subprocess.run(", "subprocess.Popen(", "__import__('os')"]
        for d in destructive:
            if d in patch.new_code and "safety" not in patch.target_function:
                return f"BLOCKED: new code contains '{d}' without safety context"

        # Risk-based approval
        if patch.risk in self.require_human_approval:
            return "NEEDS_REVIEW"

        return "APPROVED"

    def _post_patch_verify(self, patch: CodePatch, new_source: str) -> Tuple[bool, str]:
        """
        Network-free, stdlib-only post-patch verification.
        Must not execute the patched program (no runtime imports).
        Returns (ok, reason).
        """
        try:
            import ast
            # 1) Ensure the patched file is syntactically valid Python
            ast.parse(new_source)

            lowered = new_source.lower()

            # 2) Best-effort banned snippet scan (defensive)
            banned = [
                "self.code_surgeon.apply_patch",
                "requests.",
                "urllib.",
                "subprocess.run(",
                "subprocess.popen(",
                "os.system(",
                # recursive bypass markers / verifier tampering
                "_post_patch_verify",
                "post_patch_verify",
            ]
            for b in banned:
                if b in lowered:
                    return False, f"post_patch_verify: banned snippet detected: {b}"

            # 3) Ensure critical sentinels still exist (guards truncation/corruption)
            required = [
                "class CodeSurgeon",
                "TOOLS = {",
                "TOOL_FAMILIES",
                "class X19",
            ]
            for req in required:
                if req not in new_source:
                    return False, f"post_patch_verify: missing required sentinel: {req}"

            return True, "post_patch_verify: ok"
        except Exception as e:
            return False, f"post_patch_verify error: {type(e).__name__}: {e}"

    def apply_patch(self, patch: CodePatch) -> PatchResult:
        result = PatchResult(patch_id=patch.id)

        # Safety check
        verdict = self.safety_check(patch)
        if verdict != "APPROVED":
            result.error = verdict
            return result

        source = self.source_path.read_text(encoding="utf-8")

        if patch.patch_type == "modify":
            if not patch.original_code:
                result.error = "original_code is required for modify patches"
                return result
            if source.count(patch.original_code) != 1:
                if source.count(patch.original_code) == 0:
                    result.error = "original_code not found in source"
                else:
                    result.error = f"Found {source.count(patch.original_code)} matches — provide more context"
                return result
            new_source = source.replace(patch.original_code, patch.new_code, 1)

        elif patch.patch_type == "add_function":
            marker = f"# ===================== {patch.target_function.upper()} ====================="
            if marker in source:
                new_source = source.replace(marker, f"{marker}\n\n{patch.new_code}", 1)
            else:
                new_source = source + f"\n\n{patch.new_code}\n"

        elif patch.patch_type == "add_tool":
            tool_marker = '"proxy_test":'
            idx = source.find(tool_marker)
            if idx < 0:
                result.error = "Could not find tool registry insertion point"
                return result
            insert_at = source.index("\n", idx) + 1
            new_source = source[:insert_at] + patch.new_code + source[insert_at:]

        elif patch.patch_type == "add_config":
            config_marker = "class Config:"
            idx = source.find(config_marker)
            if idx < 0:
                result.error = "Could not find Config class"
                return result
            insert_at = source.index("\n", source.index(")", idx)) + 1
            new_source = source[:insert_at] + f"    {patch.new_code}\n" + source[insert_at:]

        else:
            result.error = f"Unknown patch_type: {patch.patch_type}"
            return result

        # Syntax validation
        try:
            compile(new_source, self.source_path.name, "exec")
        except SyntaxError as e:
            result.error = f"Syntax error: {e}"
            result.diff = self._generate_diff(source, new_source)
            return result

        # Backup
        backup_path = self.backup_dir / f"agent_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.py"
        backup_path.write_text(source, encoding="utf-8")
        result.backup_path = str(backup_path)

        # Generate diff
        result.diff = self._generate_diff(source, new_source)
        result.validated = True

        # Write
        self.source_path.write_text(new_source, encoding="utf-8")
        result.success = True
        result.needs_restart = patch.patch_type in ("modify", "add_function")

        self.patch_log.append(result)
        return result

    def rollback(self, patch_id: str = "") -> bool:
        if not self.patch_log:
            return False
        if patch_id:
            entries = [p for p in self.patch_log if p.patch_id == patch_id and p.backup_path]
            if not entries:
                return False
            entry = entries[-1]
        else:
            entry = self.patch_log[-1]
            if not entry.backup_path:
                return False
        try:
            backup = Path(entry.backup_path)
            if backup.exists():
                self.source_path.write_text(backup.read_text(encoding="utf-8"), encoding="utf-8")
                return True
        except Exception as e:
            _swallow(e)
        return False

    def _generate_diff(self, old: str, new: str) -> str:
        return "\n".join(difflib.unified_diff(
            old.splitlines(), new.splitlines(),
            fromfile="agent.py (before)", tofile="agent.py (after)",
            lineterm="",
        ))

    def list_applied_patches(self) -> List[Dict]:
        return [
            {
                "id": p.patch_id,
                "success": p.success,
                "error": p.error,
                "validated": p.validated,
                "diff_preview": p.diff[:200] if p.diff else "",
                "needs_restart": p.needs_restart,
            }
            for p in self.patch_log
        ]

    def summary(self) -> str:
        applied = sum(1 for p in self.patch_log if p.success)
        failed = sum(1 for p in self.patch_log if not p.success)
        return f"CodeSurgeon: {applied} applied, {failed} failed, {len(self.patch_log)} total"


# ---- Mid-session self-improvement orchestration ----

def mid_session_self_improve(agent: Any, tool_name: str, error_type: str,
                              stderr_snippet: str) -> Optional[PatchResult]:
    """Trigger mid-session self-improvement when a tool fails 2x consecutively.
    Orchestrates: SelfAwareness diagnosis -> patch generation -> validation -> apply.
    Returns PatchResult if a patch was attempted, None otherwise.
    Automatically backs up tools.py before any modification."""
    from constants import C

    print(f"{C.BOLD}{C.M}[SELF-IMPROVE TRIGGERED] Tool '{tool_name}' failed with '{error_type}'{C.N}")
    print(f"{C.B}  Diagnosing template for '{tool_name}' in tools.py...{C.N}")

    # Step 1: Diagnose the tool template
    awareness = SelfAwareness()
    patch = awareness.diagnose_tool_failure(tool_name, error_type, stderr_snippet)
    if not patch:
        print(f"{C.Y}  No fix identified for {tool_name} ({error_type}){C.N}")
        return None

    print(f"{C.G}  Suggested fix: {patch.description}{C.N}")
    print(f"{C.B}  Original: {patch.original_code[:100]}...{C.N}")
    print(f"{C.B}  Proposed: {patch.new_code[:100]}...{C.N}")

    # Step 2: Validate and apply
    surgeon = CodeSurgeon()
    tools_src = TOOLS_SOURCE_PATH.read_text(encoding="utf-8") if TOOLS_SOURCE_PATH.exists() else ""

    result = surgeon.try_mid_session_patch(patch, tools_src)

    print(f"{C.BOLD}  --- Self-Improvement Decision Log ---{C.N}")
    print(f"  What was wrong: {patch.description}")
    print(f"  What changed: tool={tool_name}, error={error_type}")
    print(f"  Why: consecutive failure detected during live session")
    print(f"  Validated: {'YES' if result.validated else 'NO'}")
    print(f"  Applied: {'YES' if result.success else 'NO'}")
    if result.error:
        print(f"  Reason not applied: {result.error}")
    if result.diff:
        print(f"  Diff preview: {result.diff[:200]}")
    print(f"{C.BOLD}  ------------------------------------{C.N}")

    return result
