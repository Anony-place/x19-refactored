"""
x19intel — shared "intelligence" helpers for X19.

Goal:
- Provide structured reasoning / memory / prioritization utilities that can be
  imported by the monolith (x19.py) without creating circular imports.
- Keep this module dependency-light so it can run in minimal environments.

Integration:
- x19.py can call into `X19Intel.build_system_prompt(...)` or
  `X19Intel.route_tool_requests(...)` / `X19Intel.rank_tasks(...)`.

No offensive exploitation logic is implemented here; this is purely planning,
ranking, and prompt/telemetry scaffolding.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
import time
import re


@dataclass
class Finding:
    severity: str
    title: str
    detail: str = ""
    evidence: str = ""


@dataclass
class IntelConfig:
    # Generic knobs
    max_tasks: int = 12
    prefer_low_risk_first: bool = True
    now: float = field(default_factory=time.time)


class X19Intel:
    """
    Lightweight intelligence layer.

    - Builds an augmented system prompt including:
      * what the agent should optimize for
      * a short "safety/bounds" note (non-blocking)
      * optional dynamic constraints (mode/target/type)
    - Ranks candidate tasks/commands based on heuristics.
    """

    def __init__(self, cfg: Optional[IntelConfig] = None):
        self.cfg = cfg or IntelConfig()

    def build_system_prompt(
        self,
        base_system: str,
        *,
        intent: Optional[str] = None,
        target: Optional[str] = None,
        target_type: Optional[str] = None,
        findings: Optional[List[Finding]] = None,
        captured_traffic: Optional[str] = None,
        constraints: Optional[Dict[str, Any]] = None,
    ) -> str:
        constraints = constraints or {}
        lines: List[str] = []

        lines.append(base_system.strip() if base_system else "")

        meta: List[str] = []
        if intent:
            meta.append(f"intent={intent}")
        if target:
            meta.append(f"target={target}")
        if target_type:
            meta.append(f"target_type={target_type}")
        if meta:
            lines.append("\n[Context]")
            lines.append(" - " + "\n - ".join(meta))

        if constraints.get("mode"):
            lines.append("\n[Mode]")
            lines.append(str(constraints.get("mode")))

        if findings:
            lines.append("\n[Prior findings (summary)]")
            for f in findings[:8]:
                lines.append(f" - [{f.severity}] {f.title}".strip())

        if captured_traffic:
            # keep it compact; caller should already trim
            lines.append("\n[Captured traffic (excerpt)]")
            lines.append(captured_traffic.strip()[:2500])

        lines.append(
            "\n[Instructions]\n"
            "- Plan in small steps.\n"
            "- Prefer methods that reduce uncertainty (detect/enum) before destructive steps.\n"
            "- Keep commands concise and parameterized.\n"
            "- When output is ambiguous, ask for clarification by producing a minimal follow-up query."
        )

        return "\n".join([p for p in lines if p])

    def rank_tasks(
        self,
        candidates: List[Dict[str, Any]],
        *,
        target_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Rank candidate tasks/commands.

        Each candidate may include:
          - "command" (str) or "name"
          - "category" (str)
          - "priority" (float) or "score" (float)
          - "severity" (str) or "risk" (str)
        """
        def sev_weight(sev: str) -> float:
            s = (sev or "").lower()
            if s in ("critical", "high"):
                return 3.0
            if s in ("medium", "med"):
                return 1.5
            return 0.5

        def detect_bias(cat: str) -> float:
            c = (cat or "").lower()
            if any(k in c for k in ("detect", "enum", "probe", "identify", "scan")):
                return 0.6
            if any(k in c for k in ("exploit", "attack")):
                return 3.0
            return 1.0

        prefer_low = self.cfg.prefer_low_risk_first

        ranked: List[Tuple[float, Dict[str, Any]]] = []
        for c in candidates:
            base = float(c.get("priority", c.get("score", 1.0)) or 1.0)
            cat = c.get("category", "")
            sev = c.get("severity", c.get("risk", "low"))
            risk = sev_weight(str(sev))
            bias = detect_bias(str(cat))
            # Heuristic: lower is better unless prioritize destructiveness explicitly
            score = base
            if prefer_low:
                score = score - (risk * 0.25) + (1.0 / bias)
            # slight preference for detection tasks
            score = score + (0.1 if "detect" in str(cat).lower() else 0.0)
            ranked.append((score, c))

        ranked.sort(key=lambda x: x[0], reverse=True)
        return [c for _, c in ranked[: self.cfg.max_tasks]]

    def extract_commands(self, model_output: str) -> List[str]:
        """
        Extract single-line shell commands that begin with 'EXEC:'.
        This mirrors existing behavior in x19_agent/cli.py.
        """
        if not model_output:
            return []
        cmds: List[str] = []
        for raw_line in model_output.splitlines():
            line = raw_line.strip()
            if not line.upper().startswith("EXEC:"):
                continue
            cmd = line.split(":", 1)[1].strip()
            if not cmd:
                continue
            cmds.append(cmd)
        return cmds

    def tool_call_parser_hint(self) -> str:
        return (
            "If you need tool execution, emit lines like: EXEC: <command>\n"
            "Keep each command one line."
        )
