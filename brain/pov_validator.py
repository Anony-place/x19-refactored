"""Chain PoV validator — XBOW/Atlantis/NodeZero pattern.

XBOW proves exploit chains by re-running combined exploits as a binary oracle;
Atlantis's PoV oracle re-runs proof after patch; NodeZero has 1-click Verify.
X19's 4-gate+review+OOB kills single-step false positives but reports chains
without combined re-execution.

This module is the P1 gap closer: when the exploit_chain engine confirms a
chain, dispatch a combined probe via the team workers and treat its result as
a binary verdict. It never creates findings — findings still go through the
normal 4-gate + adversarial review. It only answers: does the chain still
prove?
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
import time


@dataclass
class PoVRequest:
    chain_id: str
    chain_summary: str
    steps: List[str]            # shell commands that together prove the chain
    expected_evidence: str
    falsification: str = ""
    hypothesis_id: str = ""
    timeout: int = 90


@dataclass
class PoVResult:
    chain_id: str
    proved: bool
    evidence: str = ""
    duration: float = 0.0
    raw_reports: List[Any] = field(default_factory=list)
    reason: str = ""


class PoVValidator:
    """Binary oracle for exploit chains. Uses the agent's policy-gated team
    workers as the execution plane — no raw subprocess."""

    def __init__(self, team: Any = None, gateway: Any = None):
        self.team = team
        self.gateway = gateway
        self.history: List[PoVResult] = []
        self.pending: Dict[str, PoVRequest] = {}

    def request(self, req: PoVRequest) -> str:
        """Enqueue a chain PoV re-run. Returns status line."""
        if not req.steps:
            return "PoV rejected: no steps"
        req.chain_id = str(req.chain_id or f"chain-{len(self.pending)+1}")[:32]
        self.pending[req.chain_id] = req
        # dispatch via team if available, otherwise via gateway directly
        if self.team is not None and hasattr(self.team, "assign"):
            for idx, cmd in enumerate(req.steps):
                lane = "pov"
                # ensure lane exists
                if lane not in getattr(self.team, "lanes", {}):
                    try:
                        self.team.spawn(lane, "chain PoV re-run: combined exploit verification", 1)
                    except Exception:
                        pass
                try:
                    self.team.assign(lane, cmd, why=f"pov:{req.chain_id} step {idx+1}/{len(req.steps)}")
                except Exception as e:
                    return f"PoV dispatch failed: {e}"
            return f"PoV queued {req.chain_id}: {len(req.steps)} steps"
        if self.gateway is not None:
            return f"PoV queued {req.chain_id} (gateway direct — team unavailable)"
        return "PoV queued (no execution plane — will evaluate on harvest)"

    def _check_evidence(self, req: PoVRequest, excerpt: str) -> bool:
        """Deterministic evidence check — word-boundary aware, no LLM."""
        exp = (req.expected_evidence or "").strip()
        if not exp:
            # without expected evidence, any successful execution (rc 0) with output counts
            return bool(excerpt.strip())
        # word-boundary for short tokens, substring for longer
        text = excerpt
        if len(exp) <= 4:
            import re
            pattern = r"\b" + re.escape(exp) + r"\b"
            return bool(re.search(pattern, text))
        return exp in text

    def harvest_and_verdict(self) -> List[PoVResult]:
        """Collect worker reports since last call and produce verdicts.
        Called each iteration by agent.py after team.harvest_all()."""
        if not self.pending:
            return []
        # gather reports
        reports: List[Any] = []
        if self.team is not None and hasattr(self.team, "harvest_all"):
            # team already harvested into _pending; we peek at pending_reports
            try:
                reports = list(self.team.pending_reports())
            except Exception:
                reports = []
            # also try direct lane harvest if team hasn't been harvested yet
            if not reports and hasattr(self.team, "lanes"):
                for mgr in getattr(self.team, "lanes", {}).values():
                    try:
                        reports.extend(mgr.harvest())
                    except Exception:
                        pass
        # also consider gateway one-off results if any

        out: List[PoVResult] = []
        for chain_id, req in list(self.pending.items()):
            # find reports for this chain
            chain_reports = [r for r in reports if getattr(r, "lane", "") == "pov" and req.chain_id in str(getattr(r, "why", ""))]
            if not chain_reports and reports:
                # fallback: if we used gateway direct, any pov lane report counts
                chain_reports = [r for r in reports if getattr(r, "lane", "") == "pov"]
            if not chain_reports:
                continue
            # combine excerpts
            combined = "\n".join(str(getattr(r, "excerpt", "")) for r in chain_reports)
            proved = any(self._check_evidence(req, str(getattr(r, "excerpt", ""))) for r in chain_reports)
            # if expected_evidence is multi-line, check combined
            if not proved and req.expected_evidence:
                proved = self._check_evidence(req, combined)
            res = PoVResult(
                chain_id=chain_id,
                proved=proved,
                evidence=combined[:2000],
                duration=sum(float(getattr(r, "duration", 0) or 0) for r in chain_reports),
                raw_reports=chain_reports,
                reason="binary oracle: proved" if proved else "binary oracle: not proved — chain remains advisory",
            )
            out.append(res)
            self.history.append(res)
            del self.pending[chain_id]
        return out

    def verify_after_fix(self, req: PoVRequest) -> PoVResult:
        """1-click Verify pattern (NodeZero): re-run PoV after operator says fixed.
        Returns a result where proved==False means fix succeeded."""
        t0 = time.monotonic()
        # dispatch and wait briefly for team to run — for CLI this is harvested next tick
        self.request(req)
        # try immediate harvest after short wait if team workers are synchronous
        # otherwise caller should poll harvest_and_verdict next iteration
        time.sleep(0.5)
        results = self.harvest_and_verdict()
        for r in results:
            if r.chain_id == req.chain_id:
                return r
        # if not yet, return pending
        return PoVResult(chain_id=req.chain_id, proved=False, reason="verify dispatched — poll harvest_and_verdict next tick", duration=time.monotonic()-t0)

    def context_block(self) -> str:
        if not self.history and not self.pending:
            return ""
        lines = ["POV ORACLE (chain binary verification):"]
        if self.pending:
            lines.append(f"  pending: {', '.join(self.pending.keys())}")
        for r in self.history[-4:]:
            flag = "PROVED" if r.proved else "NOT PROVED"
            lines.append(f"  {r.chain_id}: {flag} — {r.reason[:80]}")
        return "\n".join(lines)
