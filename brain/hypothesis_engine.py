"""Multi-Hypothesis Reasoning Engine for X19 Cognitive Brain Migration.

Every meaningful action must correspond to a hypothesis.

Hypothesis states:
  NEW → TESTING → CONFIRMED / REJECTED / STALE / DEAD

Confidence is updated using actual observations, never trusted from LLM.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
from datetime import datetime, timezone
import hashlib


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


# Hypothesis states (P0 spec)
HYP_NEW = "NEW"
HYP_TESTING = "TESTING"
HYP_CONFIRMED = "CONFIRMED"
HYP_REJECTED = "REJECTED"
HYP_STALE = "STALE"
HYP_DEAD = "DEAD"

ALL_HYP_STATES = frozenset({HYP_NEW, HYP_TESTING, HYP_CONFIRMED, HYP_REJECTED, HYP_STALE, HYP_DEAD})

# Valid transitions
HYP_TRANSITIONS: Dict[str, Set[str]] = {
    HYP_NEW: {HYP_TESTING, HYP_REJECTED, HYP_DEAD},
    HYP_TESTING: {HYP_CONFIRMED, HYP_REJECTED, HYP_STALE, HYP_DEAD},
    HYP_CONFIRMED: {HYP_STALE, HYP_DEAD},
    HYP_REJECTED: {HYP_DEAD, HYP_NEW},
    HYP_STALE: {HYP_NEW, HYP_TESTING, HYP_DEAD},
    HYP_DEAD: set(),
}


def _clamp01(value: Any) -> float:
    """Coerce arbitrary model-supplied numbers into a safe [0, 1] float."""
    try:
        f = float(value)
    except (TypeError, ValueError):
        return 0.5
    if f != f:  # NaN
        return 0.5
    return max(0.0, min(1.0, f))


@dataclass
class CompetingHypothesis:
    """A testable hypothesis with multi-dimensional scoring."""
    id: str
    statement: str
    # Required fields (P0 spec)
    assumptions: List[str] = field(default_factory=list)
    supporting_evidence_ids: List[str] = field(default_factory=list)
    contradicting_evidence_ids: List[str] = field(default_factory=list)
    confidence: float = 0.5
    expected_information_gain: float = 0.5
    expected_impact: float = 0.5
    execution_cost: float = 0.5
    risk: float = 0.3
    expected_evidence: List[str] = field(default_factory=list)
    falsification_condition: str = ""
    attempt_count: int = 0
    last_result: str = ""
    state: str = HYP_NEW

    # Extended fields
    title: str = ""
    description: str = ""
    command: str = ""
    command_alternatives: List[str] = field(default_factory=list)
    depends_on: List[str] = field(default_factory=list)
    contradicts: List[str] = field(default_factory=list)
    supports: List[str] = field(default_factory=list)
    generation_reason: str = ""
    tested_count: int = 0
    last_tested: Optional[str] = None
    confirmation_evidence: List[str] = field(default_factory=list)
    rejection_reason: Optional[str] = None
    created_at: str = field(default_factory=utc_now)
    source: str = "engine"
    tags: List[str] = field(default_factory=list)

    @property
    def priority_score(self) -> float:
        weights = {
            'confidence': 0.25,
            'information_gain': 0.35,
            'cost': 0.20,
            'risk': 0.20,
        }
        score = (
            weights['confidence'] * self.confidence +
            weights['information_gain'] * self.expected_information_gain +
            weights['cost'] * (1.0 - self.execution_cost) +
            weights['risk'] * (1.0 - self.risk)
        )
        if self.attempt_count > 0:
            score *= (0.8 ** self.attempt_count)
        if self.state == HYP_REJECTED:
            score *= 0.1
        if self.state == HYP_DEAD:
            score *= 0.01
        return max(0.0, min(1.0, score))

    @property
    def is_active(self) -> bool:
        return self.state in (HYP_NEW, HYP_TESTING)

    # -- legacy aliases ----------------------------------------------------
    # Early consumers (and the benchmark suite) used the ``estimated_*`` names;
    # keep them as live aliases so both spellings stay valid.
    @property
    def estimated_information_gain(self) -> float:
        return self.expected_information_gain

    @property
    def estimated_execution_cost(self) -> float:
        return self.execution_cost

    @property
    def estimated_risk(self) -> float:
        return self.risk

    @estimated_information_gain.setter
    def estimated_information_gain(self, value: float) -> None:
        self.expected_information_gain = max(0.0, min(1.0, float(value)))

    @estimated_execution_cost.setter
    def estimated_execution_cost(self, value: float) -> None:
        self.execution_cost = max(0.0, min(1.0, float(value)))

    @estimated_risk.setter
    def estimated_risk(self, value: float) -> None:
        self.risk = max(0.0, min(1.0, float(value)))

    def transition(self, new_state: str, reason: str = "", result: str = "") -> bool:
        allowed = HYP_TRANSITIONS.get(self.state, set())
        if new_state not in allowed:
            return False
        self.state = new_state
        if reason:
            self.rejection_reason = reason
        if result:
            self.last_result = result
        self.attempt_count += 1
        self.last_tested = utc_now()
        return True

    def update_confidence_from_observation(self, observation_supported: bool, evidence_quality: float = 0.5) -> None:
        """Update confidence based on actual observations, not LLM claims."""
        delta = evidence_quality * 0.3
        if observation_supported:
            self.confidence = min(1.0, self.confidence + delta)
        else:
            self.confidence = max(0.0, self.confidence - delta)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'statement': self.statement,
            'title': self.title,
            'description': self.description,
            'assumptions': self.assumptions,
            'expected_evidence': self.expected_evidence,
            'falsification_condition': self.falsification_condition,
            'command': self.command,
            'confidence': round(self.confidence, 3),
            'expected_information_gain': round(self.expected_information_gain, 3),
            'expected_impact': round(self.expected_impact, 3),
            'execution_cost': round(self.execution_cost, 3),
            'risk': round(self.risk, 3),
            'priority_score': round(self.priority_score, 3),
            'state': self.state,
            'attempt_count': self.attempt_count,
            'tested_count': self.tested_count,
            'last_result': self.last_result,
            'supporting_evidence_ids': self.supporting_evidence_ids,
            'contradicting_evidence_ids': self.contradicting_evidence_ids,
            'tags': self.tags,
        }

    def summary(self) -> str:
        status_icon = {
            HYP_NEW: "💡", HYP_TESTING: "🔬", HYP_CONFIRMED: "✅",
            HYP_REJECTED: "❌", HYP_STALE: "⏳", HYP_DEAD: "💀",
        }.get(self.state, "❓")
        return f"{status_icon} [{self.state}] {self.title or self.statement[:60]} (priority={self.priority_score:.2f})"


class HypothesisComparisonResult:
    def __init__(self, winner: CompetingHypothesis, loser: CompetingHypothesis,
                 reason: str, margin: float):
        self.winner = winner
        self.loser = loser
        self.reason = reason
        self.margin = margin

    def __str__(self) -> str:
        return f"{self.winner.title} > {self.loser.title} by {self.margin:.2f} ({self.reason})"


class MultiHypothesisEngine:
    """Manages generation, comparison, and selection of competing hypotheses.
    """

    def __init__(self):
        self._hypotheses: Dict[str, CompetingHypothesis] = {}
        self._rejected_hashes: Set[str] = set()
        self._comparison_history: List[HypothesisComparisonResult] = []
        self._generation_context: Dict[str, Any] = {}

    def generate_hypothesis_id(self, statement: str, command: str = "", assumptions: Optional[List[str]] = None) -> str:
        content = f"{statement}:{command}:{','.join(sorted(assumptions or []))}"
        return hashlib.md5(content.encode()).hexdigest()[:12]

    def _hash_hypothesis(self, statement: str, command: str, assumptions: List[str]) -> str:
        content = f"{statement}:{command}:{','.join(sorted(assumptions))}"
        return hashlib.sha256(content.encode()).hexdigest()

    def _identity_hashes(self, hyp: "CompetingHypothesis") -> List[str]:
        """Every hash a hypothesis must be findable/duplicated by.

        Callers may identify a hypothesis by its full statement, its title or
        its description (older API surface did exactly that), so all three
        spellings hash to the same identity.
        """
        identities = {hyp.statement, hyp.title or "", hyp.description or ""}
        identities.discard("")
        return [self._hash_hypothesis(s, hyp.command, hyp.assumptions) for s in sorted(identities)]

    def is_duplicate_or_rejected(self, statement: str = "", command: str = "", assumptions: Optional[List[str]] = None, *, title: str = "", description: str = "") -> bool:
        identities = {str(statement or "").strip(), str(title or "").strip(), str(description or "").strip()}
        identities.discard("")
        for s in identities:
            h = self._hash_hypothesis(s, command or "", assumptions or [])
            if h in self._rejected_hashes:
                return True
        return False

    def add_hypothesis(
        self,
        statement: str = "",
        title: str = "",
        description: str = "",
        command: str = "",
        assumptions: Optional[List[str]] = None,
        expected_evidence: Optional[List[str]] = None,
        falsification_condition: str = "",
        confidence: float = 0.5,
        information_gain: float = 0.5,
        impact: float = 0.5,
        execution_cost: float = 0.5,
        risk: float = 0.3,
        depends_on: Optional[List[str]] = None,
        contradicts: Optional[List[str]] = None,
        supports: Optional[List[str]] = None,
        generation_reason: str = "",
        tags: Optional[List[str]] = None,
        command_alternatives: Optional[List[str]] = None,
    ) -> Optional[CompetingHypothesis]:
        assumptions = assumptions or []
        # ``statement`` is the canonical identity, but callers may only have a
        # title/description/command — derive one instead of raising, so keyword
        # calls like add_hypothesis(title=…, command=…) keep working.
        statement = str(statement or "").strip()
        if not statement:
            statement = str(title or "").strip() or str(description or "").strip() \
                or str(command or "").strip()
        if not statement:
            return None
        if self.is_duplicate_or_rejected(statement, command, assumptions, title=title, description=description):
            return None
        hyp_id = self.generate_hypothesis_id(statement, command, assumptions)
        if hyp_id in self._hypotheses:
            return self._hypotheses[hyp_id]
        hyp = CompetingHypothesis(
            id=hyp_id,
            statement=statement,
            title=title or statement[:80],
            description=description,
            assumptions=assumptions,
            expected_evidence=expected_evidence or [],
            falsification_condition=falsification_condition,
            command=command,
            command_alternatives=command_alternatives or [],
            confidence=max(0.0, min(1.0, confidence)),
            expected_information_gain=max(0.0, min(1.0, information_gain)),
            expected_impact=max(0.0, min(1.0, impact)),
            execution_cost=max(0.0, min(1.0, execution_cost)),
            risk=max(0.0, min(1.0, risk)),
            depends_on=depends_on or [],
            contradicts=contradicts or [],
            supports=supports or [],
            generation_reason=generation_reason,
            tags=tags or [],
        )
        self._hypotheses[hyp_id] = hyp
        return hyp

    def get_competing_hypotheses(self, limit: int = 5, active_only: bool = True) -> List[CompetingHypothesis]:
        candidates = list(self._hypotheses.values())
        if active_only:
            candidates = [h for h in candidates if h.is_active]
        candidates.sort(key=lambda h: h.priority_score, reverse=True)
        return candidates[:limit]

    def select_best_hypothesis(self) -> Optional[CompetingHypothesis]:
        top = self.get_competing_hypotheses(limit=1, active_only=True)
        if top:
            top[0].transition(HYP_TESTING)
            return top[0]
        return None

    def compare_hypotheses(self, hyp1_id: str, hyp2_id: str) -> Optional[HypothesisComparisonResult]:
        hyp1 = self._hypotheses.get(hyp1_id)
        hyp2 = self._hypotheses.get(hyp2_id)
        if not hyp1 or not hyp2:
            return None
        diff = hyp1.priority_score - hyp2.priority_score
        if abs(diff) < 0.05:
            reason = "marginal difference - both worth considering"
        elif hyp1.confidence > hyp2.confidence:
            reason = "higher confidence"
        elif hyp1.expected_information_gain > hyp2.expected_information_gain:
            reason = "higher information gain"
        elif hyp1.execution_cost < hyp2.execution_cost:
            reason = "lower execution cost"
        elif hyp1.risk < hyp2.risk:
            reason = "lower risk"
        else:
            reason = "combined scoring factors"
        if diff >= 0:
            result = HypothesisComparisonResult(hyp1, hyp2, reason, abs(diff))
        else:
            result = HypothesisComparisonResult(hyp2, hyp1, reason, abs(diff))
        self._comparison_history.append(result)
        return result

    def reject_hypothesis(self, hyp_id: str, reason: str, evidence_ids: Optional[List[str]] = None):
        hyp = self._hypotheses.get(hyp_id)
        if not hyp:
            return
        hyp.transition(HYP_REJECTED, reason=reason)
        if evidence_ids:
            hyp.contradicting_evidence_ids.extend(evidence_ids)
        # Every identity spelling of this hypothesis becomes rejected, so a
        # later add_hypothesis(title=…) cannot resurrect it either.
        self._rejected_hashes.update(self._identity_hashes(hyp))
        for contra_id in hyp.contradicts:
            if contra_id in self._hypotheses:
                self._hypotheses[contra_id].confidence = min(1.0, self._hypotheses[contra_id].confidence + 0.15)

    def confirm_hypothesis(self, hyp_id: str, evidence_ids: List[str], evidence_quality: float = 0.8):
        hyp = self._hypotheses.get(hyp_id)
        if not hyp:
            return
        hyp.confirmation_evidence = evidence_ids
        hyp.supporting_evidence_ids.extend(evidence_ids)
        hyp.update_confidence_from_observation(True, evidence_quality)
        hyp.transition(HYP_CONFIRMED, result=f"confirmed with {len(evidence_ids)} evidence items")
        for support_id in hyp.supports:
            if support_id in self._hypotheses:
                self._hypotheses[support_id].confidence = min(1.0, self._hypotheses[support_id].confidence + 0.2)
        for contra_id in hyp.contradicts:
            if contra_id in self._hypotheses:
                self.reject_hypothesis(contra_id, f"Contradicted by confirmed hypothesis: {hyp.title or hyp.statement}")

    def mark_testing(self, hyp_id: str):
        hyp = self._hypotheses.get(hyp_id)
        if hyp:
            hyp.transition(HYP_TESTING)

    def mark_stale(self, hyp_id: str, reason: str = "no new evidence"):
        hyp = self._hypotheses.get(hyp_id)
        if hyp:
            hyp.transition(HYP_STALE, reason=reason)

    def mark_dead(self, hyp_id: str, reason: str = "exhausted"):
        hyp = self._hypotheses.get(hyp_id)
        if hyp:
            hyp.transition(HYP_DEAD, reason=reason)

    def supersede_hypothesis(self, old_hyp_id: str, new_hyp_id: str):
        old = self._hypotheses.get(old_hyp_id)
        new = self._hypotheses.get(new_hyp_id)
        if old and new:
            old.transition(HYP_STALE, reason=f"Superseded by {new.title or new.statement}")
            new.depends_on.append(old_hyp_id)

    def get_hypothesis_chain(self, hyp_id: str) -> List[CompetingHypothesis]:
        chain = []
        visited = set()
        def traverse(cid):
            if cid in visited or cid not in self._hypotheses:
                return
            visited.add(cid)
            hyp = self._hypotheses[cid]
            chain.append(hyp)
            for dep_id in hyp.depends_on:
                traverse(dep_id)
        traverse(hyp_id)
        return list(reversed(chain))

    def get_confirmed_hypotheses(self) -> List[CompetingHypothesis]:
        return [h for h in self._hypotheses.values() if h.state == HYP_CONFIRMED]

    def get_rejected_hypotheses(self) -> List[CompetingHypothesis]:
        return [h for h in self._hypotheses.values() if h.state == HYP_REJECTED]

    def find_hypothesis(self, text: Any) -> Optional[CompetingHypothesis]:
        """Resolve a hypothesis by id, exact title/statement, or substring.

        The model only ever sees short ids and titles in its context, so the
        resolver must be forgiving: any of id → title → statement → substring
        match is accepted.
        """
        t = str(text or "").strip()
        if not t:
            return None
        if t in self._hypotheses:
            return self._hypotheses[t]
        tl = t.lower()
        for h in self._hypotheses.values():
            if h.title.lower() == tl or h.statement.lower() == tl:
                return h
        for h in self._hypotheses.values():
            if tl in h.statement.lower() or tl in (h.title or "").lower():
                return h
        return None

    def apply_actions(self, actions: Any) -> List[str]:
        """Apply hypothesis actions proposed by the model in a decision.

        This is the model-owned research ledger (Naptime-style): the agent —
        not hardcoded heuristics — decides which hypotheses exist, which are
        being tested, and which are confirmed or rejected.

        Each action is a dict:
          {"action": "add|test|confirm|reject|abandon",
           "statement": "...", "command": "...", "expected_evidence": [...],
           "falsification": "...", "confidence": 0.0-1.0, "impact": 0.0-1.0,
           "evidence": [...], "reason": "..."}

        Returns human-readable one-liners describing what happened (for the
        transcript); malformed entries are skipped, never raised.
        """
        notes: List[str] = []
        if isinstance(actions, dict):
            actions = [actions]
        if not isinstance(actions, list):
            return notes
        for a in actions:
            if not isinstance(a, dict):
                continue
            act = str(a.get("action") or a.get("op") or "add").strip().lower()
            stmt = str(a.get("statement") or a.get("title") or "").strip()
            if act == "add":
                if not stmt:
                    continue
                # Skip if a live/confirmed hypothesis already says this — the
                # ledger must stay a short list of distinct research threads.
                existing = self.find_hypothesis(stmt)
                new_cmd = str(a.get("command") or "").strip()
                if existing is not None:
                    if existing.state in (HYP_NEW, HYP_TESTING, HYP_CONFIRMED):
                        notes.append(f"duplicate ignored: {stmt[:70]}")
                        continue
                    # Rejected/dead threads reopen only with a genuinely
                    # different probe — otherwise the model would re-run the
                    # exact experiment that already falsified the idea.
                    if not new_cmd or new_cmd == existing.command:
                        notes.append(f"blocked (was REJECTED, same probe): {stmt[:60]}")
                        continue
                    notes.append(f"reopening after rejection with new probe: {stmt[:60]}")
                if self.is_duplicate_or_rejected(stmt, new_cmd):
                    notes.append(f"duplicate ignored: {stmt[:70]}")
                    continue
                ev = a.get("expected_evidence")
                ev_list = [str(e) for e in ev if str(e).strip()] if isinstance(ev, list) else []
                hyp = self.add_hypothesis(
                    statement=stmt,
                    command=str(a.get("command") or ""),
                    expected_evidence=ev_list,
                    falsification_condition=str(a.get("falsification") or ""),
                    confidence=_clamp01(a.get("confidence", 0.5)),
                    impact=_clamp01(a.get("impact", 0.5)),
                    generation_reason=str(a.get("reason") or "model decision"),
                )
                if hyp:
                    notes.append(f"new {hyp.id}: {stmt[:70]}")
                continue
            if act not in ("test", "confirm", "reject", "abandon", "stale", "drop"):
                notes.append(f"unknown action '{act}'")
                continue
            hyp = self.find_hypothesis(a.get("id") or stmt)
            if not hyp:
                notes.append(f"unknown hypothesis: {str(a.get('id') or stmt)[:60]}")
                continue
            reason = str(a.get("reason") or "")
            if act == "test":
                self.mark_testing(hyp.id)
                notes.append(f"testing {hyp.id}: {hyp.title[:60]}")
            elif act == "confirm":
                ev = a.get("evidence")
                ev_ids = [str(e) for e in ev if str(e).strip()][:4] if isinstance(ev, list) else []
                # State machine requires NEW -> TESTING -> CONFIRMED; a fresh
                # hypothesis confirmed on first evidence passes through testing.
                if hyp.state == HYP_NEW:
                    self.mark_testing(hyp.id)
                self.confirm_hypothesis(hyp.id, ev_ids)
                if hyp.state == HYP_CONFIRMED:
                    notes.append(f"CONFIRMED {hyp.id}: {hyp.title[:60]}")
                else:
                    notes.append(f"confirm rejected by state machine for {hyp.id} ({hyp.state})")
            elif act == "reject":
                self.reject_hypothesis(hyp.id, reason or "model rejected")
                notes.append(f"REJECTED {hyp.id}: {hyp.title[:60]}")
            elif act in ("abandon", "stale", "drop"):
                self.mark_stale(hyp.id, reason or "abandoned")
                notes.append(f"abandoned {hyp.id}: {hyp.title[:60]}")
            else:
                notes.append(f"unknown action '{act}'")
        return notes

    def render_context(self, limit: int = 6) -> str:
        """Render the research ledger for the decision prompt.

        Shows open threads (with their next probe and expected evidence) plus
        recent confirmed/rejected items so the model keeps a coherent line of
        reasoning across iterations instead of re-deriving state each turn.
        """
        active = self.get_competing_hypotheses(limit=max(1, limit), active_only=True)
        if not active and not self.get_confirmed_hypotheses():
            return ""
        lines = ["RESEARCH LEDGER (your hypotheses — test or close them):"]
        for h in active:
            lines.append(f"  [{h.state}] #{h.id} {h.title}")
            if h.command:
                lines.append(f"      next probe: {h.command[:120]}")
            if h.expected_evidence:
                lines.append(f"      expect: {str(h.expected_evidence[0])[:100]}")
        confirmed = self.get_confirmed_hypotheses()
        if confirmed:
            lines.append("CONFIRMED (file the finding with real evidence, or move on):")
            for h in confirmed[-3:]:
                lines.append(f"  + {h.title[:90]}")
        rejected = self.get_rejected_hypotheses()
        if rejected:
            names = ", ".join((h.title or h.id)[:40] for h in rejected[-4:])
            lines.append(f"REJECTED (do not revisit): {names}")
        return "\n".join(lines)

    def get_learning_summary(self) -> Dict[str, Any]:
        confirmed = self.get_confirmed_hypotheses()
        rejected = self.get_rejected_hypotheses()
        return {
            'total_hypotheses': len(self._hypotheses),
            'confirmed_count': len(confirmed),
            'rejected_count': len(rejected),
            'active_count': len([h for h in self._hypotheses.values() if h.is_active]),
            'confirmed_patterns': [
                {'title': h.title, 'statement': h.statement, 'assumptions': h.assumptions, 'evidence': h.confirmation_evidence}
                for h in confirmed
            ],
            'rejected_patterns': [
                {'title': h.title, 'reason': h.rejection_reason, 'failed_assumptions': h.assumptions}
                for h in rejected
            ],
            'comparison_insights': [str(c) for c in self._comparison_history[-10:]],
        }

    def generate_from_scenario(self, scenario_data: Dict[str, Any]) -> List[CompetingHypothesis]:
        """Generate competing hypotheses from a target scenario (template-based fallback)."""
        hypotheses = []
        ports = scenario_data.get('ports', [])
        tech_stack = scenario_data.get('tech_stack', {})
        endpoints = scenario_data.get('endpoints', [])

        web_ports = [p for p in ports if p.get('port') in {80, 443, 8080, 8443}]
        if web_ports:
            h1 = self.add_hypothesis(
                statement="Web directory brute-forcing will discover hidden/sensitive paths",
                title="Directory Enumeration Discovery",
                description="Brute-force common web paths to surface hidden admin, backup and config endpoints",
                command="gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt",
                assumptions=["Web server is responding", "Standard wordlist covers common paths"],
                expected_evidence=["HTTP 200/301 responses for discovered paths", "Interesting directories like /admin, /backup"],
                falsification_condition="No new paths discovered after full wordlist scan",
                confidence=0.7, information_gain=0.8, execution_cost=0.4, risk=0.2,
                generation_reason="Web port detected", tags=["web", "enumeration"],
                command_alternatives=[
                    "ffuf -u http://target/FUZZ -w /usr/share/wordlists/dirb/common.txt",
                    "dirsearch -u http://target -e php,html,js"
                ]
            )
            if h1:
                hypotheses.append(h1)
            for tech_name in tech_stack.keys():
                if tech_name.lower() in ['wordpress', 'joomla', 'drupal']:
                    h2 = self.add_hypothesis(
                        statement=f"The {tech_name} installation has vulnerable plugins/themes",
                        title=f"{tech_name} Plugin Vulnerability",
                        description=f"Enumerate {tech_name} plugins/themes and match versions against known public CVEs",
                        command=("wpscan --url http://target --enumerate vp,vt,u" if tech_name.lower() == "wordpress" else f"nuclei -t /nuclei-templates/{tech_name.lower()}/"),
                        assumptions=[f"{tech_name} is installed and detectable", "Public CVEs exist for plugins/themes"],
                        expected_evidence=["CVE matches", "Version disclosure", "Plugin listings"],
                        falsification_condition="No vulnerable plugins/themes found after full enumeration",
                        confidence=0.5, information_gain=0.85, execution_cost=0.5, risk=0.3,
                        generation_reason=f"{tech_name} technology detected", tags=["web", "cms", "vulnerability"]
                    )
                    if h2:
                        hypotheses.append(h2)

        git_endpoints = [e for e in endpoints if '.git' in e.get('url', '').lower()]
        if git_endpoints or any('.git' in str(t).lower() for t in tech_stack.keys()):
            h3 = self.add_hypothesis(
                statement=".git directory is publicly accessible and may contain sensitive history",
                title="Git Repository Exposure",
                description="The exposed .git directory may leak source code, history and credentials",
                command="curl -sik http://target/.git/config",
                assumptions=[".git directory exists", "Web server allows access to .git"],
                expected_evidence=["Git config file content", "Repository structure disclosure"],
                falsification_condition="403/404 or no .git artifacts found",
                confidence=0.6, information_gain=0.9, execution_cost=0.1, risk=0.1,
                generation_reason=".git endpoint detected or suspected",
                tags=["exposure", "source-code", "credentials"],
                command_alternatives=["git-dumper http://target/.git ./dump", "curl -sik http://target/.git/HEAD"]
            )
            if h3:
                hypotheses.append(h3)

        if git_endpoints:
            h4 = self.add_hypothesis(
                statement="Git commit history contains hardcoded credentials or secrets",
                title="Credentials in Git History",
                description="Commit logs and history often contain hardcoded secrets, keys and developer emails",
                command="curl -sik http://target/.git/logs/HEAD",
                assumptions=[".git is accessible", "Commits contain sensitive data"],
                expected_evidence=["Commit messages", "Potential credential strings", "Developer emails"],
                falsification_condition="No credential-like strings in commit history",
                confidence=0.5, information_gain=0.95, execution_cost=0.2, risk=0.1,
                generation_reason=".git exposure confirmed", tags=["credentials", "source-code"],
                depends_on=[h3.id] if h3 else [],
                command_alternatives=["curl -sik http://target/.git/index"]
            )
            if h4:
                hypotheses.append(h4)
                if h3:
                    h3.supports.append(h4.id)

        ssh_ports = [p for p in ports if p.get('port') == 22]
        if ssh_ports:
            h5 = self.add_hypothesis(
                statement="SSH service accepts weak/default credentials or has misconfigurations",
                title="SSH Weak Authentication",
                description="Probe SSH auth methods and credential strength for weak or default configurations",
                command="nmap -p 22 --script ssh-auth-methods,ssh-brute target",
                assumptions=["SSH service is OpenSSH or compatible", "Default credentials may exist"],
                expected_evidence=["Authentication method disclosure", "Valid credentials if brute succeeds"],
                falsification_condition="All tested credentials rejected, auth methods are strong",
                confidence=0.4, information_gain=0.7, execution_cost=0.6, risk=0.4,
                generation_reason="SSH port detected", tags=["ssh", "authentication"],
                command_alternatives=["hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://target"]
            )
            if h5:
                hypotheses.append(h5)

        self._generation_context = scenario_data
        return hypotheses

    def summary(self) -> str:
        lines = ["MULTI-HYPOTHESIS ENGINE STATE:", "=" * 40]
        total = len(self._hypotheses)
        confirmed = len(self.get_confirmed_hypotheses())
        rejected = len(self.get_rejected_hypotheses())
        active = sum(1 for h in self._hypotheses.values() if h.is_active)
        dead = sum(1 for h in self._hypotheses.values() if h.state == HYP_DEAD)
        lines.append(f"Total: {total} | Active: {active} | Confirmed: {confirmed} | Rejected: {rejected} | Dead: {dead}")
        top_active = self.get_competing_hypotheses(limit=5)
        if top_active:
            lines.append("\nTop Active Hypotheses:")
            for i, h in enumerate(top_active, 1):
                lines.append(f"  {i}. {h.summary()}")
                if h.assumptions:
                    lines.append(f"     Assumes: {', '.join(h.assumptions[:2])}")
                if h.falsification_condition:
                    lines.append(f"     Falsify: {h.falsification_condition}")
        return "\n".join(lines)
