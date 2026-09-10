"""X19 cognitive control contract.

The security engines already know *how* to test. This layer makes the model
responsible for *why this action now*: maintain a state -> hypothesis -> test ->
evidence -> update loop, with explicit progress and stop conditions.

It is intentionally advisory and fail-closed. ScopeGuard, PolicyEngine and the
existing verifier remain authoritative for execution and findings.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List


COGNITIVE_CONTRACT = """
COGNITIVE CONTROL — follow this loop on every decision:
1. STATE: summarize only facts established by previous tool output.
2. GAP: name the single most important unknown blocking progress.
3. HYPOTHESIS: state one testable explanation for that gap.
4. ACTION: choose one highest-value available tool/action that can falsify or confirm it.
5. EVIDENCE: define the exact output that would count as confirmation, rejection, or inconclusive.
6. UPDATE: after the result, retire or promote the hypothesis; never silently carry a false assumption.

OUTPUT CONTRACT — this is mandatory:
- Return exactly ONE valid JSON object and nothing else.
- `next_command` must be one concrete shell command or an empty string.
- `hypothesis_id` must be a stable short identifier for the hypothesis, or an empty string when no action is needed.
- `hypothesis` must state what the command is testing.
- `expected_evidence` must state the exact observable output that would support or reject the hypothesis.
- `evidence_required` must be true whenever `next_command` is non-empty or a finding is proposed.
- `reasoning` must map the chosen tool/action to the hypothesis and expected evidence.
- Never put imagined command output into `finding.evidence`; findings are emitted only from observed tool output already present in the context.

Required shape:
{
  "hypothesis_id": "h1",
  "hypothesis": "one testable statement",
  "next_command": "one shell command or empty string",
  "expected_evidence": "what exact output would confirm/reject it",
  "evidence_required": true,
  "reasoning": "tool:<name> | why:<reason> | evidence:<expected evidence>",
  "finding": null,
  "completed": false
}

PLANNING RULES:
- Prefer information gain over repeating familiar scans.
- Do not invent endpoints, credentials, versions, services, or vulnerabilities.
- A command returning empty/unchanged evidence is a result; record it and pivot.
- One decision should have one primary objective. Do not emit a bag of unrelated commands.
- Do not call a finding confirmed until the verifier has concrete evidence.
- Keep recon, enumeration, validation, exploitation and reporting as explicit states.
- When a branch is exhausted, mark it exhausted and choose another branch instead of looping.
- If the available toolset cannot answer the question, say so and select the nearest safe alternative.
- Completion requires either verified findings/reportable evidence or a defensible exhausted search state.

SELF-CRITIQUE:
Before repeating a technique, ask: what changed since the previous attempt?
If nothing changed, change the technique, target surface, hypothesis, or stop.
""".strip()


@dataclass
class CognitiveState:
    phase: str = "recon"
    objective: str = "map the target and identify the highest-value unknown"
    known: List[str] = field(default_factory=list)
    unknowns: List[str] = field(default_factory=list)
    hypotheses: List[str] = field(default_factory=list)
    completed_tests: List[str] = field(default_factory=list)
    dead_ends: List[str] = field(default_factory=list)
    verified_findings: List[str] = field(default_factory=list)

    def compact(self) -> Dict[str, Any]:
        return {
            "phase": self.phase,
            "objective": self.objective,
            "known": self.known[-12:],
            "unknowns": self.unknowns[-8:],
            "hypotheses": self.hypotheses[-6:],
            "completed_tests": self.completed_tests[-8:],
            "dead_ends": self.dead_ends[-6:],
            "verified_findings": self.verified_findings[-8:],
        }


class CognitiveRuntime:
    """Small deterministic state helper usable by the existing agent loop."""

    PHASES = ("recon", "enum", "vuln", "exploit", "report")

    def __init__(self) -> None:
        self.state = CognitiveState()

    def observe(
        self,
        phase: str | None = None,
        *,
        facts: Iterable[str] = (),
        unknowns: Iterable[str] = (),
        evidence: str = "",
    ) -> Dict[str, Any]:
        if phase in self.PHASES:
            self.state.phase = phase
        for fact in facts:
            if fact and fact not in self.state.known:
                self.state.known.append(fact)
        for item in unknowns:
            if item and item not in self.state.unknowns:
                self.state.unknowns.append(item)
        if evidence:
            self.state.completed_tests.append(evidence[:300])
        return self.state.compact()

    def reject_branch(self, reason: str) -> None:
        if reason:
            self.state.dead_ends.append(reason[:300])

    def prompt(self, base: str) -> str:
        return base.rstrip() + "\n\n" + COGNITIVE_CONTRACT


def augment_prompt(base: str) -> str:
    return CognitiveRuntime().prompt(base)


def self_check() -> Dict[str, Any]:
    return {
        "status": "ready",
        "phases": list(CognitiveRuntime.PHASES),
        "contract_sections": ["state", "gap", "hypothesis", "action", "evidence", "update"],
        "execution_authority": "existing ScopeGuard/PolicyEngine/Verifier",
        "output_contract": ["hypothesis_id", "hypothesis", "next_command", "expected_evidence", "evidence_required"],
    }


def install() -> None:
    """Install the prompt contract before agent.py imports the helper."""
    import utils
    if getattr(utils, "_X19_COGNITIVE_RUNTIME_INSTALLED", False):
        return
    original = utils.decision_system_prompt

    def wrapped() -> str:
        return augment_prompt(original())

    utils.decision_system_prompt = wrapped
    utils._X19_COGNITIVE_RUNTIME_INSTALLED = True
