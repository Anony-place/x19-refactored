"""Hybrid mission workflow for the X19 swarm.

Three published designs are combined here, each contributing the part it is
actually good at:

**XBOW** contributes the *shape* — a Learn → Map → Coordinate → Attack →
Validate → Debrief loop in which a coordinator decides what to test next,
attack agents are short-lived and retired after each mission to avoid bias,
and findings only surface once an independent validator reproduces them.

**Cyber-AutoAgent** contributes *metacognition* — a confidence score that
selects the behaviour (exploit / test a hypothesis / pivot / deploy more
agents) instead of a hardcoded stage order, and the assessment plan stored as
external working memory that is re-read at 20/40/60/80 % of the budget so a
long run does not lose strategic coherence.

**Hermes Agent** contributes *guardrails* — anti-loop detection that warns and
then blocks repeated identical failures, per-run budget caps, and early
stopping when a run stops making progress.

The classes here are deliberately free of I/O so they can be unit-tested
without a network, a target, or an LLM.
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Stages
# ---------------------------------------------------------------------------
class WorkflowStage(str, Enum):
    """The XBOW pipeline. ``COORDINATE`` is the decision point, not a phase."""

    LEARN = "learn"
    MAP = "map"
    COORDINATE = "coordinate"
    ATTACK = "attack"
    VALIDATE = "validate"
    DEBRIEF = "debrief"


STAGE_ORDER = [
    WorkflowStage.LEARN,
    WorkflowStage.MAP,
    WorkflowStage.COORDINATE,
    WorkflowStage.ATTACK,
    WorkflowStage.VALIDATE,
    WorkflowStage.DEBRIEF,
]

STAGE_GOAL = {
    WorkflowStage.LEARN: "ingest engagement context, scope and credentials",
    WorkflowStage.MAP: "map hosts, ports, services, endpoints into the attack graph",
    WorkflowStage.COORDINATE: "rank evidence, pick the next goal, queue tasks",
    WorkflowStage.ATTACK: "run confidence-gated attack tasks with fresh agents",
    WorkflowStage.VALIDATE: "independently reproduce every candidate finding",
    WorkflowStage.DEBRIEF: "record penalties, learn strategies, write the report",
}


# ---------------------------------------------------------------------------
# Confidence gate
# ---------------------------------------------------------------------------
ACTION_EXPLOIT = "exploit"
ACTION_TEST = "test_hypothesis"
ACTION_PIVOT = "pivot"
ACTION_SWARM = "deploy_swarm"


@dataclass
class ConfidenceDecision:
    action: str
    confidence: float
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        return {"action": self.action, "confidence": self.confidence, "reason": self.reason}


class ConfidenceGate:
    """Maps a 0–1 confidence score onto the next behaviour.

    Thresholds are the Cyber-AutoAgent ones: above 0.8 the agent exploits,
    between 0.5 and 0.8 it tests a hypothesis, below 0.5 it pivots — and when a
    pivot would not help it deploys parallel agents instead of guessing.
    """

    def __init__(self, exploit_above: float = 0.8, test_above: float = 0.5, swarm_below: float = 0.25):
        if not (0.0 <= swarm_below <= test_above <= exploit_above <= 1.0):
            raise ValueError("thresholds must satisfy 0 <= swarm_below <= test_above <= exploit_above <= 1")
        self.exploit_above = exploit_above
        self.test_above = test_above
        self.swarm_below = swarm_below

    def decide(self, confidence: float) -> ConfidenceDecision:
        value = max(0.0, min(1.0, float(confidence)))
        if value >= self.exploit_above:
            return ConfidenceDecision(
                ACTION_EXPLOIT, value, f"confidence {value:.2f} ≥ {self.exploit_above:.2f} — exploit directly"
            )
        if value >= self.test_above:
            return ConfidenceDecision(
                ACTION_TEST, value, f"confidence {value:.2f} in [{self.test_above:.2f}, {self.exploit_above:.2f}) — test first"
            )
        if value < self.swarm_below:
            return ConfidenceDecision(
                ACTION_SWARM, value, f"confidence {value:.2f} < {self.swarm_below:.2f} — deploy parallel agents"
            )
        return ConfidenceDecision(ACTION_PIVOT, value, f"confidence {value:.2f} — pivot to another path")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "exploit_above": self.exploit_above,
            "test_above": self.test_above,
            "swarm_below": self.swarm_below,
        }


# ---------------------------------------------------------------------------
# Loop guardrails
# ---------------------------------------------------------------------------
EXACT_FAILURE = "exact_failure"
SAME_TOOL_FAILURE = "same_tool_failure"
IDEMPOTENT_NO_PROGRESS = "idempotent_no_progress"

LEVEL_OK = "ok"
LEVEL_WARN = "warn"
LEVEL_STOP = "stop"


@dataclass
class GuardVerdict:
    level: str
    fired: str = ""
    reason: str = ""
    count: int = 0

    @property
    def allowed(self) -> bool:
        return self.level != LEVEL_STOP

    def to_dict(self) -> Dict[str, Any]:
        return {"level": self.level, "guardrail": self.fired, "reason": self.reason, "count": self.count}


def call_signature(tool: str, args: Any) -> str:
    """Stable hash of a call, so 'identical' means identical."""
    try:
        payload = json.dumps(args, sort_keys=True, default=str)
    except Exception:
        payload = str(args)
    return hashlib.sha256(f"{tool}:{payload}".encode()).hexdigest()[:16]


def result_signature(result: Any) -> str:
    try:
        payload = json.dumps(result, sort_keys=True, default=str)
    except Exception:
        payload = str(result)
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


class LoopGuard:
    """Hermes-style anti-loop detection.

    ``record()`` is called after every tool/command execution. It returns a
    verdict: ``ok`` to carry on, ``warn`` to inject a corrective note into the
    agent's context, ``stop`` to refuse the next identical call.

    A halt ends the *cycle*, never the mission — the caller decides whether to
    abandon the task, which is what makes this safe to run unattended.
    """

    def __init__(
        self,
        warn_after: Optional[Dict[str, int]] = None,
        hard_stop_after: Optional[Dict[str, int]] = None,
        hard_stop_enabled: bool = True,
    ):
        self.warn_after = dict(warn_after or {EXACT_FAILURE: 2, SAME_TOOL_FAILURE: 3, IDEMPOTENT_NO_PROGRESS: 2})
        self.hard_stop_after = dict(
            hard_stop_after or {EXACT_FAILURE: 5, SAME_TOOL_FAILURE: 8, IDEMPOTENT_NO_PROGRESS: 5}
        )
        self.hard_stop_enabled = hard_stop_enabled

        self._exact_failures: Dict[str, int] = {}
        self._tool_failures: Dict[str, int] = {}
        self._identical_results: Dict[str, int] = {}
        self._events: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    # -- recording ---------------------------------------------------------
    def record(
        self, tool: str, args: Any, *, succeeded: bool, result: Any = None, progressed: bool = True
    ) -> GuardVerdict:
        """Register one execution and return the guardrail verdict for it."""
        signature = call_signature(tool, args)
        digest = result_signature(result)
        fired: List[Tuple[str, int]] = []

        with self._lock:
            if not succeeded:
                self._exact_failures[signature] = self._exact_failures.get(signature, 0) + 1
                self._tool_failures[tool] = self._tool_failures.get(tool, 0) + 1
                fired.append((EXACT_FAILURE, self._exact_failures[signature]))
                fired.append((SAME_TOOL_FAILURE, self._tool_failures[tool]))
            else:
                # A success resets the failure streaks for that exact call.
                self._exact_failures.pop(signature, None)
                if not progressed:
                    key = f"{signature}:{digest}"
                    self._identical_results[key] = self._identical_results.get(key, 0) + 1
                    fired.append((IDEMPOTENT_NO_PROGRESS, self._identical_results[key]))
                else:
                    self._identical_results = {
                        k: v for k, v in self._identical_results.items() if not k.startswith(signature)
                    }

            verdict = self._evaluate(fired, tool)
            if verdict.level != LEVEL_OK:
                self._events.append(
                    {
                        "timestamp": time.time(),
                        "tool": tool,
                        "level": verdict.level,
                        "guardrail": verdict.fired,
                        "count": verdict.count,
                        "reason": verdict.reason,
                    }
                )
            return verdict

    def _evaluate(self, fired: List[Tuple[str, int]], tool: str) -> GuardVerdict:
        worst = GuardVerdict(LEVEL_OK)
        for name, count in fired:
            stop_at = int(self.hard_stop_after.get(name, 0) or 0)
            warn_at = int(self.warn_after.get(name, 0) or 0)
            if self.hard_stop_enabled and stop_at and count >= stop_at:
                return GuardVerdict(
                    LEVEL_STOP,
                    name,
                    f"{name} reached {count} (hard stop at {stop_at}) for tool '{tool}'",
                    count,
                )
            if warn_at and count >= warn_at and worst.level == LEVEL_OK:
                worst = GuardVerdict(
                    LEVEL_WARN,
                    name,
                    f"{name} reached {count} (warn at {warn_at}) for tool '{tool}' — change approach",
                    count,
                )
        return worst

    def would_allow(self, tool: str, args: Any) -> GuardVerdict:
        """Evaluate the guardrails for a call *without* recording it.

        Pre-flight checks must be queries. Recording them as successes — which
        is what the attack stage used to do — clears the exact-failure streak
        for the very call being retried, so the identical-failure guard could
        never trip there at all.
        """
        signature = call_signature(tool, args)
        with self._lock:
            fired: List[Tuple[str, int]] = []
            exact = self._exact_failures.get(signature, 0)
            tool_count = self._tool_failures.get(tool, 0)
            if exact:
                fired.append((EXACT_FAILURE, exact + 1))  # the call about to happen
            if tool_count:
                fired.append((SAME_TOOL_FAILURE, tool_count + 1))
            return self._evaluate(fired, tool)

    # -- inspection --------------------------------------------------------
    @property
    def events(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._events)

    def reset_cycle(self) -> None:
        """Clear per-cycle streaks. Called at each plan checkpoint."""
        with self._lock:
            self._identical_results.clear()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "warn_after": self.warn_after,
            "hard_stop_after": self.hard_stop_after,
            "hard_stop_enabled": self.hard_stop_enabled,
            "events": self.events,
        }


# ---------------------------------------------------------------------------
# Budget
# ---------------------------------------------------------------------------
@dataclass
class BudgetState:
    """Runtime counters against an :class:`engagement.MissionBudget`."""

    max_seconds: int = 1800
    max_llm_calls: int = 200
    max_commands: int = 500
    started_at: float = field(default_factory=time.time)
    llm_calls: int = 0
    commands: int = 0
    cycles: int = 0

    def elapsed(self) -> float:
        return max(0.0, time.time() - self.started_at)

    def spend(self, *, llm_calls: int = 0, commands: int = 0, cycles: int = 0) -> None:
        self.llm_calls += llm_calls
        self.commands += commands
        self.cycles += cycles

    def pct_used(self) -> float:
        """Worst-case utilisation across the three ceilings, 0–100."""
        ratios = [self.elapsed() / self.max_seconds] if self.max_seconds > 0 else []
        if self.max_commands > 0:
            ratios.append(self.commands / self.max_commands)
        if self.max_llm_calls > 0:
            ratios.append(self.llm_calls / self.max_llm_calls)
        return round(min(100.0, max(ratios) * 100.0) if ratios else 0.0, 1)

    def exhausted(self) -> Tuple[bool, str]:
        if self.max_seconds > 0 and self.elapsed() >= self.max_seconds:
            return True, f"time budget exhausted ({self.elapsed():.0f}s ≥ {self.max_seconds}s)"
        if self.max_commands > 0 and self.commands >= self.max_commands:
            return True, f"command budget exhausted ({self.commands} ≥ {self.max_commands})"
        if self.max_llm_calls > 0 and self.llm_calls >= self.max_llm_calls:
            return True, f"llm budget exhausted ({self.llm_calls} ≥ {self.max_llm_calls})"
        return False, ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "elapsed_seconds": round(self.elapsed(), 1),
            "llm_calls": self.llm_calls,
            "commands": self.commands,
            "cycles": self.cycles,
            "pct_used": self.pct_used(),
            "limits": {
                "max_seconds": self.max_seconds,
                "max_llm_calls": self.max_llm_calls,
                "max_commands": self.max_commands,
            },
        }


# ---------------------------------------------------------------------------
# Plan as external working memory
# ---------------------------------------------------------------------------
PHASE_PENDING = "pending"
PHASE_ACTIVE = "active"
PHASE_DONE = "done"
PHASE_SKIPPED = "skipped"


@dataclass
class PlanPhase:
    stage: str
    goal: str
    status: str = PHASE_PENDING
    criteria: str = ""
    notes: List[str] = field(default_factory=list)
    updated_at: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stage": self.stage,
            "goal": self.goal,
            "status": self.status,
            "criteria": self.criteria,
            "notes": self.notes,
            "updated_at": self.updated_at,
        }


class MissionPlan:
    """The plan lives outside the model's context and is re-read at checkpoints.

    A 200-step assessment loses coherence as tool output fills the window; this
    is the Cyber-AutoAgent answer — persist the plan, then re-inject a compact
    progress summary at 20/40/60/80 % of the budget.
    """

    def __init__(self, target: str = "", objective: str = ""):
        self.target = target
        self.objective = objective
        self.phases: List[PlanPhase] = [
            PlanPhase(stage=stage.value, goal=STAGE_GOAL[stage]) for stage in STAGE_ORDER
        ]
        self.checkpoint_reviews: List[Dict[str, Any]] = []
        self.created_at = time.time()

    # -- mutation ----------------------------------------------------------
    def phase(self, stage: WorkflowStage) -> PlanPhase:
        for phase in self.phases:
            if phase.stage == stage.value:
                return phase
        raise KeyError(stage)

    def mark(self, stage: WorkflowStage, status: str, note: str = "") -> PlanPhase:
        phase = self.phase(stage)
        phase.status = status
        phase.updated_at = time.time()
        if note:
            phase.notes.append(note)
        return phase

    # -- inspection --------------------------------------------------------
    def pct_complete(self) -> float:
        if not self.phases:
            return 0.0
        done = sum(1 for p in self.phases if p.status in (PHASE_DONE, PHASE_SKIPPED))
        return round(done / len(self.phases) * 100.0, 1)

    def active_stage(self) -> Optional[WorkflowStage]:
        for phase in self.phases:
            if phase.status == PHASE_ACTIVE:
                return WorkflowStage(phase.stage)
        return None

    def next_stage(self) -> Optional[WorkflowStage]:
        for stage in STAGE_ORDER:
            if self.phase(stage).status == PHASE_PENDING:
                return stage
        return None

    def checkpoint_review(self, pct_used: float) -> str:
        """Compact status block to re-inject into the agent's context."""
        lines = [f"PLAN CHECKPOINT @ {pct_used:.0f}% budget — {self.pct_complete():.0f}% of plan complete"]
        for phase in self.phases:
            lines.append(f"  [{phase.status:>7}] {phase.stage}: {phase.goal}")
            if phase.notes:
                lines.append(f"            last: {phase.notes[-1]}")
        review = "\n".join(lines)
        self.checkpoint_reviews.append({"pct_used": pct_used, "review": review, "timestamp": time.time()})
        return review

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "objective": self.objective,
            "phases": [p.to_dict() for p in self.phases],
            "pct_complete": self.pct_complete(),
            "checkpoint_reviews": self.checkpoint_reviews,
        }


# ---------------------------------------------------------------------------
# Short-lived agents
# ---------------------------------------------------------------------------
class AgentFactory:
    """Spawns a *fresh* agent per mission and retires it afterwards.

    XBOW retires attack workers after each mission so a failed approach cannot
    bias the next attempt. Long-lived singletons accumulate exactly that bias,
    which is what the previous coordinator did.
    """

    #: kind -> (module, class) resolved lazily so importing this module is cheap.
    REGISTRY = {
        "recon": ("brain.agents.recon_agent", "ReconAgent"),
        "web": ("brain.agents.web_agent", "WebAgent"),
        "vuln": ("brain.agents.vuln_agent", "VulnAgent"),
        "verify": ("brain.agents.verifier_agent", "VerifierAgent"),
        "critic": ("brain.agents.critic_agent", "CriticAgent"),
    }

    def __init__(self, coordinator: Any = None, scope_guard: Any = None, max_parallel: int = 4):
        self.coordinator = coordinator
        self.scope_guard = scope_guard
        self.max_parallel = max(1, int(max_parallel))
        self._live: List[Any] = []
        self.retired: List[str] = []
        self._lock = threading.Lock()

    @property
    def active_count(self) -> int:
        with self._lock:
            return len(self._live)

    def can_spawn(self) -> bool:
        return self.active_count < self.max_parallel

    def spawn(self, kind: str) -> Any:
        """Create a fresh agent of ``kind``. Raises ``RuntimeError`` at the cap."""
        import importlib

        if not self.can_spawn():
            raise RuntimeError(f"agent cap reached ({self.max_parallel} parallel)")
        if kind not in self.REGISTRY:
            raise KeyError(f"unknown agent kind {kind!r} — expected one of {sorted(self.REGISTRY)}")
        module_name, class_name = self.REGISTRY[kind]
        klass = getattr(importlib.import_module(module_name), class_name)

        kwargs: Dict[str, Any] = {"coordinator": self.coordinator}
        if kind != "critic" and self.scope_guard is not None:
            kwargs["scope_guard"] = self.scope_guard
        agent = klass(**kwargs)

        with self._lock:
            self._live.append(agent)
        return agent

    def retire(self, agent: Any) -> None:
        """Remove an agent from the live set so its state cannot leak forward."""
        name = getattr(agent, "name", agent.__class__.__name__)
        with self._lock:
            if agent in self._live:
                self._live.remove(agent)
            self.retired.append(name)
        try:
            if hasattr(agent, "stop"):
                agent.stop()
        except Exception:
            pass

    def retire_all(self) -> int:
        with self._lock:
            agents = list(self._live)
        for agent in agents:
            self.retire(agent)
        return len(agents)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "active": self.active_count,
            "max_parallel": self.max_parallel,
            "retired": list(self.retired),
        }


# ---------------------------------------------------------------------------
# Run record
# ---------------------------------------------------------------------------
@dataclass
class WorkflowRun:
    """Everything worth reporting about one workflow execution."""

    target: str = ""
    profile: str = ""
    started_at: float = field(default_factory=time.time)
    ended_at: float = 0.0
    stages_completed: List[str] = field(default_factory=list)
    cycles: int = 0
    stalls: int = 0
    stopped_reason: str = ""
    guardrail_events: List[Dict[str, Any]] = field(default_factory=list)
    decisions: List[Dict[str, Any]] = field(default_factory=list)
    findings_total: int = 0
    findings_verified: int = 0
    plan: Dict[str, Any] = field(default_factory=dict)
    budget: Dict[str, Any] = field(default_factory=dict)

    @property
    def duration(self) -> float:
        end = self.ended_at or time.time()
        return max(0.0, end - self.started_at)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "profile": self.profile,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "duration_seconds": round(self.duration, 1),
            "stages_completed": self.stages_completed,
            "cycles": self.cycles,
            "stalls": self.stalls,
            "stopped_reason": self.stopped_reason,
            "guardrail_events": self.guardrail_events,
            "decisions": self.decisions,
            "findings_total": self.findings_total,
            "findings_verified": self.findings_verified,
            "plan": self.plan,
            "budget": self.budget,
        }


def stage_after(stage: WorkflowStage) -> Optional[WorkflowStage]:
    index = STAGE_ORDER.index(stage)
    return STAGE_ORDER[index + 1] if index + 1 < len(STAGE_ORDER) else None
