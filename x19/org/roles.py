"""X19 role and capability catalog.

The X19 organization is a three-tier hierarchy:

    X19   BOSS      executive orchestrator — owns the objective, delegates, audits
    X22   MANAGER   project manager — turns objectives into tasks, assigns, tracks, reports
    workers         specialized execution agents — do the actual work with real tools

A role is a *specification*: identity, capabilities, toolsets, the delegation
role it maps onto in the real runtime, and the prompt fragment that shapes the
child agent.  Nothing here fabricates execution — specs are turned into real
``delegate_task`` dispatches by :mod:`x19.org.delegation` and their progress is
observed from the real subagent registry.

The catalog is **open**: :func:`register_role` lets a plugin, a config file or a
future team add a worker without touching the UI, the boss, the manager or the
task model.  Every consumer (registry, TUI, audit report, status projection)
renders whatever the catalog contains.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

__all__ = [
    "RoleKind",
    "RoleSpec",
    "BOSS_ROLE_ID",
    "MANAGER_ROLE_ID",
    "register_role",
    "unregister_role",
    "reset_roles",
    "get_role",
    "role_catalog",
    "roles_by_kind",
    "worker_roles",
    "manager_roles",
    "toolsets_for_role",
    "delegation_role_for",
    "capability_index",
    "roles_for_capabilities",
]


class RoleKind(str, Enum):
    """Position of a role in the organization."""

    BOSS = "boss"
    MANAGER = "manager"
    WORKER = "worker"


BOSS_ROLE_ID = "x19"
MANAGER_ROLE_ID = "x22"

# The real runtime only distinguishes two delegation capabilities: an
# ``orchestrator`` may spawn children, a ``leaf`` may not.  X19 and X22 are
# orchestrators; every worker is a leaf.
_DELEGATION_BY_KIND = {
    RoleKind.BOSS: "orchestrator",
    RoleKind.MANAGER: "orchestrator",
    RoleKind.WORKER: "leaf",
}


@dataclass(frozen=True)
class RoleSpec:
    """Declarative description of one organizational role.

    Attributes are the metadata the directive requires every agent to expose:
    identity, role, capabilities, toolsets, reporting line, and the model tier
    the orchestration layer should prefer when the provider supports it.
    """

    id: str
    kind: RoleKind
    display_name: str
    title: str
    summary: str
    capabilities: Tuple[str, ...] = ()
    toolsets: Tuple[str, ...] = ()
    manager_id: Optional[str] = None
    model_tier: Optional[str] = None
    prompt_fragment: str = ""
    # Extra managers/teams can declare how many children they may run at once.
    max_concurrent_children: Optional[int] = None
    tags: Tuple[str, ...] = ()
    extra: Dict[str, object] = field(default_factory=dict)

    @property
    def delegation_role(self) -> str:
        """``orchestrator`` for X19/X22, ``leaf`` for workers."""
        return _DELEGATION_BY_KIND[self.kind]

    @property
    def is_orchestrator(self) -> bool:
        return self.kind in (RoleKind.BOSS, RoleKind.MANAGER)

    def to_dict(self) -> Dict[str, object]:
        return {
            "id": self.id,
            "kind": self.kind.value,
            "display_name": self.display_name,
            "title": self.title,
            "summary": self.summary,
            "capabilities": list(self.capabilities),
            "toolsets": list(self.toolsets),
            "manager_id": self.manager_id,
            "model_tier": self.model_tier,
            "delegation_role": self.delegation_role,
            "max_concurrent_children": self.max_concurrent_children,
            "tags": list(self.tags),
        }


# ---------------------------------------------------------------------------
# Built-in organization
# ---------------------------------------------------------------------------

_BOSS = RoleSpec(
    id=BOSS_ROLE_ID,
    kind=RoleKind.BOSS,
    display_name="X19",
    title="Boss / Executive Orchestrator",
    summary=(
        "Owns the user's objective. Decomposes it, decides which teams are needed, "
        "delegates to managers, monitors execution, resolves blockers, reassigns work, "
        "reviews results and reports back to the user. Does not do the work itself."
    ),
    capabilities=(
        "objective_intake",
        "decomposition",
        "delegation",
        "prioritisation",
        "progress_inspection",
        "blocker_resolution",
        "reassignment",
        "result_review",
        "synthesis",
        "user_communication",
        "executive_audit",
    ),
    toolsets=("x19-org", "core", "file", "terminal"),
    manager_id=None,
    model_tier="primary",
    prompt_fragment=(
        "You are X19, the Boss. You are an executive orchestrator, not an implementer. "
        "Understand the objective, break it into tasks, choose the roles needed, delegate "
        "through X22 (or directly to a worker for a single small task), then monitor, "
        "review and synthesise. Answer status questions only from real runtime state — "
        "never invent progress, completions or agent activity."
    ),
    tags=("executive",),
)

_MANAGER = RoleSpec(
    id=MANAGER_ROLE_ID,
    kind=RoleKind.MANAGER,
    display_name="X22",
    title="Manager / Project Manager",
    summary=(
        "Receives delegated objectives from X19, converts them into actionable tasks with "
        "dependencies, assigns them to worker agents, tracks progress, detects blocked or "
        "failed workers, validates outputs, reports status upward and escalates when stuck."
    ),
    capabilities=(
        "task_planning",
        "dependency_tracking",
        "worker_assignment",
        "progress_monitoring",
        "blocker_detection",
        "output_validation",
        "status_reporting",
        "escalation",
        "retry_decisions",
    ),
    toolsets=("x19-org", "core", "file", "terminal"),
    manager_id=BOSS_ROLE_ID,
    model_tier="primary",
    max_concurrent_children=4,
    prompt_fragment=(
        "You are X22, the Manager. You coordinate, you do not chat. Take the objective you "
        "were given, plan concrete tasks with explicit dependencies, assign each to the "
        "worker role that owns that capability, track real progress, validate what workers "
        "return, and report factual status back to X19. Escalate anything you cannot "
        "resolve. Never claim a task finished unless the runtime says it did."
    ),
    tags=("management",),
)


def _worker(
    id: str,
    display_name: str,
    title: str,
    summary: str,
    capabilities: Sequence[str],
    toolsets: Sequence[str],
    prompt: str,
    *,
    tags: Sequence[str] = (),
    model_tier: Optional[str] = None,
) -> RoleSpec:
    return RoleSpec(
        id=id,
        kind=RoleKind.WORKER,
        display_name=display_name,
        title=title,
        summary=summary,
        capabilities=tuple(capabilities),
        toolsets=tuple(toolsets),
        manager_id=MANAGER_ROLE_ID,
        model_tier=model_tier,
        prompt_fragment=prompt,
        tags=tuple(tags),
    )


_WORKERS: Tuple[RoleSpec, ...] = (
    _worker(
        "research",
        "Research Worker",
        "Recon / Research",
        "Gathers external information: web research, documentation lookup, source "
        "discovery, prior-art and landscape analysis. Returns sourced findings.",
        ("web_research", "documentation_lookup", "source_discovery", "summarisation"),
        ("core", "web", "file", "browser"),
        "You are the Research worker. Find real, sourced information. Report what you "
        "actually retrieved, with the source for each claim. Say plainly when something "
        "could not be found rather than filling the gap.",
        tags=("discovery",),
    ),
    _worker(
        "coding",
        "Coding Worker",
        "Implementation",
        "Writes and edits code: features, refactors, bug fixes, scripts. Works in the "
        "real repository with the real file and terminal tools.",
        ("code_writing", "code_editing", "refactoring", "bug_fixing", "build_execution"),
        ("core", "file", "terminal", "code_execution"),
        "You are the Coding worker. Implement the task in the real workspace. Read before "
        "you write, keep changes minimal and coherent with the surrounding code, and report "
        "exactly which files you changed and what you verified.",
        tags=("implementation",),
    ),
    _worker(
        "security",
        "Security Worker",
        "Security Analysis",
        "Reviews code and configuration for vulnerabilities, unsafe patterns, secret "
        "leakage and permission-boundary weaknesses. Analysis only — never attacks "
        "third-party systems.",
        ("security_review", "vulnerability_analysis", "secret_scanning", "threat_modelling"),
        ("core", "file", "terminal"),
        "You are the Security worker. Review the code and configuration you are pointed at. "
        "Report concrete weaknesses with file/line evidence, severity and a suggested fix. "
        "Never probe systems you do not own; this is a static/dynamic review role, not an "
        "attack role.",
        tags=("assurance",),
    ),
    _worker(
        "testing",
        "Testing Worker",
        "Testing & Verification",
        "Writes and runs tests, reproduces reported failures, and verifies that a change "
        "actually does what was claimed. Reports real command output.",
        ("test_writing", "test_execution", "failure_reproduction", "regression_checking"),
        ("core", "file", "terminal", "code_execution"),
        "You are the Testing worker. Run the real tests and report the real output. If "
        "something fails, capture the failure verbatim and the smallest reproduction. Never "
        "report a pass you did not observe.",
        tags=("assurance",),
    ),
    _worker(
        "documentation",
        "Documentation Worker",
        "Documentation",
        "Writes and updates documentation that describes the actual implementation: "
        "READMEs, guides, API references, changelogs.",
        ("documentation_writing", "api_reference", "changelog", "example_authoring"),
        ("core", "file", "web"),
        "You are the Documentation worker. Document what the code really does — read it "
        "first. Prefer accurate and terse over comprehensive and speculative.",
        tags=("communication",),
    ),
    _worker(
        "analysis",
        "Analysis Worker",
        "Data & Code Analysis",
        "Analyses code structure, logs, metrics and datasets. Produces structured findings, "
        "correlations and recommendations.",
        ("data_analysis", "log_analysis", "codebase_analysis", "metrics", "correlation"),
        ("core", "file", "terminal", "code_execution"),
        "You are the Analysis worker. Work from the real data you are given. Show the "
        "numbers, state the method, and separate observation from interpretation.",
        tags=("insight",),
    ),
    _worker(
        "devops",
        "DevOps Worker",
        "DevOps / Deployment",
        "Handles build, packaging, CI configuration, containerisation and deployment "
        "plumbing. Executes real commands and reports their real results.",
        ("ci_configuration", "containerisation", "build_pipeline", "deployment", "infrastructure"),
        ("core", "file", "terminal"),
        "You are the DevOps worker. Change build/CI/deploy configuration deliberately and "
        "verify it by running it. Report the exact commands you ran and their exit status. "
        "Anything destructive or externally visible needs an explicit approval first.",
        tags=("operations",),
    ),
    _worker(
        "debugging",
        "Debugging Worker",
        "Debugging & Root Cause",
        "Diagnoses failures: reproduces them, traces them to a root cause, and proposes or "
        "implements the minimal fix.",
        ("root_cause_analysis", "failure_reproduction", "trace_analysis", "fix_proposal"),
        ("core", "file", "terminal", "code_execution"),
        "You are the Debugging worker. Reproduce the failure first, then narrow it down with "
        "evidence. Report the root cause, the evidence chain, and the smallest fix.",
        tags=("assurance",),
    ),
    _worker(
        "execution",
        "Execution Worker",
        "Tool Execution",
        "Runs concrete, well-specified tool operations that need no domain reasoning: "
        "batch commands, file operations, data transforms, scheduled jobs.",
        ("tool_execution", "batch_operations", "file_operations", "command_runner"),
        ("core", "file", "terminal"),
        "You are the Execution worker. Carry out exactly the operations specified, no more. "
        "Report each command and its real output. Stop and ask if the instruction is "
        "ambiguous or looks destructive.",
        tags=("operations",),
    ),
)

_BUILTIN: Tuple[RoleSpec, ...] = (_BOSS, _MANAGER) + _WORKERS

# id -> spec.  Mutable so roles can be registered at runtime.
_ROLES: Dict[str, RoleSpec] = {r.id: r for r in _BUILTIN}


def register_role(spec: RoleSpec, *, replace: bool = False) -> RoleSpec:
    """Add (or replace) a role in the live catalog.

    This is the extension point the directive requires: a new worker is one
    ``register_role`` call away, with no UI, boss, manager or task-model change.
    """
    if not spec.id or not spec.id.strip():
        raise ValueError("role id must be a non-empty string")
    if spec.id in _ROLES and not replace:
        raise ValueError(f"role {spec.id!r} already registered (pass replace=True to override)")
    if spec.kind is RoleKind.BOSS and spec.id != BOSS_ROLE_ID:
        raise ValueError(f"only {BOSS_ROLE_ID!r} may be the boss role")
    if spec.manager_id and spec.manager_id not in _ROLES and spec.manager_id != spec.id:
        raise ValueError(f"manager {spec.manager_id!r} is not a registered role")
    _ROLES[spec.id] = spec
    return spec


def unregister_role(role_id: str) -> bool:
    """Remove a non-builtin role.  Built-in organization roles cannot be removed."""
    if role_id in {r.id for r in _BUILTIN}:
        return False
    return _ROLES.pop(role_id, None) is not None


def reset_roles() -> None:
    """Restore the built-in catalog (used by tests and by config reload)."""
    _ROLES.clear()
    _ROLES.update({r.id: r for r in _BUILTIN})


def get_role(role_id: Optional[str]) -> Optional[RoleSpec]:
    if not role_id:
        return None
    return _ROLES.get(role_id)


def role_catalog() -> Tuple[RoleSpec, ...]:
    """Every registered role: boss first, then managers, then workers."""
    order = {RoleKind.BOSS: 0, RoleKind.MANAGER: 1, RoleKind.WORKER: 2}
    return tuple(sorted(_ROLES.values(), key=lambda r: (order[r.kind], r.id)))


def roles_by_kind(kind: RoleKind) -> Tuple[RoleSpec, ...]:
    return tuple(r for r in role_catalog() if r.kind is kind)


def worker_roles() -> Tuple[RoleSpec, ...]:
    return roles_by_kind(RoleKind.WORKER)


def manager_roles() -> Tuple[RoleSpec, ...]:
    return roles_by_kind(RoleKind.MANAGER)


def toolsets_for_role(role_id: str) -> Tuple[str, ...]:
    role = get_role(role_id)
    return role.toolsets if role else ()


def delegation_role_for(role_id: str) -> str:
    """Map an X19 role onto the real runtime's delegation capability."""
    role = get_role(role_id)
    return role.delegation_role if role else "leaf"


def capability_index() -> Dict[str, List[str]]:
    """capability -> [role_id, ...] across the whole live catalog."""
    index: Dict[str, List[str]] = {}
    for role in role_catalog():
        for cap in role.capabilities:
            index.setdefault(cap, []).append(role.id)
    return index


def roles_for_capabilities(capabilities: Iterable[str]) -> Tuple[RoleSpec, ...]:
    """Roles that declare *any* of the requested capabilities."""
    wanted = {c for c in capabilities if c}
    if not wanted:
        return ()
    return tuple(r for r in worker_roles() if wanted.intersection(r.capabilities))


def with_manager(spec: RoleSpec, manager_id: Optional[str]) -> RoleSpec:
    """Return a copy of *spec* reporting to *manager_id* (multi-team support)."""
    return replace(spec, manager_id=manager_id)
