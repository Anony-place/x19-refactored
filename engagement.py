"""Engagement profiles — the input boundary for an X19 assessment.

Modelled on XBOW's Assessment Guidance, whose four cards map one-to-one onto
the stages of its platform (see xbow.com/blog/introducing-assessment-guidance):

    Attack Surface  → what the discovery stage should map
    Priorities      → what the coordinator should care about
    Attack Strategy → what the attack agents should try
    Validation      → how the validators prove exploitation

X19 adds a fifth block the reference systems keep implicit: an explicit
**budget** and **loop-guardrail** configuration, because an autonomous agent
that cannot be bounded cannot be run unattended.

A profile is a plain JSON document under ``~/.x19/engagements/<name>.json``.
It is the only supported way to give an assessment context; nothing reads
free-form environment variables for scope any more.
"""
from __future__ import annotations

import json
import os
import re
import time
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any, Dict, List, Optional, Iterable

PROFILE_SCHEMA_VERSION = 1

TARGET_TYPES = ("auto", "public_real_world", "authorized", "ctf", "lab")

#: Severity ladder used by ``Validation.min_severity``.
SEVERITIES = ("critical", "high", "medium", "low", "info")

_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")

#: Keys whose values must never be printed verbatim.
SECRET_KEYS = ("secret", "password", "token", "value", "key")

#: Cap on how many items of each kind the guidance block spells out.
_MAX_GUIDANCE_ITEMS = 25


def engagements_dir() -> Path:
    directory = Path(os.path.expanduser(os.getenv("X19_ENGAGEMENTS_DIR", "~/.x19/engagements")))
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def profile_path(name: str) -> Path:
    return engagements_dir() / f"{name}.json"


# ---------------------------------------------------------------------------
# Guidance blocks
# ---------------------------------------------------------------------------
@dataclass
class AttackSurface:
    """Card 1 — give discovery a head start."""

    api_specs: List[str] = field(default_factory=list)     # OpenAPI / Swagger / SOAP files
    docs: List[str] = field(default_factory=list)          # architecture notes, READMEs
    endpoints: List[str] = field(default_factory=list)     # explicit route hints
    source_files: List[str] = field(default_factory=list)  # route files, controllers
    credentials: List[Dict[str, str]] = field(default_factory=list)  # label/username/secret/scope
    limit_to_listed: bool = False                          # "only test what I listed"

    def is_empty(self) -> bool:
        return not (self.api_specs or self.docs or self.endpoints or self.source_files or self.credentials)


@dataclass
class Priorities:
    """Card 2 — what to care about."""

    focus: List[str] = field(default_factory=list)
    deprioritize: List[str] = field(default_factory=list)
    vuln_classes: List[str] = field(default_factory=list)
    max_findings: int = 0  # 0 = unlimited


@dataclass
class AttackStrategy:
    """Card 3 — what the attack agents should try."""

    payload_formats: List[str] = field(default_factory=list)
    exploit_knowledge: str = ""
    known_weaknesses: List[str] = field(default_factory=list)
    allow_destructive: bool = False
    notes: str = ""


@dataclass
class Validation:
    """Card 4 — how a finding earns the right to be reported."""

    canaries: List[Dict[str, str]] = field(default_factory=list)  # label/value/kind
    require_poc: bool = True
    min_severity: str = "info"

    def canary_values(self) -> List[str]:
        return [str(c.get("value", "")).strip() for c in self.canaries if str(c.get("value", "")).strip()]


@dataclass
class MissionBudget:
    """Hard ceilings for one run. Zero disables a ceiling."""

    max_seconds: int = 1800
    max_llm_calls: int = 200
    max_commands: int = 500
    #: Consecutive cycles with no new evidence before the run stops early.
    early_stop_stalls: int = 3
    #: Plan checkpoints as a percentage of the budget (Cyber-AutoAgent pattern).
    checkpoints: List[int] = field(default_factory=lambda: [20, 40, 60, 80])

    def checkpoint_at(self, pct: float) -> bool:
        """True once ``pct`` (0-100, same scale as ``BudgetState.pct_used``) has
        reached at least one configured checkpoint."""
        return any(float(point) <= float(pct) for point in self.checkpoints)

    def next_checkpoint(self, pct: float, consumed: Iterable[int]) -> Optional[int]:
        """Lowest checkpoint reached by ``pct`` that is not already in ``consumed``.

        Comparing with ``>=`` instead of a narrow band matters: budget use is
        sampled once per cycle, so a 20 % checkpoint can be jumped straight over
        by a cycle that lands on 27 %. Returns ``None`` when there is nothing new.
        """
        done = {int(point) for point in consumed}
        for point in sorted(int(p) for p in self.checkpoints):
            if point not in done and float(point) <= float(pct):
                return point
        return None


@dataclass
class LoopGuardConfig:
    """Hermes-style anti-loop guardrails.

    ``warn_after`` injects a warning into the agent's context; ``hard_stop_after``
    refuses the call. Hard stops default to on because an unattended assessment
    has no human to notice a stuck loop.
    """

    warn_after: Dict[str, int] = field(
        default_factory=lambda: {"exact_failure": 2, "same_tool_failure": 3, "idempotent_no_progress": 2}
    )
    hard_stop_after: Dict[str, int] = field(
        default_factory=lambda: {"exact_failure": 5, "same_tool_failure": 8, "idempotent_no_progress": 5}
    )
    hard_stop_enabled: bool = True
    max_parallel_agents: int = 4
    max_retries_per_task: int = 2


# ---------------------------------------------------------------------------
# Profile
# ---------------------------------------------------------------------------
@dataclass
class EngagementProfile:
    """Everything an assessment needs to know before it starts attacking."""

    name: str
    target: str = ""
    targets: List[str] = field(default_factory=list)
    target_type: str = "auto"
    rules_of_engagement: str = ""
    out_of_scope: List[str] = field(default_factory=list)

    attack_surface: AttackSurface = field(default_factory=AttackSurface)
    priorities: Priorities = field(default_factory=Priorities)
    strategy: AttackStrategy = field(default_factory=AttackStrategy)
    validation: Validation = field(default_factory=Validation)
    budget: MissionBudget = field(default_factory=MissionBudget)
    guardrails: LoopGuardConfig = field(default_factory=LoopGuardConfig)

    created_at: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%S"))
    updated_at: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%S"))
    schema_version: int = PROFILE_SCHEMA_VERSION

    # -- scope -------------------------------------------------------------
    def scope_allowlist(self) -> List[str]:
        """Every host the assessment is permitted to touch."""
        seen: List[str] = []
        for entry in ([self.target] if self.target else []) + list(self.targets):
            entry = str(entry).strip()
            if entry and entry not in seen:
                seen.append(entry)
        return seen

    def is_in_scope(self, host: str) -> bool:
        """Explicit ``out_of_scope`` entries win over the allowlist."""
        host = str(host or "").strip().lower()
        if not host:
            return False
        if any(host == o.lower() or host.endswith("." + o.lower().lstrip("*.")) for o in self.out_of_scope):
            return False
        return host in [t.lower() for t in self.scope_allowlist()]

    # -- validation ----------------------------------------------------------
    def severity_allowed(self, severity: str) -> bool:
        """True when a finding of ``severity`` clears ``validation.min_severity``.

        Fails closed: an unparseable severity label is never reportable. Treating
        an unknown label as ``info`` would let a mislabelled finding through
        whenever the floor was ``info``, which is the wrong default for a filter.
        """
        severity = str(severity or "").strip().lower()
        floor = self.validation.min_severity
        if floor not in SEVERITIES:
            floor = "info"
        if severity not in SEVERITIES:
            return False
        return SEVERITIES.index(severity) <= SEVERITIES.index(floor)

    # -- serialisation -------------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EngagementProfile":
        known = {f.name for f in fields(cls)}
        payload = {k: v for k, v in data.items() if k in known}
        for key, klass in (
            ("attack_surface", AttackSurface),
            ("priorities", Priorities),
            ("strategy", AttackStrategy),
            ("validation", Validation),
            ("budget", MissionBudget),
            ("guardrails", LoopGuardConfig),
        ):
            block = payload.get(key)
            if isinstance(block, dict):
                allowed = {f.name for f in fields(klass)}
                payload[key] = klass(**{k: v for k, v in block.items() if k in allowed})
        return cls(**payload)

    def save(self) -> Path:
        self.updated_at = time.strftime("%Y-%m-%dT%H:%M:%S")
        path = profile_path(self.name)
        path.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")
        return path

    # -- guidance text -------------------------------------------------------
    def guidance_block(self) -> str:
        """The profile as instructions the agents can read.

        This is the terminal analogue of XBOW's Target Context: one compact
        block that every stage receives instead of each agent guessing.
        """
        lines = [f"ENGAGEMENT: {self.name}", f"TARGET: {self.target or ', '.join(self.targets) or 'unset'}"]
        if self.scope_allowlist():
            lines.append(f"IN-SCOPE: {', '.join(self.scope_allowlist())}")
        if self.out_of_scope:
            lines.append(f"OUT-OF-SCOPE: {', '.join(self.out_of_scope)}")
        if self.target_type != "auto":
            lines.append(f"ENGAGEMENT TYPE: {self.target_type}")
        if self.rules_of_engagement:
            lines.append(f"RULES: {self.rules_of_engagement}")

        surface = self.attack_surface
        if not surface.is_empty():
            parts = []
            if surface.api_specs:
                parts.append(f"api_specs={len(surface.api_specs)}")
            if surface.endpoints:
                parts.append(f"endpoints={len(surface.endpoints)}")
            if surface.credentials:
                parts.append(f"credentials={len(surface.credentials)}")
            if surface.limit_to_listed:
                parts.append("limit-to-listed")
            lines.append("ATTACK SURFACE: " + ", ".join(parts))
            # Counts alone are useless to an agent; the whole point of this card
            # is that the fleet starts already knowing the routes and the specs.
            for label, values in (
                ("KNOWN ROUTES", surface.endpoints),
                ("API SPECS", surface.api_specs),
                ("SOURCE FILES", surface.source_files),
                ("DOCS", surface.docs),
            ):
                listed = [str(v) for v in values if str(v).strip()][:_MAX_GUIDANCE_ITEMS]
                if listed:
                    suffix = "" if len(values) <= _MAX_GUIDANCE_ITEMS else f" (+{len(values) - len(listed)} more)"
                    lines.append(f"{label}: {', '.join(listed)}{suffix}")
            if surface.credentials:
                # Labels only — secrets are handed to agents out of band.
                labels = [str(c.get("label") or c.get("username") or "credential")
                          for c in surface.credentials][:_MAX_GUIDANCE_ITEMS]
                lines.append(f"CREDENTIAL LABELS: {', '.join(labels)} (secrets redacted)")
        if self.priorities.focus:
            lines.append(f"PRIORITIES: focus on {', '.join(self.priorities.focus)}")
        if self.priorities.deprioritize:
            lines.append(f"DEPRIORITIZE: {', '.join(self.priorities.deprioritize)}")
        if self.priorities.vuln_classes:
            lines.append(f"VULN CLASSES: {', '.join(self.priorities.vuln_classes)}")
        # Card 3 keeps its own header so agents see the same four-part structure
        # the profile UI shows, even when only one field is filled in.
        strategy_parts = []
        if self.strategy.payload_formats:
            strategy_parts.append(f"payload_formats={', '.join(self.strategy.payload_formats)}")
        if self.strategy.known_weaknesses:
            strategy_parts.append(f"known_weaknesses={', '.join(self.strategy.known_weaknesses)}")
        if self.strategy.exploit_knowledge:
            strategy_parts.append(f"exploit_knowledge={self.strategy.exploit_knowledge}")
        if self.strategy.notes:
            strategy_parts.append(f"notes={self.strategy.notes}")
        strategy_parts.append(
            "destructive=" + ("allowed" if self.strategy.allow_destructive else "forbidden")
        )
        lines.append("ATTACK STRATEGY: " + "; ".join(strategy_parts))
        lines.append(
            "VALIDATION: "
            + ("PoC required" if self.validation.require_poc else "PoC optional")
            + f", min severity {self.validation.min_severity}"
            + (f", {len(self.validation.canaries)} canary(ies)" if self.validation.canaries else "")
        )
        lines.append(
            f"BUDGET: {self.budget.max_seconds}s / {self.budget.max_commands} commands / "
            f"{self.budget.max_llm_calls} llm calls"
        )
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Validation & storage helpers
# ---------------------------------------------------------------------------
def validate_name(name: str) -> None:
    if not _NAME_RE.match(str(name or "")):
        raise ValueError(
            f"invalid profile name {name!r} — use lowercase letters, digits, '.', '_', '-' (max 64 chars)"
        )


def validate_profile(profile: EngagementProfile) -> List[str]:
    """Return a list of human-readable problems. Empty list == valid."""
    problems: List[str] = []
    if not profile.name:
        problems.append("profile has no name")
    else:
        try:
            validate_name(profile.name)
        except ValueError as exc:
            problems.append(str(exc))
    if not profile.scope_allowlist():
        problems.append("no target or targets set — nothing is in scope")
    if profile.target_type not in TARGET_TYPES:
        problems.append(f"target_type must be one of {', '.join(TARGET_TYPES)}")
    if profile.validation.min_severity not in SEVERITIES:
        problems.append(f"min_severity must be one of {', '.join(SEVERITIES)}")
    if profile.budget.max_seconds < 0 or profile.budget.max_commands < 0:
        problems.append("budget values cannot be negative")
    if not profile.strategy.allow_destructive and profile.target_type == "auto":
        problems.append(
            "target_type is 'auto' — set authorized/ctf/lab explicitly before allowing attacks"
        )
    for spec in profile.attack_surface.api_specs + profile.attack_surface.source_files:
        if not Path(os.path.expanduser(spec)).exists():
            problems.append(f"attack-surface file not found: {spec}")
    return problems


def list_profiles() -> List[Dict[str, Any]]:
    """Every saved profile as a summary dict, newest first."""
    rows: List[Dict[str, Any]] = []
    for path in sorted(engagements_dir().glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        rows.append(
            {
                "name": data.get("name", path.stem),
                "target": data.get("target", ""),
                "target_type": data.get("target_type", "auto"),
                "targets": len(data.get("targets") or []),
                "updated_at": data.get("updated_at", ""),
                "path": str(path),
                "has_canaries": bool((data.get("validation") or {}).get("canaries")),
                "has_credentials": bool((data.get("attack_surface") or {}).get("credentials")),
            }
        )
    rows.sort(key=lambda r: str(r.get("updated_at", "")), reverse=True)
    return rows


def load_profile(name: str) -> Optional[EngagementProfile]:
    path = profile_path(name)
    if not path.exists():
        return None
    try:
        return EngagementProfile.from_dict(json.loads(path.read_text(encoding="utf-8")))
    except Exception:
        return None


def delete_profile(name: str) -> bool:
    path = profile_path(name)
    if path.exists():
        path.unlink()
        return True
    return False


def ad_hoc_profile(target: str, *, target_type: str = "auto", name: str = "") -> EngagementProfile:
    """Build a throwaway profile for ``x19 run -t host`` with no saved profile.

    Deliberately conservative: recon-classified, no destructive testing, PoC
    required. A bare target on the command line is not authorization.
    """
    return EngagementProfile(
        name=name or f"adhoc-{re.sub(r'[^a-z0-9._-]', '-', str(target).lower())[:40]}",
        target=target,
        targets=[target],
        target_type=target_type if target_type in TARGET_TYPES else "auto",
        rules_of_engagement="Ad-hoc run: no engagement profile supplied.",
        strategy=AttackStrategy(allow_destructive=False),
        validation=Validation(require_poc=True, min_severity="low"),
    )


def mask_secret(value: str) -> str:
    text = str(value or "")
    if not text:
        return ""
    if len(text) <= 8:
        return "•" * len(text)
    return f"{text[:3]}{'•' * 6}{text[-3:]}"


def redact(data: Any) -> Any:
    """Deep-copy ``data`` with secret-looking values masked, for display/JSON."""
    if isinstance(data, dict):
        return {
            key: (mask_secret(value) if any(s in key.lower() for s in SECRET_KEYS) and value else redact(value))
            for key, value in data.items()
        }
    if isinstance(data, list):
        return [redact(item) for item in data]
    return data
