"""Gate for frontier models rated at their vendor's highest cyber tier.

GPT-6 Astra (OpenAI, September 2026) is the first model OpenAI rated **Critical**
for cybersecurity under its Preparedness Framework — autonomous zero-day
discovery and exploitation. OpenAI gates advanced cyber workflows behind
Daybreak / Trusted Access for Cyber. Anthropic routes pentest work to a
verification-program model on the same basis.

X19 cannot verify a user's access tier, so it does not assume one. When the
active model matches a known critical-tier pattern, the exploitation phase is
refused unless the engagement is explicitly classified as authorized research.
This is a policy gate, not a security boundary — it keeps X19 from being the
thing that routes unauthorized exploitation work through a model whose vendor
requires authorization for it.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Tuple

__all__ = [
    "TIER_CRITICAL",
    "TIER_STANDARD",
    "AUTHORIZED_TYPES",
    "EXPLOITATION_PHASES",
    "CRITICAL_CYBER_MODELS",
    "FrontierVerdict",
    "is_critical_cyber_model",
    "model_tier",
    "check_model_for_phase",
    "check_model_for_target_data",
    "gate_status",
]

TIER_CRITICAL = "critical_cyber"
TIER_STANDARD = "standard"

#: Engagement classifications that constitute explicit authorization to exploit.
#: ``auto`` and ``public_real_world`` deliberately do not qualify: a bare target
#: on a command line is not authorization.
AUTHORIZED_TYPES = ("authorized", "ctf", "lab")

#: Phases that constitute exploitation rather than observation.
#: Both vocabularies are accepted because the agent tracks a cognitive phase
#: ("exploitation") while its tool table is keyed by short phase ("exploit").
EXPLOITATION_PHASES = ("exploit", "exploitation")

#: ``(substring, human label)`` — matched case-insensitively against the model id.
#: Substring matching is intentional: providers prefix model ids with their own
#: namespace (``openai/gpt-6-astra``, ``anthropic/claude-mythos-5.1``).
CRITICAL_CYBER_MODELS: Tuple[Tuple[str, str], ...] = (
    ("gpt-6-astra", "OpenAI GPT-6 Astra — Critical under the Preparedness Framework"),
    ("gpt-5.6-cyber", "OpenAI GPT-5.6 Cyber (Daybreak Red) — Trusted Access for Cyber only"),
    ("daybreak", "OpenAI Daybreak Red tier — Trusted Access for Cyber only"),
    ("claude-mythos", "Anthropic Claude Mythos — Cyber Verification Program only"),
    ("mythos-5", "Anthropic Claude Mythos — Cyber Verification Program only"),
)


@dataclass
class FrontierVerdict:
    """Whether a gated model may be used for a given activity."""

    allowed: bool
    reason: str
    model: str = ""
    tier: str = TIER_STANDARD
    requires: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "model": self.model,
            "tier": self.tier,
            "requires": self.requires,
        }


def is_critical_cyber_model(model_id: Any) -> bool:
    """True when the model id matches a known critical-tier cyber model."""
    return model_tier(model_id) == TIER_CRITICAL


def model_tier(model_id: Any) -> str:
    """Classify a model id."""
    text = str(model_id or "").lower()
    if not text:
        return TIER_STANDARD
    for pattern, _label in CRITICAL_CYBER_MODELS:
        if pattern in text:
            return TIER_CRITICAL
    return TIER_STANDARD


def _label_for(model_id: Any) -> str:
    """Human-readable tier label. Never empty — `doctor` prints this directly."""
    text = str(model_id or "").lower()
    for pattern, label in CRITICAL_CYBER_MODELS:
        if pattern in text:
            return label
    if not text:
        return "no model resolved"
    return "not rated Critical for cyber — no exploitation restriction"


def _normalise_target_type(target_type: Any) -> str:
    return str(target_type or "auto").strip().lower() or "auto"


def check_model_for_phase(
    model_id: Any,
    target_type: Any,
    phase: Any,
) -> FrontierVerdict:
    """Gate the exploitation phase for critical-tier models.

    Observation phases (recon, enum, vuln, report) are never gated — scanning and
    reporting are not the activity the vendor restriction covers.
    """
    model = str(model_id or "")
    tier = model_tier(model)
    phase_name = str(phase or "").strip().lower()

    if tier != TIER_CRITICAL:
        return FrontierVerdict(True, "model is not a gated critical-tier cyber model",
                               model, TIER_STANDARD)

    if phase_name not in EXPLOITATION_PHASES:
        return FrontierVerdict(True, f"phase '{phase_name}' is observational, not gated",
                               model, TIER_CRITICAL)

    resolved = _normalise_target_type(target_type)
    if resolved in AUTHORIZED_TYPES:
        return FrontierVerdict(
            True,
            f"engagement is classified '{resolved}' — explicit authorization present",
            model, TIER_CRITICAL,
        )

    return FrontierVerdict(
        False,
        f"{_label_for(model)} is gated for exploitation, and target_type "
        f"'{resolved}' is not explicit authorization. Refusing to run the "
        f"exploitation phase through this model.",
        model,
        TIER_CRITICAL,
        requires=f"classify the engagement as one of {', '.join(AUTHORIZED_TYPES)} "
                 f"(x19 config set TARGET_TYPE authorized, or "
                 f"x19 engagement new <name> -t <target> --target-type authorized)",
    )


def check_model_for_target_data(model_id: Any, target_type: Any) -> FrontierVerdict:
    """Gate sending target specifics to a critical-tier model.

    Weaker than the phase gate: a model under a vendor cyber programme is
    expected to receive target context. This exists so an unclassified run
    against a public target does not silently ship reconnaissance of a system
    nobody authorized to a gated model.
    """
    model = str(model_id or "")
    tier = model_tier(model)
    if tier != TIER_CRITICAL:
        return FrontierVerdict(True, "model is not a gated critical-tier cyber model",
                               model, TIER_STANDARD)

    resolved = _normalise_target_type(target_type)
    if resolved == "public_real_world":
        return FrontierVerdict(
            False,
            f"refusing to send reconnaissance of an unclassified public target to "
            f"{_label_for(model)}",
            model, TIER_CRITICAL,
            requires="classify the engagement explicitly before using a gated model",
        )
    return FrontierVerdict(True, f"target_type '{resolved}' permits target context",
                           model, TIER_CRITICAL)


def gate_status(model_id: Any, target_type: Any) -> Dict[str, Any]:
    """Current gate state, for `doctor` and the workspace."""
    model = str(model_id or "")
    tier = model_tier(model)
    phase = check_model_for_phase(model, target_type, "exploit")
    data = check_model_for_target_data(model, target_type)
    return {
        "model": model,
        "tier": tier,
        "gated": tier == TIER_CRITICAL,
        "label": _label_for(model),
        "exploitation_allowed": phase.allowed,
        "target_data_allowed": data.allowed,
        "reason": phase.reason if not phase.allowed else data.reason,
        "requires": phase.requires or data.requires,
        "target_type": _normalise_target_type(target_type),
    }
