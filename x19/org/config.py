"""X19 organization settings, resolved from the real config layer.

Deliberately narrow.  This module configures **how the organization executes**.
It does *not* configure the roster: roles are registered in code
(:mod:`x19.org.roles`) and may be added at runtime, so a team list in config
would drift from the registry that actually runs the work — and the registry is
the only thing the status, audit and UI layers are allowed to read.

Every key here has a consumer.  There is no decorative configuration:

===========================  ==============================================
``org.state_dir``            where the operating record is persisted
``org.persist``              whether it is persisted at all
``org.stale_after_seconds``  when an idle-but-active role is marked stale
``execution.max_attempts``   retry budget per worker task
``execution.max_parallel``   tasks dispatched in one pass
``authority.approval_roles`` roles whose tasks need operator sign-off first
===========================  ==============================================

Human authority cannot be configured away: there is no ``auto_approve`` switch.
A pending approval always blocks dispatch until an operator resolves it.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Dict, Mapping, Optional, Tuple

__all__ = ["OrgSettings", "DEFAULT_ORG_SETTINGS", "load_org_settings"]


def _clamp(value: Any, low: float, high: float, default: float) -> float:
    try:
        n = float(value)
    except (TypeError, ValueError):
        return default
    if n != n:  # NaN
        return default
    return max(low, min(high, n))


@dataclass(frozen=True)
class OrgSettings:
    """Resolved organization settings."""

    # org
    state_dir: str = ""
    persist: bool = True
    stale_after_seconds: float = 900.0
    # execution
    max_attempts: int = 3
    max_parallel_dispatch: int = 4
    # authority
    approval_required_roles: Tuple[str, ...] = ()

    def requires_approval(self, role_id: Optional[str]) -> bool:
        """True when *role_id* is configured to need operator sign-off."""
        return bool(role_id) and role_id in self.approval_required_roles

    def to_dict(self) -> Dict[str, Any]:
        return {
            "state_dir": self.state_dir,
            "persist": self.persist,
            "stale_after_seconds": self.stale_after_seconds,
            "max_attempts": self.max_attempts,
            "max_parallel_dispatch": self.max_parallel_dispatch,
            "approval_required_roles": list(self.approval_required_roles),
        }


DEFAULT_ORG_SETTINGS = OrgSettings()

_BOUNDS = {
    "stale_after_seconds": (30.0, 86_400.0),
    "max_attempts": (1, 10),
    "max_parallel_dispatch": (1, 32),
}


def _string_tuple(value: Any) -> Tuple[str, ...]:
    if isinstance(value, str):
        items = [p.strip() for p in value.split(",")]
    elif isinstance(value, (list, tuple, set)):
        items = [str(v).strip() for v in value]
    else:
        return ()
    return tuple(dict.fromkeys(i for i in items if i))


def load_org_settings(config: Optional[Mapping[str, Any]] = None) -> OrgSettings:
    """Resolve :class:`OrgSettings` from the real config, clamped to safe ranges.

    Never raises: an unreadable or malformed config yields the defaults, because
    a bad ``config.yaml`` must not stop the organization from running.
    """
    if config is None:
        try:
            from x19_cli.config import load_config_readonly

            config = load_config_readonly() or {}
        except Exception:
            config = {}

    section = config.get("x19") if isinstance(config, Mapping) else None
    if not isinstance(section, Mapping):
        return DEFAULT_ORG_SETTINGS

    org = section.get("org") if isinstance(section.get("org"), Mapping) else {}
    exe = section.get("execution") if isinstance(section.get("execution"), Mapping) else {}
    auth = section.get("authority") if isinstance(section.get("authority"), Mapping) else {}

    s = DEFAULT_ORG_SETTINGS
    s = replace(s, state_dir=str(org.get("state_dir") or "").strip())
    if isinstance(org.get("persist"), bool):
        s = replace(s, persist=org["persist"])

    s = replace(
        s,
        stale_after_seconds=_clamp(
            org.get("stale_after_seconds"), *_BOUNDS["stale_after_seconds"], s.stale_after_seconds
        ),
        max_attempts=int(
            _clamp(exe.get("max_attempts"), *_BOUNDS["max_attempts"], s.max_attempts)
        ),
        max_parallel_dispatch=int(
            _clamp(exe.get("max_parallel"), *_BOUNDS["max_parallel_dispatch"], s.max_parallel_dispatch)
        ),
        approval_required_roles=_string_tuple(auth.get("approval_roles")),
    )
    return s
