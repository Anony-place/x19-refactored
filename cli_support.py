"""Non-rendering helpers shared by the CLI commands and the interactive app.

Keeping this logic out of :mod:`ui` means ``x19 doctor --json`` and the
``/doctor`` slash command produce exactly the same result, and the checks stay
unit-testable without a console.
"""
from __future__ import annotations

import ast
import importlib
import os
import shutil
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parent

#: Modules that must import for a mission to run.
CRITICAL_MODULES = [
    "version",
    "config",
    "constants",
    "brain.coordinator",
    "brain.attack_graph",
    "brain.planner",
    "execution.command_gateway",
    "execution.policy_engine",
    "execution.scope_guard",
    "execution.native_net",
    "execution.native_fuzzer",
    "execution.native_vuln",
    "learning.self_adaptation",
    "reporting.report_generator",
    "reporting.compliance",
    "reporting.remediation",
    "brain.exploit_chain",
    "brain.frontier_gate",
    "ui.dashboard",
    "ui.screens",
]

#: Python packages X19 needs at runtime (extras are optional).
REQUIRED_PACKAGES = ["requests", "rich"]

#: Third-party binaries that materially extend coverage when installed.
PREFERRED_BINARIES = [
    "nmap", "masscan", "rustscan", "nuclei", "ffuf", "gobuster", "httpx",
    "whatweb", "sqlmap", "hydra", "searchsploit", "curl", "git", "ollama",
]


# ---------------------------------------------------------------------------
# Toolchain
# ---------------------------------------------------------------------------
def toolchain_rows() -> List[Dict[str, Any]]:
    """Map every binary referenced by a tool preset to its install state."""
    presets: Dict[str, List[str]] = {}
    try:
        from tools import TOOLS

        for name, spec in TOOLS.items():
            command = str(spec).split("|")[0].strip()
            binary = command.split()[0] if command else ""
            if not binary or binary.startswith("{"):
                continue
            presets.setdefault(binary, []).append(name)
    except Exception:
        pass

    for binary in PREFERRED_BINARIES:
        presets.setdefault(binary, [])

    rows = [
        {
            "binary": binary,
            "presets": sorted(names)[:6],
            "available": shutil.which(binary) is not None,
            "path": shutil.which(binary) or "",
        }
        for binary, names in sorted(presets.items())
    ]
    return rows


def toolchain_coverage() -> Dict[str, Any]:
    """Counts plus the binary names, so callers never have to re-derive them."""
    rows = toolchain_rows()
    preferred_rows = [row for row in rows if row["binary"] in PREFERRED_BINARIES]
    return {
        "total": len(rows),
        "installed": sum(1 for row in rows if row["available"]),
        "missing": [row["binary"] for row in rows if not row["available"]],
        "preferred_total": len(preferred_rows),
        "preferred_installed": sum(1 for row in preferred_rows if row["available"]),
        "preferred_missing": [row["binary"] for row in preferred_rows if not row["available"]],
        "rows": rows,
    }


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------
def list_sessions(limit: int = 50) -> List[Dict[str, Any]]:
    import json

    from config import CONFIG

    directory = Path(CONFIG.SESSIONS_DIR)
    rows: List[Dict[str, Any]] = []
    if not directory.exists():
        return rows
    for path in sorted(directory.glob("*.json"), reverse=True)[:limit]:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        rows.append(
            {
                "id": data.get("session_id", path.stem),
                "target": data.get("target", ""),
                "started": data.get("started", ""),
                "iterations": data.get("iterations", 0),
                "findings": len(data.get("findings") or []),
                "status": data.get("status", ""),
                "path": str(path),
            }
        )
    return rows


def load_session(session_id: str) -> Optional[Dict[str, Any]]:
    import json

    from config import CONFIG

    path = Path(CONFIG.SESSIONS_DIR) / f"{session_id}.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def latest_session() -> Optional[Dict[str, Any]]:
    rows = list_sessions(limit=1)
    return load_session(rows[0]["id"]) if rows else None


def session_findings(session_data: Dict[str, Any]) -> List[Any]:
    """Convert stored session findings into ``VulnerabilityFinding`` objects.

    Sessions persist findings as plain dicts; the report generator works on the
    typed dataclass, so this is the single conversion point between the two.
    """
    from execution.native_vuln import VulnerabilityFinding

    findings = []
    for entry in session_data.get("findings") or []:
        if isinstance(entry, VulnerabilityFinding):
            findings.append(entry)
            continue
        if not isinstance(entry, dict):
            continue
        findings.append(
            VulnerabilityFinding(
                title=str(entry.get("title", "Untitled finding")),
                severity=str(entry.get("severity", "info")).lower(),
                target=str(entry.get("target", session_data.get("target", ""))),
                endpoint=str(entry.get("endpoint", "")),
                description=str(entry.get("detail") or entry.get("description", "")),
                evidence=str(entry.get("evidence", "")),
                remediation=str(entry.get("remediation", "")),
                cvss_score=float(entry.get("cvss_score") or 0.0),
                cwe_id=str(entry.get("cwe_id", "")),
                poc_command=str(entry.get("poc_command", "")),
                confirmed=bool(entry.get("confirmed", True)),
                metadata={"recorded_at": entry.get("ts", "")},
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Diagnostics
# ---------------------------------------------------------------------------
def _syntax_errors() -> List[str]:
    problems: List[str] = []
    for path in sorted(ROOT.rglob("*.py")):
        parts = set(path.parts)
        if ".git" in parts or "__pycache__" in parts or ".venv" in parts:
            continue
        try:
            ast.parse(path.read_bytes(), filename=str(path))
        except SyntaxError as exc:
            problems.append(f"{path.relative_to(ROOT)}:{exc.lineno} {exc.msg}")
    return problems


def run_diagnostics(*, check_network: bool = False) -> Dict[str, Any]:
    """Run every health check and return ``{checks, score, detail}``."""
    from version import MIN_PYTHON, __version__

    checks: List[Dict[str, Any]] = []
    score = 100

    def add(name: str, status: str, detail: str, penalty: int = 0) -> None:
        nonlocal score
        checks.append({"name": name, "status": status, "detail": detail})
        score -= penalty

    # 1. interpreter
    running = sys.version_info[:2]
    if running >= MIN_PYTHON:
        add("python version", "pass", f"{'.'.join(map(str, running))} (>= {'.'.join(map(str, MIN_PYTHON))})")
    else:
        add("python version", "fail", f"{'.'.join(map(str, running))} is below {'.'.join(map(str, MIN_PYTHON))}", 25)

    # 2. dependencies
    missing_packages = []
    for package in REQUIRED_PACKAGES:
        try:
            importlib.import_module(package)
        except Exception as exc:
            missing_packages.append(f"{package} ({type(exc).__name__})")
    if missing_packages:
        add("python dependencies", "fail", "missing: " + ", ".join(missing_packages), 20)
    else:
        add("python dependencies", "pass", ", ".join(REQUIRED_PACKAGES))

    # 3. module integrity
    broken = []
    for module in CRITICAL_MODULES:
        try:
            importlib.import_module(module)
        except Exception as exc:
            broken.append(f"{module}: {type(exc).__name__}")
    if broken:
        add("module imports", "fail", "; ".join(broken[:3]), 20)
    else:
        add("module imports", "pass", f"{len(CRITICAL_MODULES)} critical modules")

    # 4. syntax
    problems = _syntax_errors()
    if problems:
        add("syntax", "fail", "; ".join(problems[:3]), 15)
    else:
        add("syntax", "pass", "all modules parse")

    # 5. configuration
    try:
        from constants import PROVIDERS
        from config import CONFIG, CONFIG_FILE, load_config

        config = load_config()
        if config:
            add("config file", "pass", str(CONFIG_FILE))
        else:
            add("config file", "warn", f"no saved config at {CONFIG_FILE} — run: x19 setup")
        provider = config.get("AI_PROVIDER") or CONFIG.AI_PROVIDER
        info = PROVIDERS.get(provider, {})
        key_env = info.get("api_key_env", "")
        if not info.get("needs_key", True) or os.getenv(key_env) or config.get(key_env):
            add("ai provider", "pass", f"{provider} ({key_env or 'no key required'})")
        else:
            add("ai provider", "warn", f"{provider} has no API key — run: x19 setup", 5)
        try:
            from provider_setup import configured_chain

            chain = configured_chain()
            add("failover chain", "pass" if chain else "warn",
                " → ".join(f"{c.get('provider')}/{c.get('model')}" for c in chain) or "not configured")
        except Exception as exc:
            add("failover chain", "warn", f"unreadable ({type(exc).__name__})")
    except Exception as exc:
        add("config file", "fail", f"{type(exc).__name__}: {exc}", 15)

    # 6. writable state directories
    try:
        from config import CONFIG

        for label, directory in (("sessions dir", CONFIG.SESSIONS_DIR), ("workspace", CONFIG.WORKSPACE)):
            path = Path(directory)
            path.mkdir(parents=True, exist_ok=True)
            probe = path / ".x19_write_probe"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink(missing_ok=True)
            add(label, "pass", str(path))
    except Exception as exc:
        add("state directories", "fail", f"{type(exc).__name__}: {exc}", 15)

    # 7. interface contract — the web UI must stay gone
    legacy = [name for name in ("webui.py", "webui_templates") if (ROOT / name).exists()]
    if legacy:
        add("cli-only contract", "fail", "web UI still present: " + ", ".join(legacy), 10)
    else:
        add("cli-only contract", "pass", "no web server, terminal interface only")

    # 8. toolchain
    coverage = toolchain_coverage()
    if coverage["preferred_installed"]:
        status = "pass" if not coverage["preferred_missing"] or coverage["preferred_installed"] >= 4 else "warn"
        add(
            "toolchain",
            status,
            f"{coverage['preferred_installed']}/{coverage['preferred_total']} preferred tools installed"
            + (f" (missing: {', '.join(coverage['preferred_missing'][:5])})" if coverage["preferred_missing"] else ""),
        )
    else:
        add("toolchain", "warn", "no preferred binaries found — native fallbacks will be used")

    # 9. optional network probe
    if check_network:
        try:
            import requests

            response = requests.get("https://api.github.com", timeout=8)
            add("network egress", "pass", f"api.github.com → HTTP {response.status_code}")
        except Exception as exc:
            add("network egress", "warn", f"{type(exc).__name__}: {exc}")

    # 10. frontier cyber-model gating. Vendors rate some models Critical for
    # cyber and gate advanced workflows behind access tiers X19 cannot inspect,
    # so the gate refuses exploitation unless the engagement is authorised.
    try:
        from brain.frontier_gate import gate_status
        from config import CONFIG, load_config
        from constants import PROVIDERS

        cfg = load_config()
        primary = cfg.get("AI_PROVIDER", CONFIG.AI_PROVIDER) or "openrouter"
        active_model = (
            cfg.get("AI_MODEL") or PROVIDERS.get(primary, {}).get("default_model", "")
        )
        status_info = gate_status(active_model, CONFIG.TARGET_TYPE)
        if not status_info["gated"]:
            add("frontier model gate", "pass",
                f"{active_model or '(provider default)'} — {status_info['label']}")
        elif status_info["exploitation_allowed"]:
            add("frontier model gate", "pass",
                f"{active_model} is Critical-tier cyber — target_type "
                f"'{CONFIG.TARGET_TYPE}' authorises exploitation")
        else:
            add("frontier model gate", "warn",
                f"{active_model} is Critical-tier cyber — exploitation blocked "
                f"(target_type '{CONFIG.TARGET_TYPE}')")
    except Exception as exc:  # a gate that cannot be read must not hide itself
        add("frontier model gate", "fail", f"{type(exc).__name__}: {exc}", 10)

    add("x19 version", "pass", __version__)

    return {
        "checks": checks,
        "score": max(0, score),
        "detail": "",
        "toolchain": coverage,
    }


# ---------------------------------------------------------------------------
# Provider bootstrap
# ---------------------------------------------------------------------------
def usable_providers() -> List[str]:
    """Provider ids that can actually serve a request right now.

    ``ollama`` only counts when the binary is on PATH — otherwise it would make
    every install look configured and the first-run wizard would never run.
    """
    from constants import PROVIDERS, _provider_has_key

    ollama_available = shutil.which("ollama") is not None
    usable = []
    for pid, info in PROVIDERS.items():
        if pid == "ollama":
            if ollama_available:
                usable.append(pid)
        elif _provider_has_key(pid):
            usable.append(pid)
    return usable


def resolve_provider() -> Optional[str]:
    """The provider X19 should use: the configured one if it works, else the
    best available one by failover priority."""
    from config import CONFIG, load_config
    from constants import PROVIDER_PRIORITY

    usable = usable_providers()
    if not usable:
        return None
    selected = load_config().get("AI_PROVIDER") or CONFIG.AI_PROVIDER or ""
    if selected in usable:
        return selected
    for pid in PROVIDER_PRIORITY:
        if pid in usable:
            return pid
    return usable[0]


def provider_configured() -> bool:
    """True when a usable provider already exists (no wizard needed)."""
    return resolve_provider() is not None


def ensure_provider_configured(*, force: bool = False) -> bool:
    """Run the first-run wizard only when it is actually needed.

    If a working provider exists but the saved ``AI_PROVIDER`` points at one
    that has no key, the saved value is corrected instead of failing later
    inside ``make_ai()``.
    """
    from config import CONFIG, load_config, set_data
    from provider_setup import setup_if_needed

    if not force:
        resolved = resolve_provider()
        if resolved:
            selected = load_config().get("AI_PROVIDER") or CONFIG.AI_PROVIDER or ""
            if selected != resolved:
                set_data({"AI_PROVIDER": resolved})
            return True
    return setup_if_needed(force=force)
