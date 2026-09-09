"""Bridge completed X19 sessions into reviewable procedural skills."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from config import CONFIG
from runtime.hermes_runtime import SkillStore


def _latest_session() -> Optional[Dict[str, Any]]:
    import json
    from pathlib import Path

    directory = Path(CONFIG.SESSIONS_DIR).expanduser()
    files = sorted(directory.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True) if directory.exists() else []
    if not files:
        return None
    try:
        return json.loads(files[0].read_text(encoding="utf-8"))
    except Exception:
        return None


def learn_from_latest_session() -> Optional[str]:
    """Promote observed successful session structure into procedural memory.

    This is intentionally evidence-derived: no source code is rewritten and no
    invented steps are added. The resulting skill is a normal Markdown file
    that can be reviewed or deleted before being reused.
    """
    if not CONFIG.AUTO_LEARN_SKILLS:
        return None
    session = _latest_session()
    if not session or str(session.get("status", "")).lower() not in {"completed", "success", "done"}:
        return None

    target = str(session.get("target", "unknown"))
    target_type = str(session.get("target_type") or CONFIG.TARGET_TYPE or "authorized")
    findings = session.get("findings") or []
    iterations = int(session.get("iterations") or 0)
    if not findings and iterations <= 0:
        return None

    # Only promote high-level observed workflow facts. Do not copy secrets or
    # raw credentials into procedural memory.
    successful_steps: List[str] = []
    for item in session.get("research_log") or []:
        if not isinstance(item, dict):
            continue
        result = str(item.get("result") or item.get("status") or "").lower()
        technique = str(item.get("technique") or item.get("tool") or "").strip()
        if technique and result not in {"fail", "failed", "error", "rejected"}:
            successful_steps.append(technique[:160])
    for finding in findings[:8]:
        if isinstance(finding, dict):
            title = str(finding.get("title") or "").strip()
            if title:
                successful_steps.append(f"verify candidate: {title[:160]}")

    # De-duplicate while preserving observed order.
    seen = set()
    successful_steps = [s for s in successful_steps if not (s in seen or seen.add(s))]
    if not successful_steps:
        successful_steps = [f"complete the X19 autonomous workflow ({iterations} iterations observed)"]

    safe_target = re.sub(r"[^a-z0-9]+", "-", target.lower()).strip("-")[:24] or "target"
    name = f"learned-{safe_target}"
    summary = (
        f"Completed X19 session against target class `{target_type}` with "
        f"{iterations} iterations and {len(findings)} recorded finding(s)."
    )
    SkillStore(CONFIG.SKILLS_DIR).promote_outcome(
        name=name,
        target_type=target_type,
        summary=summary,
        successful_steps=successful_steps[:20],
    )
    return name
