"""Adversarial self-review for high-impact findings (XBOW-style debate).

Naptime/Big Sleep's core principle is *perfect verification*: a critical claim
is only reported when the evidence is unambiguous. X19's first verification
pass (4-gate validation + LLM verify) is necessarily optimistic — the same
model that proposed the finding judges it. XBOW's answer is internal debate:
independent reviewer models evaluate every discovery before it is reported.

This module adds the second, *hostile* reviewer. Only critical/high findings
pay the extra model call. The reviewer's default stance is "this is a false
positive" and it must be argued out of that position. A disagreement demotes
the finding back to a lead (the loop keeps hunting instead of reporting a
probable false positive); an unreachable reviewer fails open so the pipeline
never bricks on a transient model error.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict

_REVIEW_SYSTEM = (
    "You are a hostile senior vulnerability reviewer. Your default stance is "
    "that every report is a FALSE POSITIVE: scanner noise, a default page, an "
    "expected error, or evidence misread from output. You accept a finding "
    "only when the claimed evidence is unambiguous and really present in the "
    "provided command output. You never take the reporter's word for it."
)

_REVIEW_INSTRUCTIONS = """Decide if this finding should be REPORTED or is a FALSE POSITIVE.

FINDING UNDER REVIEW
  title:    {title}
  severity: {severity}
  claim:    {detail}
  claimed evidence: {evidence}

ACTUAL COMMAND OUTPUT (may be truncated)
---
{output}
---

Rules:
- If the claimed evidence does NOT appear (verbatim or as a regex-compatible
  match) in the actual output, the finding is a false positive.
- Generic error pages, 403/404/302 responses, default banners and "not found"
  messages are NOT vulnerabilities, whatever the title says.
- A real critical/high leaves no doubt: an executed command's output, a
  returned secret/file, a definitive version banner with a known exploit, an
  OOB callback, or an authenticated action that should have been impossible.

Respond with EXACTLY one JSON object and nothing else:
{{"verdict": "real|false_positive|unsure", "reason": "<one tight sentence>"}}"""


def adversarial_review(ai: Any, finding: Dict[str, Any], output: str,
                       target: str = "") -> Dict[str, str]:
    """Run the hostile second review. Never raises.

    Returns {"verdict": "real" | "false_positive" | "unsure", "reason": str}.
    "unsure" is treated as pass-through by callers (fail-open): a reviewer
    outage must not block an otherwise verified critical finding.
    """
    if ai is None or not isinstance(finding, dict) or not finding.get("title"):
        return {"verdict": "unsure", "reason": "reviewer unavailable"}
    prompt = _REVIEW_INSTRUCTIONS.format(
        title=str(finding.get("title") or "")[:200],
        severity=str(finding.get("severity") or "info")[:20],
        detail=str(finding.get("detail") or "")[:600],
        evidence=str(finding.get("evidence") or "")[:600],
        output=str(output or "")[:4000],
    )
    try:
        raw = ai.chat(_REVIEW_SYSTEM, prompt)
    except Exception as exc:  # reviewer outage — fail open
        return {"verdict": "unsure", "reason": f"reviewer error: {exc}"[:120]}
    if not raw:
        return {"verdict": "unsure", "reason": "empty review"}
    return parse_review(raw)


def parse_review(raw: str) -> Dict[str, str]:
    """Parse the reviewer's JSON verdict out of raw model text."""
    decoder = json.JSONDecoder()
    idx = raw.find("{")
    while idx != -1:
        try:
            obj, end = decoder.raw_decode(raw, idx)
        except json.JSONDecodeError:
            obj, end = None, idx + 1
        if isinstance(obj, dict) and "verdict" in obj:
            verdict = str(obj.get("verdict") or "").strip().lower()
            if verdict in ("real", "false_positive", "false-positive"):
                if verdict == "false-positive":
                    verdict = "false_positive"
                reason = str(obj.get("reason") or "").strip()[:300]
                return {"verdict": verdict, "reason": reason}
            break
        idx = raw.find("{", end)
    # Fallback: bare-word verdict in prose ("verdict: false_positive").
    m = re.search(r'verdict["\s:]+(real|false[_-]?positive|unsure)', raw, re.I)
    if m:
        v = m.group(1).lower().replace("-", "_")
        return {"verdict": v, "reason": "prose verdict"}
    return {"verdict": "unsure", "reason": "unparseable review"}
