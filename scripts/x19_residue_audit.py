#!/usr/bin/env python3
"""Zero-residue audit for the legacy product identity.

X19 replaced an earlier product. This script is the auditable check that no
product *identity* from that earlier product survives in the tree, and that
every remaining occurrence of the legacy token is one of a small number of
explicitly justified classes.

It is deliberately conservative: anything it cannot justify is reported as
residue, so a new leak fails the audit rather than being silently absorbed.

Usage:
    python scripts/x19_residue_audit.py            # human-readable report
    python scripts/x19_residue_audit.py --json     # machine-readable
    python scripts/x19_residue_audit.py --strict   # exit 1 on any residue
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# The legacy product token. Matched case-insensitively; the classifier below
# decides whether each occurrence is justified.
TOKEN = "hermes"

# The legacy product name spelled in other scripts. A token scan for the Latin
# form cannot see these, and this is not hypothetical: the Urdu README carried
# the name ten times while the ASCII audit reported zero. Any hit is residue —
# there is no justified use of the legacy name in another script.
TRANSLITERATIONS = {
    "Urdu/Arabic script": "ہرمیس",
    "Arabic": "هرمس",
    "Chinese (simplified)": "赫尔墨斯",
    "Chinese (traditional)": "赫爾墨斯",
    "Japanese katakana": "ヘルメス",
    "Korean hangul": "헤르메스",
    "Russian cyrillic": "Гермес",
    "Greek": "Ερμής",
    "Hebrew": "הרמס",
    "Thai": "เฮอร์มีส",
}

# This script. It is the measuring instrument, so it necessarily spells the
# token it searches for — in `TOKEN`, in every classification pattern and in
# the comments explaining them. Reported as its own class rather than excluded
# from the scan, so the report stays a complete accounting of every line.
SELF_PATH = Path(__file__).resolve().relative_to(REPO).as_posix()

# The published audit report quotes the occurrences it classifies, including the
# adversarial probes, so it contains the token by construction. Counted as part
# of the tooling for the same reason: dropping it from the scan would make the
# reported totals stop matching a plain `git grep`.
REPORT_PATH = "X19_IDENTITY_AUDIT.md"

# ── Justified classes ────────────────────────────────────────────────
# Each entry: (class name, compiled pattern tested against the occurrence's
# surrounding line, and an optional path restriction).

MODEL_RE = re.compile(
    r"""(
        # `\b(?!>)` : a bare digit after a SPACE separator also matches shell
        # redirection — `which hermes 2>/dev/null` read as the model "Hermes 2",
        # which justified a legacy binary lookup as a model name. Real model
        # strings put `/`, `&`, `.` or a space after the digit, never `>`.
        hermes[-_. ]?(4|3|2)\b(?!>)       # Hermes-4, hermes_3, Hermes 4.5
      | hermes[-_. ]?4\.\d                # Hermes-4.5 / hermes-4.3
      | hermes[-_]3[-_]llama              # Hermes-3-Llama-3.1-405B
      | nousresearch/hermes               # provider-qualified model path
      | FP16_Hermes                       # local GGUF/MLX artifact naming
      | hermes-\d+-\d+b                   # hermes-4-405b
      | hermes[-_.]\d+[-_.]\d+b           # hermes_4_70b (underscore-separated id)
      | hermes-[a-z0-9]+:[a-z0-9.\-]*\d   # Modelfile tag: hermes-brain:qwen3-14b-ctx16k
      | hermes\d*-(instruct|beta|preview)
    )""",
    re.IGNORECASE | re.VERBOSE,
)

NPM_RE = re.compile(r"hermes-(parser|estree|engine)\b", re.IGNORECASE)

THIRD_PARTY_URL_RE = re.compile(
    r"(docs\.honcho\.dev|honcho)[^\s\"')]*hermes|hermes[^\s\"')]*honcho", re.IGNORECASE
)

# Upstream repositories we vendor or attribute. The repo name belongs to the
# third-party project, so renaming it would point at something that does not
# exist and break installs/attribution. Our own org is excluded explicitly: a
# `hermes` repo under it would be genuine residue, never justified.
THIRD_PARTY_REPO_RE = re.compile(
    r"github\.com/(?!Anony-place/)[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]*hermes[A-Za-z0-9_.-]*",
    re.IGNORECASE,
)

# Upstream Nous Research companion repositories. Each was verified live
# (HTTP 200) under this name and 404 under the renamed `x19-*` form the brand
# rewrite produced, so the real name is restored rather than left broken.
# Listed explicitly because a bare `NousResearch/hermes-...` slug would
# otherwise match MODEL_RE's provider-qualified model path and be reported as
# justified for the wrong reason — a model name, not a repository.
UPSTREAM_REPO_RE = re.compile(
    r"NousResearch/hermes-(?:example-plugins|plugin-snyk|plugin-touchdesigner"
    r"|memory-wiki|telegram-business|desktop-accent-picker)\b",
    re.IGNORECASE,
)

# Assertions that FORBID the legacy token. These lines are the residue check
# itself, so naming the token is the point — they are not residue.
GUARD_ASSERT_RE = re.compile(r"""assert\s+["']hermes["']\s+not\s+in""", re.IGNORECASE)

# The one regex that matches the Nous model FAMILY. Scoped to that named
# constant so it cannot become a general excuse for a legacy-token pattern:
# any other `re.compile(...hermes...)` is still reported as residue.
MODEL_PATTERN_RE = re.compile(
    r"_NOUS_CHAT_MODEL_NON_AGENTIC_RE\s*=\s*re\.compile\([^\n]*hermes", re.IGNORECASE
)

# Contributor attribution data: commit author emails preserved for git history.
CONTRIBUTOR_PATHS = ("contributors/emails/", ".mailmap")

# A security-research corpus that quotes third-party jailbreak prompt text
# verbatim. The token appears inside quoted material, not as our identity.
HISTORICAL_PATHS = (
    "optional-skills/security/godmode/references/jailbreak-templates.md",
)

# An email address carrying the token in either part: a contributor's alias
# domain (`…@nadyahermes.anonaddy.com`) is attribution data, not our identity.
EMAILISH_RE = re.compile(
    r"""(
        [A-Za-z0-9._%+-]*hermes[A-Za-z0-9._%+-]*@[A-Za-z0-9.-]+   # local part
      | [A-Za-z0-9._%+-]+@[A-Za-z0-9.-]*hermes[A-Za-z0-9.-]*       # domain part
    )""",
    re.IGNORECASE | re.VERBOSE,
)


def classify(path: str, line: str) -> tuple[str, str]:
    """Return ``(class, reason)`` for one occurrence.

    ``class`` is ``RESIDUE`` when the occurrence is not justified.
    """
    if path in (SELF_PATH, REPORT_PATH):
        return "audit-tooling", "the residue detector and its report; they name what they look for"

    if GUARD_ASSERT_RE.search(line):
        return "legacy-token-guard", "assertion forbidding the legacy token"

    if any(path.startswith(p) or f"/{p}" in path for p in CONTRIBUTOR_PATHS):
        return "contributor-attribution", "git history author email; kept for attribution"

    if EMAILISH_RE.search(line):
        return "contributor-attribution", "legacy author email address in history data"

    if any(path.endswith(p) or path.startswith(p) for p in HISTORICAL_PATHS):
        return "historical-corpus", "verbatim third-party research text, not product identity"

    if NPM_RE.search(line):
        return "third-party-dependency", "Facebook/Meta Hermes JS engine npm package"

    if THIRD_PARTY_REPO_RE.search(line):
        return "third-party-url", "upstream third-party repository we vendor or attribute"

    if THIRD_PARTY_URL_RE.search(line):
        return "third-party-url", "external documentation URL"

    if UPSTREAM_REPO_RE.search(line):
        return "third-party-url", "upstream Nous Research companion repository"

    if MODEL_RE.search(line):
        return "model-identifier", "Nous Research model name (real provider artifact)"

    if MODEL_PATTERN_RE.search(line):
        return "model-identifier", "pattern matching the Nous model family (provider artifact)"

    return "RESIDUE", "unjustified legacy product identity"


def occurrences() -> list[dict]:
    """Every occurrence of the token across tracked files, with its line."""
    files = subprocess.run(
        ["git", "grep", "-il", TOKEN, "--", "."],
        cwd=REPO, capture_output=True, text=True, check=False,
    ).stdout.split()

    out: list[dict] = []
    for rel in files:
        path = rel.lstrip("./")
        full = REPO / path
        if not full.is_file():
            continue
        try:
            text = full.read_text(errors="replace")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            if TOKEN not in line.lower():
                continue
            count = len(re.findall(TOKEN, line, re.IGNORECASE))
            cls, reason = classify(path, line)
            out.append(
                {
                    "path": path,
                    "line": lineno,
                    "count": count,
                    "class": cls,
                    "reason": reason,
                    "text": line.strip()[:160],
                }
            )
    return out


def transliteration_occurrences() -> list[dict]:
    """Occurrences of the legacy name spelled in a non-Latin script.

    Scanned separately because `git grep -i TOKEN` only sees the Latin form.
    Every hit is residue: no justified class spells the legacy product name in
    another script.
    """
    out: list[dict] = []
    for label, needle in TRANSLITERATIONS.items():
        files = subprocess.run(
            ["git", "grep", "-l", "-F", needle, "--", "."],
            cwd=REPO, capture_output=True, text=True, check=False,
        ).stdout.split()
        for rel in files:
            path = rel.lstrip("./")
            if path in (SELF_PATH, REPORT_PATH):
                # The detector and its report must spell what they look for.
                continue
            full = REPO / path
            if not full.is_file():
                continue
            try:
                text = full.read_text(errors="replace")
            except OSError:
                continue
            for lineno, line in enumerate(text.splitlines(), 1):
                count = line.count(needle)
                if not count:
                    continue
                out.append(
                    {
                        "path": path,
                        "line": lineno,
                        "count": count,
                        "class": "RESIDUE",
                        "reason": f"legacy product name in {label}",
                        "text": line.strip()[:160],
                    }
                )
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true", help="emit machine-readable findings")
    ap.add_argument("--strict", action="store_true", help="exit non-zero if residue is found")
    args = ap.parse_args()

    rows = occurrences() + transliteration_occurrences()
    residue = [r for r in rows if r["class"] == "RESIDUE"]
    justified = [r for r in rows if r["class"] != "RESIDUE"]

    if args.json:
        print(json.dumps({"residue": residue, "justified": justified}, indent=2))
        return 1 if (args.strict and residue) else 0

    by_class = Counter(r["class"] for r in rows)
    files_by_class: dict[str, set] = defaultdict(set)
    for r in rows:
        files_by_class[r["class"]].add(r["path"])

    print("X19 legacy-identity residue audit")
    print("=" * 62)
    print(f"tracked files containing '{TOKEN}': {len({r['path'] for r in rows})}")
    print(f"total occurrences (lines):          {len(rows)}")
    print()
    for cls, n in by_class.most_common():
        print(f"  {cls:<28} {n:>4} line(s) across {len(files_by_class[cls])} file(s)")

    if residue:
        print()
        print("RESIDUE — must be removed or justified:")
        for r in residue[:80]:
            print(f"  {r['path']}:{r['line']}: {r['text'][:110]}")
        if len(residue) > 80:
            print(f"  … and {len(residue) - 80} more")
    else:
        print()
        print("RESIDUE: none. Every remaining occurrence is a justified class.")

    return 1 if (args.strict and residue) else 0


if __name__ == "__main__":
    sys.exit(main())
