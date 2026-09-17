"""Evidence coverage matrix for autonomous security assessments.

The matrix tracks endpoint x security-domain coverage as a first-class state
object. It is advisory: it never forces an exploit or bypasses policy. The
planner can use uncovered cells to choose the next discriminating experiment,
while completed cells retain provenance so the UI/report can explain what was
actually tested.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Iterable, List


DEFAULT_DOMAINS = (
    "injection",
    "access-control",
    "authentication",
    "session",
    "ssrf",
    "file-handling",
    "xss",
    "request-smuggling",
    "misconfiguration",
    "business-logic",
    "api",
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass
class CoverageCell:
    endpoint: str
    domain: str
    status: str = "untested"  # untested|testing|covered|blocked|not-applicable
    evidence_ids: List[str] = field(default_factory=list)
    last_command: str = ""
    updated_at: str = field(default_factory=_now)

    def mark(self, status: str, *, evidence_id: str = "", command: str = "") -> None:
        self.status = status
        if evidence_id and evidence_id not in self.evidence_ids:
            self.evidence_ids.append(evidence_id)
        if command:
            self.last_command = command
        self.updated_at = _now()


@dataclass
class CoverageMatrix:
    domains: tuple[str, ...] = DEFAULT_DOMAINS
    cells: Dict[str, CoverageCell] = field(default_factory=dict)

    @staticmethod
    def _key(endpoint: str, domain: str) -> str:
        return f"{endpoint}|{domain}"

    def ensure_endpoint(self, endpoint: str) -> None:
        endpoint = str(endpoint or "").strip()
        if not endpoint:
            return
        for domain in self.domains:
            key = self._key(endpoint, domain)
            self.cells.setdefault(key, CoverageCell(endpoint=endpoint, domain=domain))

    def mark(self, endpoint: str, domain: str, status: str,
             *, evidence_id: str = "", command: str = "") -> None:
        endpoint = str(endpoint or "").strip()
        domain = str(domain or "").strip().lower()
        if not endpoint or domain not in self.domains:
            return
        self.ensure_endpoint(endpoint)
        self.cells[self._key(endpoint, domain)].mark(
            status, evidence_id=evidence_id, command=command
        )

    def uncovered(self, *, limit: int = 20) -> List[CoverageCell]:
        rows = [cell for cell in self.cells.values() if cell.status in {"untested", "testing"}]
        rows.sort(key=lambda c: (c.status != "testing", c.endpoint, c.domain))
        return rows[:limit]

    def summary(self) -> dict:
        counts: Dict[str, int] = {}
        for cell in self.cells.values():
            counts[cell.status] = counts.get(cell.status, 0) + 1
        total = len(self.cells)
        covered = counts.get("covered", 0)
        return {
            "total": total,
            "covered": covered,
            "untested": counts.get("untested", 0),
            "testing": counts.get("testing", 0),
            "blocked": counts.get("blocked", 0),
            "not_applicable": counts.get("not-applicable", 0),
            "ratio": round(covered / total, 3) if total else 0.0,
        }

    def context_block(self, *, limit: int = 12) -> str:
        if not self.cells:
            return ""
        s = self.summary()
        lines = [
            "ATTACK-SURFACE COVERAGE:",
            f"  covered={s['covered']}/{s['total']} ({s['ratio']:.0%}) "
            f"untested={s['untested']} blocked={s['blocked']}",
        ]
        for cell in self.uncovered(limit=limit):
            lines.append(f"  · {cell.endpoint} × {cell.domain} → {cell.status}")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "domains": list(self.domains),
            "summary": self.summary(),
            "cells": {
                key: {
                    "endpoint": cell.endpoint,
                    "domain": cell.domain,
                    "status": cell.status,
                    "evidence_ids": list(cell.evidence_ids),
                    "last_command": cell.last_command,
                    "updated_at": cell.updated_at,
                }
                for key, cell in self.cells.items()
            },
        }
