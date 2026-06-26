"""Reporting subsystem interfaces for X19.

Phase 1 stub — logic still lives in the root-level reporting.py module.
To avoid circular imports, this package re-exports the legacy module's
public symbols by loading it via importlib.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

_LEGACY_PATH = Path(__file__).resolve().parent.parent / "reporting.py"
_spec = importlib.util.spec_from_file_location("reporting._legacy", _LEGACY_PATH)
_legacy = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_legacy)

# Re-export known public symbols from the legacy module.
_LEGACY_EXPORTS = [
    "ReportWriter",
    "Finding",
    "TargetModel",
    "ThreatIntel",
    "OTX",
    "prioritize_findings",
    "build_report",
    "crtsh_subdomains",
    "nessus_scan",
    "remediation_for",
]

for _name in _LEGACY_EXPORTS:
    if hasattr(_legacy, _name):
        globals()[_name] = getattr(_legacy, _name)

__all__ = list(_LEGACY_EXPORTS)
