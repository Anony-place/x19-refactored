"""Learning subsystem interfaces for X19.

Phase 1 stub — logic still lives in the root-level memory.py and
self_improve.py modules. This package re-exports those symbols so new
code can gradually migrate to package imports.
"""

from __future__ import annotations

from memory import (
    ChromaMemory,
    PGVectorMemory,
    BackgroundLearner,
    _memory_disabled,
    is_actionable_technique,
    technique_metadata,
    is_bug_bounty_mode,
    is_ctf_mode,
    is_fast_mode,
)
from self_improve import (
    SelfAwareness,
    PerformanceAnalyzer,
    CodeSurgeon,
    CodePatch,
    PatchResult,
    ImprovementSuggestion,
    Bottleneck,
    mid_session_self_improve,
)

__all__ = [
    "ChromaMemory",
    "PGVectorMemory",
    "BackgroundLearner",
    "_memory_disabled",
    "is_actionable_technique",
    "technique_metadata",
    "is_bug_bounty_mode",
    "is_ctf_mode",
    "is_fast_mode",
    "SelfAwareness",
    "PerformanceAnalyzer",
    "CodeSurgeon",
    "CodePatch",
    "PatchResult",
    "ImprovementSuggestion",
    "Bottleneck",
    "mid_session_self_improve",
]
