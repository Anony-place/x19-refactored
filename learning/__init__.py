"""Learning subsystem interfaces for X19.

Phase 1 stub — logic still lives in the root-level memory.py and
self_improve.py modules. This package re-exports those symbols so new
code can gradually migrate to package imports.
"""

from __future__ import annotations

try:
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
except Exception:
    ChromaMemory = PGVectorMemory = BackgroundLearner = None  # type: ignore
    _memory_disabled = lambda: True  # type: ignore
    is_actionable_technique = lambda *a, **kw: False  # type: ignore
    technique_metadata = lambda *a, **kw: {}  # type: ignore
    is_bug_bounty_mode = lambda *a, **kw: False  # type: ignore
    is_ctf_mode = lambda *a, **kw: False  # type: ignore
    is_fast_mode = lambda *a, **kw: False  # type: ignore
try:
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
except Exception:
    SelfAwareness = PerformanceAnalyzer = CodeSurgeon = None  # type: ignore
    CodePatch = PatchResult = ImprovementSuggestion = Bottleneck = None  # type: ignore
    mid_session_self_improve = lambda *a, **kw: None  # type: ignore
try:
    from learning.episodic_memory import EpisodicMemory, Episode  # type: ignore
except Exception:
    EpisodicMemory = Episode = None  # type: ignore

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
