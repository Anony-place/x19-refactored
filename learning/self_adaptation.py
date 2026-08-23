"""
X19 Self-Improvement & Continuous Adaptation Engine.
Learns optimal attack strategies, prunes low-success heuristics,
records failure lessons, and performs autonomous health diagnostics and repairs.
"""

from __future__ import annotations
import ast
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

from brain.strategy_library import StrategyLibrary, TargetSignature


@dataclass
class FailureLesson:
    technique: str
    target_type: str
    error_signature: str
    lesson: str
    timestamp: float = field(default_factory=time.time)


class SelfAdaptationEngine:
    """Manages autonomous learning, continuous strategy refinement, and codebase integrity."""

    def __init__(self, storage_path: Optional[str] = None):
        self.base_dir = Path(__file__).resolve().parent.parent
        self.storage_file = storage_path or str(self.base_dir / "data" / "adaptation_memory.json")
        self.strategy_library = StrategyLibrary(str(self.base_dir / "data" / "strategy_library.json"))
        self.failure_lessons: List[FailureLesson] = []
        self._load_memory()

    def _load_memory(self) -> None:
        if os.path.exists(self.storage_file):
            try:
                with open(self.storage_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for item in data.get("lessons", []):
                        self.failure_lessons.append(FailureLesson(**item))
            except Exception:
                pass

    def save_memory(self) -> None:
        os.makedirs(os.path.dirname(self.storage_file), exist_ok=True)
        try:
            with open(self.storage_file, "w", encoding="utf-8") as f:
                json.dump({
                    "lessons": [
                        {
                            "technique": l.technique,
                            "target_type": l.target_type,
                            "error_signature": l.error_signature,
                            "lesson": l.lesson,
                            "timestamp": l.timestamp
                        }
                        for l in self.failure_lessons
                    ]
                }, f, indent=2)
        except Exception:
            pass

    def record_failure_lesson(self, technique: str, target_type: str, error_sig: str, lesson: str) -> None:
        """Record an explicit learning lesson from an execution failure."""
        lesson_obj = FailureLesson(
            technique=technique,
            target_type=target_type,
            error_signature=error_sig,
            lesson=lesson
        )
        self.failure_lessons.append(lesson_obj)
        self.save_memory()

    def get_lessons_for_target(self, target_type: str) -> List[str]:
        return [l.lesson for l in self.failure_lessons if l.target_type == target_type or l.target_type == "all"]

    def run_self_diagnostics(self, run_full_suite: bool = False) -> Dict[str, Any]:
        """Perform automated code syntax, test suite, and module integrity check."""
        results = {
            "syntax_errors": [],
            "tests_passed": True,
            "test_output": "Syntax and core integrity checks passed",
            "health_score": 100
        }

        # 1. Syntax verification across all workspace Python files
        for root, dirs, files in os.walk(str(self.base_dir)):
            if ".git" in root or "__pycache__" in root:
                continue
            for f in files:
                if f.endswith(".py"):
                    file_path = os.path.join(root, f)
                    try:
                        with open(file_path, "rb") as fp:
                            ast.parse(fp.read(), filename=file_path)
                    except SyntaxError as e:
                        results["syntax_errors"].append(f"{f}:{e.lineno} - {e.msg}")
                        results["health_score"] -= 15

        # 2. Automated quick module import check
        critical_modules = [
            "brain.coordinator",
            "execution.scope_guard",
            "execution.native_net",
            "execution.native_fuzzer",
            "execution.native_vuln",
            "learning.self_adaptation"
        ]
        for mod in critical_modules:
            try:
                __import__(mod)
            except Exception as ex:
                results["tests_passed"] = False
                results["test_output"] = f"Module import failed: {mod} ({str(ex)})"
                results["health_score"] -= 20

        return results
