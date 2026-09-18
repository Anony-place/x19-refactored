"""
X19 Bug Bounty Datasets — structured data with provenance, license checks, PII removal.

Provides:
- Methodology examples
- Vuln class examples with discovery methodology, evidence pattern, validation, etc.
- Program scope patterns
- All with metadata: source, license, provenance, version
- No secrets, PII, credentials, tokens — normalized, deduped, classified
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field


@dataclass
class DatasetMetadata:
    """Metadata for dataset."""

    source: str
    license: str
    date: str
    provenance: str
    version: str
    references: List[str] = field(default_factory=list)
    safety: str = ""
    categories: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DatasetMetadata":
        return cls(
            source=data.get("source", ""),
            license=data.get("license", ""),
            date=data.get("date", ""),
            provenance=data.get("provenance", ""),
            version=data.get("version", ""),
            references=data.get("references", []),
            safety=data.get("safety", ""),
            categories=data.get("categories", []),
        )


class BugBountyDatasets:
    """Loads and queries bug bounty datasets from datasets/bug_bounty/."""

    def __init__(self, datasets_dir: Optional[str] = None):
        if datasets_dir:
            self.datasets_dir = Path(datasets_dir)
        else:
            current = Path(__file__).resolve()
            repo_root = current.parent.parent.parent
            self.datasets_dir = repo_root / "datasets" / "bug_bounty"

        self._loaded = False
        self.methodology: List[Dict[str, Any]] = []
        self.vuln_examples: List[Dict[str, Any]] = []
        self.program_patterns: List[Dict[str, Any]] = []
        self.metadata: Optional[DatasetMetadata] = None

    def load(self):
        """Load all datasets."""
        if self._loaded:
            return

        if not self.datasets_dir.exists():
            alt_paths = [
                Path.cwd() / "datasets" / "bug_bounty",
                Path(__file__).parent.parent.parent / "datasets" / "bug_bounty",
            ]
            for alt in alt_paths:
                if alt.exists():
                    self.datasets_dir = alt
                    break

        if not self.datasets_dir.exists():
            return

        # Load metadata
        metadata_file = self.datasets_dir / "metadata.json"
        if metadata_file.exists():
            try:
                with open(metadata_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.metadata = DatasetMetadata.from_dict(data.get("metadata", {}))
            except Exception:
                pass

        # Load methodology
        methodology_file = self.datasets_dir / "methodology.json"
        if methodology_file.exists():
            try:
                with open(methodology_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.methodology = data.get("methodologies", [])
            except Exception:
                pass

        # Load vuln examples
        vuln_file = self.datasets_dir / "vuln_examples.json"
        if vuln_file.exists():
            try:
                with open(vuln_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.vuln_examples = data.get("examples", [])
            except Exception:
                pass

        # Load program patterns
        program_file = self.datasets_dir / "program_patterns.json"
        if program_file.exists():
            try:
                with open(program_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.program_patterns = data.get("patterns", [])
            except Exception:
                pass

        self._loaded = True

    def get_methodology(self, vuln_class: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get methodology, optionally filtered by vuln class."""
        if not self._loaded:
            self.load()

        if vuln_class:
            return [m for m in self.methodology if m.get("vuln_class") == vuln_class.lower()]

        return self.methodology

    def get_vuln_examples(self, vuln_class: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get vuln examples, optionally filtered by vuln class."""
        if not self._loaded:
            self.load()

        if vuln_class:
            return [e for e in self.vuln_examples if e.get("vuln_class") == vuln_class.lower()]

        return self.vuln_examples

    def get_program_patterns(self, pattern: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get program patterns, optionally filtered."""
        if not self._loaded:
            self.load()

        if pattern:
            return [p for p in self.program_patterns if pattern.lower() in p.get("pattern", "").lower()]

        return self.program_patterns

    def get_example_by_id(self, example_id: str) -> Optional[Dict[str, Any]]:
        """Get example by ID."""
        if not self._loaded:
            self.load()

        for example in self.vuln_examples:
            if example.get("id") == example_id:
                return example

        return None

    def get_stats(self) -> Dict[str, Any]:
        """Get dataset stats."""
        if not self._loaded:
            self.load()

        by_vuln = {}
        for ex in self.vuln_examples:
            vc = ex.get("vuln_class", "unknown")
            by_vuln[vc] = by_vuln.get(vc, 0) + 1

        by_method_vuln = {}
        for m in self.methodology:
            vc = m.get("vuln_class", "unknown")
            by_method_vuln[vc] = by_method_vuln.get(vc, 0) + 1

        return {
            "total_methodologies": len(self.methodology),
            "total_examples": len(self.vuln_examples),
            "total_program_patterns": len(self.program_patterns),
            "by_vuln_class_examples": by_vuln,
            "by_vuln_class_methodology": by_method_vuln,
            "datasets_dir": str(self.datasets_dir),
            "loaded": self._loaded,
            "metadata": self.metadata.__dict__ if self.metadata else None,
        }

    def query(self, query: str) -> List[Dict[str, Any]]:
        """Query datasets for vuln class, methodology, etc."""
        if not self._loaded:
            self.load()

        results = []
        q_lower = query.lower()

        for example in self.vuln_examples:
            if q_lower in example.get("vuln_class", "").lower() or q_lower in example.get("affected_component", "").lower():
                results.append({"type": "vuln_example", "data": example})

        for meth in self.methodology:
            if q_lower in meth.get("vuln_class", "").lower() or q_lower in meth.get("affected_component", "").lower():
                results.append({"type": "methodology", "data": meth})

        for pattern in self.program_patterns:
            if q_lower in pattern.get("pattern", "").lower() or q_lower in pattern.get("description", "").lower():
                results.append({"type": "program_pattern", "data": pattern})

        return results
