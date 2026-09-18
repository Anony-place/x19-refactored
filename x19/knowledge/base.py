"""
X19 Knowledge Base — loads public security knowledge with metadata.

Provides query interface for specialists to use knowledge:
- Vuln classes (XSS, SQLi, BOLA, etc.)
- OWASP Top 10, CWE
- Methodology (recon, testing, verification)
- Payloads (public, witness, minimal proof)
- Verification strategies, bypass techniques
- False positives, remediation, report templates

All knowledge is from public authoritative sources, synthesized in our own words,
no verbatim copyrighted text, no secrets/PII/credentials/tokens.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field


@dataclass
class KnowledgeMetadata:
    """Metadata for knowledge file."""

    source: str
    license: str
    date: str
    category: str
    confidence: str
    provenance: str
    version: str
    applicable_technologies: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "KnowledgeMetadata":
        return cls(
            source=data.get("source", ""),
            license=data.get("license", ""),
            date=data.get("date", ""),
            category=data.get("category", ""),
            confidence=data.get("confidence", ""),
            provenance=data.get("provenance", ""),
            version=data.get("version", ""),
            applicable_technologies=data.get("applicable_technologies", []),
            references=data.get("references", []),
        )


@dataclass
class KnowledgeEntry:
    """Single knowledge entry with metadata."""

    id: str
    data: Dict[str, Any]
    metadata: KnowledgeMetadata
    file_path: str


class KnowledgeBase:
    """Loads and queries X19 knowledge base from knowledge/ directory."""

    def __init__(self, knowledge_dir: Optional[str] = None):
        if knowledge_dir:
            self.knowledge_dir = Path(knowledge_dir)
        else:
            # Try to find knowledge/ from current file
            current = Path(__file__).resolve()
            # x19-refactored/x19/knowledge/base.py -> repo root is parent.parent.parent
            repo_root = current.parent.parent.parent
            self.knowledge_dir = repo_root / "knowledge"

        self.entries: Dict[str, KnowledgeEntry] = {}
        self._loaded = False

    def load(self):
        """Load all knowledge files from knowledge/ directory."""
        if self._loaded:
            return

        if not self.knowledge_dir.exists():
            # Try alternative locations
            alt_paths = [
                Path.cwd() / "knowledge",
                Path(__file__).parent.parent.parent / "knowledge",
            ]
            for alt in alt_paths:
                if alt.exists():
                    self.knowledge_dir = alt
                    break

        if not self.knowledge_dir.exists():
            return

        # Load JSON files recursively
        for json_file in self.knowledge_dir.rglob("*.json"):
            try:
                with open(json_file, "r", encoding="utf-8") as f:
                    data = json.load(f)

                metadata_dict = data.get("metadata", {})
                metadata = KnowledgeMetadata.from_dict(metadata_dict)

                # Use file path relative as primary ID to avoid collisions
                rel_path = json_file.relative_to(self.knowledge_dir)
                file_id = str(rel_path).replace("/", "_").replace(".json", "")

                # For files with specific vuln class, also index by vuln_class but with preference for methodology
                vuln_class = data.get("vuln_class")

                entry = KnowledgeEntry(
                    id=file_id,
                    data=data,
                    metadata=metadata,
                    file_path=str(json_file),
                )

                # Store by file_id
                self.entries[file_id] = entry

                # Also index by vuln_class if present, but prefer entries with methodology over payloads
                if vuln_class:
                    vc_lower = vuln_class.lower()
                    # If not exists, or existing is payloads and new has methodology, replace
                    existing = self.entries.get(vc_lower)
                    if existing is None:
                        self.entries[vc_lower] = entry
                    else:
                        # Prefer entry with methodology over payloads-only
                        existing_has_method = "methodology" in existing.data
                        new_has_method = "methodology" in data
                        existing_is_payloads = existing.metadata.category == "payloads"
                        new_is_payloads = metadata.category == "payloads"

                        if existing_is_payloads and new_has_method:
                            # New has methodology, existing is payloads-only, replace
                            self.entries[vc_lower] = entry
                        elif not existing_has_method and new_has_method:
                            # New has methodology, existing doesn't, replace
                            self.entries[vc_lower] = entry
                        # Otherwise keep existing (first wins for same type)

                    # Also store payloads-specific entry
                    if metadata.category == "payloads":
                        payload_id = f"payloads_{vc_lower}"
                        self.entries[payload_id] = entry

                # Index OWASP and CWE separately
                if "owasp_top10_2021" in data:
                    self.entries["owasp_top10_2021"] = entry
                    self.entries["owasp_top10"] = entry
                if "cwe_top25" in data:
                    self.entries["cwe_top25"] = entry
                    self.entries["cwe_top25_2023"] = entry

            except Exception as e:
                # Skip invalid files
                continue

        self._loaded = True

    def get_vuln_class(self, vuln_class: str) -> Optional[Dict[str, Any]]:
        """Get knowledge for vuln class (xss, sqli, bola, etc.)."""
        if not self._loaded:
            self.load()

        entry = self.entries.get(vuln_class.lower())
        if entry:
            return entry.data

        # Try to find by file name
        for eid, entry in self.entries.items():
            if vuln_class.lower() in eid.lower() or eid.lower() in vuln_class.lower():
                if "vuln_class" in entry.data and entry.data["vuln_class"] == vuln_class.lower():
                    return entry.data

        return None

    def get_payloads(self, vuln_class: str) -> Optional[Dict[str, Any]]:
        """Get payloads for vuln class."""
        if not self._loaded:
            self.load()

        # Check payloads directory
        payload_entry = self.entries.get(f"payloads_{vuln_class.lower()}")
        if payload_entry:
            return payload_entry.data

        # Check if vuln class data has payloads
        vuln_data = self.get_vuln_class(vuln_class)
        if vuln_data and "payloads" in vuln_data:
            return vuln_data["payloads"]

        # Try payloads/xss.json etc.
        for eid, entry in self.entries.items():
            if f"payloads" in eid and vuln_class.lower() in eid.lower():
                return entry.data

        return None

    def get_methodology(self, phase: str) -> Optional[Dict[str, Any]]:
        """Get methodology for phase (recon, bug_bounty, etc.)."""
        if not self._loaded:
            self.load()

        # Try methodology/recon, methodology/bug_bounty
        for eid, entry in self.entries.items():
            if "methodology" in eid and phase.lower() in eid.lower():
                return entry.data

        # Try direct
        entry = self.entries.get(phase.lower())
        if entry:
            return entry.data

        # Try methodology file that contains phase
        for eid, entry in self.entries.items():
            if "methodology" in eid:
                data = entry.data
                if "methodology" in data and phase in data["methodology"]:
                    return data
                if "phase" in data and data["phase"] == phase:
                    return data

        return None

    def get_owasp_top10(self) -> Optional[Dict[str, Any]]:
        """Get OWASP Top 10 knowledge."""
        if not self._loaded:
            self.load()

        entry = self.entries.get("owasp_top10_2021")
        if entry:
            return entry.data

        for eid, entry in self.entries.items():
            if "owasp" in eid.lower() and "top10" in eid.lower():
                return entry.data

        return None

    def get_cwe_top25(self) -> Optional[Dict[str, Any]]:
        """Get CWE Top 25 knowledge."""
        if not self._loaded:
            self.load()

        entry = self.entries.get("cwe_top25")
        if entry:
            return entry.data

        for eid, entry in self.entries.items():
            if "cwe" in eid.lower() and "top25" in eid.lower():
                return entry.data

        return None

    def get_verification(self, vuln_class: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Get verification strategies, optionally for specific vuln class."""
        if not self._loaded:
            self.load()

        for eid, entry in self.entries.items():
            if "verification" in eid.lower() or "bypass" in eid.lower():
                if vuln_class:
                    # Check if entry has bypass for vuln_class
                    data = entry.data
                    if "bypass_techniques" in data and vuln_class.lower() in data["bypass_techniques"]:
                        return data
                else:
                    return entry.data

        return None

    def get_false_positives(self, vuln_class: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Get false positive patterns."""
        if not self._loaded:
            self.load()

        for eid, entry in self.entries.items():
            if "false_positive" in eid.lower():
                if vuln_class:
                    # Filter for vuln_class
                    data = entry.data
                    if "false_positives" in data:
                        for fp in data["false_positives"]:
                            if fp.get("vuln_class") == vuln_class.lower():
                                return fp
                        return data
                else:
                    return entry.data

        return None

    def get_remediation(self, vuln_class: Optional[str] = None) -> Optional[str]:
        """Get remediation guidance for vuln class."""
        if not self._loaded:
            self.load()

        for eid, entry in self.entries.items():
            if "remediation" in eid.lower():
                data = entry.data
                if "remediations" in data:
                    if vuln_class and vuln_class.lower() in data["remediations"]:
                        return data["remediations"][vuln_class.lower()]
                    elif not vuln_class:
                        return data["remediations"]
                return data

        return None

    def list_vuln_classes(self) -> List[str]:
        """List all vuln classes with knowledge."""
        if not self._loaded:
            self.load()

        vuln_classes = []
        for eid, entry in self.entries.items():
            data = entry.data
            if "vuln_class" in data:
                vc = data["vuln_class"]
                if vc not in vuln_classes:
                    vuln_classes.append(vc)

        return sorted(vuln_classes)

    def list_all_entries(self) -> List[str]:
        """List all knowledge entry IDs."""
        if not self._loaded:
            self.load()

        return sorted(self.entries.keys())

    def get_stats(self) -> Dict[str, Any]:
        """Get knowledge base stats."""
        if not self._loaded:
            self.load()

        categories = {}
        for entry in self.entries.values():
            cat = entry.metadata.category
            categories[cat] = categories.get(cat, 0) + 1

        return {
            "total_entries": len(self.entries),
            "by_category": categories,
            "vuln_classes": self.list_vuln_classes(),
            "knowledge_dir": str(self.knowledge_dir),
            "loaded": self._loaded,
        }

    def query(self, query: str) -> List[Dict[str, Any]]:
        """Simple query: search for vuln class, methodology, etc. containing query."""
        if not self._loaded:
            self.load()

        results = []
        q_lower = query.lower()

        for eid, entry in self.entries.items():
            data = entry.data
            # Check if query in ID, vuln_class, description, etc.
            if q_lower in eid.lower():
                results.append({"id": eid, "data": data, "metadata": entry.metadata.__dict__})
            elif "vuln_class" in data and q_lower in data["vuln_class"].lower():
                results.append({"id": eid, "data": data, "metadata": entry.metadata.__dict__})
            elif "description" in data and q_lower in data["description"].lower():
                results.append({"id": eid, "data": data, "metadata": entry.metadata.__dict__})
            elif "name" in data and q_lower in str(data["name"]).lower():
                results.append({"id": eid, "data": data, "metadata": entry.metadata.__dict__})

        return results
