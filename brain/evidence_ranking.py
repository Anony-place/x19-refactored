"""Evidence Ranking Engine for X19 Cognitive Brain Migration.

Every observation receives scoring across multiple dimensions:
- confidence
- novelty  
- information_gain
- exploitability
- mission_impact
- dependency_value
- uncertainty

The Planner uses these scores to pursue highest-value evidence,
never the first discovered service.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timezone
import math


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass
class EvidenceScore:
    """Multi-dimensional scoring for evidence items."""
    
    confidence: float = 0.5          # How certain are we this is true (0.0-1.0)
    novelty: float = 0.0             # How new/unique is this evidence (0.0-1.0)
    information_gain: float = 0.0    # Expected reduction in uncertainty (0.0-1.0)
    exploitability: float = 0.0      # How directly can this be exploited (0.0-1.0)
    mission_impact: float = 0.0      # Relevance to mission objectives (0.0-1.0)
    dependency_value: float = 0.0    # How many other attacks depend on this (0.0-1.0)
    uncertainty: float = 0.5         # Remaining unknown after this evidence (0.0-1.0)
    
    @property
    def total_score(self) -> float:
        """Weighted combination of all scoring dimensions.
        
        Weights favor information gain and exploitability for offensive security.
        """
        weights = {
            'confidence': 0.15,
            'novelty': 0.10,
            'information_gain': 0.25,
            'exploitability': 0.20,
            'mission_impact': 0.15,
            'dependency_value': 0.10,
            'uncertainty': 0.05,  # Lower uncertainty is better, so inverted
        }
        
        score = (
            weights['confidence'] * self.confidence +
            weights['novelty'] * self.novelty +
            weights['information_gain'] * self.information_gain +
            weights['exploitability'] * self.exploitability +
            weights['mission_impact'] * self.mission_impact +
            weights['dependency_value'] * self.dependency_value +
            weights['uncertainty'] * (1.0 - self.uncertainty)  # Invert: lower uncertainty = higher score
        )
        return max(0.0, min(1.0, score))
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'confidence': round(self.confidence, 3),
            'novelty': round(self.novelty, 3),
            'information_gain': round(self.information_gain, 3),
            'exploitability': round(self.exploitability, 3),
            'mission_impact': round(self.mission_impact, 3),
            'dependency_value': round(self.dependency_value, 3),
            'uncertainty': round(self.uncertainty, 3),
            'total_score': round(self.total_score, 3),
        }


@dataclass
class RankedEvidence:
    """Evidence item with multi-dimensional scoring."""
    
    id: str
    source: str                    # Command/tool that produced this
    kind: str                      # port, service, endpoint, credential, vuln, tech, etc.
    data: Dict[str, Any]
    score: EvidenceScore = field(default_factory=EvidenceScore)
    timestamp: str = field(default_factory=utc_now)
    seen_count: int = 1            # How many times we've seen similar evidence
    related_evidence: List[str] = field(default_factory=list)  # IDs of related evidence
    
    @property
    def summary(self) -> str:
        """Human-readable summary of this evidence."""
        if self.kind == "port":
            port = self.data.get('port', '?')
            service = self.data.get('service', 'unknown')
            return f"Port {port}/{self.data.get('proto', 'tcp')} open ({service})"
        elif self.kind == "endpoint":
            return f"Endpoint: {self.data.get('method', 'GET')} {self.data.get('url', '?')}"
        elif self.kind == "credential":
            return f"Credential: {self.data.get('username', '?')}@{self.data.get('service', '?')}"
        elif self.kind == "vulnerability":
            severity = self.data.get('severity', 'info')
            title = self.data.get('title', 'Unknown')
            return f"Vulnerability [{severity}]: {title}"
        elif self.kind == "technology":
            return f"Technology: {self.data.get('name', '?')} {self.data.get('version', '')}"
        elif self.kind == "subdomain":
            return f"Subdomain: {self.data.get('hostname', '?')}"
        else:
            return f"{self.kind}: {str(self.data)[:50]}"


class EvidenceRankingEngine:
    """Ranks all evidence by multi-dimensional scoring.
    
    The Planner queries this engine to determine which evidence
    to pursue next, based on total_score and strategic context.
    """
    
    def __init__(self):
        self._evidence: Dict[str, RankedEvidence] = {}
        self._evidence_by_kind: Dict[str, List[str]] = {}  # kind -> [evidence_ids]
        self._known_patterns: Dict[str, int] = {}  # pattern -> count (for novelty calculation)
        self._dependency_graph: Dict[str, Set[str]] = {}  # evidence_id -> dependent evidence_ids
        
    def add_evidence(self, evidence: RankedEvidence):
        """Add or update evidence in the ranking engine."""
        # Update novelty based on pattern frequency
        pattern = self._extract_pattern(evidence)
        known_count = self._known_patterns.get(pattern, 0)
        
        if known_count == 0:
            evidence.score.novelty = 1.0  # Completely novel
        else:
            # Novelty decreases as we see similar evidence
            evidence.score.novelty = max(0.1, 1.0 / (1 + math.log(known_count + 1)))
        
        evidence.seen_count = known_count + 1
        self._known_patterns[pattern] = known_count + 1
        
        # Store evidence
        self._evidence[evidence.id] = evidence
        
        # Index by kind
        if evidence.kind not in self._evidence_by_kind:
            self._evidence_by_kind[evidence.kind] = []
        if evidence.id not in self._evidence_by_kind[evidence.kind]:
            self._evidence_by_kind[evidence.kind].append(evidence.id)
    
    def _extract_pattern(self, evidence: RankedEvidence) -> str:
        """Extract a pattern string for novelty detection."""
        if evidence.kind == "port":
            return f"port:{evidence.data.get('port', 0)}:{evidence.data.get('service', '')}"
        elif evidence.kind == "endpoint":
            url = evidence.data.get('url', '')
            # Normalize URL pattern
            normalized = url.split('?')[0].split('/')[-1]
            return f"endpoint:{normalized}"
        elif evidence.kind == "vulnerability":
            return f"vuln:{evidence.data.get('title', '')}:{evidence.data.get('severity', '')}"
        elif evidence.kind == "technology":
            return f"tech:{evidence.data.get('name', '')}"
        else:
            return f"{evidence.kind}:{str(evidence.data)[:50]}"
    
    def update_scores(
        self,
        evidence_id: str,
        confidence: Optional[float] = None,
        information_gain: Optional[float] = None,
        exploitability: Optional[float] = None,
        mission_impact: Optional[float] = None,
        dependency_value: Optional[float] = None,
        uncertainty: Optional[float] = None,
    ):
        """Update individual score dimensions for an evidence item."""
        if evidence_id not in self._evidence:
            return
        
        ev = self._evidence[evidence_id]
        
        if confidence is not None:
            ev.score.confidence = max(0.0, min(1.0, confidence))
        if information_gain is not None:
            ev.score.information_gain = max(0.0, min(1.0, information_gain))
        if exploitability is not None:
            ev.score.exploitability = max(0.0, min(1.0, exploitability))
        if mission_impact is not None:
            ev.score.mission_impact = max(0.0, min(1.0, mission_impact))
        if dependency_value is not None:
            ev.score.dependency_value = max(0.0, min(1.0, dependency_value))
        if uncertainty is not None:
            ev.score.uncertainty = max(0.0, min(1.0, uncertainty))
    
    def get_ranked_evidence(self, limit: int = 10, kind_filter: Optional[str] = None) -> List[RankedEvidence]:
        """Return evidence ranked by total_score.
        
        Args:
            limit: Maximum number of evidence items to return
            kind_filter: Optional filter by evidence kind (port, endpoint, etc.)
        
        Returns:
            List of RankedEvidence sorted by total_score descending
        """
        candidates = list(self._evidence.values())
        
        if kind_filter:
            candidates = [e for e in candidates if e.kind == kind_filter]
        
        # Sort by total_score descending
        candidates.sort(key=lambda e: e.score.total_score, reverse=True)
        
        return candidates[:limit]
    
    def get_highest_priority_evidence(self) -> Optional[RankedEvidence]:
        """Return the single highest-priority evidence item."""
        ranked = self.get_ranked_evidence(limit=1)
        return ranked[0] if ranked else None
    
    def get_evidence_by_id(self, evidence_id: str) -> Optional[RankedEvidence]:
        """Retrieve specific evidence by ID."""
        return self._evidence.get(evidence_id)
    
    def calculate_information_gain(self, evidence: RankedEvidence, model_state: Dict[str, Any]) -> float:
        """Calculate expected information gain for potential evidence.
        
        This estimates how much uncertainty would be reduced if this
        evidence were confirmed/discovered.
        
        For now, uses heuristics based on evidence type and current model state.
        Future: implement entropy-based calculation.
        """
        base_gain = 0.5
        
        # Ports/services provide high initial information gain
        if evidence.kind == "port":
            existing_ports = len(model_state.get('ports', []))
            if existing_ports == 0:
                base_gain = 0.9  # First port discovery is very valuable
            elif existing_ports < 5:
                base_gain = 0.7
            else:
                base_gain = 0.4
        
        # Vulnerabilities with high severity have high gain
        elif evidence.kind == "vulnerability":
            severity = evidence.data.get('severity', 'info')
            severity_map = {'critical': 0.95, 'high': 0.85, 'medium': 0.6, 'low': 0.4, 'info': 0.2}
            base_gain = severity_map.get(severity, 0.5)
        
        # Credentials always have high gain
        elif evidence.kind == "credential":
            base_gain = 0.85
        
        # Endpoints vary based on uniqueness
        elif evidence.kind == "endpoint":
            existing_endpoints = len(model_state.get('endpoints', []))
            if existing_endpoints < 10:
                base_gain = 0.6
            else:
                base_gain = 0.3
        
        return base_gain
    
    def calculate_exploitability(self, evidence: RankedEvidence) -> float:
        """Calculate direct exploitability score for evidence.
        
        Higher scores mean the evidence more directly leads to exploitation.
        """
        if evidence.kind == "vulnerability":
            severity = evidence.data.get('severity', 'info')
            cve = evidence.data.get('cve', '')
            
            base = {'critical': 0.95, 'high': 0.8, 'medium': 0.5, 'low': 0.2, 'info': 0.1}.get(severity, 0.3)
            
            # CVE with known exploit gets boost
            if cve:
                base = min(1.0, base + 0.1)
            
            return base
        
        elif evidence.kind == "credential":
            # Credentials are highly exploitable
            return 0.8
        
        elif evidence.kind == "port":
            service = evidence.data.get('service', '').lower()
            port = evidence.data.get('port', 0)
            
            # Services commonly associated with exploits
            high_value_services = {'mysql', 'mssql', 'postgres', 'mongodb', 'redis', 'smb', 'ftp', 'ssh'}
            if service in high_value_services or port in {3306, 1433, 5432, 27017, 6379, 445, 21}:
                return 0.6
            
            return 0.3
        
        elif evidence.kind == "endpoint":
            url = evidence.data.get('url', '').lower()
            
            # Potentially exploitable endpoints
            exploit_patterns = ['admin', 'login', 'upload', 'api', '.git', '.env', 'backup', 'config']
            if any(p in url for p in exploit_patterns):
                return 0.7
            
            return 0.3
        
        return 0.2
    
    def calculate_dependency_value(self, evidence: RankedEvidence) -> float:
        """Calculate how many potential attack paths depend on this evidence.
        
        Higher scores mean this evidence unlocks more follow-up actions.
        """
        if evidence.kind == "port":
            port = evidence.data.get('port', 0)
            
            # Web ports unlock many tools
            if port in {80, 443, 8080, 8443}:
                return 0.9
            # SMB/AD ports
            elif port in {445, 139, 389, 88}:
                return 0.8
            # Database ports
            elif port in {3306, 5432, 1433, 27017, 6379}:
                return 0.7
            # SSH
            elif port == 22:
                return 0.5
            else:
                return 0.4
        
        elif evidence.kind == "credential":
            # Credentials unlock authentication-based attacks
            return 0.85
        
        elif evidence.kind == "technology":
            tech_name = evidence.data.get('name', '').lower()
            
            # CMS/frameworks unlock specific scanners
            if any(cms in tech_name for cms in ['wordpress', 'joomla', 'drupal']):
                return 0.7
            
            return 0.5
        
        elif evidence.kind == "endpoint":
            url = evidence.data.get('url', '').lower()
            
            # Admin/config endpoints enable further enumeration
            if any(p in url for p in ['admin', 'config', '.git', '.env']):
                return 0.7
            
            return 0.4
        
        return 0.3
    
    def record_dependency(self, evidence_id: str, depends_on: List[str]):
        """Record that this evidence depends on other evidence items."""
        self._dependency_graph[evidence_id] = set(depends_on)
        
        # Update dependency_value for the depended-on evidence
        for dep_id in depends_on:
            if dep_id in self._evidence:
                # Increase dependency_value for evidence that others depend on
                current = self._evidence[dep_id].score.dependency_value
                self._evidence[dep_id].score.dependency_value = min(1.0, current + 0.1)
    
    def get_attack_chain_starters(self) -> List[RankedEvidence]:
        """Return evidence items that could start attack chains.
        
        These are high-dependency-value items that unlock many follow-ups.
        """
        candidates = [
            e for e in self._evidence.values()
            if e.score.dependency_value >= 0.7
        ]
        candidates.sort(key=lambda e: e.score.total_score, reverse=True)
        return candidates[:5]
    
    def get_exploitation_targets(self) -> List[RankedEvidence]:
        """Return evidence items that are directly exploitable.
        
        These are high-exploitability items ready for action.
        """
        candidates = [
            e for e in self._evidence.values()
            if e.score.exploitability >= 0.6
        ]
        candidates.sort(key=lambda e: e.score.exploitability, reverse=True)
        return candidates[:5]
    
    def get_knowledge_gaps(self, model_state: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify gaps in knowledge based on current evidence.
        
        Returns list of suggested investigations to fill gaps.
        """
        gaps = []
        
        # Check for common ports without service info
        ports = model_state.get('ports', [])
        for port_info in ports:
            port = port_info.get('port', 0)
            service = port_info.get('service', '')
            version = port_info.get('version', '')
            
            if not service:
                gaps.append({
                    'type': 'missing_service_info',
                    'target': f'port {port}',
                    'suggestion': f'Run service version detection on port {port}',
                    'priority': 0.8
                })
            elif not version:
                gaps.append({
                    'type': 'missing_version_info',
                    'target': f'{service} on port {port}',
                    'suggestion': f'Get version information for {service}',
                    'priority': 0.6
                })
        
        # Check for web services without endpoint enumeration
        web_ports = {80, 443, 8080, 8443}
        has_web_port = any(p.get('port') in web_ports for p in ports)
        has_endpoints = len(model_state.get('endpoints', [])) > 0
        
        if has_web_port and not has_endpoints:
            gaps.append({
                'type': 'missing_web_enumeration',
                'target': 'web services',
                'suggestion': 'Enumerate web directories and endpoints',
                'priority': 0.85
            })
        
        # Check for credentials without usage testing
        creds = model_state.get('credentials', [])
        if creds:
            # Could suggest testing credentials against services
            gaps.append({
                'type': 'untested_credentials',
                'target': f'{len(creds)} credential(s)',
                'suggestion': 'Test discovered credentials against relevant services',
                'priority': 0.9
            })
        
        gaps.sort(key=lambda g: g['priority'], reverse=True)
        return gaps
    
    def summary(self) -> str:
        """Generate human-readable summary of evidence ranking state."""
        lines = ["EVIDENCE RANKING SUMMARY:", "=" * 40]
        
        total = len(self._evidence)
        lines.append(f"Total evidence items: {total}")
        
        if total == 0:
            return "\n".join(lines)
        
        # Top 5 by score
        top = self.get_ranked_evidence(limit=5)
        lines.append("\nTop 5 Evidence by Priority:")
        for i, ev in enumerate(top, 1):
            lines.append(f"  {i}. [{ev.kind}] {ev.summary}")
            lines.append(f"     Score: {ev.score.total_score:.3f} (conf={ev.score.confidence:.2f}, gain={ev.score.information_gain:.2f}, exploit={ev.score.exploitability:.2f})")
        
        # Knowledge gaps
        gaps = self.get_knowledge_gaps({'ports': [], 'endpoints': [], 'credentials': []})
        if gaps:
            lines.append("\nKnowledge Gaps:")
            for gap in gaps[:3]:
                lines.append(f"  - {gap['suggestion']} (priority: {gap['priority']:.2f})")
        
        return "\n".join(lines)
