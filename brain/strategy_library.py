"""Strategy Library - Cross-session learning for autonomous adaptation.

This module persists successful strategies across missions, enabling X19 to:
1. Remember what worked on similar targets
2. Avoid repeating failed approaches across sessions  
3. Build a library of effective attack patterns
4. Adapt strategy selection based on historical success rates

True self-improvement requires learning that persists beyond a single session.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Any
from datetime import datetime, timezone
from pathlib import Path


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass
class StrategyPattern:
    """A learned attack pattern with success/failure statistics."""
    pattern_id: str
    name: str                      # Human-readable name
    description: str               # What this strategy does
    target_signature: str          # Target characteristics where this works
    technique_chain: List[str]     # Sequence of techniques
    success_count: int = 0
    failure_count: int = 0
    avg_iterations: float = 0.0
    total_iterations: int = 0
    last_success: Optional[str] = None
    last_failure: Optional[str] = None
    contexts: List[str] = field(default_factory=list)  # Target types where tried
    prerequisites: List[str] = field(default_factory=list)  # Required conditions
    risk_level: str = "medium"     # low/medium/high
    detection_probability: float = 0.5
    
    @property
    def success_rate(self) -> float:
        total = self.success_count + self.failure_count
        if total == 0:
            return 0.5
        return self.success_count / total
    
    @property
    def confidence(self) -> float:
        """Confidence in this strategy based on success rate and sample size."""
        base_rate = self.success_rate
        # Apply Bayesian smoothing with prior of 0.5
        total = self.success_count + self.failure_count
        if total < 3:
            # Not enough data, regress toward prior
            return (self.success_count + 0.5) / (total + 1.0)
        return base_rate
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "pattern_id": self.pattern_id,
            "name": self.name,
            "description": self.description,
            "target_signature": self.target_signature,
            "technique_chain": self.technique_chain,
            "success_count": self.success_count,
            "failure_count": self.failure_count,
            "avg_iterations": self.avg_iterations,
            "success_rate": self.success_rate,
            "confidence": self.confidence,
            "last_success": self.last_success,
            "last_failure": self.last_failure,
            "contexts": self.contexts,
            "prerequisites": self.prerequisites,
            "risk_level": self.risk_level,
            "detection_probability": self.detection_probability,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "StrategyPattern":
        return cls(
            pattern_id=data["pattern_id"],
            name=data["name"],
            description=data["description"],
            target_signature=data["target_signature"],
            technique_chain=data["technique_chain"],
            success_count=data.get("success_count", 0),
            failure_count=data.get("failure_count", 0),
            avg_iterations=data.get("avg_iterations", 0.0),
            total_iterations=data.get("total_iterations", 0),
            last_success=data.get("last_success"),
            last_failure=data.get("last_failure"),
            contexts=data.get("contexts", []),
            prerequisites=data.get("prerequisites", []),
            risk_level=data.get("risk_level", "medium"),
            detection_probability=data.get("detection_probability", 0.5)
        )


@dataclass
class TargetSignature:
    """Fingerprint of a target for strategy matching."""
    ports: List[int]
    services: List[str]
    technologies: List[str]
    target_type: str         # web/ad/cloud/ctf/network
    has_credentials: bool = False
    exposed_endpoints: List[str] = field(default_factory=list)
    
    def signature_hash(self) -> str:
        """Generate hash for similarity comparison."""
        key_parts = [
            sorted(self.ports),
            sorted(self.services),
            sorted(self.technologies),
            self.target_type,
        ]
        return json.dumps(key_parts, sort_keys=True)
    
    def similarity_score(self, other: "TargetSignature") -> float:
        """Calculate similarity between two target signatures (0.0-1.0)."""
        score = 0.0
        components = 0
        
        # Port overlap
        if self.ports and other.ports:
            common_ports = set(self.ports) & set(other.ports)
            port_score = len(common_ports) / max(len(self.ports), len(other.ports))
            score += port_score * 0.3
            components += 1
        
        # Service overlap
        if self.services and other.services:
            common_services = set(self.services) & set(other.services)
            service_score = len(common_services) / max(len(self.services), len(other.services))
            score += service_score * 0.25
            components += 1
        
        # Technology overlap
        if self.technologies and other.technologies:
            common_tech = set(self.technologies) & set(other.technologies)
            tech_score = len(common_tech) / max(len(self.technologies), len(other.technologies))
            score += tech_score * 0.25
            components += 1
        
        # Type match
        if self.target_type == other.target_type:
            score += 0.2
        components += 1
        
        return score / components if components > 0 else 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "ports": self.ports,
            "services": self.services,
            "technologies": self.technologies,
            "target_type": self.target_type,
            "has_credentials": self.has_credentials,
            "exposed_endpoints": self.exposed_endpoints,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TargetSignature":
        return cls(
            ports=data.get("ports", []),
            services=data.get("services", []),
            technologies=data.get("technologies", []),
            target_type=data.get("target_type", "unknown"),
            has_credentials=data.get("has_credentials", False),
            exposed_endpoints=data.get("exposed_endpoints", [])
        )


@dataclass
class MissionResult:
    """Result of a completed mission for learning."""
    mission_id: str
    target_signature: TargetSignature
    strategy_used: str           # pattern_id
    succeeded: bool
    iterations_taken: int
    findings_count: int
    critical_findings: List[str]
    timestamp: str = field(default_factory=utc_now)
    lessons_learned: List[str] = field(default_factory=list)


class StrategyLibrary:
    """Persistent library of learned attack strategies.
    
    The Strategy Library:
    1. Stores successful attack patterns with statistics
    2. Matches new targets to similar past targets
    3. Recommends strategies based on historical success
    4. Updates pattern statistics after each mission
    5. Prunes ineffective patterns over time
    
    This enables cross-session learning and true adaptation.
    """
    
    DEFAULT_LIBRARY_PATH = "data/strategy_library.json"
    
    def __init__(self, library_path: Optional[str] = None):
        self.library_path = library_path or self.DEFAULT_LIBRARY_PATH
        self.patterns: Dict[str, StrategyPattern] = {}
        self.mission_history: List[MissionResult] = []
        self._pattern_counter = 0
        
        # Ensure directory exists
        Path(self.library_path).parent.mkdir(parents=True, exist_ok=True)
        
        # Load existing library
        self._load_library()
    
    def _generate_pattern_id(self) -> str:
        self._pattern_counter += 1
        return f"strat_{self._pattern_counter:04d}"
    
    def _load_library(self):
        """Load strategy library from disk."""
        if not os.path.exists(self.library_path):
            return
        
        try:
            with open(self.library_path, 'r') as f:
                data = json.load(f)
            
            for p_data in data.get("patterns", []):
                pattern = StrategyPattern.from_dict(p_data)
                self.patterns[pattern.pattern_id] = pattern
            
            for m_data in data.get("mission_history", []):
                mission = MissionResult(
                    mission_id=m_data["mission_id"],
                    target_signature=TargetSignature.from_dict(m_data["target_signature"]),
                    strategy_used=m_data["strategy_used"],
                    succeeded=m_data["succeeded"],
                    iterations_taken=m_data["iterations_taken"],
                    findings_count=m_data["findings_count"],
                    critical_findings=m_data.get("critical_findings", []),
                    timestamp=m_data.get("timestamp", utc_now()),
                    lessons_learned=m_data.get("lessons_learned", [])
                )
                self.mission_history.append(mission)
            
            self._pattern_counter = len(self.patterns)
        except (json.JSONDecodeError, KeyError) as e:
            print(f"Warning: Could not load strategy library: {e}")
    
    def _save_library(self):
        """Save strategy library to disk."""
        data = {
            "patterns": [p.to_dict() for p in self.patterns.values()],
            "mission_history": [
                {
                    "mission_id": m.mission_id,
                    "target_signature": m.target_signature.to_dict(),
                    "strategy_used": m.strategy_used,
                    "succeeded": m.succeeded,
                    "iterations_taken": m.iterations_taken,
                    "findings_count": m.findings_count,
                    "critical_findings": m.critical_findings,
                    "timestamp": m.timestamp,
                    "lessons_learned": m.lessons_learned,
                }
                for m in self.mission_history[-100:]  # Keep last 100 missions
            ],
        }
        
        with open(self.library_path, 'w') as f:
            json.dump(data, f, indent=2)
    
    def record_mission_result(self, result: MissionResult):
        """Record the result of a completed mission."""
        self.mission_history.append(result)
        
        # Update pattern statistics
        if result.strategy_used in self.patterns:
            pattern = self.patterns[result.strategy_used]
            if result.succeeded:
                pattern.success_count += 1
                pattern.last_success = result.timestamp
            else:
                pattern.failure_count += 1
                pattern.last_failure = result.timestamp
            
            # Update average iterations
            pattern.total_iterations += result.iterations_taken
            total_attempts = pattern.success_count + pattern.failure_count
            pattern.avg_iterations = pattern.total_iterations / total_attempts if total_attempts > 0 else 0.0
        
        # Save library
        self._save_library()
    
    def learn_new_strategy(
        self,
        name: str,
        description: str,
        target_signature: TargetSignature,
        technique_chain: List[str],
        succeeded: bool,
        iterations: int,
        prerequisites: Optional[List[str]] = None,
        risk_level: str = "medium"
    ) -> StrategyPattern:
        """Learn a new strategy from a mission outcome."""
        pattern = StrategyPattern(
            pattern_id=self._generate_pattern_id(),
            name=name,
            description=description,
            target_signature=target_signature.signature_hash(),
            technique_chain=technique_chain,
            success_count=1 if succeeded else 0,
            failure_count=0 if succeeded else 1,
            avg_iterations=float(iterations),
            total_iterations=iterations,
            last_success=utc_now() if succeeded else None,
            last_failure=utc_now() if not succeeded else None,
            contexts=[target_signature.target_type],
            prerequisites=prerequisites or [],
            risk_level=risk_level
        )
        
        self.patterns[pattern.pattern_id] = pattern
        self._save_library()
        
        return pattern
    
    def recommend_strategies(
        self, 
        target_signature: TargetSignature,
        min_confidence: float = 0.4,
        max_recommendations: int = 5
    ) -> List[Tuple[StrategyPattern, float, str]]:
        """Recommend strategies for a new target.
        
        Returns:
            List of (pattern, match_score, reasoning) tuples sorted by relevance
        """
        recommendations = []
        
        for pattern in self.patterns.values():
            if pattern.confidence < min_confidence:
                continue
            
            # Calculate target similarity
            # We need to reconstruct a target signature from the pattern's stored hash
            # For now, use context matching as proxy
            context_match = any(
                ctx == target_signature.target_type 
                for ctx in pattern.contexts
            )
            
            if not context_match:
                continue
            
            # Score based on confidence and recency
            recency_bonus = 0.0
            if pattern.last_success:
                # More recent success = higher bonus
                try:
                    last_success_date = datetime.fromisoformat(pattern.last_success.replace('Z', '+00:00'))
                    days_since = (datetime.now(timezone.utc) - last_success_date).days
                    recency_bonus = max(0, 0.2 - (days_since * 0.01))  # Decay over 20 days
                except:
                    pass
            
            total_score = (pattern.confidence * 0.6) + (recency_bonus * 0.4)
            
            reasoning = (
                f"Success rate: {pattern.success_rate:.0%} | "
                f"Used {pattern.success_count + pattern.failure_count} times | "
                f"Chain: {' → '.join(pattern.technique_chain[:4])}"
            )
            
            recommendations.append((pattern, total_score, reasoning))
        
        # Sort by score descending
        recommendations.sort(key=lambda x: x[1], reverse=True)
        
        return recommendations[:max_recommendations]
    
    def find_similar_missions(
        self, 
        target_signature: TargetSignature,
        min_similarity: float = 0.5,
        max_results: int = 10
    ) -> List[Tuple[MissionResult, float]]:
        """Find past missions with similar targets."""
        similar = []
        
        for mission in self.mission_history:
            sim_score = mission.target_signature.similarity_score(target_signature)
            if sim_score >= min_similarity:
                similar.append((mission, sim_score))
        
        similar.sort(key=lambda x: x[1], reverse=True)
        return similar[:max_results]
    
    def get_effective_strategies_for_context(
        self, 
        context: str,
        min_success_rate: float = 0.6
    ) -> List[StrategyPattern]:
        """Get all strategies effective in a specific context."""
        effective = []
        
        for pattern in self.patterns.values():
            if context not in pattern.contexts:
                continue
            if pattern.success_rate < min_success_rate:
                continue
            
            effective.append(pattern)
        
        return sorted(effective, key=lambda p: p.confidence, reverse=True)
    
    def prune_ineffective_patterns(self, min_attempts: int = 3, max_success_rate: float = 0.3):
        """Remove patterns that consistently fail."""
        to_remove = []
        
        for pattern_id, pattern in self.patterns.items():
            total = pattern.success_count + pattern.failure_count
            if total >= min_attempts and pattern.success_rate <= max_success_rate:
                to_remove.append(pattern_id)
        
        for pattern_id in to_remove:
            del self.patterns[pattern_id]
        
        if to_remove:
            self._save_library()
        
        return len(to_remove)
    
    def export_summary(self) -> Dict[str, Any]:
        """Export library summary for analysis."""
        return {
            "total_patterns": len(self.patterns),
            "total_missions": len(self.mission_history),
            "patterns_by_context": {},
            "top_performers": [
                p.to_dict() for p in 
                sorted(self.patterns.values(), key=lambda x: x.confidence, reverse=True)[:5]
            ],
            "recent_missions": [
                {
                    "mission_id": m.mission_id,
                    "target_type": m.target_signature.target_type,
                    "succeeded": m.succeeded,
                    "strategy": m.strategy_used,
                }
                for m in self.mission_history[-10:]
            ]
        }
    
    def clear_history(self):
        """Clear mission history but keep patterns."""
        self.mission_history.clear()
        self._save_library()
