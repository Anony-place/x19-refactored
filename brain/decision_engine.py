"""Decision Engine - Dynamic Tool Scoring and Ranking Layer.

This module provides deterministic scoring for candidate actions based on:
- Goal Relevance
- Information Gain
- Estimated Cost
- Estimated Risk
- Failure Penalty

Every decision produces a DecisionTrace object with full rationale.

This is a SCORING LAYER ONLY - it does not replace the Planner or execute tools.
Flow: Planner → Generate Candidate Actions → DecisionEngine.score() → Return ranked actions
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Any
from datetime import datetime, timezone
import hashlib


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass
class ScoreBreakdown:
    """Detailed breakdown of how a score was calculated."""
    goal_relevance: float = 0.0       # How well this action advances the mission goal (0.0-1.0)
    information_gain: float = 0.0     # Expected new information value (0.0-1.0)
    estimated_cost: float = 0.5       # Lower is better (0.0=expensive, 1.0=cheap)
    estimated_risk: float = 0.5       # Lower is better (0.0=risky, 1.0=safe)
    failure_penalty: float = 1.0      # Multiplier based on past failures (0.0-1.0)
    
    @property
    def final_score(self) -> float:
        """Calculate weighted final score.
        
        Weights:
        - goal_relevance: 30% (most important - must advance the mission)
        - information_gain: 25% (value of learning)
        - estimated_cost: 20% (efficiency matters)
        - estimated_risk: 15% (safety consideration)
        - failure_penalty: 10% (historical performance)
        """
        score = (
            self.goal_relevance * 0.30 +
            self.information_gain * 0.25 +
            self.estimated_cost * 0.20 +
            self.estimated_risk * 0.15 +
            self.failure_penalty * 0.10
        )
        return max(0.0, min(1.0, score))
    
    def to_dict(self) -> Dict[str, float]:
        return {
            "goal_relevance": self.goal_relevance,
            "information_gain": self.information_gain,
            "estimated_cost": self.estimated_cost,
            "estimated_risk": self.estimated_risk,
            "failure_penalty": self.failure_penalty,
            "final_score": self.final_score,
        }


@dataclass
class DecisionTrace:
    """Complete audit trail for why an action was selected or rejected.
    
    Every chosen action must include:
    - why selected
    - why alternatives rejected
    - expected evidence
    - confidence
    """
    action_name: str
    action_category: str
    timestamp: str = field(default_factory=utc_now)
    
    # Selection rationale
    why_selected: str = ""
    why_alternatives_rejected: List[str] = field(default_factory=list)
    
    # Expectations
    expected_evidence: List[str] = field(default_factory=list)
    confidence: float = 0.5
    
    # Scoring details
    score_breakdown: Optional[ScoreBreakdown] = None
    rank_among_candidates: int = 0
    total_candidates: int = 0
    
    # Context
    mission_goal: str = ""
    world_model_state_summary: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "action_name": self.action_name,
            "action_category": self.action_category,
            "timestamp": self.timestamp,
            "why_selected": self.why_selected,
            "why_alternatives_rejected": self.why_alternatives_rejected,
            "expected_evidence": self.expected_evidence,
            "confidence": self.confidence,
            "score_breakdown": self.score_breakdown.to_dict() if self.score_breakdown else {},
            "rank_among_candidates": self.rank_among_candidates,
            "total_candidates": self.total_candidates,
            "mission_goal": self.mission_goal,
            "world_model_state_summary": self.world_model_state_summary,
        }


@dataclass
class ScoredAction:
    """An action with its complete scoring information."""
    action_name: str
    action_category: str
    action_phase: str
    description: str
    
    # Computed scores
    score_breakdown: ScoreBreakdown
    final_score: float
    
    # Metadata
    prerequisites: List[str] = field(default_factory=list)
    unlocks: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "action_name": self.action_name,
            "action_category": self.action_category,
            "action_phase": self.action_phase,
            "description": self.description,
            "score_breakdown": self.score_breakdown.to_dict(),
            "final_score": self.final_score,
            "prerequisites": self.prerequisites,
            "unlocks": self.unlocks,
        }


class DecisionEngine:
    """Dynamic scoring layer for tool/action selection.
    
    The Decision Engine evaluates candidate actions and ranks them based on
    multiple factors without replacing the Planner's core logic.
    
    Usage:
        engine = DecisionEngine()
        candidates = planner.suggest_next_tools(model)  # Get candidates from Planner
        scored = engine.score(candidates, model, mission_goal)
        best_action = scored[0] if scored else None
    """
    
    # Default cost estimates by category (0.0-1.0, higher = cheaper/faster)
    DEFAULT_COSTS: Dict[str, float] = {
        "port_scan": 0.8,      # Fast, low resource
        "fingerprint": 0.7,    # Moderate
        "subdomain": 0.6,      # Can be slow
        "dirbust": 0.4,        # Often slow, many requests
        "crawl": 0.5,          # Variable
        "param": 0.6,          # Moderate
        "scanner": 0.5,        # Variable
        "exploit_search": 0.9, # Fast lookup
        "web_exploit": 0.3,    # Slow, careful
        "crypto": 0.6,         # Moderate
        "smb": 0.7,            # Usually fast
        "ad": 0.5,             # Can be complex
        "auth": 0.2,           # Very slow (brute force)
        "exploit_framework": 0.3,  # Slow, careful
        "privesc": 0.4,        # Variable
        "cloud": 0.7,          # Usually fast
        "mobile": 0.4,         # Slow analysis
        "general": 0.6,        # Default
    }
    
    # Default risk estimates by category (0.0-1.0, higher = safer)
    DEFAULT_RISKS: Dict[str, float] = {
        "port_scan": 0.9,      # Very safe, passive
        "fingerprint": 0.9,    # Safe
        "subdomain": 0.95,     # Very safe, passive
        "dirbust": 0.7,        # Can trigger WAF
        "crawl": 0.8,          # Generally safe
        "param": 0.6,          # Can be detected
        "scanner": 0.7,        # Generally safe
        "exploit_search": 1.0, # Completely safe (local DB)
        "web_exploit": 0.3,    # Risky (active exploitation)
        "crypto": 0.9,         # Safe
        "smb": 0.8,            # Generally safe
        "ad": 0.7,             # Can trigger alerts
        "auth": 0.2,           # Very risky (account lockout)
        "exploit_framework": 0.3,  # Risky
        "privesc": 0.5,        # Variable risk
        "cloud": 0.8,          # Generally safe
        "mobile": 1.0,         # Safe (offline analysis)
        "general": 0.7,        # Default
    }
    
    def __init__(self):
        self._failure_counts: Dict[str, int] = {}  # action_name → failure count
        self._last_scores: Dict[str, ScoreBreakdown] = {}  # action_name → last score
        self._decision_traces: List[DecisionTrace] = []
        
    def record_failure(self, action_name: str):
        """Record a failure for an action to increase future penalty."""
        self._failure_counts[action_name] = self._failure_counts.get(action_name, 0) + 1
    
    def record_success(self, action_name: str):
        """Record a success to reset failure count."""
        if action_name in self._failure_counts:
            del self._failure_counts[action_name]
    
    def get_failure_count(self, action_name: str) -> int:
        """Get the current failure count for an action."""
        return self._failure_counts.get(action_name, 0)
    
    def _calculate_failure_penalty(self, action_name: str) -> float:
        """Calculate penalty multiplier based on past failures.
        
        Returns:
            1.0 = no penalty, 0.0 = completely blocked
        """
        fail_count = self._failure_counts.get(action_name, 0)
        
        if fail_count == 0:
            return 1.0
        elif fail_count == 1:
            return 0.8  # Minor penalty for first failure
        elif fail_count == 2:
            return 0.5  # Significant penalty
        elif fail_count == 3:
            return 0.2  # Heavy penalty
        else:
            return 0.0  # Blocked after 4+ failures
    
    def _estimate_goal_relevance(
        self,
        action_name: str,
        action_category: str,
        phase: str,
        mission_goal: str,
        world_model: Any
    ) -> float:
        """Estimate how relevant this action is to the mission goal.
        
        This uses heuristic matching between the action's purpose and the goal.
        In a future iteration, this could use semantic similarity.
        """
        goal_lower = mission_goal.lower()
        
        # Phase-based relevance
        phase_priority = {"recon": 0, "web_enum": 1, "vuln_scan": 2, "exploit": 3}
        current_phase = self._get_current_phase(world_model)
        
        # Actions in the current or next phase are most relevant
        action_phase_idx = phase_priority.get(phase, 0)
        current_phase_idx = phase_priority.get(current_phase, 0)
        
        phase_score = 1.0 if action_phase_idx == current_phase_idx else \
                      0.8 if action_phase_idx == current_phase_idx + 1 else \
                      0.5 if action_phase_idx < current_phase_idx else \
                      0.3
        
        # Goal keyword matching
        keyword_matches = 0.0
        
        if any(kw in goal_lower for kw in ["scan", "discover", "find", "enumerate"]):
            if action_category in ["port_scan", "subdomain", "fingerprint"]:
                keyword_matches = 1.0
            elif action_category in ["dirbust", "crawl"]:
                keyword_matches = 0.7
        
        if any(kw in goal_lower for kw in ["vulnerability", "cve", "exploit", "weakness"]):
            if action_category in ["scanner", "exploit_search", "web_exploit"]:
                keyword_matches = max(keyword_matches, 1.0)
            elif action_category in ["vuln_scan"]:
                keyword_matches = max(keyword_matches, 0.8)
        
        if any(kw in goal_lower for kw in ["credential", "password", "access", "login"]):
            if action_category in ["auth", "ad", "smb"]:
                keyword_matches = max(keyword_matches, 1.0)
            elif action_category in ["privesc"]:
                keyword_matches = max(keyword_matches, 0.7)
        
        if any(kw in goal_lower for kw in ["web", "http", "endpoint", "directory"]):
            if action_category in ["dirbust", "crawl", "fingerprint", "param"]:
                keyword_matches = max(keyword_matches, 1.0)
        
        # If no specific keywords matched, use phase alignment
        if keyword_matches == 0.0:
            keyword_matches = 0.5  # Neutral
        
        # Combine phase and keyword scores
        return max(0.1, min(1.0, (phase_score * 0.6 + keyword_matches * 0.4)))
    
    def _get_current_phase(self, world_model: Any) -> str:
        """Determine the current attack phase from world model state."""
        if not world_model:
            return "recon"
        
        # Check what has been discovered
        ports = getattr(world_model, "ports", []) or []
        tech_stack = getattr(world_model, "tech_stack", {}) or {}
        endpoints = getattr(world_model, "endpoints", []) or []
        findings = getattr(world_model, "findings", []) or []
        
        # If we have high/critical findings, we're in exploit phase
        for f in findings:
            if isinstance(f, dict):
                if f.get("severity") in ("high", "critical"):
                    return "exploit"
        
        # If we have endpoints and tech, we're in vuln_scan
        if endpoints and tech_stack:
            return "vuln_scan"
        
        # If we have ports and tech, we're in web_enum
        if ports and tech_stack:
            return "web_enum"
        
        # Default to recon
        return "recon"
    
    def _estimate_information_gain(
        self,
        action_name: str,
        action_category: str,
        unlocks: List[str],
        world_model: Any
    ) -> float:
        """Estimate the potential information gain from this action.
        
        Higher gain for actions that:
        - Unlock many other tools
        - Discover fundamental data (ports, tech stack)
        - Fill known knowledge gaps
        """
        base_gain = 0.5
        
        # Tools that unlock many others have high information gain
        unlock_bonus = min(len(unlocks) * 0.1, 0.4)
        
        # Category-based base gains
        category_gains = {
            "port_scan": 0.8,      # Fundamental discovery
            "fingerprint": 0.7,    # Tech stack is valuable
            "subdomain": 0.6,      # Expands surface
            "dirbust": 0.5,        # Finds endpoints
            "crawl": 0.5,          # Finds endpoints
            "scanner": 0.6,        # Finds vulns
            "exploit_search": 0.4, # Lookup only
        }
        
        base_gain = category_gains.get(action_category, 0.5)
        
        # Reduce gain if we've already run similar tools
        if world_model:
            ports = getattr(world_model, "ports", []) or []
            tech_stack = getattr(world_model, "tech_stack", {}) or {}
            
            if action_category == "port_scan" and len(ports) > 10:
                base_gain *= 0.5  # Diminishing returns
            
            if action_category == "fingerprint" and len(tech_stack) > 5:
                base_gain *= 0.6
        
        return max(0.1, min(1.0, base_gain + unlock_bonus))
    
    def _estimate_cost(self, action_category: str) -> float:
        """Get estimated cost for an action category.
        
        Returns 0.0-1.0 where higher = cheaper/faster.
        """
        return self.DEFAULT_COSTS.get(action_category, 0.5)
    
    def _estimate_risk(self, action_category: str) -> float:
        """Get estimated risk for an action category.
        
        Returns 0.0-1.0 where higher = safer.
        """
        return self.DEFAULT_RISKS.get(action_category, 0.5)
    
    def score(
        self,
        candidates: List[Any],
        world_model: Any,
        mission_goal: str = ""
    ) -> List[ScoredAction]:
        """Score and rank candidate actions.
        
        Args:
            candidates: List of candidate actions (ChainStep or similar objects)
                       Must have: tool, category/phase, description, prerequisites, unlocks
            world_model: Current world model state
            mission_goal: Text description of the mission objective
            
        Returns:
            List of ScoredAction objects, sorted by final_score descending
        """
        scored_actions: List[ScoredAction] = []
        
        for candidate in candidates:
            # Extract candidate properties
            action_name = getattr(candidate, "tool", "") or getattr(candidate, "name", "")
            action_category = getattr(candidate, "category", "general")
            action_phase = getattr(candidate, "phase", "recon")
            description = getattr(candidate, "rationale", "") or getattr(candidate, "description", "")
            prerequisites = getattr(candidate, "prerequisites", []) or []
            unlocks = getattr(candidate, "unlocks", []) or []
            
            if not action_name:
                continue
            
            # Calculate score breakdown
            breakdown = ScoreBreakdown(
                goal_relevance=self._estimate_goal_relevance(
                    action_name, action_category, action_phase, mission_goal, world_model
                ),
                information_gain=self._estimate_information_gain(
                    action_name, action_category, unlocks, world_model
                ),
                estimated_cost=self._estimate_cost(action_category),
                estimated_risk=self._estimate_risk(action_category),
                failure_penalty=self._calculate_failure_penalty(action_name),
            )
            
            scored = ScoredAction(
                action_name=action_name,
                action_category=action_category,
                action_phase=action_phase,
                description=description,
                score_breakdown=breakdown,
                final_score=breakdown.final_score,
                prerequisites=prerequisites,
                unlocks=unlocks,
            )
            
            scored_actions.append(scored)
            self._last_scores[action_name] = breakdown
        
        # Sort by final score descending
        scored_actions.sort(key=lambda x: x.final_score, reverse=True)
        
        return scored_actions
    
    def select_best(
        self,
        candidates: List[Any],
        world_model: Any,
        mission_goal: str = "",
        alternatives_to_consider: int = 3
    ) -> Tuple[Optional[ScoredAction], DecisionTrace]:
        """Select the best action and generate a decision trace.
        
        Args:
            candidates: List of candidate actions
            world_model: Current world model state
            mission_goal: Text description of the mission objective
            alternatives_to_consider: How many top alternatives to track
            
        Returns:
            Tuple of (best_action, decision_trace)
            best_action is None if no valid candidates
        """
        scored = self.score(candidates, world_model, mission_goal)
        
        if not scored:
            trace = DecisionTrace(
                action_name="",
                action_category="",
                why_selected="No valid candidates available",
                confidence=0.0,
                mission_goal=mission_goal,
            )
            return None, trace
        
        best = scored[0]
        alternatives = scored[1:alternatives_to_consider+1]
        
        # Build decision trace
        why_selected_parts = [
            f"Highest overall score ({best.final_score:.2f})",
            f"Goal relevance: {best.score_breakdown.goal_relevance:.2f}",
            f"Information gain: {best.score_breakdown.information_gain:.2f}",
        ]
        
        if best.score_breakdown.failure_penalty < 1.0:
            why_selected_parts.append(
                f"Note: Has {self._failure_counts.get(best.action_name, 0)} past failure(s)"
            )
        
        why_rejected = []
        for alt in alternatives:
            reason = f"{alt.action_name}: score {alt.final_score:.2f} ("
            sub_reasons = []
            if alt.score_breakdown.goal_relevance < best.score_breakdown.goal_relevance - 0.1:
                sub_reasons.append("lower goal relevance")
            if alt.score_breakdown.information_gain < best.score_breakdown.information_gain - 0.1:
                sub_reasons.append("lower information gain")
            if alt.score_breakdown.estimated_cost < best.score_breakdown.estimated_cost - 0.1:
                sub_reasons.append("higher cost")
            if alt.score_breakdown.failure_penalty < best.score_breakdown.failure_penalty:
                sub_reasons.append("past failures")
            reason += ", ".join(sub_reasons) if sub_reasons else "comparable but lower priority"
            reason += ")"
            why_rejected.append(reason)
        
        # Expected evidence based on what the tool unlocks
        expected_evidence = []
        if best.unlocks:
            expected_evidence.append(f"Will enable: {', '.join(best.unlocks[:3])}")
        if best.action_category == "port_scan":
            expected_evidence.append("Open ports and services")
        elif best.action_category == "fingerprint":
            expected_evidence.append("Technology stack details")
        elif best.action_category == "dirbust":
            expected_evidence.append("Hidden directories and files")
        elif best.action_category == "scanner":
            expected_evidence.append("Vulnerability matches")
        
        # World model summary
        wm_summary = ""
        if world_model:
            ports = len(getattr(world_model, "ports", []) or [])
            tech = len(getattr(world_model, "tech_stack", {}) or {})
            endpoints = len(getattr(world_model, "endpoints", []) or [])
            wm_summary = f"ports={ports}, tech={tech}, endpoints={endpoints}"
        
        trace = DecisionTrace(
            action_name=best.action_name,
            action_category=best.action_category,
            why_selected="; ".join(why_selected_parts),
            why_alternatives_rejected=why_rejected,
            expected_evidence=expected_evidence,
            confidence=best.final_score,
            score_breakdown=best.score_breakdown,
            rank_among_candidates=1,
            total_candidates=len(scored),
            mission_goal=mission_goal,
            world_model_state_summary=wm_summary,
        )
        
        self._decision_traces.append(trace)
        
        return best, trace
    
    def get_decision_history(self, limit: int = 10) -> List[DecisionTrace]:
        """Get recent decision traces."""
        return self._decision_traces[-limit:]
    
    def clear_history(self):
        """Clear decision trace history."""
        self._decision_traces.clear()
    
    def reset_for_new_target(self):
        """Reset engine state for a new target."""
        self._failure_counts.clear()
        self._last_scores.clear()
        self._decision_traces.clear()
    
    def export_state(self) -> Dict[str, Any]:
        """Export engine state for persistence."""
        return {
            "failure_counts": self._failure_counts,
            "recent_decisions": [t.to_dict() for t in self._decision_traces[-20:]],
        }
    
    def import_state(self, state: Dict[str, Any]):
        """Import engine state from persistence."""
        self._failure_counts = state.get("failure_counts", {})
        # Note: Decision traces are not restored as they are historical
