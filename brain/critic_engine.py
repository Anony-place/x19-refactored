"""Critic Engine - Converts reflection into state changes.

This module transforms text-based reflections into hard numerical penalties/bonuses
that permanently modify the World Model, preventing repeated failed techniques
and reinforcing successful strategies.

True autonomy requires that reflection changes behavior, not just context.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Any
from datetime import datetime, timezone
import hashlib


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass
class TechniquePenalty:
    """Tracks penalties applied to specific techniques."""
    technique_hash: str
    technique_signature: str  # e.g., "nmap:port_scan:target"
    penalty_value: float      # 0.0 = blocked, 1.0 = no penalty
    reason: str
    timestamp: str = field(default_factory=utc_now)
    expires_after: Optional[int] = None  # iterations until expiry (None = permanent)
    iteration_applied: int = 0
    
    def is_expired(self, current_iteration: int) -> bool:
        if self.expires_after is None:
            return False
        return current_iteration > self.iteration_applied + self.expires_after


@dataclass
class StrategyBonus:
    """Tracks bonuses for successful strategies."""
    strategy_hash: str
    strategy_signature: str  # e.g., "git_exposure→credentials→privesc"
    bonus_value: float       # >1.0 boosts priority
    success_count: int = 1
    last_success: str = field(default_factory=utc_now)
    contexts: List[str] = field(default_factory=list)  # target types where this worked


@dataclass
class CritiqueSummary:
    """Summary of criticism applied this cycle."""
    penalties_applied: int
    bonuses_applied: int
    techniques_blocked: List[str]
    strategies_reinforced: List[str]
    confidence_changes: Dict[str, float]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "penalties_applied": self.penalties_applied,
            "bonuses_applied": self.bonuses_applied,
            "techniques_blocked": self.techniques_blocked,
            "strategies_reinforced": self.strategies_reinforced,
            "confidence_changes": self.confidence_changes,
        }


class CriticEngine:
    """Converts reflection outcomes into World Model state changes.
    
    The Critic Engine ensures that:
    1. Failed techniques receive permanent penalties (confidence → 0.0)
    2. Repeated failures escalate to hard blocks
    3. Successful strategies receive bonuses (priority multiplier)
    4. Entity confidences are adjusted based on evidence quality
    5. Hypothesis confidences are updated based on validation results
    
    This makes reflection STATEFUL, not just textual.
    """
    
    def __init__(self):
        self.penalties: Dict[str, TechniquePenalty] = {}
        self.bonuses: Dict[str, StrategyBonus] = {}
        self.failure_counts: Dict[str, int] = {}  # technique_signature → count
        self.success_counts: Dict[str, int] = {}  # strategy_signature → count
        self._iteration = 0
        
    def advance_iteration(self):
        """Called at the start of each planning cycle."""
        self._iteration += 1
        # Clean up expired penalties
        expired = [k for k, v in self.penalties.items() if v.is_expired(self._iteration)]
        for k in expired:
            del self.penalties[k]
    
    def _technique_hash(self, signature: str) -> str:
        return hashlib.sha256(signature.encode()).hexdigest()[:16]
    
    def _strategy_hash(self, signature: str) -> str:
        return hashlib.sha256(signature.encode()).hexdigest()[:16]
    
    def criticize_failure(
        self,
        technique: str,
        category: str,
        target_context: str,
        failure_reason: str,
        output_snippet: str = ""
    ) -> TechniquePenalty:
        """Record a failure and apply appropriate penalty.
        
        Args:
            technique: Tool/method name (e.g., "nmap", "sqlmap")
            category: Technique category (e.g., "port_scan", "web_exploit")
            target_context: Target description (e.g., "web:nginx:80")
            failure_reason: Why it failed (e.g., "timeout", "connection_refused")
            output_snippet: Relevant output for analysis
            
        Returns:
            TechniquePenalty object with assigned penalty value
        """
        signature = f"{technique}:{category}:{target_context}"
        tech_hash = self._technique_hash(signature)
        
        # Track failure count
        self.failure_counts[signature] = self.failure_counts.get(signature, 0) + 1
        fail_count = self.failure_counts[signature]
        
        # Escalating penalty based on failure count
        if fail_count == 1:
            # First failure: soft penalty
            penalty_value = 0.7
            reason = f"Initial failure: {failure_reason}"
            expires_after = 5  # May retry after 5 iterations
        elif fail_count == 2:
            # Second failure: stronger penalty
            penalty_value = 0.4
            reason = f"Repeated failure ({fail_count}x): {failure_reason}"
            expires_after = 10
        elif fail_count >= 3:
            # Third+ failure: hard block
            penalty_value = 0.0
            reason = f"Technique blocked after {fail_count} failures: {failure_reason}"
            expires_after = None  # Permanent until manual reset
        else:
            penalty_value = 0.5
            reason = f"Failure recorded: {failure_reason}"
            expires_after = 5
        
        # Special cases for specific failure types
        if "rate limit" in failure_reason.lower() or "429" in failure_reason:
            # Rate limiting affects all similar techniques
            penalty_value = max(penalty_value, 0.3)
            reason = f"Rate-limited: reducing aggression across related techniques"
            
        if "permission denied" in failure_reason.lower():
            # Permission issues may be resolvable with different creds
            penalty_value = max(penalty_value, 0.5)
            reason = f"Permission issue: may require privilege escalation first"
        
        penalty = TechniquePenalty(
            technique_hash=tech_hash,
            technique_signature=signature,
            penalty_value=penalty_value,
            reason=reason,
            expires_after=expires_after,
            iteration_applied=self._iteration
        )
        
        self.penalties[tech_hash] = penalty
        
        return penalty
    
    def criticize_success(
        self,
        strategy_chain: List[str],
        outcome_description: str,
        target_context: str,
        evidence_quality: float = 0.8
    ) -> StrategyBonus:
        """Record a successful strategy and apply bonus.
        
        Args:
            strategy_chain: Sequence of techniques that led to success
                           e.g., ["nmap", "whatweb", "gobuster", "credential_found"]
            outcome_description: What was achieved
            target_context: Target type where this worked
            evidence_quality: Quality of evidence found (0.0-1.0)
            
        Returns:
            StrategyBonus object with assigned bonus value
        """
        signature = "→".join(strategy_chain)
        strat_hash = self._strategy_hash(signature)
        
        # Track success count
        self.success_counts[signature] = self.success_counts.get(signature, 0) + 1
        success_count = self.success_counts[signature]
        
        # Bonus calculation: base + success_count bonus + evidence quality multiplier
        base_bonus = 1.2
        success_multiplier = min(success_count * 0.1, 0.5)  # Cap at +0.5
        quality_multiplier = evidence_quality * 0.3
        
        bonus_value = base_bonus + success_multiplier + quality_multiplier
        
        bonus = StrategyBonus(
            strategy_hash=strat_hash,
            strategy_signature=signature,
            bonus_value=bonus_value,
            success_count=success_count,
            contexts=[target_context]
        )
        
        # Merge with existing bonus if present
        if strat_hash in self.bonuses:
            existing = self.bonuses[strat_hash]
            existing.bonus_value = max(existing.bonus_value, bonus_value)
            existing.success_count += 1
            existing.last_success = utc_now()
            if target_context not in existing.contexts:
                existing.contexts.append(target_context)
            bonus = existing
        else:
            self.bonuses[strat_hash] = bonus
        
        return bonus
    
    def get_technique_penalty(self, technique: str, category: str, target_context: str) -> Optional[TechniquePenalty]:
        """Check if a technique has an active penalty."""
        signature = f"{technique}:{category}:{target_context}"
        tech_hash = self._technique_hash(signature)
        
        penalty = self.penalties.get(tech_hash)
        if penalty and not penalty.is_expired(self._iteration):
            return penalty
        return None
    
    def get_strategy_bonus(self, strategy_chain: List[str]) -> Optional[StrategyBonus]:
        """Check if a strategy has an active bonus."""
        signature = "→".join(strategy_chain)
        strat_hash = self._strategy_hash(signature)
        
        return self.bonuses.get(strat_hash)
    
    def calculate_priority_multiplier(
        self,
        technique: str,
        category: str,
        target_context: str,
        proposed_strategy: Optional[List[str]] = None
    ) -> float:
        """Calculate combined priority multiplier for a technique/strategy.
        
        Returns:
            Multiplier: 0.0 = blocked, <1.0 = penalized, >1.0 = boosted
        """
        multiplier = 1.0
        
        # Apply penalty if exists
        penalty = self.get_technique_penalty(technique, category, target_context)
        if penalty:
            multiplier *= penalty.penalty_value
        
        # Apply bonus if strategy matches
        if proposed_strategy:
            bonus = self.get_strategy_bonus(proposed_strategy)
            if bonus:
                multiplier *= bonus.bonus_value
        
        return max(0.0, multiplier)
    
    def apply_critique_to_world_model(self, world_model: Any) -> CritiqueSummary:
        """Apply all active critiques to the World Model.
        
        This modifies entity confidences, hypothesis confidences, and
        attack path priorities based on accumulated penalties/bonuses.
        
        Args:
            world_model: WorldModel instance to modify
            
        Returns:
            CritiqueSummary of changes applied
        """
        summary = CritiqueSummary(
            penalties_applied=0,
            bonuses_applied=0,
            techniques_blocked=[],
            strategies_reinforced=[],
            confidence_changes={}
        )
        
        # Apply penalties to service/tool confidences
        for penalty in self.penalties.values():
            if penalty.is_expired(self._iteration):
                continue
                
            if penalty.penalty_value == 0.0:
                summary.techniques_blocked.append(penalty.technique_signature)
                summary.penalties_applied += 1
                
                # Find and downgrade relevant entities in world model
                parts = penalty.technique_signature.split(":")
                if len(parts) >= 2:
                    technique = parts[0]
                    # Downgrade confidence in services that would use this technique
                    for host in world_model.hosts.values():
                        for service in host.services.values():
                            if technique.lower() in service.service.lower():
                                old_conf = service.confidence
                                service.confidence = max(0.1, service.confidence * 0.5)
                                key = f"{host.hostname}:{service.key}"
                                summary.confidence_changes[key] = service.confidence - old_conf
        
        # Apply bonuses to attack path priorities
        for bonus in self.bonuses.values():
            summary.bonuses_applied += 1
            summary.strategies_reinforced.append(bonus.strategy_signature)
            
            # Boost confidence in paths matching this strategy
            for i, path in enumerate(world_model.candidate_attack_paths):
                path_str = str(path.get("chain", []))
                if any(step in path_str for step in bonus.strategy_signature.split("→")):
                    old_priority = path.get("priority", 0.5)
                    new_priority = min(0.98, old_priority * bonus.bonus_value)
                    path["priority"] = new_priority
                    path["reinforced_by"] = bonus.strategy_signature
                    summary.confidence_changes[f"path_{i}"] = new_priority - old_priority
        
        return summary
    
    def should_block_technique(self, technique: str, category: str, target_context: str) -> bool:
        """Check if a technique should be completely blocked."""
        penalty = self.get_technique_penalty(technique, category, target_context)
        return penalty is not None and penalty.penalty_value == 0.0
    
    def get_learning_summary(self) -> Dict[str, Any]:
        """Generate a summary of learned patterns for cognitive memory."""
        return {
            "iteration": self._iteration,
            "total_penalties": len([p for p in self.penalties.values() if not p.is_expired(self._iteration)]),
            "total_bonuses": len(self.bonuses),
            "blocked_techniques": len(self.techniques_blocked()),
            "successful_strategies": len(self.bonuses),
            "failure_patterns": dict(list(self.failure_counts.items())[-10:]),  # Last 10
            "success_patterns": dict(list(self.success_counts.items())[-10:]),  # Last 10
        }
    
    def techniques_blocked(self) -> List[str]:
        """List all currently blocked techniques."""
        return [
            p.technique_signature 
            for p in self.penalties.values() 
            if p.penalty_value == 0.0 and not p.is_expired(self._iteration)
        ]
    
    def reset_for_new_target(self):
        """Reset critic state for a new target (keep cross-target learning separate)."""
        # Keep bonuses (they represent general strategic knowledge)
        # Clear penalties (they are target-specific)
        self.penalties.clear()
        self.failure_counts.clear()
        self._iteration = 0
    
    def export_state(self) -> Dict[str, Any]:
        """Export critic state for persistence."""
        return {
            "penalties": [
                {
                    "signature": p.technique_signature,
                    "value": p.penalty_value,
                    "reason": p.reason,
                    "expires_after": p.expires_after,
                    "iteration_applied": p.iteration_applied,
                }
                for p in self.penalties.values()
            ],
            "bonuses": [
                {
                    "signature": b.strategy_signature,
                    "value": b.bonus_value,
                    "success_count": b.success_count,
                    "contexts": b.contexts,
                }
                for b in self.bonuses.values()
            ],
            "failure_counts": self.failure_counts,
            "success_counts": self.success_counts,
        }
    
    def import_state(self, state: Dict[str, Any]):
        """Import critic state from persistence."""
        for p_data in state.get("penalties", []):
            penalty = TechniquePenalty(
                technique_hash=self._technique_hash(p_data["signature"]),
                technique_signature=p_data["signature"],
                penalty_value=p_data["value"],
                reason=p_data["reason"],
                expires_after=p_data.get("expires_after"),
                iteration_applied=p_data.get("iteration_applied", 0)
            )
            self.penalties[penalty.technique_hash] = penalty
        
        for b_data in state.get("bonuses", []):
            bonus = StrategyBonus(
                strategy_hash=self._strategy_hash(b_data["signature"]),
                strategy_signature=b_data["signature"],
                bonus_value=b_data["value"],
                success_count=b_data.get("success_count", 1),
                contexts=b_data.get("contexts", [])
            )
            self.bonuses[bonus.strategy_hash] = bonus
        
        self.failure_counts = state.get("failure_counts", {})
        self.success_counts = state.get("success_counts", {})
