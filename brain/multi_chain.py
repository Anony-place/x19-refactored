"""Evidence-driven multi-chain controller for X19.

This module provides orchestration primitives rather than direct offensive
execution. Chains produce structured action intents; the existing command
Gateway/Policy layer remains the only execution boundary.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Optional


class ChainStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETE = "complete"
    BLOCKED = "blocked"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass(frozen=True)
class ChainContext:
    mission_id: str
    state: Dict[str, Any] = field(default_factory=dict)
    observations: List[Dict[str, Any]] = field(default_factory=list)
    hypotheses: List[Dict[str, Any]] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True)
class ChainAction:
    """An intent emitted by a chain; execution happens elsewhere."""

    chain: str
    action: str
    reason: str = ""
    hypothesis_id: str = ""
    expected_evidence: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ChainResult:
    chain: str
    status: ChainStatus
    actions: List[ChainAction] = field(default_factory=list)
    observations: List[Dict[str, Any]] = field(default_factory=list)
    message: str = ""


@dataclass
class AgentChain:
    """A bounded reasoning chain with explicit input/output ownership."""

    name: str
    stages: List[Callable[[ChainContext], ChainResult]]
    priority: int = 100
    enabled: bool = True

    def run(self, context: ChainContext) -> ChainResult:
        if not self.enabled:
            return ChainResult(self.name, ChainStatus.SKIPPED, message="chain disabled")

        actions: List[ChainAction] = []
        observations: List[Dict[str, Any]] = []
        current = context

        for stage in self.stages:
            result = stage(current)
            actions.extend(result.actions)
            observations.extend(result.observations)

            if result.status in {
                ChainStatus.BLOCKED,
                ChainStatus.FAILED,
            }:
                return ChainResult(
                    self.name,
                    result.status,
                    actions=actions,
                    observations=observations,
                    message=result.message,
                )

            current = ChainContext(
                mission_id=context.mission_id,
                state=dict(current.state),
                observations=current.observations + result.observations,
                hypotheses=current.hypotheses,
                findings=current.findings,
            )

        return ChainResult(
            self.name,
            ChainStatus.COMPLETE,
            actions=actions,
            observations=observations,
        )


class MultiChainController:
    """Coordinate independent specialist chains around shared mission state.

    The controller does not execute shell/network operations. It merges chain
    observations, resolves duplicate actions, and returns intents to the
    caller, which must pass them through the command gateway and policy layer.
    """

    def __init__(self, chains: Optional[Iterable[AgentChain]] = None):
        self._chains: Dict[str, AgentChain] = {}
        for chain in chains or ():
            self.register(chain)

    def register(self, chain: AgentChain) -> None:
        if not chain.name.strip():
            raise ValueError("chain name cannot be empty")
        if chain.name in self._chains:
            raise ValueError(f"chain already registered: {chain.name}")
        self._chains[chain.name] = chain

    def names(self) -> List[str]:
        return sorted(self._chains, key=lambda name: self._chains[name].priority)

    def run(self, context: ChainContext, *, selected: Optional[Iterable[str]] = None) -> List[ChainResult]:
        names = list(selected) if selected is not None else self.names()
        results: List[ChainResult] = []
        seen_actions: set[tuple[str, str, str]] = set()

        for name in names:
            chain = self._chains.get(name)
            if chain is None:
                results.append(ChainResult(name, ChainStatus.FAILED, message="unknown chain"))
                continue

            result = chain.run(context)
            unique_actions: List[ChainAction] = []
            for action in result.actions:
                key = (action.chain, action.action, action.hypothesis_id)
                if key not in seen_actions:
                    seen_actions.add(key)
                    unique_actions.append(action)

            results.append(
                ChainResult(
                    result.chain,
                    result.status,
                    actions=unique_actions,
                    observations=result.observations,
                    message=result.message,
                )
            )

        return results

    @staticmethod
    def merge_observations(results: Iterable[ChainResult]) -> List[Dict[str, Any]]:
        merged: List[Dict[str, Any]] = []
        fingerprints: set[str] = set()
        for result in results:
            for observation in result.observations:
                fingerprint = repr(sorted(observation.items()))
                if fingerprint not in fingerprints:
                    fingerprints.add(fingerprint)
                    merged.append(observation)
        return merged
