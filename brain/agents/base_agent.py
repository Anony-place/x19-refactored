"""
X19 Swarm Base Agent Interface.
Defines lifecycle, status, logging, task processing, and event contracts for all specialized agents.
"""

from __future__ import annotations
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Callable


class AgentState(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    WAITING = "waiting"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"


@dataclass
class AgentMessage:
    sender: str
    recipient: str
    msg_type: str  # "finding", "task", "evidence", "penalty", "status"
    payload: Dict[str, Any]
    timestamp: float = field(default_factory=time.time)


class BaseSwarmAgent(ABC):
    """Abstract base class for all X19 parallel cognitive swarm agents."""

    def __init__(self, name: str, role: str, coordinator: Optional[Any] = None):
        self.name = name
        self.role = role
        self.coordinator = coordinator
        self.state: AgentState = AgentState.IDLE
        self.current_task: str = ""
        self.progress_pct: int = 0
        self.logs: List[str] = []
        self.discovered_count: int = 0
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    def log(self, message: str) -> None:
        timestamp = time.strftime("%H:%M:%S")
        entry = f"[{timestamp}] [{self.name}] {message}"
        self.logs.append(entry)
        if self.coordinator and hasattr(self.coordinator, "publish_log"):
            self.coordinator.publish_log(self.name, message)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "role": self.role,
            "state": self.state.value,
            "current_task": self.current_task,
            "progress_pct": self.progress_pct,
            "discovered_count": self.discovered_count,
            "last_log": self.logs[-1] if self.logs else ""
        }

    def start_async(self, target: str, **kwargs) -> threading.Thread:
        """Launch agent execution in a managed background thread."""
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_wrapper,
            args=(target,),
            kwargs=kwargs,
            name=f"Agent-{self.name}",
            daemon=True
        )
        self._thread.start()
        return self._thread

    def stop(self) -> None:
        """Signal agent to abort current work."""
        self._stop_event.set()
        self.state = AgentState.BLOCKED
        self.log("Received stop signal. Halting.")

    def is_stopped(self) -> bool:
        return self._stop_event.is_set()

    def _run_wrapper(self, target: str, **kwargs) -> None:
        self.state = AgentState.RUNNING
        self.log(f"Started mission task on target: {target}")
        try:
            self.run(target, **kwargs)
            if not self.is_stopped():
                self.state = AgentState.COMPLETED
                self.progress_pct = 100
                self.log("Mission task completed successfully.")
        except Exception as e:
            self.state = AgentState.FAILED
            self.log(f"Agent failed with error: {str(e)}")
        finally:
            if self.coordinator and hasattr(self.coordinator, "on_agent_finished"):
                self.coordinator.on_agent_finished(self.name)

    @abstractmethod
    def run(self, target: str, **kwargs) -> None:
        """Execute core specialized agent logic."""
        pass
