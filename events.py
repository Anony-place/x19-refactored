"""Minimal thread-safe event bus for agent observability.

The terminal UI is *reactive*: it renders whatever the agent actually does,
as it does it (the same push-based model Claude Code/Codex use). The agent
core publishes facts here — commands executed, findings verified, status
changes — and any number of subscribers (the live ribbon, activity cards,
log writers) consume them.

Design notes:

* No dependencies, no daemon threads: publishing is synchronous so an event
  is visible to subscribers the moment ``publish`` returns.
* A failing subscriber can never break the agent: exceptions are swallowed.
* Bounded per-subscriber queues: a UI that stops draining must not grow the
  agent's memory without limit.
"""
from __future__ import annotations

import queue
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional


@dataclass(frozen=True)
class AgentEvent:
    """One thing the agent did. ``kind`` is a stable, machine-readable name."""

    kind: str                 # command | finding | ports | os | status | phase
    target: str = ""
    text: str = ""            # human-readable one-liner
    detail: Dict[str, Any] = field(default_factory=dict)
    ts: float = field(default_factory=time.time)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind,
            "target": self.target,
            "text": self.text,
            "detail": dict(self.detail),
            "ts": self.ts,
        }


Subscriber = Callable[[AgentEvent], None]


class AgentEventBus:
    """Fan-out event broadcaster with bounded per-subscriber queues."""

    def __init__(self, max_queue: int = 500):
        self._lock = threading.RLock()
        self._subs: Dict[int, tuple] = {}  # id -> (queue.Queue, subscriber fn)
        self._next_id = 0
        self._max_queue = max(10, int(max_queue))
        self._seq = 0

    def subscribe(self, fn: Optional[Subscriber] = None):
        """Register a subscriber. Returns ``(token, event_queue)``.

        Can also be used as a decorator: ``@bus.subscribe`` on a function —
        the function becomes the drain hook and the queue is still returned
        via ``token``.
        """
        q: "queue.Queue[AgentEvent]" = queue.Queue(maxsize=self._max_queue)
        with self._lock:
            token = self._next_id
            self._next_id += 1
            if fn is not None:
                self._subs[token] = (q, fn)
            else:
                self._subs[token] = (q, None)
        return token, q

    def unsubscribe(self, token: int) -> None:
        with self._lock:
            self._subs.pop(token, None)

    def publish(self, kind: str, text: str = "", *, target: str = "", **detail: Any) -> AgentEvent:
        event = AgentEvent(kind=kind, text=text, target=target, detail=detail)
        with self._lock:
            self._seq += 1
            subscribers = list(self._subs.values())
        for q, fn in subscribers:
            if fn is not None:
                try:
                    fn(event)
                except Exception:
                    pass
            else:
                try:
                    q.put_nowait(event)
                except queue.Full:
                    # Drop the oldest and keep the newest — a live view wants
                    # freshness more than completeness.
                    try:
                        q.get_nowait()
                        q.put_nowait(event)
                    except Exception:
                        pass
        return event


def summarize_event(event: AgentEvent) -> str:
    """One dim transcript line for an event (tool-card style)."""
    kind = event.kind
    detail = event.detail
    if kind == "command":
        cmd = str(detail.get("cmd", event.text or ""))[:96]
        rc = detail.get("rc", "?")
        secs = detail.get("secs")
        suffix = f" · rc {rc}" + (f" · {secs}s" if isinstance(secs, (int, float)) else "")
        return f"⚙ {cmd}{suffix}"
    if kind == "finding":
        sev = str(detail.get("severity", "info")).upper()
        return f"!! finding [{sev}] {event.text or detail.get('title', '')}"
    if kind == "ports":
        return f"+ ports: {event.text}"
    if kind == "os":
        return f"+ os fingerprint: {event.text}"
    if kind == "status":
        return f"■ status: {event.text}"
    if kind == "oob":
        proto = str(detail.get("protocol", "?"))
        return f"◉ oob callback [{proto}] {event.text}"
    if kind == "team":
        return f"♛ {event.text}"
    if kind == "escalation":
        return f"⤴ {event.text}"
    return f"· {event.text or kind}"
