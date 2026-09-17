"""Observability — PentAGI OTEL pattern, XBOW audit treemap.

PentAGI ships OTEL→VictoriaMetrics/Jaeger/Loki/Grafana + Langfuse→ClickHouse;
XBOW ships every packet/log + treemap per endpoint. X19 has events.py + ribbon
but no span tracing. This module is a lightweight OTEL-style tracer that writes
to events + optional file + stdout, and builds the XBOW treemap hint.

It is dependency-free (no otel package required) and additive — existing code
keeps running if this is not used.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class Span:
    trace_id: str
    span_id: str
    name: str
    start: float = field(default_factory=time.monotonic)
    end: Optional[float] = None
    attrs: Dict[str, Any] = field(default_factory=dict)
    events: List[Dict[str, Any]] = field(default_factory=list)
    parent_id: Optional[str] = None
    status: str = "ok"  # ok | error

    def finish(self, status: str = "ok", **attrs):
        self.end = time.monotonic()
        self.status = status
        self.attrs.update(attrs)

    @property
    def duration(self) -> float:
        if self.end is None:
            return time.monotonic() - self.start
        return self.end - self.start

    def add_event(self, name: str, **attrs):
        self.events.append({"name": name, "ts": time.time(), "attrs": attrs})

    def to_dict(self) -> Dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "parent_id": self.parent_id,
            "name": self.name,
            "duration": self.duration,
            "status": self.status,
            "attrs": self.attrs,
            "events": self.events,
        }


class Tracer:
    """Minimal tracer. Create one per mission; share trace_id across spans."""

    def __init__(self, trace_id: Optional[str] = None, log_file: Optional[str|Path]=None):
        self.trace_id = trace_id or uuid.uuid4().hex[:16]
        self.spans: List[Span] = []
        self.log_file = Path(log_file) if log_file else None
        self._stack: List[Span] = []

    def start_span(self, name: str, **attrs) -> Span:
        span_id = uuid.uuid4().hex[:8]
        parent = self._stack[-1].span_id if self._stack else None
        span = Span(trace_id=self.trace_id, span_id=span_id, name=name, parent_id=parent, attrs=dict(attrs))
        self.spans.append(span)
        self._stack.append(span)
        return span

    def end_span(self, span: Span, status: str = "ok", **attrs):
        if span.end is None:
            span.finish(status=status, **attrs)
        if self._stack and self._stack[-1] is span:
            self._stack.pop()
        self._emit(span)

    def span(self, name: str, **attrs):
        """Context manager."""
        class _Ctx:
            def __init__(self_, tracer, name, attrs):
                self_.tracer=tracer; self_.span=tracer.start_span(name, **attrs)
            def __enter__(self_): return self_.span
            def __exit__(self_, exc_type, exc, tb):
                status="error" if exc_type else "ok"
                self_.tracer.end_span(self_.span, status=status, error=str(exc)[:200] if exc else "")
        return _Ctx(self, name, attrs)

    def _emit(self, span: Span):
        if self.log_file:
            try:
                self.log_file.parent.mkdir(parents=True, exist_ok=True)
                with self.log_file.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(span.to_dict()) + "\n")
            except Exception:
                pass

    def treemap(self) -> Dict[str, Any]:
        """XBOW-style treemap hint: per-span-type duration + count."""
        agg: Dict[str, Dict[str, float]] = {}
        for s in self.spans:
            g = agg.setdefault(s.name, {"count":0, "total":0.0})
            g["count"] += 1
            g["total"] += s.duration
        return {"trace_id": self.trace_id, "spans": agg, "total_spans": len(self.spans)}

    def summary(self) -> str:
        m = self.treemap()
        parts = [f"trace {m['trace_id']} {m['total_spans']} spans"]
        for name, v in sorted(m["spans"].items()):
            parts.append(f"{name}: {int(v['count'])}×{v['total']:.1f}s")
        return " | ".join(parts)


# global tracer for convenience
_global_tracer: Optional[Tracer] = None

def get_tracer() -> Tracer:
    global _global_tracer
    if _global_tracer is None:
        _global_tracer = Tracer()
    return _global_tracer

def set_tracer(tracer: Tracer) -> None:
    global _global_tracer
    _global_tracer = tracer
