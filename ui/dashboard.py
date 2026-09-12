"""Live mission control — the terminal replacement for the web dashboard.

The web UI exposed four things the operator actually watched:

1. mission status + KPI strip
2. swarm agent monitor
3. the attack graph
4. the real-time event stream, plus finding triage and report export

``MissionDashboard`` renders all of them in one full-screen layout and drives
them off the same :class:`brain.coordinator.SwarmCoordinator` the Flask app
used, so no capability was lost — only the transport changed.

The class is deliberately decoupled from the coordinator: it consumes the
plain ``dict`` returned by ``get_summary()``/``get_attack_graph_d3()``, which
makes it directly testable with fixture data.
"""
from __future__ import annotations

import threading
import time
from collections import deque
from typing import Any, Dict, List, Optional

from rich.console import Group
from rich.layout import Layout
from rich.live import Live
from rich.padding import Padding

from ui import widgets
from ui.console import get_console, is_json_mode
from ui.keys import KeyListener, key_capture_supported

#: Keys the dashboard listens for. Mirrors the old dashboard's toolbar.
KEY_BINDINGS = [
    ("ctrl-c", "stop mission"),
    ("q", "quit"),
    ("r", "report"),
    ("g", "graph"),
    ("f", "findings"),
    ("space", "pause redraw"),
]

#: How long the mission must look finished before the view lets go.
SETTLE_SECONDS = 2.0

# The full dashboard needs enough room for two panel columns, a log and a task
# queue.  Below these dimensions Rich must crop meaningful state, so use the
# scrollable renderer instead of presenting a visually broken TUI.
MIN_LIVE_WIDTH = 100
MIN_LIVE_HEIGHT = 30


def severity_summary(counts: Dict[str, int]) -> str:
    """``critical:1 high:2`` — the compact finding roll-up in a panel corner."""
    if not counts:
        return "none"
    order = ("critical", "high", "medium", "low", "info")
    parts = [f"{k}:{counts[k]}" for k in order if counts.get(k)]
    return " ".join(parts) or "none"


def chrome(renderable: Any) -> Padding:
    """Borderless wrapper for the header / KPI / footer rows."""
    return Padding(renderable, (0, 1))


class MissionDashboard:
    """Full-screen mission control for a swarm run."""

    def __init__(
        self,
        coordinator: Any = None,
        *,
        version: str = "",
        refresh: float = 0.5,
        max_events: int = 400,
        console: Any = None,
    ):
        self.coordinator = coordinator
        self.version = version
        self.refresh = max(0.05, float(refresh))
        self.console = console or get_console()

        self._events: "deque[Dict[str, Any]]" = deque(maxlen=max_events)
        self._lock = threading.Lock()
        self._summary: Dict[str, Any] = {}
        self._graph: Dict[str, Any] = {"nodes": [], "edges": []}
        self._started: Optional[float] = None
        self._focus = "all"          # all | graph | findings
        self._paused = False
        self._dirty = True
        self.report_requested = False
        self._stop = False

        if coordinator is not None and hasattr(coordinator, "subscribe_events"):
            try:
                coordinator.subscribe_events(self.on_event)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Data plumbing
    # ------------------------------------------------------------------
    def on_event(self, payload: Dict[str, Any]) -> None:
        """Event subscriber callback (same shape the SSE stream emitted)."""
        record = {
            "type": payload.get("type") or payload.get("event_type") or "log",
            "sender": payload.get("sender", ""),
            "data": payload.get("data") or {},
            "timestamp": payload.get("timestamp") or time.time(),
        }
        with self._lock:
            self._events.append(record)
        self._dirty = True

    @property
    def events(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._events)

    def refresh_state(self) -> Dict[str, Any]:
        """Pull the latest summary/graph from the coordinator."""
        if self.coordinator is None:
            return self._summary
        try:
            self._summary = self.coordinator.get_summary() or {}
        except Exception:
            pass
        try:
            self._graph = self.coordinator.get_attack_graph_d3() or self._graph
        except Exception:
            pass
        self._dirty = True
        return self._summary

    def load(self, summary: Dict[str, Any], graph: Optional[Dict[str, Any]] = None) -> None:
        """Inject state directly (used by tests and by ``x19 dash --demo``)."""
        self._summary = summary or {}
        if graph is not None:
            self._graph = graph
        self._dirty = True

    # ------------------------------------------------------------------
    # Derived values
    # ------------------------------------------------------------------
    def elapsed(self) -> Optional[float]:
        summary = self._summary
        if summary.get("duration_seconds") is not None:
            try:
                return float(summary["duration_seconds"])
            except (TypeError, ValueError):
                pass
        if self._started:
            return time.time() - self._started
        return None

    def stats(self) -> Dict[str, int]:
        return dict(self._summary.get("stats") or {})

    def _metrics(self, *, compact: bool = False) -> List[tuple[str, Any, str]]:
        """Return the KPI set that fits the active dashboard layout."""
        stats = self.stats()
        counts = widgets.findings_by_severity(self.findings())
        metrics = [
            ("open ports", stats.get("open_ports", 0), "cyan"),
            ("endpoints", stats.get("endpoints", 0), "magenta"),
            ("verified", stats.get("verified_findings", 0), "bright_green"),
            ("critical", counts.get("critical", 0), "bright_red"),
        ]
        if compact:
            return metrics
        return [
            *metrics[:2],
            ("raw findings", stats.get("raw_findings", 0), "yellow"),
            *metrics[2:],
            ("queued", stats.get("pending_tasks", 0), "grey74"),
            ("elapsed", widgets.human_duration(self.elapsed()), "bright_white"),
        ]

    def findings(self) -> List[Dict[str, Any]]:
        return list(self._summary.get("verified_findings") or [])

    @property
    def target(self) -> str:
        return str(self._summary.get("target") or (getattr(self.coordinator, "target", "") or ""))

    @property
    def running(self) -> bool:
        if self.coordinator is not None:
            return bool(getattr(self.coordinator, "is_running", False)) or bool(self._summary.get("is_running"))
        return bool(self._summary.get("is_running"))

    def status(self) -> str:
        if self.running:
            return "running"
        if self.coordinator is not None:
            # end_time is only set when a pipeline actually finished.
            return "completed" if getattr(self.coordinator, "end_time", 0) else "standby"
        return "completed" if self._summary.get("duration_seconds") else "standby"

    # ------------------------------------------------------------------
    # Rendering
    # ------------------------------------------------------------------
    def frame(self) -> Layout:
        """Compose the whole screen. Pure function of the current state."""
        self.refresh_state()
        summary = self._summary
        stats = self.stats()
        counts = widgets.findings_by_severity(self.findings())

        header = widgets.header_bar(
            self.version,
            target=self.target or "—",
            status=self.status(),
            elapsed=self.elapsed(),
            mode=str(summary.get("mode") or ""),
        )

        strip = widgets.metric_strip(self._metrics())

        agents = widgets.panel(
            "swarm agents",
            widgets.agents_table(summary.get("agents") or []),
            subtitle=f"{len(summary.get('agents') or [])} registered",
        )
        graph = widgets.panel(
            "attack graph",
            widgets.attack_graph_tree(self._graph),
            subtitle=f"{len(self._graph.get('nodes', []))} nodes / {len(self._graph.get('edges', []))} edges",
        )
        surface = Group(
            widgets.panel("open ports", widgets.ports_table(summary.get("ports") or [])),
            widgets.panel("endpoints", widgets.endpoints_table(summary.get("endpoints") or [])),
        )
        findings = widgets.panel(
            "verified findings",
            widgets.findings_table(self.findings(), limit=8),
            subtitle=severity_summary(counts),
        )
        queue = widgets.panel(
            "task queue",
            widgets.task_queue_table(summary.get("tasks") or []),
            subtitle=f"{stats.get('pending_tasks', 0)} pending",
        )
        stream = widgets.panel(
            "event stream",
            widgets.event_stream(self.events, limit=12),
            subtitle="live",
        )

        if self._focus == "graph":
            body = Layout(name="body")
            body.split_column(
                Layout(graph, name="graph", ratio=4),
                Layout(stream, name="stream", ratio=2),
            )
        elif self._focus == "findings":
            body = Layout(name="body")
            body.split_column(
                Layout(findings, name="findings", ratio=3),
                Layout(queue, name="queue", ratio=2),
                Layout(stream, name="stream", ratio=2),
            )
        else:
            columns = Layout(name="columns")
            columns.split_row(
                Layout(name="left", ratio=1),
                Layout(name="right", ratio=1),
            )
            columns["left"].split_column(
                Layout(agents, name="agents", ratio=3),
                Layout(surface, name="surface", ratio=3),
            )
            columns["right"].split_column(
                Layout(graph, name="graph", ratio=3),
                Layout(findings, name="findings", ratio=3),
            )
            body = Layout(name="body")
            body.split_column(
                Layout(columns, name="columns", ratio=6),
                Layout(stream, name="stream", ratio=2),
                Layout(queue, name="queue", ratio=2),
            )

        root = Layout(name="root")
        root.split_column(
            Layout(chrome(header), name="header", size=4),
            Layout(chrome(strip), name="kpi", size=4),
            Layout(body, name="body"),
            Layout(chrome(widgets.key_hint_bar(KEY_BINDINGS)), name="footer", size=1),
        )
        return root

    def scrolling_frame(self) -> Any:
        """The same panels stacked vertically instead of a fixed full-screen grid.

        Used whenever there is no real terminal to occupy (pipes, CI, ``--once``,
        ``--no-tui``): a fixed Layout would be squeezed into 25 rows and crop the
        event stream, while stacked panels scroll naturally.
        """
        from rich.console import Group

        self.refresh_state()
        summary = self._summary
        stats = self.stats()
        counts = widgets.findings_by_severity(self.findings())

        return Group(
            chrome(
                widgets.header_bar(
                    self.version,
                    target=self.target or "—",
                    status=self.status(),
                    elapsed=self.elapsed(),
                    mode=str(summary.get("mode") or ""),
                )
            ),
            chrome(widgets.metric_strip(self._metrics(compact=self.console.width < MIN_LIVE_WIDTH))),
            widgets.panel(
                "swarm agents",
                widgets.agents_table(summary.get("agents") or []),
                subtitle=f"{len(summary.get('agents') or [])} registered",
            ),
            widgets.panel(
                "attack graph",
                widgets.attack_graph_tree(self._graph),
                subtitle=f"{len(self._graph.get('nodes', []))} nodes / {len(self._graph.get('edges', []))} edges",
            ),
            widgets.panel("open ports", widgets.ports_table(summary.get("ports") or [], limit=25)),
            widgets.panel("endpoints", widgets.endpoints_table(summary.get("endpoints") or [], limit=25)),
            widgets.panel(
                "verified findings",
                widgets.findings_table(self.findings(), limit=25),
                subtitle=severity_summary(counts),
            ),
            widgets.panel(
                "task queue",
                widgets.task_queue_table(summary.get("tasks") or [], limit=15),
                subtitle=f"{stats.get('pending_tasks', 0)} pending",
            ),
            widgets.panel(
                "event stream",
                widgets.event_stream(self.events, limit=30),
                subtitle=f"{len(self.events)} events",
            ),
        )

    def capture(self, width: int = 120, height: int = 40) -> str:
        """Render one frame to text — used by tests and non-TTY output."""
        import io

        from rich.console import Console

        from ui.theme import X19_THEME

        buf = Console(
            file=io.StringIO(),
            width=width,
            height=height,
            force_terminal=False,
            record=True,
            theme=X19_THEME,
        )
        buf.print(self.frame())
        return buf.export_text(clear=True, styles=False)

    # ------------------------------------------------------------------
    # Live loop
    # ------------------------------------------------------------------
    def run(
        self,
        *,
        target: str = "",
        start: bool = True,
        once: bool = False,
        headless: Optional[bool] = None,
        wait: bool = True,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Run the dashboard until the mission ends, the user quits, or timeout."""
        if target and self.coordinator is not None and hasattr(self.coordinator, "set_target"):
            self.coordinator.set_target(target)
        if start and self.coordinator is not None and hasattr(self.coordinator, "start_mission_pipeline"):
            self.coordinator.start_mission_pipeline(target or None)

        self._started = time.time()
        self.refresh_state()

        if is_json_mode():
            return self._run_json(timeout=timeout)
        if once:
            self.console.print(self.scrolling_frame())
            return self.refresh_state()

        interactive = key_capture_supported() if headless is None else not headless
        terminal_is_too_small = (
            self.console.width < MIN_LIVE_WIDTH
            or self.console.height < MIN_LIVE_HEIGHT
        )
        if not interactive or terminal_is_too_small:
            return self._run_polling(wait=wait, timeout=timeout)
        return self._run_live(timeout=timeout, wait=wait)

    def _run_live(self, *, timeout: Optional[float], wait: bool) -> Dict[str, Any]:
        # A caller that asked not to wait needs a useful, durable snapshot.  Rich's
        # alternate-screen live renderer is intentionally ephemeral, so it can
        # produce no readable output when the process exits immediately (notably
        # for programmatic callers and redirected terminal adapters).  Render the
        # same complete dashboard used by the non-interactive path instead.
        if not wait:
            self.console.print(self.scrolling_frame())
            return self.refresh_state()

        settled: Optional[float] = None
        with KeyListener() as keys:
            with Live(
                self.frame(),
                console=self.console,
                screen=True,
                refresh_per_second=max(2, int(1 / self.refresh)),
                transient=False,
            ) as live:
                deadline = (time.time() + timeout) if timeout else None
                while True:
                    key = keys.read()
                    if key and not self._handle_key(key, live):
                        break
                    if self._dirty and not self._paused:
                        live.update(self.frame())
                        self._dirty = False
                    if self.running:
                        settled = None
                    else:
                        settled = time.time() if settled is None else settled
                        if settled and time.time() - settled >= SETTLE_SECONDS:
                            live.update(self.frame())
                            break
                    if not wait:
                        break
                    if deadline and time.time() > deadline:
                        break
                    time.sleep(self.refresh)
        return self.refresh_state()

    def status_line(self) -> Any:
        """Compact one-line progress used while streaming to a non-terminal."""
        from rich.text import Text

        stats = self.stats()
        text = Text()
        text.append(f"[{widgets.human_duration(self.elapsed())}] ", style="grey50")
        text.append(self.target or "—", style="bold bright_white")
        text.append(
            f"  ports={stats.get('open_ports', 0)} "
            f"endpoints={stats.get('endpoints', 0)} "
            f"raw={stats.get('raw_findings', 0)} "
            f"verified={stats.get('verified_findings', 0)} "
            f"queued={stats.get('pending_tasks', 0)}",
            style="grey70",
        )
        return text

    def _run_polling(self, *, wait: bool, timeout: Optional[float]) -> Dict[str, Any]:
        """Non-interactive fallback (pipes, CI, ``--no-tui``).

        Streams a compact status line while the mission runs and prints the full
        panel set once, at the end.
        """
        start = time.time()
        last = 0.0
        settled: Optional[float] = None
        deadline = (start + timeout) if timeout else None
        while True:
            self.refresh_state()
            now = time.time()
            if now - last >= 5.0:
                self.console.print(self.status_line())
                last = now
            if self.running:
                settled = None
            else:
                settled = now if settled is None else settled
                if settled and now - settled >= SETTLE_SECONDS:
                    break
            if not wait:
                break
            if deadline and now > deadline:
                break
            time.sleep(self.refresh)
        self.console.print(self.scrolling_frame())
        return self.refresh_state()

    def _run_json(self, *, timeout: Optional[float]) -> Dict[str, Any]:
        from ui.console import emit_json

        start = time.time()
        while self.running and (not timeout or time.time() - start < timeout):
            time.sleep(max(self.refresh, 0.25))
        summary = self.refresh_state()
        emit_json(
            {
                "target": summary.get("target"),
                "stats": summary.get("stats"),
                "agents": summary.get("agents"),
                "verified_findings": summary.get("verified_findings"),
                "graph": self._graph,
                "events": self.events,
            }
        )
        return summary

    def _handle_key(self, key: str, live: Any) -> bool:
        """Return ``False`` to exit the loop."""
        if key == "ctrl-c" and self.running and self.coordinator is not None:
            try:
                self.coordinator.stop_mission()
            except Exception:
                pass
            return True
        if key == "q":
            return False
        if key == "r":
            self.report_requested = True
        elif key == "g":
            self._focus = "graph" if self._focus != "graph" else "all"
        elif key == "f":
            self._focus = "findings" if self._focus != "findings" else "all"
        elif key == "space":
            self._paused = not self._paused
        self._dirty = True
        return True

    # ------------------------------------------------------------------
    # Post-run
    # ------------------------------------------------------------------
    def report(self) -> Any:
        """Final mission panel — printed after the live view closes."""
        self.refresh_state()
        stats = self.stats()
        counts = widgets.findings_by_severity(self.findings())
        body = widgets.kv_table(
            [
                ("target", self.target or "—"),
                ("status", self.status().upper()),
                ("duration", widgets.human_duration(self.elapsed())),
                ("open ports", stats.get("open_ports", 0)),
                ("endpoints", stats.get("endpoints", 0)),
                ("raw findings", stats.get("raw_findings", 0)),
                ("verified", stats.get("verified_findings", 0)),
                ("by severity", severity_summary(counts)),
            ]
        )
        return widgets.panel("mission complete", body, border_style="bright_green")
