"""Process-wide rich Console plus the shared output helpers.

Two output contracts live here:

* **Human mode** (default) — styled panels, tables and status lines.
* **Machine mode** (``--json``) — nothing decorative is written to *stdout*;
  ``emit_json()`` owns stdout and every human message is redirected to
  *stderr*, so ``x19 report --json | jq .`` always parses.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
from contextlib import contextmanager
from typing import Any, Dict, Iterable, NoReturn, Optional

from rich.console import Console, ConsoleOptions, RenderResult

from ui.theme import X19_THEME

_console: Optional[Console] = None
_json_mode = False
_plain_mode = False


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------
def init_console(
    no_color: bool = False,
    plain: bool = False,
    json_mode: bool = False,
    width: Optional[int] = None,
    force_terminal: Optional[bool] = None,
) -> Console:
    """Create (or replace) the global console. Safe to call more than once."""
    global _console, _json_mode, _plain_mode

    _json_mode = bool(json_mode)
    _plain_mode = bool(plain)

    if width is None and not plain:
        detected = shutil.get_terminal_size((100, 24)).columns
        width = max(60, min(detected, int(os.getenv("X19_MAX_WIDTH", "160"))))

    _console = Console(
        theme=X19_THEME,
        no_color=bool(no_color) or os.getenv("NO_COLOR", "") != "",
        highlight=False,
        soft_wrap=False,
        width=width,
        force_terminal=force_terminal,
        legacy_windows=None,
        markup=True,
        emoji=False,
        # None (human mode) keeps stdout resolved dynamically so redirection
        # and tests work; machine mode pins stderr so stdout stays pure JSON.
        file=sys.stderr if _json_mode else None,
    )
    return _console


def get_console() -> Console:
    """Return the active console, initialising a default one on first use."""
    global _console
    if _console is None:
        _console = init_console()
    return _console


def is_json_mode() -> bool:
    return _json_mode


def is_plain_mode() -> bool:
    return _plain_mode


def terminal_width() -> int:
    return get_console().width


# ---------------------------------------------------------------------------
# Machine-readable output
# ---------------------------------------------------------------------------
def emit_json(payload: Any) -> None:
    """Write one JSON document to stdout (machine mode)."""
    sys.stdout.write(json.dumps(payload, indent=2, default=str, ensure_ascii=False))
    sys.stdout.write("\n")
    sys.stdout.flush()


def emit_jsonl(records: Iterable[Dict[str, Any]]) -> None:
    for record in records:
        sys.stdout.write(json.dumps(record, default=str, ensure_ascii=False) + "\n")
    sys.stdout.flush()


# ---------------------------------------------------------------------------
# Human output helpers
# ---------------------------------------------------------------------------
def ok(message: str = "") -> None:
    if _json_mode:
        return
    get_console().print(f"[app.ok]✔[/] {message}" if message else "[app.ok]✔[/]")


def fail(message: str = "") -> None:
    if _json_mode:
        return
    get_console().print(f"[app.err]✖[/] {message}" if message else "[app.err]✖[/]")


def warn(message: str = "") -> None:
    if _json_mode:
        return
    get_console().print(f"[app.warn]![/] {message}" if message else "[app.warn]![/]")


def err(message: str = "") -> None:
    if _json_mode:
        return
    get_console().print(f"[app.err]✖[/] {message}" if message else "[app.err]✖[/]")


def info(message: str = "") -> None:
    if _json_mode:
        return
    get_console().print(f"[app.info]•[/] {message}" if message else "[app.info]•[/]")


def step(message: str = "") -> None:
    """Secondary/progress line, dimmed so it never competes with results."""
    if _json_mode:
        return
    get_console().print(f"[app.dim]»[/] [app.dim]{message}[/]")


def raw(message: str = "") -> None:
    get_console().print(message)


def rule(title: str = "", style: str = "panel.border") -> None:
    if _json_mode:
        return
    get_console().rule(title, style=style)


def die(message: str, code: int = 1) -> NoReturn:
    """Print an error and exit with ``code``."""
    get_console().print(f"[app.err]✖ {message}[/]")
    raise SystemExit(code)


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
_LOGO = (
    "██╗  ██╗ ██╗ ██████╗ \n"
    "╚██╗██╔╝███║╚════██╗\n"
    " ╚███╔╝ ╚██║ █████╔╝\n"
    " ██╔██╗  ██║ ╚═══██╗\n"
    "██╔╝ ██╗ ██║██████╔╝\n"
    "╚═╝  ╚═╝ ╚═╝╚═════╝ "
)

_LOGO_ASCII = r"""
\ \  / / _ \  | __)
 \ \/ / (_) | |__ \
  \  / \__, | ___) |
   \/    /_/  |____/
""".strip("\n")


class Banner:
    """The application header. Renders as a logo panel, or one line when the
    terminal is narrow / unicode is unavailable."""

    def __init__(self, version: str, subtitle: str = "", meta: str = ""):
        self.version = version
        self.subtitle = subtitle
        self.meta = meta

    def __rich_console__(self, console: Console, options: ConsoleOptions) -> RenderResult:
        from rich.align import Align
        from rich.panel import Panel
        from rich.table import Table
        from rich.text import Text as _Text

        encoding = (console.options.encoding or "").lower()
        unicode_ok = encoding.startswith("utf")
        logo_src = _LOGO if unicode_ok else _LOGO_ASCII

        if console.width < 64:
            line = _Text()
            line.append("X19", style="bold bright_cyan")
            line.append(f"  {self.version}", style="grey62")
            if self.subtitle:
                line.append(f"  ·  {self.subtitle}", style="grey50")
            yield line
            return

        logo = _Text(logo_src, style="bold cyan")
        right = _Text()
        right.append("AUTONOMOUS AI SECURITY ASSESSMENT", style="bold bright_white")
        right.append("\n")
        right.append(self.subtitle or "recon → enumeration → exploitation → verified evidence", style="grey62")
        right.append("\n\n")
        right.append(f"version {self.version}", style="bold cyan")
        if self.meta:
            right.append(f"\n{self.meta}", style="grey50")

        grid = Table.grid(padding=(0, 2))
        grid.add_column(justify="left", no_wrap=True)
        grid.add_column(justify="left")
        grid.add_row(logo, Align(right, vertical="middle"))

        yield Panel(
            grid,
            border_style="cyan",
            padding=(0, 1),
            title="[panel.title] X19 [/]",
            title_align="left",
            subtitle="[app.dim]cli · no web ui[/]",
            subtitle_align="right",
        )


def banner(version: str, subtitle: str = "", meta: str = "") -> None:
    """Print the application banner (suppressed in machine mode)."""
    if _json_mode:
        return
    get_console().print(Banner(version, subtitle, meta))


# ---------------------------------------------------------------------------
# Spinner / status
# ---------------------------------------------------------------------------
@contextmanager
def working(message: str, transient: bool = True):
    """``with working("loading"): ...`` — spinner in human mode, no-op in JSON."""
    con = get_console()
    if _json_mode or _plain_mode or not con.is_terminal:
        yield
        return
    with con.status(f"[app.info]{message}[/]", spinner="dots"):
        yield
