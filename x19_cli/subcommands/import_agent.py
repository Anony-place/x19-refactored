"""``x19 import-agent`` subcommand parser (logic lives in ``x19_cli/agent_import.py``)."""

from __future__ import annotations

from typing import Callable

from x19_cli.subcommands._shared import add_yes_flag


def build_import_agent_parser(subparsers, *, cmd_import_agent: Callable) -> None:
    """Attach the ``import-agent`` subcommand to ``subparsers``."""
    parser = subparsers.add_parser(
        "import-agent", help="Import a Claude Code or Codex CLI setup into X19",
        description="One-command import of another coding agent's setup into X19. "
            "Maps CLAUDE.md/AGENTS.md instructions, permission allowlists, MCP "
            "servers, skills, and memories into their X19 equivalents. "
            "Always shows a preview before making changes. API keys and "
            "credentials are never imported — run 'x19 setup' for those.")
    parser.add_argument(
        "agent", nargs="?", choices=["claude-code", "codex"],
        help="Which agent to import from (default: auto-detect ~/.claude or ~/.codex)")
    parser.add_argument(
        "--source", help="Path to the agent's config directory (default: ~/.claude or ~/.codex)")
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Preview only — stop after showing what would be imported")
    parser.add_argument(
        "--overwrite", action="store_true",
        help="Overwrite existing X19 items on name conflicts (default: skip)")
    add_yes_flag(parser, "Skip confirmation prompts")
    parser.add_argument(
        "--sync", action="store_true",
        help="Re-import every previously imported source whose files changed since the last "
             "import (registered in X19_HOME/import-sync.json). Runs without prompts; "
             "combine with --dry-run to preview.")
    parser.set_defaults(func=cmd_import_agent)
