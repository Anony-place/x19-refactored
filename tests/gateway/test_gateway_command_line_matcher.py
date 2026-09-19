"""Tests for the strict gateway command-line matcher.

Regression guard for the Windows ``x19 gateway restart`` silent-outage bug:
the previous loose substring match (``"... gateway" in cmdline``) false-matched
``gateway status``/``dashboard`` siblings and unrelated processes such as
``python -m tui_gateway``, which let ``restart()`` race a still-draining old
process and ``status``/``start`` report false positives.
"""

from __future__ import annotations

import pytest

from gateway.status import (
    looks_like_gateway_command_line as matches,
    looks_like_gateway_runtime_command_line as matches_runtime,
)


ACCEPT = [
    "pythonw.exe -m x19_cli.main gateway run",
    r"C:\Users\me\x19\venv\Scripts\pythonw.exe -m x19_cli.main gateway run",
    "python -m x19_cli.main --profile work gateway run",
    "python -m x19_cli.main gateway run --replace",
    "python -m x19_cli/main.py gateway run",
    "python gateway/run.py",
    "x19-gateway.exe",
    "x19 gateway",          # bare `x19 gateway` defaults to run
    "x19 gateway run",
    # profile selector AFTER the `gateway` token (argv is profile-position
    # agnostic — _apply_profile_override strips --profile/-p anywhere)
    "x19 gateway --profile work run",
    "python -m x19_cli.main gateway -p work run",
    "x19 gateway --profile=work run",
    # a profile literally NAMED "gateway"
    "x19 -p gateway gateway run",
    "python -m x19_cli.main --profile gateway gateway run",
    # quoted Windows paths with spaces (shlex-aware tokenization)
    r'"C:\Program Files\X19\x19-gateway.exe"',
    r'"C:\Program Files\X19\gateway\run.py" run',
    r'"C:\Program Files\Py\pythonw.exe" -m x19_cli.main gateway run',
]

REJECT = [
    "python -m tui_gateway",                              # unrelated module
    "python -m x19_cli.main gateway status",           # other subcommand
    "python -m x19_cli.main gateway restart",
    "python -m x19_cli.main gateway stop",
    "python -m x19_cli.main --profile x dashboard",    # non-gateway subcommand
    "some random python -m mygateway thing",
    "",
    None,
]


@pytest.mark.parametrize("cmd", ACCEPT)
def test_accepts_real_gateway_run(cmd):
    assert matches(cmd) is True


