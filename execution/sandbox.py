from __future__ import annotations

import os
import shlex
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from tools import ToolResult


@dataclass(frozen=True)
class SandboxPolicy:
    """Host-side policy for untrusted command execution.

    The default is intentionally offline. A network-enabled Docker network must
    be selected explicitly by the operator; target scope is still enforced by
    the command gateway before this runner is reached.
    """

    image: str = field(default_factory=lambda: os.getenv("X19_SANDBOX_IMAGE", "x19-sandbox:latest"))
    network: str = field(default_factory=lambda: os.getenv("X19_SANDBOX_NETWORK", "none"))
    memory: str = field(default_factory=lambda: os.getenv("X19_SANDBOX_MEMORY", "1g"))
    cpus: str = field(default_factory=lambda: os.getenv("X19_SANDBOX_CPUS", "2"))
    pids_limit: int = field(default_factory=lambda: int(os.getenv("X19_SANDBOX_PIDS", "256")))
    tmpfs_size: str = field(default_factory=lambda: os.getenv("X19_SANDBOX_TMPFS", "256m"))
    workspace_mode: str = "rw"


class SandboxExecutor:
    """Run X19 shell commands inside an ephemeral, least-privilege container.

    This class deliberately owns the Docker invocation on the host side. The
    agent container/workload never receives docker.sock and therefore cannot
    control the host Docker daemon.
    """

    def __init__(self, workspace: str | Path, policy: Optional[SandboxPolicy] = None):
        self.workspace = Path(workspace).expanduser().resolve()
        self.policy = policy or SandboxPolicy()
        self._docker = shutil.which("docker")

    @property
    def available(self) -> bool:
        return bool(self._docker)

    def run(self, command: str, timeout: int = 120) -> ToolResult:
        if not command.strip():
            return ToolResult("", "", -1, "empty command")
        if not self.available:
            return ToolResult("", "", -1, "sandbox_unavailable: docker CLI not found")
        if not self.policy.image.strip():
            return ToolResult("", "", -1, "sandbox_unavailable: no image configured")

        try:
            self.workspace.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            return ToolResult("", "", -1, f"sandbox_workspace_error: {exc}")

        cmd = self._docker_command(command)
        try:
            completed = subprocess.run(
                cmd,
                cwd=str(self.workspace),
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=max(1, int(timeout)),
                check=False,
                env=self._clean_host_env(),
            )
        except subprocess.TimeoutExpired as exc:
            return ToolResult(
                (exc.stdout or "") if isinstance(exc.stdout, str) else "",
                (exc.stderr or "") if isinstance(exc.stderr, str) else "",
                -1,
                f"sandbox_timeout: exceeded {timeout}s",
            )
        except OSError as exc:
            return ToolResult("", "", -1, f"sandbox_launch_error: {exc}")

        return ToolResult(completed.stdout, completed.stderr, completed.returncode)

    def _docker_command(self, command: str) -> list[str]:
        p = self.policy
        # No host filesystem is exposed except the dedicated X19 workspace.
        # Root filesystem is read-only; /tmp and /run are ephemeral tmpfs.
        return [
            self._docker or "docker",
            "run",
            "--rm",
            "--init",
            "--network",
            p.network,
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges=true",
            "--pids-limit",
            str(max(16, p.pids_limit)),
            "--memory",
            p.memory,
            "--cpus",
            p.cpus,
            "--tmpfs",
            f"/tmp:rw,nosuid,nodev,noexec,size={p.tmpfs_size}",
            "--tmpfs",
            "/run:rw,nosuid,nodev,noexec,size=64m",
            "--mount",
            f"type=bind,src={self.workspace},dst=/workspace,{p.workspace_mode}",
            "--workdir",
            "/workspace",
            "--env",
            "HOME=/tmp/x19-home",
            "--env",
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            p.image,
            "/bin/sh",
            "-lc",
            command,
        ]

    @staticmethod
    def _clean_host_env() -> dict[str, str]:
        """Avoid leaking host credentials/config into the Docker CLI process."""
        keep = {"PATH", "HOME", "DOCKER_HOST", "DOCKER_CONFIG"}
        return {k: v for k, v in os.environ.items() if k in keep}

    def resolve_tool(self, tool_name: str, target: str, legacy_executor, **kwargs):
        """Delegate tool-template resolution to the existing registry.

        Tool discovery/templating stays unchanged; only the final execution
        boundary is sandboxed.
        """
        return legacy_executor.resolve_tool(tool_name, target, **kwargs)
