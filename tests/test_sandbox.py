from pathlib import Path

from execution.sandbox import SandboxExecutor, SandboxPolicy


def test_sandbox_command_is_hardened(tmp_path: Path):
    sandbox = SandboxExecutor(
        tmp_path,
        SandboxPolicy(
            image="x19-test:latest",
            network="none",
            memory="512m",
            cpus="1",
            pids_limit=64,
            tmpfs_size="64m",
        ),
    )

    command = sandbox._docker_command("printf 'ok'")

    assert Path(command[0]).name == "docker"
    assert command[1:3] == ["run", "--rm"]
    assert "--network" in command and command[command.index("--network") + 1] == "none"
    assert "--read-only" in command
    assert command[command.index("--cap-drop") + 1] == "ALL"
    assert command[command.index("--security-opt") + 1] == "no-new-privileges=true"
    assert command[command.index("--pids-limit") + 1] == "64"
    assert command[command.index("--memory") + 1] == "512m"
    assert command[command.index("--cpus") + 1] == "1"
    assert command[command.index("--workdir") + 1] == "/workspace"
    assert command[-4:] == ["x19-test:latest", "/bin/sh", "-lc", "printf 'ok'"]


def test_sandbox_does_not_forward_host_environment(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "should-not-leak")
    monkeypatch.setenv("OPENAI_API_KEY", "should-not-leak")

    env = SandboxExecutor._clean_host_env()

    assert "AWS_SECRET_ACCESS_KEY" not in env
    assert "OPENAI_API_KEY" not in env


def test_sandbox_fails_closed_without_docker(monkeypatch, tmp_path: Path):
    monkeypatch.setattr("execution.sandbox.shutil.which", lambda _: None)
    sandbox = SandboxExecutor(tmp_path)

    result = sandbox.run("printf ok")

    assert result.returncode == -1
    assert result.error == "sandbox_unavailable: docker CLI not found"
