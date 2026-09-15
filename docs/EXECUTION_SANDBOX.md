# X19 Execution Sandbox

Phase 1 moves autonomous shell execution behind a host-side Docker boundary.
The existing `ToolExecutor` remains responsible for tool discovery/template
resolution; `CommandGateway` is the mandatory execution boundary.

## Security boundary

```text
X19 planner/agent
      |
      v
CommandGateway
      |
      +--> PolicyEngine (scope / timeout / reasoning checks)
      |
      v
SandboxExecutor
      |
      v
Ephemeral Docker container
```

The default sandbox is intentionally fail-closed:

- `--network none` by default
- read-only container root filesystem
- only the dedicated X19 workspace is bind-mounted read/write
- all Linux capabilities dropped
- `no-new-privileges=true`
- PID, CPU and memory limits
- ephemeral `/tmp` and `/run`
- host credentials are not forwarded into the container
- `docker.sock` is never mounted into the workload
- autonomous requests use `backend=auto`, which resolves to the sandbox

`backend=host` exists only as an explicit compatibility/debug escape hatch and
must not be selected by autonomous planner logic.

## Build the image

The repository ships `docker/Dockerfile.sandbox` based on Kali's official
`kalilinux/kali-rolling` image. The base image is intentionally small and the
project image adds the common command-line tools needed by the current runtime.

```bash
docker build -f docker/Dockerfile.sandbox -t x19-sandbox:latest .
```

Then X19 can use the defaults:

```bash
export X19_SANDBOX_IMAGE=x19-sandbox:latest
# Keep the default network isolated for local/lab execution.
export X19_SANDBOX_NETWORK=none
```

For an explicitly authorized lab/engagement where network access is required,
select a dedicated Docker network rather than `host` networking. The command
policy still checks target references before execution, but Docker network
selection alone is **not** a kernel-level per-destination firewall. A future
network-isolation phase should add host-side egress enforcement for strict
IP/host allowlisting.

## Verification

The unit tests cover:

1. sandbox command hardening flags;
2. host credential/environment non-forwarding;
3. fail-closed behavior when Docker is unavailable;
4. gateway defaulting to the sandbox;
5. explicit host backend behavior.

Run:

```bash
pytest -q tests/test_sandbox.py tests/test_command_gateway_sandbox.py
```

The implementation does not claim a kernel-level target firewall yet. The safe
default is no network, and network-enabled execution must remain an explicit
operator choice until destination-level egress enforcement is implemented.
