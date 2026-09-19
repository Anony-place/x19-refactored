<p align="center">
  <img src="assets/banner.png" alt="X19" width="100%">
</p>

# X19 ☤

<p align="center">
  <a href="https://anony-place.github.io/x19-refactored/">Documentation</a> ·
  <a href="https://anony-place.github.io/x19-refactored/docs/getting-started/installation">Install</a> ·
  <a href="CONTRIBUTING.md">Contributing</a>
</p>
<p align="center">
  <a href="https://anony-place.github.io/x19-refactored/docs/"><img src="https://img.shields.io/badge/Docs-x19--refactored-FFD700?style=for-the-badge" alt="Documentation"></a>
  <a href="https://github.com/Anony-place/x19-refactored/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License: MIT"></a>
  <a href="README.es.md"><img src="https://img.shields.io/badge/Lang-Español-blue?style=for-the-badge" alt="Español"></a>
  <a href="README.zh-CN.md"><img src="https://img.shields.io/badge/Lang-中文-red?style=for-the-badge" alt="中文"></a>
  <a href="README.ur-pk.md"><img src="https://img.shields.io/badge/Lang-اردو-green?style=for-the-badge" alt="اردو"></a>
</p>

**X19 is an executive orchestrator for agent work.** You give it an objective in
plain language. X19 decomposes it into a task graph, assigns each task to a
specialized worker through a project manager, monitors real execution, and
reports back from what actually happened — not from what a model believes
happened.

It is built on the agent runtime in this repository: real terminal execution,
streaming, skills, memory, sessions, delegation, gateway and provider routing,
approvals, and a terminal UI. The organization layer on top is what X19 adds.

---

## The organization

Three tiers, each a real role with its own capabilities, toolsets and reporting
line — declared in `x19/org/roles.py`, not hardcoded in the UI:

| Role | Tier | Reports to | What it does |
| --- | --- | --- | --- |
| **X19** | Boss / Executive Orchestrator | you | Owns the objective. Decomposes, delegates, prioritises, inspects progress, resolves blockers, reassigns, reviews results, synthesises, talks to you. |
| **X22** | Manager / Project Manager | X19 | Plans tasks, tracks dependencies, assigns workers, monitors progress, detects blockers, validates outputs, reports status, escalates, decides retries. |
| **Workers** | Specialized execution | X22 | Do the actual work with real tools. |

The nine worker roles shipping in the catalog:

| Role | Focus | Toolsets |
| --- | --- | --- |
| `research` | Recon / research, source discovery, summarisation | core, web, file, browser |
| `coding` | Implementation, refactoring, bug fixing, builds | core, file, terminal, code_execution |
| `debugging` | Root-cause analysis, reproduction, trace analysis | core, file, terminal, code_execution |
| `testing` | Test writing and execution, regression checking | core, file, terminal, code_execution |
| `security` | Security review, vulnerability analysis, secret scanning | core, file, terminal |
| `devops` | CI, containerisation, pipelines, deployment, infra | core, file, terminal |
| `documentation` | Docs, API reference, changelogs, examples | core, file, web |
| `analysis` | Data, log and codebase analysis, metrics, correlation | core, file, terminal, code_execution |
| `execution` | Tool execution, batch and file operations, command running | core, file, terminal |

**The catalog is open.** `register_role()` adds a worker from a plugin or a
config file without touching the boss, the manager, the task model or the UI —
every consumer (registry, console, audit report, status projection) renders
whatever the catalog contains.

Delegation is hierarchical, not nominal. X19 and X22 are *orchestrators* in the
underlying runtime and may spawn children; workers are *leaves* and may not. A
role spec is turned into a real `delegate_task` dispatch by
`x19/org/delegation.py`, and its progress is observed from the real subagent
registry rather than assumed.

---

## Task lifecycle

Every task moves through an enforced state machine (`x19/org/tasks.py`). The
fine-grained status is the source of truth; a coarse phase is derived from it:

```
QUEUED → PLANNED → ASSIGNED → RUNNING → IN_REVIEW → COMPLETED
                                ↓  ↑
                    BLOCKED / WAITING_DEPENDENCY / WAITING_APPROVAL
                                ↓
                     FAILED → (retry) QUEUED          CANCELLED
```

Illegal jumps are rejected — a task cannot go from `QUEUED` to `COMPLETED`.
Transitions are guarded in code, not by convention, and are covered by
regression tests.

Each task carries: its own ID, its parent task, the assigned agent and role,
current phase and status, created/started/updated/finished timestamps, its
dependency edges, progress, its outputs, errors, blockers, and its retry count
against a real retry budget.

---

## Talking to X19

You state an objective. X19 accepts it, breaks it down, dispatches it, and keeps
you informed. Ask it what is happening at any point and the answer is built from
runtime state — the task store, the event stream and the live agent registry.

The organization is driven through one tool, `x19_org`, with 22 actions:

- **Read** — `status`, `audit`, `answer`, `org`, `agents`, `roles`, `tasks`,
  `events`, `approvals`
- **Write** — `objective`, `plan`, `dispatch`, `review`, `retry`, `cancel`,
  `resolve_blocker`, `escalate`, `approve`, `deny`, `pause`, `resume`, `stop`

It is reachable only through the `x19-org` toolset, which is granted to X19 and
X22 — a worker cannot reorganize the organization it works in. The same surface
is exposed to the terminal UI and the desktop app as 13 typed JSON-RPC methods
(`org.status`, `org.audit`, `org.agents`, `org.roles`, `org.tasks`,
`org.events`, `org.approvals`, `org.approve`, `org.deny`, `org.pause`,
`org.resume`, `org.stop`, `org.task.control`), contracted in
`tui_gateway/contracts/org.py`.

### Boss Audit Mode

X19 can inspect the organization it is running, on demand: every manager and
worker with its real status and last heartbeat, the full task graph with
dependencies, the live queue, what has failed and why, what is blocked and on
what, and what is waiting for you. `x19_org audit` returns that view from the
same state the console renders, so an audit and the screen cannot disagree.

---

## Events

The organization is event-driven. Every state change emits a typed `OrgEvent`
(`x19/org/events.py`) with a monotonic sequence number, timestamp, and the task,
parent task, agent, role and manager it concerns:

- **Tasks** — `task.created`, `planned`, `assigned`, `started`, `progress`,
  `waiting`, `blocked`, `unblocked`, `review_required`, `reviewed`,
  `completed`, `failed`, `cancelled`, `retried`, `reassigned`
- **Agents** — `agent.registered`, `started`, `progress`, `waiting`, `blocked`,
  `completed`, `failed`, `interrupted`
- **Organization** — `objective.accepted`, `manager.report`, `boss.audit`,
  `workflow.completed`, `escalation`
- **Human authority** — `approval.requested`, `approval.resolved`,
  `operator.pause`, `operator.resume`, `operator.stop`

The event stream is appended to the persisted operating record and is what the
console's event pane, `x19_org events`, and `org.events` all read.

---

## The operations console

```bash
x19 --tui        # or: X19_TUI=1 x19
```

A dense, information-first panel (`ui-tui/src/components/orgPanel.tsx`): the
executive hierarchy X19 → X22 → workers, task graph counts, what is live right
now, what needs the operator, and the event stream.

It renders **only** when the gateway reports a real run. There is no placeholder
org chart, no synthetic row and no invented progress — what is on screen is the
runtime. Layout is width-driven rather than fixed: rows truncate to the composer
width and lower-priority sections drop out first on narrow terminals, so the
hierarchy and task counts always survive.

---

## Human authority

You stay in charge of the run:

- **Approvals.** Roles listed in `x19.authority.approval_roles` cannot start
  until an operator signs off; the task sits in `WAITING_APPROVAL` and appears in
  the console's attention row. Approve or deny through `x19_org`, the console, or
  the desktop app.
- **Pause / resume / stop.** Operator controls that halt dispatch and new work,
  lift the halt, or end the run. They are first-class events, not flags.
- **Retry budget.** A failed task returns to `QUEUED` only while attempts remain
  under `x19.execution.max_attempts`. Exhausted, it stays `FAILED` and is
  reported as failed.

X19 fails closed: if a required control is unavailable or a task falls outside
what the organization is authorized to do, the task is blocked rather than run.

---

## Configuration

X19 runs with no configuration. To tune it, add an `x19` section to
`~/.x19/config.yaml` (on Windows, `%LOCALAPPDATA%\x19\config.yaml`):

```yaml
x19:
  org:
    state_dir: ""              # where the operating record is persisted
    persist: true              # set false to keep it in memory only
    stale_after_seconds: 900   # idle-but-active role marked stale (30–86400)
  execution:
    max_attempts: 3            # retry budget per worker task (1–10)
    max_parallel: 4            # tasks dispatched in one pass (1–32)
  authority:
    approval_roles: []         # roles needing operator sign-off before running
```

Values are clamped to the ranges shown. A malformed `config.yaml` never stops the
organization: unparseable sections fall back to defaults rather than raising
(`x19/org/config.py`).

There is no `x19.enabled` switch — the organization layer is part of the product.

### State

The operating record is kept deliberately separate from conversation state. The
chat history is a transcript; `x19/state/` holds the task graph, the event
stream, approvals and run metadata, written atomically so an interrupted run
cannot leave a half-written record.

`~/.x19` is the state root. Override it with `X19_HOME`; use
`x19 profile` for multiple isolated instances.

---

## Install

### Linux, macOS, WSL2, Termux

```bash
curl -fsSL https://raw.githubusercontent.com/Anony-place/x19-refactored/main/scripts/install.sh | bash
```

### Windows (native PowerShell)

```powershell
iex (irm https://raw.githubusercontent.com/Anony-place/x19-refactored/main/scripts/install.ps1)
```

Native Windows needs no WSL — the CLI, gateway, TUI and tools all run natively,
installed to `%LOCALAPPDATA%\x19`. The Linux command above also works under WSL2,
which installs to `~/.x19`.

Then:

```bash
source ~/.bashrc   # reload your shell (or: source ~/.zshrc)
x19                # start talking
```

Full instructions, including Termux and Nix:
[Installation guide](https://anony-place.github.io/x19-refactored/docs/getting-started/installation).

### From source

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
uv pip install -e ".[all,dev]"
```

Three entry points are installed (`pyproject.toml`):

| Command | Purpose |
| --- | --- |
| `x19` | The product CLI — interactive chat, `--tui`, and every subcommand below |
| `x19-agent` | The agent runtime entry point |
| `x19-acp` | X19 as an ACP (Agent Client Protocol) server |

---

## Getting started

```bash
x19              # interactive chat
x19 --tui        # the operations console
x19 model        # choose your provider and model
x19 tools        # configure which tools are enabled
x19 config set   # set individual config values
x19 gateway      # start the messaging gateway (Telegram, Discord, …)
x19 setup        # full setup wizard
x19 status       # status of all components
x19 doctor       # diagnose problems
x19 update       # update to the latest version
```

Any provider works — [Nous Portal](https://portal.nousresearch.com),
[OpenRouter](https://openrouter.ai), OpenAI, or your own endpoint. Switch with
`x19 model`; no code changes, no new dependencies.

---

## Documentation

- [Quickstart](https://anony-place.github.io/x19-refactored/docs/getting-started/quickstart)
- [Terminal UI](https://anony-place.github.io/x19-refactored/docs/user-guide/tui)
- [Delegation](https://anony-place.github.io/x19-refactored/docs/user-guide/features/delegation)
- [Delegation patterns](https://anony-place.github.io/x19-refactored/docs/guides/delegation-patterns)
- [Build a plugin](https://anony-place.github.io/x19-refactored/docs/developer-guide/plugins)
- [Full documentation](https://anony-place.github.io/x19-refactored/docs/)

Translations of this README:
[Español](README.es.md) · [中文](README.zh-CN.md) · [اردو](README.ur-pk.md)

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Clone and file issues against
[`Anony-place/x19-refactored`](https://github.com/Anony-place/x19-refactored).

Every string in this repository that names the product is verified by a checked-in
scan: `python scripts/x19_residue_audit.py --strict` exits non-zero on any
occurrence it cannot justify, so a stray legacy identifier fails the build
instead of surfacing later as a broken guard. What it finds, and why each
remaining occurrence must stay, is recorded in
[X19_IDENTITY_AUDIT.md](X19_IDENTITY_AUDIT.md).

---

## License

MIT. See [LICENSE](LICENSE) for the repository license and preserved upstream
attribution.
