# X19

**Autonomous AI security assessment platform — terminal application.**

X19 plans, executes and verifies penetration-testing work against a target you
authorize it to test. An AI decides each next action; a cognitive layer (world
model, attack graph, hypothesis engine, critic) keeps it honest, and findings
must be backed by real command output before they are reported.

> **4.0.0 is a terminal-only release.** The Flask web dashboard was removed.
> Everything it did — live mission control, swarm monitor, attack graph,
> finding triage, diagnostics, report export, provider configuration — is now
> served by the CLI/TUI in this repo. There is no HTTP server, no port to
> expose and no web attack surface to defend.

---

## Install

```bash
pip install -r requirements.txt     # requests, rich, PyJWT + research extras
python run.py                       # first run: full setup, then the workspace
```

`x19` below means `python run.py` (or the `x19` entry point if you install the
package).

### First run

The first time you run `x19` it walks you through setup before it will do
anything else. Four stages, each one skippable only if it is already done:

| Stage | What it configures |
| --- | --- |
| 1/4 | **AI provider chain** — provider, model and failover order, verified before it is saved |
| 2/4 | **Offensive toolchain** — reports what is installed and what is missing |
| 3/4 | **Engagement profile** — scope, guidance cards, canaries, budget |
| 4/4 | **Verify** — resolves the provider and shows where every piece of state lives |

Setup is resumable: re-running `x19` picks up where a cancelled attempt stopped
and skips the stages that already completed. It is mandatory — `run`, `dash`,
`chat` and `workspace` refuse to start until a working provider exists, while
`doctor`, `config`, `providers`, `tools`, `engagement` and `version` stay
available so you can diagnose a broken install.

## Quick start

```bash
x19                                         # workspace home: status + every function
x19 engagement new acme -t acme.example.com --target-type authorized
x19 dash -t acme.example.com --engagement acme   # live assessment, in scope
x19 run  -t scanme.nmap.org                 # one-shot autonomous assessment
x19 findings                                # what it found, by severity
x19 report --format html --out report.html  # exportable report
```

## Commands

| Command | What it does |
| --- | --- |
| `workspace` | X19 home — status, state, every function and next actions. **The default** |
| `run` | Autonomous assessment (`-t`, `--bug-bounty`, `--ctf`, `--fast`, `--swarm`) |
| `dash` | Full-screen live swarm mission control (`--once`, `--no-tui`, `--timeout`, `--engagement`) |
| `chat` | Interactive AI assistant console |
| `findings` | Findings by severity (`--severity`, `--session`) |
| `report` | Export `markdown` / `html` / `json` / `text` (`--out FILE`) |
| `sessions` | `list` or `show` stored assessment sessions |
| `engagement` | Engagement profiles — scope, guidance cards, canaries, budget (`list`/`show`/`new`/`rm`/`wizard`) |
| `providers` | List providers, `--use` one, `--test` connectivity |
| `config` | `show` / `get` / `set` / `unset` / `reset` / `path` |
| `setup` | Guided setup — `all` (default), `app` or `engagement` (`--force` to re-run) |
| `doctor` | Dependencies, module integrity, config, toolchain, health score |
| `tools` | Toolchain availability (`--missing` for gaps) |
| `debug` | Source-code diagnostics: `scan` / `fix` / `check` / `stats` |
| `upgrade` | Autonomous self-upgrade pipeline |
| `completion` | Print a bash / zsh / fish completion script |
| `version` | Version and environment details |

Global flags: `--json`, `--no-color`, `--plain`, `-q/--quiet`, `-v/--verbose`,
`-V/--version`. Legacy flag-first invocations still work: `x19 -t host` is
routed to `x19 run -t host`.

## Live mission control

`x19 dash` is the terminal equivalent of the retired web dashboard. It renders
one screen that updates while the swarm works:

```
 X19 v4.0.0  MISSION CONTROL              target 10.0.0.5   ● RUNNING   01:23
        3         5          2           1          1          2       01:23
   OPEN PORTS  ENDPOINTS  RAW FINDINGS  VERIFIED  CRITICAL   QUEUED   ELAPSED
╭─ swarm agents ───────────────╮╭─ attack graph ────────────────────────╮
│ ▶ ReconAgent  ▰▰▰▰▰▰ 62.0%  7 ││ └── host Target: 10.0.0.1  (1.0)      │
│ ○ WebAgent    ▱▱▱▱▱▱  0.0%  0 ││     ├── serv 22/tcp ssh  (0.6)        │
╰──────────────────────────────╯│     └── endp /.env  (0.9)             │
╭─ open ports ─────────────────╮│         └── cred AWS creds  (1.0)     │
│ 22/tcp  ssh  OpenSSH 8.9     │╰───────────────────────────────────────╯
╰──────────────────────────────╯╭─ verified findings ───────────────────╮
                                │ CRITICAL  Exposed .env  …        9.1  │
╭─ event stream ────────────────┴───────────────────────── critical:1 ──╯
│ 14:53:01 ReconAgent   -> Port 22/tcp OPEN (ssh) [OpenSSH 8.9]
╰───────────────────────────────────────────────────────────────────────╯
 ctrl-c stop mission · q quit · r report · g graph · f findings · space pause
```

Keys work only on a real terminal. When stdout is a pipe or CI log, the same
panels are streamed as scrolling output instead, and `--json` emits the whole
mission (stats, agents, findings, graph, events) as one JSON document.

## Layout

```
cli.py            subcommand parser + command handlers
cli_support.py    provider resolution, sessions, diagnostics (no rendering)
ui/               the terminal application
  console.py        global rich Console, ok/warn/err, --json contract
  theme.py          palette, severity and state styling
  widgets.py        panels, tables, trees, progress, key hints
  dashboard.py      MissionDashboard — live mission control
  app.py            ConsoleApp — interactive REPL with slash commands
  screens.py        providers / config / sessions / findings / doctor views
  keys.py           non-blocking keyboard capture (POSIX + Windows)
version.py          single source of truth for the version
brain/              world model, planner, attack graph, hypothesis, critic
execution/          command gateway, policy engine, native scan/fuzz/vuln
parsers/            structured output parsers (nmap, httpx, gobuster, ffuf)
learning/           self-adaptation and failure lessons
reporting/          markdown / html / json report generation
tests/              180 unit tests
```

## Tests

```bash
python -m unittest discover -s tests -v
```

## Authorized use only

X19 executes real attacks. Only run it against systems you own or have written
permission to test. `--target-type public_real_world` restricts it to
reconnaissance; `ENFORCE_SCOPE` / `SCOPE_ALLOWLIST` keep it inside the targets
you named.
