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
# Or on Python 3.11+ systems: pip install --break-system-packages -r requirements.txt
python run.py                       # first run: full setup, then the workspace
```

`python run.py` is the **single canonical entry point**. For convenience, an `x19` executable launcher is also provided in the repo (and can be linked to your `PATH` or installed via `pip install -e .`). All entry points (`python run.py`, `./x19`, `x19`, `python x19.py`, `python cli.py`, `python -m x19`) now delegate to the same unified engine.

### First run

The first time you run `x19` it walks you through setup before it will do
anything else. Four stages, each one skippable only if it is already done:

| Stage | What it configures |
| --- | --- |
| 1/4 | **AI provider chain** — provider, model and failover order, verified before it is saved |
| 2/4 | **Offensive toolchain** — reports what is installed and what is missing |
| 3/4 | **Engagement profile** — scope, guidance cards, canaries, budget |
| 4/4 | **Verify** — resolves the provider and shows where every piece of state lives |

Setup is resumable and flexible:
- **Environment auto-detection**: If you set `GROQ_API_KEY`, `OPENAI_API_KEY`, or `OPENROUTER_API_KEY` in your environment, setup auto-detects it and configures it with 1 click.
- **Offline / Demo mode**: No API key or internet? Choose "Demo / Offline Mode" during setup or run with `X19_DEMO=1` to explore the workspace and local toolchain.
- **Save anyway option**: If an endpoint is temporarily unreachable or local Ollama is starting up, you can choose to save the configuration without failing.
- Non-interactive / CI / headless environments print clear status and setup instructions without crashing.

## Quick start — single entry

```bash
python run.py                               # ONLY supported command — setup if needed → single-screen workspace (no scroll)
python run.py run -t scanme.nmap.org        # one-shot autonomous assessment (alias: python run.py already blocks until setup)
python run.py --help                        # all subcommands (run is the only assessment entry; dash is its live-view alias)
# Any `x19` / `python -m x19` / `python x19.py` invocation works but prints a deprecation hint — use run.py.
```

After setup you can also manage state directly:

```bash
python run.py setup app                     # re-run provider wizard (add custom base URL + API key)
python run.py providers                     # show failover chain
python run.py findings                      # what it found, by severity
python run.py report --format html --out report.html
```

## Authorization is evidence, not a flag

One policy covers the workspace, `run`, `dash` and `fleet`: a target's posture
comes from what can be *shown*, and a claim only buys you a chance to show it.

| You run | What X19 does |
| --- | --- |
| `-t 10.0.0.5`, `-t app.local`, `-t app.apk` | your network, your artifact — full testing |
| `-t machine.hackthebox.eu` | practice platform — full testing |
| `-t www.paytm.com` | the program's own scope metadata declares it — full testing |
| `-t scanme.nmap.org` | no claim: recon/enumeration only, auth attacks blocked |
| `-t scanme.nmap.org --bug-bounty` | **refused** until you prove or assert it |
| `-t paytm.com --bug-bounty` | **refused** — Paytm's scope declares `*.paytm.com`, not the apex |

Proof and assertions, in the order you'd reach for them:

```bash
x19 run -t host --bug-bounty --scope-url https://program/scope   # verify against the program
x19 engagement new acme -t host --target-type authorized         # written authorization, recorded
X19_ALLOW_UNVERIFIED=1 x19 run -t host --bug-bounty              # you assert it, on the record
x19 run -t host                                                  # no claim: recon/enumeration run
```

At a terminal a refusal asks once and takes three answers: paste a scope URL
(verified before it counts), re-type the target (recorded as *your* assertion),
or press enter for the narrower recon-only run. Non-interactively it exits
non-zero and names every way out. Verdicts are per run — nothing is written to
`~/.x19/config.json`, because a persisted `TARGET_TYPE=authorized` would
authorize every target you ever ran afterwards.

## Commands

| Command | What it does |
| --- | --- |
| `workspace` | X19 home — status, state, every function and next actions. **The default** |
| `run` | Autonomous assessment (`-t`, `--bug-bounty`, `--scope-url`, `--ctf`, `--fast`, `--swarm`) |
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

## The terminal workspace (`python run.py`)

`python run.py` lands in a single-screen workspace — header + telemetry strip + compact conversation + footer,
no scrolling (XBOW/Hermes-inspired, more powerful). The chat view underneath is a rolling transcript — every
message renders once, so nothing flickers — with a **live status ribbon** above the prompt. Long work never blocks
the conversation: assessments run on background threads while you keep typing.

```
 X19   X19 4.0.0 (3cde5d5)  ·  terminal workspace
  ai groq/llama-3.3-70b  ·  failover groq > openrouter  ·  target —

 X19 · scanme.nmap.org · groq/llama-3.3-70b   ● assessment scanme.nmap.org 00:41 · iter 12/50 · 3 findings
  ⚙ nmap -sV --top-ports 500 scanme.nmap.org · rc 0 · 4.2s
you ❯ █
```

* **Type a target, get a decision — not a lecture.** A bare `scanme.nmap.org`
  (or `scan scanme.nmap.org`, or a URL) is resolved by deterministic scope code
  before any model is asked anything, then X19 offers the next step:
  `p` read-only observation now, `a` active assessment (only when scope is
  verified), `s` verify a claimed program against its public scope URL, `c`
  cancel. Prose still goes to the chat model; `run.py` in the working directory
  is a file, not a host.
* `/passive <host>` — read-only public observation with no authorization gate:
  DNS, a TLS handshake and **one** HTTP GET, reported as facts (`resolves to …`,
  `TLSv1.3`, `absent security headers: …`). No scanning, no exploitation, and
  the result is added to the conversation so you can ask about it.
* `/target <host>` — scope check, explicit confirmation, then a quiet background
  assessment. Every command the agent runs appears **inline as a live activity
  card** (`⚙ cmd · rc · time`) the moment it starts — the UI is fed by
  structured agent events, never by scraping stdout.
* **The prompt owns the bottom two rows.** Anything else that writes to the
  terminal — the provider router, a tool warning, a background thread — is
  lifted above the prompt and the prompt is repainted underneath, so output can
  never shred the ribbon or leave ghost prompt rows behind. A resize is picked
  up on the next repaint instead of wrapping the ribbon.
* **Chat keeps context**: the last few turns travel with each request (bounded
  by `X19_CHAT_HISTORY_TURNS` / `X19_CHAT_HISTORY_CHARS`) and are framed as
  untrusted data, so quoted target output cannot steer the model.
* **Streaming replies** — model output streams into the transcript with a live
  tail preview (`✎ …`) for every backend that supports SSE/NDJSON, with
  automatic provider/model failover on the stream path too. Streams are decoded
  as UTF-8 regardless of what the response headers claim, so emoji and non-Latin
  text arrive intact instead of as `ð`-mojibake.
* `/stop` — asks the running agent to wrap up at the next decision point;
  **Esc** does the same without leaving the prompt.
* **Ctrl+C is safe**: with an assessment running the first press warns and the
  second is required to quit — the agent is never killed silently.
* `/resume [session-id]` — reload a previous session into the workspace (bare
  `/resume` lists the last 10) and pick up where you left off.
* The ribbon shows the iteration budget (`iter N/M`) live while work runs.
* `/tasks` — background tasks with status and elapsed time; `/tasks log <id>`
  replays a task's captured output.
* Completion notifications (findings by severity, failure tails) appear in the
  transcript the moment work finishes — once per task: a passive recon reports
  through its own card and is not announced twice.

Concurrency and feel are configurable: `X19_BG_WORKERS` (or config
`BG_WORKERS`) caps background tasks, `X19_UI_POLL` sets the ribbon refresh,
`X19_UI_BANNER`/`UI_BANNER` brings back the ASCII splash screen.

## Bug-hunting team (boss → managers → workers)

X19 is not a single agent. A **MissionDirector** (boss) decomposes the target
into dynamic workstream lanes from what the target actually exposes, each lane
run by a **manager** with its own **worker** pool. Workers execute probes
through the same policy-gated command gateway as the main loop and return raw
evidence — never findings; verification stays with the deterministic gates.
The boss reviews verified findings each iteration (severity rollup +
exploit-chain summary) and hands breadth work to the team.

**Parallel research trajectories**: hypotheses in the agent's research ledger
that pre-register a probe command *and* the output that would prove it are
auto-dispatched to workers every iteration — Naptime-style sampling. A match
against the pre-registered evidence auto-confirms the hypothesis (the model
defined the falsifier itself); the finding still goes through normal
verification before it is reported.

Knobs: `X19_TEAM_DISABLE=1`, `X19_TEAM_MAX_LANES` (3), `X19_TEAM_WORKERS` (2
per lane), `X19_TEAM_PROBES_PER_ITER` (6), `X19_TEAM_TRAJECTORIES` (2).

**Frontier escalation**: set `X19_ESCALATE="provider/model,..."` and hard
steps (critical deep-dives, flail/stuck streaks, high-impact hypotheses)
automatically run on the stronger model — gate-respecting (critical-tier
models stay blocked on unauthorised exploitation), cooldown-bounded
(`X19_ESCALATE_EVERY`, default 4 decisions), and fully accounted: the
ribbon shows `N calls ~Tk tok` per run, and `~$X` too when you set your
blended rate via `X19_PRICE_PER_MTOK`.

## Fleet mode — many targets, one supervisor

`x19 fleet -t target1,target2,target3 --max 3` runs independent assessments
concurrently (XBOW-scale pattern): each unit is a full X19 agent with its own
session, so the scope gate, policy engine, verification gates and team org
are inherited per unit. Failure isolation, cooperative `/fleet stop`-style
control, severity rollup across targets, and shared-tech-stack correlation
(intel and confirmed hypotheses transfer between targets running the same
stack). In the workspace: `/fleet t1, t2, t3` to launch, `/fleet status`,
`/fleet stop`. Concurrency: `X19_FLEET_CONCURRENCY` (default 2, max 8).

## Knowledge layer (live intel + your own corpus)

The agent reasons over **real-time data, not hardcoded lists**: CISA KEV
(actively-exploited vulnerabilities), NVD, FIRST EPSS and local searchsploit
are correlated against what your target actually runs and injected into the
decision context — version-matched, sorted by exploitation signal, tightly
capped so the agent stays focused.

Your own knowledge is a first-class layer: drop markdown/txt notes (program
policy, target notes, house methodology) into `~/.x19/knowledge/` and they are
embedded into the vector store and recalled semantically during decisions.

Knobs: `X19_INTEL_DISABLE=1` turns feeds off, `X19_INTEL_SOURCES=kev,nvd`
selects sources, `X19_KNOWLEDGE_DIR` moves the corpus dir, `NVD_API_KEY`
raises NVD rate limits. Feed copies are cached in `~/.x19/cache/intel/` so a
network outage degrades to slightly-stale intel instead of blindness.

## Look & feel

The UI is a design system, not a pile of prints. Colours live in semantic
palettes — pick one with `x19 config set UI_THEME <name>` or
`X19_UI_THEME=<name>`:

| palette | vibe |
| --- | --- |
| `midnight` (default) | cool teal-on-slate |
| `matrix` | classic terminal green |
| `ember` | warm amber |
| `mono` | colour-blind-safe greyscale |

`--no-color` / `NO_COLOR` disable styling, `--plain` disables live TUIs, and
`X19_ASCII=1` swaps unicode glyphs for ASCII fallbacks.

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
  theme.py          palettes, severity and state styling (UI_THEME selects)
  widgets.py        panels, tables, trees, progress, key hints
  prompt.py         live prompt that redraws the status ribbon while you type
  background.py     quiet background task runner (captured output, callbacks)
  dashboard.py      MissionDashboard — live mission control
  app.py            ConsoleApp — rolling-transcript chat with slash commands
  screens.py        providers / config / sessions / findings / doctor views
  keys.py           non-blocking keyboard capture (POSIX + Windows)
version.py          single source of truth for the version
brain/              world model, planner, attack graph, hypothesis, critic
execution/          command gateway, policy engine, native scan/fuzz/vuln
parsers/            structured output parsers (nmap, httpx, gobuster, ffuf)
learning/           self-adaptation and failure lessons
reporting/          markdown / html / json report generation
tests/              unit + regression tests
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
