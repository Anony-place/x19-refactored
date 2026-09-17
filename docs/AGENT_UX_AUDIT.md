# Agent & Terminal-UX Audit — evidence → gaps → decisions

Date: 2026-09-15
Scope: how production autonomous-agent CLIs actually behave, where X19's
terminal application deviates, and what was changed as a result.

## 1. Evidence base (how real agent CLIs work)

Sources studied: Claude Code internals analyses (UI state machine, query
loop), the Claude Agent SDK docs (agent loop, permissions), OpenAI Codex CLI
(sandbox/approval modes, resume, slash commands), HumanLayer's 12-Factor
Agents, and agent-observability practice (traces/spans).

Patterns that every serious agent CLI shares:

| # | Pattern | Evidence |
|---|---------|----------|
| P1 | **The UI is event-driven and never polls.** Streaming API events push state transitions (idle → requesting → thinking → responding → tool-use); the UI reacts. | Claude Code's five-state UI machine is driven by SSE events, "The UI never polls – all transitions are driven by push-based streaming events" |
| P2 | **Every tool call is visible inline** as a structured message (`⚙ ToolName(input…)` + result), not hidden in a log. | Claude Code message types (AssistantMessage / ToolUseMessage / ToolResultMessage); agent SDK quickstart prints `Tool: name` as work happens |
| P3 | **Tokens stream** into the transcript as they arrive (async generator loop; UI renders "Claude typing" in real time). | Claude Code query loop yields StreamEvents; aider/Codex stream the same way |
| P4 | **Interrupts are first-class**: Esc interrupts the current work; Ctrl+C requires a second press to quit; the running agent is never silently killed. | Claude Code "Esc to rewind"/Ctrl+C semantics; Codex Ctrl+C cancel |
| P5 | **Sessions can be resumed** (`codex resume`); state is persisted as one unified event/state log. | Codex CLI `codex resume`; 12-factor #5 "unify execution and business state", #6 "launch/pause/resume", #12 "stateless reducer" |
| P6 | **Deterministic code owns the loop**: stop conditions, retries, approval gates, budget ceilings live in product code, not in the model. | 12-factor #8 "own your control flow"; Codex sandbox×approval matrix; Claude Code permission layers (deny → allow → ask) |
| P7 | **Budget/turn/cost transparency** — the operator can see how much of the run's budget has been consumed. | Claude Code `--max-turns` cap + budget tracking in QueryEngine; Codex `/status` |
| P8 | **Human-in-the-loop is structured**, not a side channel (approval arrives as tool/permission results the loop continues from). | 12-factor #7; Claude Code permission modes |

## 2. X19 today — audit against each pattern

Verified in code (`agent.py`, `providers.py`, `storage.py`, `ui/*`), not assumed:

| Pattern | X19 status | Evidence |
|---------|-----------|----------|
| P1 event-driven UI | ✅ **Fixed** (was: UI scraped worker stdout). `ui/background.py` captured `print()` lines; the ribbon's "note" was the last printed line. No structured events exist. | `Session.add_cmd()` only persists; nothing notifies consumers |
| P2 inline tool visibility | ✅ **Fixed** (was: ribbon line only; shows a ribbon line only; seeing what the agent ran required typing `/tasks log <id>` manually. | verified in pty smoke test |
| P3 streaming | ✅ **Fixed** (was: zero streaming; Every backend blocks (`"stream": False` for Ollama; plain `requests.post` elsewhere); the chat shows a spinner for the whole reply. | `providers.py` — no `stream` handling anywhere |
| P4 interrupts | ✅ **Fixed** (was: Ctrl+C exited immediately, killing the daemon assessment thread with it. No Esc semantics. | `ui/app.py` run loop (pre-fix) |
| P5 resume | ✅ **Fixed**: `/resume [id]` loads persisted JSON; `codex resume` equivalent missing. | `storage.Session`, `ui/app.py` had `/sessions` (view-only) |
| P6 control flow | ✅ Strong. Policy engine, scope gate, budget caps, failover chain — all deterministic code. | `execution/policy_engine.py`, `agent.py` loop conditions |
| P7 budget transparency | ✅ **Fixed**: ribbon shows `iter N/M`; and `CONFIG.MAX_ITERATIONS` enforced, but neither shown to the operator. | `storage.Session.add_cmd`, `config.py` |
| P8 HITL | ✅ Scope confirmation before assessment; policy gates. | `scope_guard.resolve_scope`, app `/target` flow |

## 3. Decisions & implementation

**Status: implemented and verified** (605 tests green; live PTY smokes:
activity cards streaming during a background run, `iter N/M` budget ribbon,
Esc → graceful stop, Ctrl+C guard-then-exit, streaming chat preview).

Ordered by impact-per-risk; each is data-driven (no hardcoded behaviour):

1. **Structured agent events (P1, P2).** New `events.py` (thread-safe pub/sub,
   no deps). `storage.Session` — the state chokepoint every agent action
   already flows through — now publishes `command`, `finding`, `ports`,
   `os`, `status` events to subscribers. The background task records them;
   the workspace drains them each prompt poll and renders **live activity
   cards** in the transcript (`⚙ cmd → rc in Ns`, `!! finding: title`).
   stdout capture stays as a fallback for untagged prints.
2. **Streaming chat (P3).** `chat_stream()` added to the OpenAI-compatible,
   Ollama and Anthropic backends (SSE/NDJSON parsed incrementally) and to
   `FailoverRouter` (walks the same chain as `chat()`). Feature-detected via
   `hasattr` — custom backends without streaming keep working. The UI streams
   a live tail preview (transient region) and prints the final rendered
   Markdown when the reply completes. `chat()` stays non-stream for the agent
   loop (it needs one complete string for parsing).
3. **Interrupt semantics (P4).** Esc at the prompt asks a running assessment
   to wrap up (same code path as `/stop`). Ctrl+C at the prompt no longer
   kills a live assessment silently: first press warns with guidance, second
   consecutive press exits.
4. **Resume (P5).** `/resume <session-id>` loads a stored session JSON into
   the workspace; `/findings` and `/report` immediately work over it.
5. **Budget line (P7).** Ribbon shows `iter N/M` (M = configured max) and
   finding count, computed from live session state.

## 4. Deliberately not done (and why)

- **Full-screen alternate-buffer TUI**: production CLIs converge on a rolling
  transcript + one live region because it keeps scrollback, copy-paste and
  screen readers working. X19's rolling layout already matches this; adding
  an Ink-style tree would trade accessibility for looks.
- **Pause/resume of a mid-flight assessment process**: the loop runs inside
  one process; true pause/resume needs the stateless-reducer split (12-factor
  #12) which is an agent-core refactor, not a UI change. Session persistence
  already gives crash-level resume of *results*.
- **Auto-approval classifier (Claude "auto" mode)**: X19's risk surface is
  offensive security; approvals stay deterministic (policy engine + explicit
  confirmations) per P6/P8.

---

# Round 2 — 2026-09-16: operator-reported display corruption and a dead-end first contact

Trigger: an operator ran `python run.py run`, typed a hostname, and pasted the
resulting screen back. Two complaints: *"the workflow is off"* and *"the
terminal UI/UX is not good"*. Both reproduced in a pty before anything was
changed (`tests/pty_support.py` runs the real workspace under a real
pseudo-terminal; `pyte` reconstructs the screen the operator saw):

```
 X19 · no target · OpenRouter/openrouter/free          ○ idle   /help commands
you › [router] OpenRouter/openrouter/free
 X19 · no target · OpenRouter/openrouter/free          ○ idle   /help commands
you › hello[router] OpenRouter/openrouter/free
[router] Groq/llama-3.3-70b failed (rate-limited) → next
you ❯ hello
```

## 5. Root causes (all verified in code, not guessed)

| # | Defect | Cause | Fix |
|---|--------|-------|-----|
| C1 | Ghost prompt rows, duplicated ribbons, text mashed onto one line | The prompt paints two rows with raw ANSI, but **nothing owned stdout while it was painted**. `FailoverRouter.chat()`/`chat_stream()` `print()` a `[router] …` line on *every* request; each such write pushed the cursor and desynced the `\x1b[1A` repaint maths | `ui/prompt.py` installs a thread-safe output guard for the raw window: erase prompt area → write foreign text → repaint. Foreign writes now always land *above* the prompt |
| C2 | Every message appeared twice (`you ›` then `you ❯ hello`) | The prompt row was erased on Enter and the same text re-printed as a transcript row, with a *different* glyph | One glyph (`you ❯`); on Enter the prompt row is restyled **in place** into the committed transcript row (`committed_fn`) |
| C3 | Blank rows interleaved with foreign output | `print("x")` reaches a stream as two writes (`"x"`, `"\n"`); repainting per write inserts a row | Foreign writes are joined into whole lines before painting; an unterminated tail is flushed on the next poll tick |
| C4 | Staircase output possible while typing | cbreak mode turns `OPOST` off, so a bare `\n` no longer returns to column 0 | Foreign writes get lone `\n` → `\r\n` |
| C5 | Ribbon wrapped on a resized/narrow terminal, breaking the same cursor maths | Rich caches the width detected at startup; the ribbon was padded to that stale width | Ribbon width is re-read from the OS each repaint, clamped, and cropped to exactly one row |
| C6 | `[router] …` noise on every single turn | The router announced the working combo per request | Announced **once per change** (plus a `recovered` note), failures deduped per (combo, reason), and routed through `providers.notice()` so a UI sink can own placement — the workspace queues notices while a streaming preview is on screen |
| C7 | `ðhttps://hackerone.com/paytm` — mojibake in model output | `_iter_sse_data` used `response.iter_lines(decode_unicode=True)`; requests decodes `text/event-stream` as **ISO-8859-1** when the header omits a charset | New `_iter_stream_lines()`: incremental UTF-8 decode over `iter_content`, which also keeps multi-byte characters that straddle a chunk boundary |
| C8 | Typing a hostname produced a policy lecture instead of work | `_parse_target_request` only matched verb-prefixed lines, so a bare `paytm.com` fell through to the chat model, which improvised an authorization refusal | Bare hosts/URLs/IPs are recognised deterministically; `run.py`-shaped tokens and prose are not |
| C9 | No way to do anything useful without an authorization argument | The only paths were "verified scope → active assessment" or "nothing" | `/passive <host>` + intake option `p`: DNS, TLS handshake and **one** HTTP GET, reported as facts. Three requests, no scanning, no exploitation, no gate — and the result enters the conversation |
| C10 | Chat had no memory | `ConsoleApp.history` was maintained and then never sent; every turn was a one-shot request | Bounded transcript (`X19_CHAT_HISTORY_TURNS`/`_CHARS`) travels with each request, framed as **untrusted data** |
| C11 | Model invented program details and answered as a generic assistant | One-paragraph system prompt, no injection stance | `ROLE_PROMPT` + `GUARDRAILS`; `compose_system_prompt()` keeps the guardrails even when an operator overrides the role with `--system` |
| C12 | Passive recon reported twice | `on_done` rendered the card and the generic task notification announced it again, with `/report`·`/findings` hints that mean nothing for a read-only observation | A task that reported itself is marked notified |

## 6. Verification

`tests/test_terminal_ui_integrity.py` (51 tests): row geometry, the output
guard (buffering, CRLF, capture passthrough, suspend), ribbon single-row
invariants at 40–200 columns, transcript/context/prompt-hardening contracts,
target-intake routing, `passive_recon` facts-only guarantees (a patched
`net_scan` raises if called), notice dedup/sink routing, UTF-8 stream decoding
across chunk boundaries, and four **live pty** scenarios asserting on the
reconstructed screen. The pty tests were confirmed to have teeth: disabling
`_install_guard()` fails them. Full suite: 788 passed.

---

# Round 3 — 2026-09-16: the one-shot path and the workspace disagreed about authorization

Trigger: after Round 2 made the workspace resolve scope before it acts, the
one-shot path was audited and found to do the opposite. `scope_guard.resolve_scope`
had exactly one caller in the whole repository — `ui/app.py`. Everything else
that could attack a host took its posture from a flag:

```
$ x19 run -t scanme.nmap.org --bug-bounty      # before
[BB] Bug bounty mode: using authorized scope (full testing)
```

No program was looked up, nothing was verified, and `_apply_runtime_config`
wrote `TARGET_TYPE=authorized` into `~/.x19/config.json` — where the agent
trusts it for **every later run**, against any target. The same host typed into
the workspace was refused. Two doors, two policies; the unlocked one was the
one that runs unattended.

## 7. Root causes

| # | Defect | Cause | Fix |
|---|--------|-------|-----|
| A1 | `--bug-bounty` alone granted full testing on any public host | `_apply_runtime_config` translated the flag into `TARGET_TYPE=authorized` before anything looked at the target | The flag now records *intent* (hands-off, bootstrapped, parallel) only; `_authorize_active_run()` decides the posture from evidence |
| A2 | One run's verdict authorized every later run | The verdict was persisted to the config file, and `agent._resolve_target_type` returns a configured posture without asking again | Authorization state is per run (`set_data(..., save=False)`); a `TARGET_TYPE=authorized` found in the config file is treated as a **claim** that must be re-earned per host |
| A3 | Two posture heuristics could drift | The classification lived inline in `agent._resolve_target_type`; the workspace had its own resolver | `scope_guard.classify_target()` is the single heuristic, the agent delegates to it, and a parity test pins it to the code it replaced (39 samples, zero drift). One deliberate difference: an empty target now fails closed instead of classifying as `authorized` |
| A4 | `x19 dash -t host` had no gate at all | The dashboard launches the same offensive work as `run` but went straight to `SwarmCoordinator` | Same gate, same message, before the coordinator is built |
| A5 | A fleet inherited whichever target was verified first | `fleet.cli()` submitted every target it was given | Per-target decision: authorized targets run, the rest are reported as `skipped — <reason>` with the evidence that would unlock them; nothing authorized → exit 2 |
| A6 | The agent loop re-widened a narrowed run | `elif is_bug_bounty_mode(): self.target_type = "authorized"` ran regardless of evidence | The branch asks `decide_active_run()`; an explicitly configured posture is honored, a bare claim on `auto` is not. The recon-only fallback also clears `BUG_BOUNTY_MODE`, which is what that branch keys on |
| A7 | No way to present evidence on a command line | Scope URLs were env-only, and an engagement name was accepted as proof | `--scope-url` on `run` and `dash` (same value as `X19_SCOPE_URL`); an engagement counts only when a **recorded** profile states the posture — `ad_hoc_profile` synthesised from `-t` is not evidence, as its own docstring says |
| A8 | A refusal was a dead end | The workspace had intake options; the CLI had nothing | At a terminal: one prompt, three honest answers — paste a scope URL (verified before it counts), re-type the target (recorded as your assertion), enter (recon-only run). Non-interactively: exit 1 with all four exits named |
| A9 | A refused run still started things | `cmd_run` built the agent, created its session and started the telegram poller *before* the gate ran | The gate moved ahead of all three: a run that will not happen starts nothing |
| A10 | Drive-by: `X19._split_target` was decorated `@staticmethod` twice | Duplicate decorator line | Removed — harmless on 3.10+, a `TypeError` on older interpreters |

## 8. The decision, stated once

`scope_guard.decide_active_run(target, claimed=…, scope_url=…, engagement=…)`
returns one `ActiveRunDecision` (`allowed`, `state`, `target_type`, `reason`,
`needs_input`) that every entry point obeys:

| Evidence | Decision |
| --- | --- |
| Program found, target declared (`www.paytm.com` → `*.paytm.com`) | run, `authorized` |
| Program found, target **not** declared (`paytm.com` apex) | refuse, naming the declared scope — nothing to confirm, wrong evidence |
| Private range, loopback, `.local`/`.internal`/`.lan`, local artifact | run, `authorized` — no public program needed |
| Practice platform (`hackthebox`, `tryhackme`, `ctf`, `vulnhub`, …) | run, `ctf` |
| Recorded engagement profile with an explicit posture | run, `authorized` |
| `X19_ALLOW_UNVERIFIED=1` | run, `authorized`, with the assertion printed as the reason |
| Public host, no claim | run, recon/enumeration posture only |
| Public host **with** a claim and nothing to back it | refuse, `needs_input` — one prompt at a terminal, exit 1 otherwise |

Permissive where permission is obvious, fail-closed where it is not, and the
reason printed is the reason that was used.

## 9. Verification

`tests/test_active_run_authorization.py` (44 tests): heuristic parity with the
code it replaced, the decision matrix above, the CLI gate in all four of its
outcomes (refuse / verify / assert / narrow) with `Prompt.ask` and `isatty`
driven explicitly, the interrupt path, per-run persistence asserted through a
recording `set_data` (a persisted verdict is a regression, not a feature), a
config-file `TARGET_TYPE=authorized` treated as a claim, `cmd_run` and
`cmd_dash` returning 1 *before* the agent loop or the coordinator, source-order
assertions that the gate precedes both, and per-target fleet filtering.
Existing fleet CLI tests were retargeted to lab hosts so they keep testing
supervisor mechanics rather than accidentally depending on an unauthorized
public target. Full suite: 832 passed, 20 subtests.

Known pre-existing flake, unrelated to this round: `tests/test_knowledge_layer.py`
KEV cache tests fail roughly one full-suite run in five, on either
`test_fetch_parse_and_cache` or `test_ttl_expiry_refetches`, and always pass in
isolation. It reproduces with this round's changes stashed, so it was not
introduced here — it is left alone rather than half-diagnosed.

Real CLI transcripts (non-interactive, no provider needed to reach the gate):

```
$ X19_BUG_BOUNTY_MODE=1 x19 dash -t scanme.nmap.org --once --no-start
! active run not started — active testing was requested, but no public program or
  scope source verifies scanme.nmap.org
› prove it:  x19 run -t scanme.nmap.org --bug-bounty --scope-url <program scope url>
›            x19 engagement new <name> -t scanme.nmap.org --target-type authorized
› assert it: X19_ALLOW_UNVERIFIED=1 x19 run -t scanme.nmap.org --bug-bounty
› narrow it: drop --bug-bounty for a recon/enumeration run          # exit 1

$ x19 dash -t paytm.com --once --no-start
! active run not started — Paytm Bug Bounty was found, but paytm.com is outside its
  declared scope (*.paytm.com, *.paytm.in, *.mypaytm.com, paytmfoundation.org, …)
› program: Paytm Bug Bounty · https://bugbounty.paytm.com/scope/
› in-scope hosts run normally; observation needs no authorization: x19 chat → /passive paytm.com

$ x19 dash -t www.paytm.com --once --no-start
• scope: verified — Paytm Bug Bounty declares *.paytm.com                # mission control renders
```

## 10. Addendum — merging with main's full-screen workspace

`main` moved while this branch was open: `run.py` now swaps `ConsoleApp.run` for
a full-screen renderer (`ui/fullscreen_workspace.py`) on a tty, and
`_chat_reply()` grew `render=`/`on_chunk=` so an embedded workspace can own
presentation. Rebasing onto it surfaced five things worth recording, because
each one is a way the two designs could have quietly cancelled each other out:

| # | Defect | Cause | Fix |
|---|--------|-------|-----|
| A11 | The new default surface sent a bare hostname straight to the model — the exact failure round 2 fixed | `FullscreenWorkspace._submit()` routed anything not starting with `/` to `_submit_chat()`, bypassing `ConsoleApp.handle()` and therefore the deterministic intake | Non-slash lines are offered to `_parse_target_request()` first; a target goes through `app.handle()` (scope resolves, operator picks), prose still goes to chat |
| A12 | Two `_chat_reply()` rewrites collided | This branch wrapped the call in a notice sink + transcript context; main added `render`/`on_chunk` gating | One method with both: `render=False` means no spinner, no nested `Live`, no warnings painted into somebody else's layout, chunks handed to `on_chunk` — while the hardened prompt, the bounded transcript and the notice sink stay |
| A13 | Worker output escaped capture for every manager but the first | `_QuietStream` is installed once per process but bound to the constructing manager's thread-local, and a process can build several managers (workspace, dashboard, fleet). Under `unittest discover` this failed outright; under pytest per-test stdout capture hid it | A weak registry of manager capture states; the wrapper and `output_is_captured()` both ask "does *this thread* belong to a task?" — which is also what the prompt's output guard needs to know |
| A14 | `x19 run --max-iterations N` died before its first decision | `_apply_runtime_config` passed `str(N)` and `MAX_ITERATIONS` was missing from `set_data`'s int-coerced keys, so the loop's `iteration < CONFIG.MAX_ITERATIONS` raised `TypeError`. This — not an unreachable provider — is why the CI smoke step exited non-zero | `MAX_ITERATIONS` joins `_int_keys`, coercion tolerates a typo by keeping the working cap, and the CLI hands over the int the parser validated |
| A15 | A refusal in `--json` mode was prose on stderr and an interactive prompt | The gate spoke through `info`/`warn`/`step`, which are silent in machine mode, then offered a `Prompt.ask` | Machine mode emits one JSON document (`authorized`, `state`, `reason`, `program`, `scope_patterns`, `next`) on stdout and never prompts |

Verification after the rebase: `pytest tests/` **846 passed, 20 subtests**, and
the command CI actually runs — `python -m unittest discover -s tests -t .` —
**829 tests, OK** (it was failing on `main` before this branch touched it).
`ui/fullscreen_workspace.py` is covered by eight new tests: intake routing for a
bare host / prose / a local file, `render=False` streaming to `on_chunk` with
nothing painted, the hardened prompt and transcript surviving `render=False`, a
provider failure staying silent, and the non-tty fallback to the rolling
transcript.
