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
