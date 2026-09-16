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
