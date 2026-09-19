# X19 legacy-identity residue audit

**Verdict: zero unjustified occurrences.** Every remaining appearance of the
legacy product token in the repository is classified below, with a reason it
must stay.

This report is the deliverable for the transformation's final audit step. It is
generated from a repeatable scan, not from a manual read, and the scan is
checked into the repository so the result can be re-verified at any time.

```
$ python scripts/x19_residue_audit.py --strict
X19 legacy-identity residue audit
==============================================================
tracked files containing 'hermes': 94
total occurrences (lines):          318

  model-identifier              169 line(s) across 59 file(s)
  audit-tooling                 103 line(s) across  2 file(s)
  third-party-url                30 line(s) across 23 file(s)
  contributor-attribution         6 line(s) across  6 file(s)
  third-party-dependency          6 line(s) across  1 file(s)
  historical-corpus               2 line(s) across  1 file(s)
  legacy-token-guard              2 line(s) across  2 file(s)

RESIDUE: none. Every remaining occurrence is a justified class.
$ echo $?
0
```

`--strict` exits non-zero if any line fails to classify, so this is usable as a
CI gate. `--json` emits the same data machine-readably.

---

## Scope and method

| Property | Value |
| --- | --- |
| Token searched | `hermes`, case-insensitive |
| Non-Latin spellings searched | 10 — Urdu, Arabic, Chinese (simplified + traditional), Japanese katakana, Korean hangul, Russian cyrillic, Greek, Hebrew, Thai |
| Corpus | every git-tracked file: **13,918** |
| Files with a match | **94** |
| Lines with a match | **318** |
| Non-Latin matches | **0**, outside the detector and this report |
| Unjustified | **0** |

The scan is `git grep -il` over the tracked tree, then a per-line classifier, plus
a second pass for the legacy name written in non-Latin scripts. Four properties
make the result trustworthy:

1. **Binary files are included.** `git grep` was invoked without `-I`, so
   binary blobs are searched rather than skipped. Confirmed independently: the
   86 tracked files that contain a NUL byte in their first 8 KiB were read as
   bytes and lowercased separately — none contains the token. So the
   text/binary split cannot be hiding an occurrence.
2. **The count was cross-checked by a second implementation.** A Python walk
   over `git ls-files`, reading raw bytes and counting matching lines, reports
   the same 94 files and 318 lines over the same 13,918 tracked files. Two
   independent methods agreeing is what
   makes "zero" a claim rather than an assumption.
3. **The classifier is narrow and was probed for loopholes.** Each justification
   is a pattern matched against the occurrence's own line, not a directory-wide
   exemption. Eight adversarial identity strings were fed to it and all eight
   still report as residue — see
   [Keeping it at zero](#keeping-it-at-zero).
4. **Non-Latin spellings are searched, because they were missed at first.** A
   first run of this audit reported zero while the Urdu README still named the
   product in Urdu script — ten times, including in the title. The token-based
   scan cannot see that. It now also searches ten spellings of the legacy name in
   other scripts; every hit is residue, since no justified class writes the
   product name in another alphabet. See
   [The blind spot this audit had](#9-the-blind-spot-this-audit-had).

Working-tree state at the time of writing is clean, so the tracked tree and the
files on disk are the same thing; there is no uncommitted or ignored artifact
that the scan would have missed. Legacy-named *paths* were checked separately:
the only tracked paths containing the token are the 23 contributor-address
files under `contributors/emails/`, covered below.

---

## Justified classes

### `model-identifier` — 169 lines / 59 files

Nous Research model names. These are a **provider's product artifacts**, not
ours: `Hermes-3-Llama-3.1-70B`, `hermes-4-405b`, `hermes_4_70b`,
`FP16_Hermes_4.5`, `openrouter/hermes3:70b`,
`NousResearch/Hermes-Agent-Thinking-GLM-4.7-SFT2`, and Modelfile tags such as
`hermes-brain:qwen3-14b-ctx16k`. Renaming them would point at models that do
not exist, breaking model resolution, pricing lookup, catalog matching,
fallback chains and the non-agentic warning.

Concentrated in `apps/desktop/src/app/settings/model-settings.test.tsx` (25),
`tests/x19_cli/test_nous_x19_non_agentic.py` (16),
`tests/x19_cli/test_fallback_cmd.py` (8), and `agent/model_metadata.py`, plus
55 further files.

One line in this class deserves specific mention because it was the site of a
real bug — see
[the model-family detector](#4-the-model-family-detector-could-never-fire).

### `audit-tooling` — 103 lines / 2 files

The scanner (`scripts/x19_residue_audit.py`, 24 lines) and this report (79
lines). A detector must spell the thing it detects: the token appears in
`TOKEN`, in every classification pattern, and in the comments explaining them.
This document quotes the occurrences it classifies — including the adversarial
probes that must keep failing — so it contains the token by construction.

Both are reported as their own class rather than excluded from the scan, so the
accounting stays complete and the totals keep matching a plain `git grep`: all
318 lines are classified, none are silently dropped. Excluding them instead
would make the headline numbers unverifiable by anyone running the obvious
command.

### `third-party-url` — 30 lines / 23 files

External repositories and documentation we link to or vendor from, where the
name belongs to the other project. Each was resolved over the network rather
than assumed, and the status codes are in parentheses:

- Six **upstream Nous Research companion repositories**, referenced from
  `plugin-catalog/*.yaml`, `nix/x19.nix`, `CONTRIBUTING.md` and the desktop
  install tests: `hermes-example-plugins`, `hermes-plugin-snyk`,
  `hermes-plugin-touchdesigner`, `hermes-memory-wiki`,
  `hermes-telegram-business`, `hermes-desktop-accent-picker` (all **200**; the
  rewritten `x19-…` spellings are all **404**). Not ours to rename.
- `plugin-catalog/x19-nous-prices.yaml` → `github.com/Adolanium/hermes-nous-prices`
  (the upstream plugin's actual home; renaming it breaks installation)
- `plugins/x19-achievements/dashboard/dist/index.js` →
  `github.com/PCinkusz/hermes-achievements` (MIT attribution for the original
  author — legally required to keep)
- `AaronWong1999/hermesclaw` (**200**, MIT, 714 stars) in
  `README.{es,zh-CN,ur-pk}.md`, which a rewrite had corrupted to a nonexistent
  `x19claw`
- Honcho memory-provider documentation URLs in
  `website/docs/user-guide/features/memory-providers.md` and its `zh-Hans`
  translation, plus the related desktop settings tests and
  `optional-skills/autonomous-ai-agents/honcho/SKILL.md`

These are matched by `THIRD_PARTY_REPO_RE` for community authors and by an
explicit `UPSTREAM_REPO_RE` list for the six Nous companion repositories. That
list is enumerated rather than patterned because the two shapes are not
separable by a general rule: `NousResearch/Hermes-Agent-v0.16.0-GGUF` is a real
model artifact and must keep classifying as a model, while
`NousResearch/hermes-plugin-snyk` is a repository. Without the explicit rule the
repository slugs were being justified by the wrong pattern — `MODEL_RE`'s
provider-qualified model path — and the stated reason was false.

The rule deliberately excludes our own GitHub organisation via a negative
lookahead, so a legacy-named repository under `Anony-place/` would still be
reported as residue. Attribution URLs cannot be used as cover.

### `contributor-attribution` — 6 lines / 6 files

Git-history author identities. `contributors/emails/` holds one file per
historical commit-author address (`hermes@server.local`,
`mchermes@edu.dreamcatcher.ai`, `jerry@hermes.local`, …); these are records of
who contributed, and rewriting them would falsify attribution. `scripts/release.py`
carries one contributor alias-domain address
(`github@nadyahermes.anonaddy.com` → handle `ruangraung`, credited for PR
#42308) in the release-notes mapping.

Both the local-part and the domain-part spellings are recognised, since a
contributor's privacy-alias domain carries the token on the right of the `@`.

Related: `.mailmap` and `LICENSE` contain **zero** occurrences. The licence reads
`MIT License / Copyright (c) 2025 Nous Research` and is kept as-is on legal
grounds; it needed no change.

### `third-party-dependency` — 6 lines / 1 file

`package-lock.json` only: `hermes-parser@0.25.1` and `hermes-estree@0.25.1`,
published by Facebook/Meta for the Hermes JavaScript engine and pulled in
transitively by `eslint-plugin-react-hooks@7.1.1` (verified: neither appears in
any `package.json`, so nothing of ours declares them). These are npm package
names resolved from `registry.npmjs.org` with integrity hashes. Editing them
would corrupt the lockfile and break `npm ci`.

### `historical-corpus` — 2 lines / 1 file

`optional-skills/security/godmode/references/jailbreak-templates.md` quotes
third-party security-research prompt text verbatim. The token appears inside
quoted material that must not be altered, since the file's purpose is to
preserve the original wording for analysis.

### `legacy-token-guard` — 2 lines / 2 files

Assertions that *forbid* the token — the residue checks themselves, in
`tests/test_x19/test_x19_runtime.py` and `tests/x19_cli/test_profiles.py`. A
test that pins "no legacy branding reaches the user" has to name the string it
rejects. These are enforcement, not residue.

---

## What the audit caught

The point of auditing string-by-string rather than trusting the rename is that
a mechanical rename does not just leave ugly text behind — it rewrites
**literals that were never ours to rewrite**: provider model names, process
cmdlines, socket names, module paths, service labels. Several of these were
live bugs, and in most cases the test suite already knew.

### 1. Two safety guards were inert

`cron/lifecycle_guard.py` exists to stop a cron job from restarting the gateway
out from under itself (a SIGTERM-respawn loop). Its own docstring names the
commands it blocks: `x19 gateway restart`, `launchctl kickstart ai.x19.gateway`,
`systemctl restart x19-gateway`. Branch A matched the CLI form correctly, but
branches B/C/D and `_X19_GATEWAY_LABEL_RE` still required
`hermes[.-]?gateway` — while `x19_cli/gateway.py` installs `x19-gateway.service`.
**None of those three commands was blocked.**

`tools/approval_detection.py` had the same defect: its comment describes
`x19 -p ade gateway restart`, but the patterns matched `hermes gateway
stop|restart` and `hermes update`. Those commands kill every running agent and
are supposed to require explicit approval. **They stopped asking.**

This was not test churn — the suite was already asserting that
`systemctl restart x19-gateway` must block. Re-anchoring both guards took
**106 failures to 0** (`tests/x19_cli/test_gateway_restart_loop.py`,
`tests/cron/`, `tests/tools/test_approval.py`; 1,918 passing).

One parametrized case spelled the legacy command as
`"Hermez Gateway Restart".lower().replace("z", "s")` — obfuscation that hid the
token from residue scans while asserting a command form that no longer exists.
It was replaced with a mixed-case check on the real command.

### 2. Both plugin dashboards rendered nothing

The kanban and achievements dashboards read `window.__HERMES_PLUGIN_SDK__`,
`window.__HERMES_PLUGINS__`, the API path `/api/plugins/hermes-achievements`,
the auth header `X-Hermes-Session-Token` and the cookie `hermes_session_at`.
The host provides `__X19_PLUGIN_SDK__`, `__X19_PLUGINS__`,
`/api/plugins/x19-achievements`, `X-X19-Session-Token` and `x19_session_at`.
**The dashboards could not register with the host, could not authenticate, and
called a route that does not exist.** These `dist/` files are hand-written
source with no build step, so they were repaired directly, along with their CSS
class names, URLs and CLI copy — taking care not to clobber the upstream
attribution URL noted above.

### 3. The Windows profile wrapper invoked a deleted executable

`x19_cli/profiles.py` wrote `@echo off / hermes -p <profile> %*` into every
Windows alias, while the POSIX branch correctly resolved `shutil.which("x19")`.
The root launcher had been deleted, so **every Windows profile alias was
broken**. Fixing it by quoting the resolved path exposed a second bug:
`_is_our_wrapper` searched for the literal `x19 -p`, so it returned `False` for
any quoted wrapper — making it undeletable via `remove_wrapper_script` and
unreusable on alias collision. That function gates deletion, so it was
tightened to a regex anchored on the same `x19 … -p` shape that tolerates each
platform's spelling, with a strictness test so the guard cannot widen to
arbitrary files.

### 4. The model-family detector could never fire

`x19_cli/model_switch.py` warned that Nous Hermes 3/4 chat models are not
agentic and will fail at tool calling. The rename rewrote its pattern to
`x19[-_ ]?[34]`. **No model is named after this product**, so the warning could
never trigger again — a user would select Hermes-3 and get silent tool-calling
failures with no explanation. Restored to the provider's real family name, and
the constant renamed `_NOUS_CHAT_MODEL_NON_AGENTIC_RE` so its name stops
implying the pattern is about us. The negative cases its docstring described but
nothing tested (`*-brain:*` wrappers, other vendors, v2) are now covered.

### 5. The desktop UI mis-rendered inter-agent messages

`agent-delivery.tsx` matches a CLI invocation to render sender-side deliveries
as compact "Messaged X" notices instead of raw terminal transcripts. Its
`DELIVERY_COMMAND_RE` matched `\bhermes\s+-p` while its own comment and all
three shipped fixtures said `x19 -p`. Verified against those fixtures by
extracting the regex from the source: **2 of 5 failing before, 0 of 5 after.**

### 6. Seven test files asserted against the wrong literal

| File | Defect |
| --- | --- |
| `tests/gateway/test_status.py` | fed `hermes_cli/main.py` to `/proc`, asserted `x19_cli/main.py` in the result — failing |
| `tests/gateway/test_systemd_notify.py` | bound `\0hermes-test-notify` while `NOTIFY_SOCKET` pointed at `@x19-test-notify`, so the datagram went nowhere — failing |
| `tests/tools/test_code_kernel.py` | imported `x19_tools`, then called `hermes_tools.web_search` — `NameError`, failing |
| `tests/x19_state/test_fts_runtime_rebuild.py` | used `-mhermes_cli.main` for the "is this process one of ours" cmdlines — 2 holder-recognition tests failing |
| `tests/x19_cli/test_stale_pid_guard.py` | probed token boundaries with `c:\users\shermesa\app.exe`, which contains no `x19` and therefore tested nothing |
| `tests/x19_cli/test_profiles.py` | wrote a legacy `.bat` and asserted it was recognised as ours — `windows_only`, so it had been skipped into brokenness |
| `tests/x19_cli/test_update_stale_dashboard.py` | same stale module path in a cmdline fixture |

### 7. Documentation told users to delete the wrong account

The Matrix device-deletion walkthrough used `@x19:your-server` in its SQL but
`%40hermes%3Ayour-server` in the Synapse admin-API `curl` immediately below —
which would have deleted some other user's device. Fixed in both the English
and `zh-Hans` copies.

### 8. The TUI counted the same task twice

Not a token issue, but found while verifying the console against the runtime:
`x19/org/status.py` builds `status.blocked` as the union of BLOCKED,
WAITING_DEPENDENCY and WAITING_APPROVAL, and `counts.waiting` is that same
union. The console rendered the union in error red under "attention" — so a
task merely waiting on its upstream dependency looked like a stall needing
someone — and showed `waiting 2 · blocked 1` for two tasks. Both are now
partitioned per row, with regression tests.

### 9. The blind spot this audit had

This report's first draft said "zero unjustified residue". It was wrong, and it
was wrong in a way the methodology could not have found.

`README.ur-pk.md` still named the product in Urdu script — `ہرمیس ایجنٹ` — ten
times, including in the title heading and in sentences explaining how to install
and configure it. The audit searched for `hermes`, case-insensitively. An Urdu
spelling of the same word contains no ASCII letters in common with it, so the
scan scored it as clean while the file, opened by a human, was unchanged.

Fixed by replacing all ten with `X19` (including the title, which now reads the
same as the English, Spanish and Chinese READMEs) and by extending the scanner to
search ten non-Latin spellings: Urdu and Arabic script, simplified and
traditional Chinese, Japanese katakana, Korean hangul, Russian cyrillic, Greek,
Hebrew and Thai. Every hit in that pass is residue — no justified class writes
the product name in another script — so they bypass the classifier rather than
being matched against the model-identifier and attribution patterns.

The scanner and this report are exempted from the transliteration pass only, for
the same reason they are counted rather than excluded from the token pass: a
detector has to spell what it detects. They stay visible in `audit-tooling`.

Verified non-vacuous: the clean tree reports no residue and exits 0; injecting
`ہرمیس ایجنٹ` into the Urdu README's title produces exactly one residue line
naming that file and line; restoring it returns to clean.

### 10. Documentation pointed at hosts that cannot exist

Not a residue count, but the same root cause — a hostname rewritten as though it
were prose. Verified by DNS lookup, not by reading:

- `x19.nousresearch.com` — **no DNS record at all**. Referenced 42 times across
  the bundled X19 skill and its references, the skill's generated docs page in
  two locales, `CONTRIBUTING.es.md` and a sandbox matrix comment, including
  three install one-liners (`curl -fsSL https://x19.nousresearch.com/install.sh`).
- `x19.security.local` — **cannot resolve, by definition**: `.local` is reserved
  for link-local name resolution. It appeared as a documentation link in all
  three translated READMEs, which also claimed `https://x19.security.local` was
  the canonical repository.

Both were produced by rewriting an upstream hostname, not by a typo. Every
reference now uses the host `website/docusaurus.config.ts` actually declares
(`url: https://anony-place.github.io/x19-refactored`, `baseUrl: /docs/`), which
resolves. The paths mapped one-to-one, so each `/docs/<page>` and
`/install.{sh,ps1}` reference keeps its meaning.

### 11. Sixty documentation links had a path segment eaten

The three translated READMEs linked `tree/main/websitedeveloper-guide/...` —
the `/docs/` segment between `website` and the page path was gone, so the URL
was `website` glued directly to the page name. Sixty such links across
`README.es.md` (19), `README.zh-CN.md` (20) and `README.ur-pk.md` (20), plus one
in the bundled skill's webhook reference.

Rather than restore a GitHub link to an extension-less path — `tree/main/<dir>`
without `.md` is a 404 — these now point at the rendered documentation site, the
form already used by 68 other links in the repository. Every converted page was
verified to have a real markdown source file; none was missing.

`CONTRIBUTING.md` linked `/docs/guides/build-a-x19-plugin`, which works only via
the client-side redirect declared in `docusaurus.config.ts`. It now points at the
redirect's own target, `/docs/developer-guide/plugins` — the page whose title is
already "Build a X19 Plugin".

### 12. Renamed repository slugs resolved to 404s

Each was checked with an HTTP request, both spellings, rather than assumed:

| Slug as rewritten | Status | Real name | Status |
| --- | --- | --- | --- |
| `NousResearch/x19-example-plugins` | 404 | `NousResearch/hermes-example-plugins` | 200 |
| `NousResearch/x19-plugin-snyk` | 404 | `NousResearch/hermes-plugin-snyk` | 200 |
| `NousResearch/x19-plugin-touchdesigner` | 404 | `NousResearch/hermes-plugin-touchdesigner` | 200 |
| `NousResearch/x19-memory-wiki` | 404 | `NousResearch/hermes-memory-wiki` | 200 |
| `NousResearch/x19-telegram-business` | 404 | `NousResearch/hermes-telegram-business` | 200 |
| `NousResearch/x19-desktop-accent-picker` | 404 | `NousResearch/hermes-desktop-accent-picker` | 200 |
| `NousResearch/x19` (this repo) | 404 | `Anony-place/x19-refactored` | 200 |
| `AaronWong1999/x19claw` | 404 | `AaronWong1999/hermesclaw` | 200 |

Twelve references to the six companion repositories were restored to the real
upstream names across `plugin-catalog/*.yaml`, `nix/x19.nix`,
`CONTRIBUTING.md`, the desktop install tests and a sandbox script; ten
self-references — the clone URL and issues link in `CONTRIBUTING.es.md`, the Nix
homepage, the skill's declared homepage and source tree, the PR-review guide's
`gh --repo` examples, and a provider-detection test fixture — were pointed at
`Anony-place/x19-refactored`. `hermesclaw` and its link text were restored in all
three translated READMEs.

`generate-llms-txt.py` built its install one-liner from two concatenated string
literals, so the wrong slug survived a plain search-and-replace and contradicted
the `Repo:` line two lines below it.

`NousResearch/x19-media-studio` is deliberately left as-is: it 404s under both
spellings because it is a fabricated fixture in
`apps/desktop/electron/desktop-plugin-install.test.ts`, not a real repository.
Renaming a made-up project would be noise.

### 13. A rename deleted a step from the state-path fallback chain

`get_x19_home()` in `x19_constants.py` read the same variable twice in one `or`:

```python
os.environ.get("X19_HOME", "").strip() or os.environ.get("X19_HOME", "").strip()
```

The second operand was a different variable before the rewrite. Renaming both
sides to the same name left a dead branch — `not (A or A)` is `not A`, so
behaviour was unchanged, but the docstring still advertised four resolution
steps for a function performing three. The same pattern was in
`get_process_x19_home()`.

There is no legacy home to fall back to: the state root is `~/.x19`
(`%LOCALAPPDATA%\x19` on Windows) and nothing else is honoured, so the dead
branch was removed rather than repointed, and the docstring now states the chain
that runs. A repo-wide scan for the signature — one env var read twice inside a
single `or`/`||`, across `.py`/`.ts`/`.tsx`/`.js`/`.mjs`/`.sh`/`.ps1` — found
these two and no others. Tests now pin the resolution order and an AST guard
asserts each resolver reads the environment exactly once; the count matters
rather than the name, because de-duplicating into a set would have passed on the
very bug it guards.

### 14. Two names became one, and the installer lost a launcher

The rename mapped two distinct upstream identifiers onto the same string:
`hermes` (the CLI command) and `hermes-agent` (the agent entrypoint console
script) both became `x19`. Collapsing two names into one does not look like a
deletion — it looks like a duplicate in a list — but it deletes a thing.

**`install.sh` wrote the same launcher twice.** `setup_path()` wrote a `x19`
launcher, then a second block whose comment read "Also expose `x19`" and whose
target was `run_agent.py` — the `x19-agent` entrypoint — wrote `x19` again,
overwriting the first. Every venv install ended with the CLI launcher replaced
by the agent launcher. Restored to `x19-agent`. The covering test had been
renamed the same way: `HERMES_AGENT_BLOCK` became `X19_AGENT_BLOCK`, but its
pattern went from `command_link_dir/hermes-agent` to `command_link_dir/x19`, so
it matched the *CLI* block and asserted `run_agent.py` inside it.

**The CLI launcher pointed at a directory.** `X19_ENTRYPOINT="$INSTALL_DIR/x19"`
was upstream `$INSTALL_DIR/hermes`, a checked-in root launcher script. The rename
deleted that file — its new name would have collided with the `x19/` package
directory — and left the variable aimed at the path, which is now a directory.
The guard `[ ! -f "$X19_ENTRYPOINT" ]` therefore always failed, `setup_path()`
logged "X19 launcher prerequisites not found" and returned, so a real venv
install created **no `x19` command at all**. The launcher now runs the CLI as a
module, `-m x19_cli.main`: what `pyproject.toml`'s `x19 = "x19_cli.main:main"`
declares, and what `setup-x19.sh` already does. The guard checks the module file.

**`which hermes`.** The non-venv path resolved its interpreter by looking for a
binary named `hermes` on PATH — a name nothing in this repository installs, so
that branch always warned "not found on PATH after install" and returned.

**Console-script sets lost a member.** `frozenset({"x19", "x19", "x19-acp"})` is
a two-element set written as a three-element literal, in `profiles.py`,
`_install_repair.py`, `main_install_repair.py` and `uninstall.py`; the docstring
in `_install_repair.py` still called it "the well-known trio". So
`x19-agent.exe` was never quarantined before a Windows reinstall — the exact
file contention the quarantine ladder exists to survive — `_is_x19_argv()` did
not recognize a bare interpreter exec'ing the `x19-agent` shim, and the
uninstaller never removed the `x19-agent` wrapper. All four restored to
`{"x19", "x19-agent", "x19-acp"}`, matching `[project.scripts]` exactly.

**The Docker group remap addressed a user that does not exist.** `Dockerfile`
creates the runtime user with `useradd -u 10000 -m -d /opt/data x19`, but
`docker/stage2-hook.sh` ran `groupmod -o -g "$X19_GID" hermes`, `id -G hermes`
and `usermod -aG "$sock_group" hermes`. All three were suffixed `2>/dev/null`
and two had `|| true`, so they failed silently: the GID remap never happened —
the volume-permission failure the surrounding comment says it prevents (#15290)
— and Docker socket group membership was never granted, which is the "docker
backend may fail with EACCES" case two lines below. The warning printed on
failure already said `x19`; the command above it said `hermes`.

**Why the audit missed all of this.** It classified `which hermes 2>/dev/null`
and `groupmod … hermes 2>/dev/null` as `model-identifier`, because
`hermes[-_. ]?(4|3|2)\b` permits a space separator: `hermes 2>` read as the
model "Hermes 2". A shell redirection was being accepted as a version number,
and four lines of live residue were filed as justified. The rule now requires
that the digit not be followed by `>`. All 17 genuine space-separated model
references survive — `Hermes 3/4`, `Hermes 3 & 4`, `Hermes 4 405B`,
`Hermes 2/3`, and their Chinese translations — because a real model string puts
`/`, `&`, `.` or a space after the digit, never `>`. The four shell lines were
fixed at source, so `model-identifier` fell by exactly four (173 → 169) and no
other line changed class.

### 15. The installer URL this audit's own sweep had just broken

Section 10 normalised 47 references from a host with no DNS record to the host
`docusaurus.config.ts` declares. That was right for documentation pages and
wrong for the installer: `.github/workflows/deploy-site.yml` stages the Pages
artifact as `cp -r website/build/* _site/docs/` plus `llms.txt` at the root, so
the published site contains `docs/` and nothing else. There is no
`/install.sh` on it, and `website/static/` holds only `api`, `img` and `oauth`.
The normalisation therefore turned 47 dead links into 67 well-formed 404s.

The repository already stated the correct form in the two files that sweep never
touched — `website/docs/user-guide/windows-native.md` and `scripts/install.cmd`
both use
`raw.githubusercontent.com/Anony-place/x19-refactored/main/scripts/install.ps1`,
as does `generate-llms-txt.py`. All 67 installer references now use that raw
path, and each of the three targets (`install.sh`, `install.ps1`,
`install.cmd`) was confirmed to exist at the referenced path in the tree.

This one mattered beyond documentation. `x19_cli/update_cmd.py`,
`update_cmd_maint.py` and `uninstall.py` print the one-liner as the recovery
instruction when an update or uninstall fails, and the desktop app prints it in
five languages when a remote host has no X19 installed — so the broken URL was
in user-facing runtime output, not just prose.

### 16. A workspace restore resurrected files the transformation had deleted

Late in the work the sandbox was re-cloned at the branch point and the workspace
restored on top of it. Every commit this transformation was built from was
discarded — the branch had never been pushed, so the history was unrecoverable —
but the file contents survived, and the tree was re-committed in full.

The restore was not faithful in one respect, and the audit caught it: it brought
back two directories the transformation had removed, and with them 608 lines of
residue that had already been fixed once.

`plugins/hermes-achievements/dashboard/dist/` reappeared alongside its own
rename target `plugins/x19-achievements/`, so the plugin existed twice — once
under the legacy name and once without the dashboard bundle its manifest
declares (`entry: dist/index.js`, `css: dist/style.css`). The achievements
plugin was therefore broken in a second way: the manifest pointed at files that
were not there.

`plugins/kanban/dashboard/dist/` came back with its original contents, which is
the defect recorded in section 2 all over again. Both bundles read
`window.__HERMES_PLUGIN_SDK__`, `window.__HERMES_PLUGINS__`,
`window.__HERMES_SESSION_TOKEN__`, the header `X-Hermes-Session-Token`, the
cookie `hermes_session_at` and the route `/api/plugins/hermes-achievements`,
while the host provides `__X19_PLUGIN_SDK__`, `__X19_PLUGINS__`,
`__X19_SESSION_TOKEN__`, `X-X19-Session-Token`, `x19_session_at` and
`/api/plugins/x19-achievements` — each of those host-side names verified present
in `apps/desktop/src/sdk/runtime.ts`, `web/src/plugins/registry.test.ts` and
`plugins/x19-achievements/dashboard/plugin_api.py`. Read against the host, both
dashboards resolve to `undefined`: they cannot register, cannot authenticate and
call a route that does not exist.

Repaired again, and this time verified rather than assumed: the achievements
bundle was moved back to the path its manifest declares and the empty legacy
directory removed; the SDK globals, auth header, cookie, API route, drag-drop
MIME type, storage key, database path, ~200 CSS class names and custom
properties, and the user-facing copy were all repointed; and the two
documentation links went to the canonical site, both pages confirmed present.
`node --check` parses both scripts, both manifests resolve to files that exist,
and the upstream MIT attribution to the original author
(`github.com/PCinkusz/hermes-achievements`) is intact in both bundles — it is the
only occurrence of the token left in either.

The methodological point is worth keeping: these are `dist/` files with no build
step, so they are hand-written source and nothing regenerates them. A restore, a
merge or a careless checkout can silently revert them, and the only thing that
notices is a scan that runs afterwards. This audit is that scan.

### 17. Two more addresses that cannot exist

Found by sweeping every host in the repository containing the product name —
which the token scan cannot do, because none of these strings contain the token.

`setup.py` printed `https://x19.security.local/docs/getting-started/installation`
in the message shown to anyone who tries to build a wheel or an sdist. `.local`
is reserved for link-local name resolution and cannot appear in public DNS, so
the one person most likely to need the installation guide was handed a URL that
cannot resolve. Repointed at the canonical site; the target page exists.

`SECURITY.md` and `SECURITY.es.md` each advertised `security@x19.local` twice —
once as an alternative reporting channel and once as the disclosure channel
("the GHSA thread or email correspondence with security@x19.local"). No mail
domain ending in `.local` is deliverable, so a vulnerability reporter who chose
the email path would have heard nothing back, in a document whose entire purpose
is to be reachable. No replacement address exists in this repository and
inventing one would be worse than removing it, so both files now name the one
channel that works — GitHub Security Advisories, whose URL correctly points at
this repository — in both languages.

Not changed, and recorded here rather than quietly left: four references to
`https://x19-assets.nousresearch.com/X19-Setup.{dmg,exe}` in the desktop install
e2e harness. That host was renamed from an upstream artifact CDN, and this
repository publishes no workflow that builds or uploads those installers, so
neither the renamed host nor the original can be assumed to serve an X19
artifact. The references are defaults for `workflow_dispatch`-only jobs — never
triggered automatically — and are overridable per run. Guessing a replacement
would be a worse failure than leaving a known-unverifiable default and saying so;
see [Limitations](#limitations).

---

## Protected items (deliberately not renamed)

| Item | Why it stays |
| --- | --- |
| `LICENSE` | `Copyright (c) 2025 Nous Research`, MIT. Contains zero occurrences; no change was needed or permitted. |
| `.mailmap`, `contributors/emails/*` (23 paths) | Git-history contributor attribution. Rewriting it falsifies who contributed. |
| Six `NousResearch/hermes-*` companion repos | Upstream projects, not ours to rename; all resolve 200, the `x19-*` spellings 404. |
| `hermes-parser`, `hermes-estree` in `package-lock.json` | Facebook/Meta npm packages, transitive via `eslint-plugin-react-hooks`. Renaming corrupts the lockfile and breaks `npm ci`. |
| Nous model names (169 lines) | Provider artifacts. Renaming breaks model resolution, pricing and fallback chains. |
| `Adolanium/hermes-nous-prices`, `PCinkusz/hermes-achievements` | Upstream third-party repositories; the second is an MIT attribution requirement. |
| `github@nadyahermes.anonaddy.com` in `scripts/release.py` | A contributor's alias-domain address in release-notes credit. |
| Jailbreak-template corpus | Verbatim third-party research text whose value depends on being unaltered. |
| `scripts/x19_residue_audit.py` | The detector must name what it detects. |

Compatibility note for the isolation requirement: there is **no legacy
`~/.hermes` home-directory migration path** in this repository. The state root
is `~/.x19` (`X19_HOME`), so there is no legacy naming to isolate into a
dedicated module and none leaks through normal X19 configuration.

---

## Keeping it at zero

```bash
python scripts/x19_residue_audit.py            # human-readable report
python scripts/x19_residue_audit.py --strict   # exit 1 on any unclassified line
python scripts/x19_residue_audit.py --json     # machine-readable
```

`--strict` is suitable as a pre-merge gate: a new legacy-named identifier,
service label, environment variable or UI string fails the build instead of
waiting to be discovered as a broken guard.

The classifier was probed to confirm the justification rules cannot be abused.
Each of these still reports as `RESIDUE`:

```
systemctl restart hermes-gateway
launchctl kickstart ai.hermes.gateway
b"python\x00hermes_cli/main.py\x00gateway\x00"
hermes-gateway:latest
exec hermes -p mybot
window.__HERMES_PLUGIN_SDK__
See website/docs/hermes-guide.md
cell = "hermes_tools.web_search()"
```

while each of these is correctly justified: a Modelfile tag,
`"hermes_4_70b"`, the `_NOUS_CHAT_MODEL_NON_AGENTIC_RE` pattern, an
`assert "hermes" not in …` guard, the `Adolanium/hermes-nous-prices` repo URL,
and the contributor alias-domain address.

The transliteration pass was probed the same way, because a rule that only ever
returns nothing is indistinguishable from a rule that never runs. Injecting
`ہرمیس ایجنٹ` into the Urdu README's title line produces exactly one `RESIDUE`
entry naming that file and line; removing it returns the tree to clean and exit
0.

Two rules are intentionally scoped so they cannot become general exemptions:
the third-party-repository rule excludes our own GitHub organisation, and the
model-family-pattern rule is anchored to one named constant rather than
permitting any `re.compile(...)` that happens to contain the token. The
upstream-repository list is an explicit enumeration of six names rather than a
pattern, because a pattern broad enough to catch them would also swallow the
model-artifact URLs it must leave to `MODEL_RE`.

---

## Limitations

Stated plainly, so the "zero" is not over-read:

- **Token-based, and the transliteration list is finite.** The scan finds the
  legacy product *name* in the Latin alphabet plus ten explicitly listed
  non-Latin spellings. Anything else — a codename, an abbreviation, or a
  spelling in a script not on that list — is outside its reach. The ten scripts
  were chosen as the ones the repository's own translations actually use; they
  cover what this codebase writes, not every language that has a word for the
  messenger god.
- **It cannot see a broken domain or a mangled path.** Neither
  `x19.nousresearch.com` nor `x19.security.local` nor the 60 links with an eaten
  path segment contains the token, so the residue scan scored all of them as
  clean. They were found by a separate sweep that resolved every host by DNS and
  every documentation link against the repository's own file tree and over HTTP.
  That sweep is not automated and not repeatable as a gate; the residue scan is.
- **Some hosts cannot be verified from here, and are named rather than fixed.**
  This sandbox resolves and reaches `github.com` but not
  `raw.githubusercontent.com` or `anony-place.github.io`, so the canonical site
  and the raw installer paths are verified from the repository's own build and
  deploy configuration — `docusaurus.config.ts` for the host, `deploy-site.yml`
  for what is actually published — rather than by request. One host is not
  verifiable by either route: `x19-assets.nousresearch.com`, in four
  manual-trigger desktop e2e jobs, renamed from an upstream artifact CDN that
  this repository publishes nothing to. It is left alone and recorded in
  [section 17](#17-two-more-addresses-that-cannot-exist) instead of being
  replaced with a guess.
- **Tracked files only.** Build output, `node_modules` and other ignored
  artifacts are not scanned; they are not part of the repository and are
  regenerated from the sources that are. The plugin `dist/` files that were
  repaired *are* tracked (they are hand-written source with no build step), and
  are covered.
- **Justification is line-local.** Each occurrence is classified from its own
  line. A line that is genuinely justified could in principle mask a second,
  unrelated problem on the same line; the classes above are narrow enough that
  this did not occur, but the audit is not a substitute for review.
- **Run the test suite serially.** Verification for this report was done with
  `pytest -p no:randomly` and no `-n`. Under `-n 2` on a 2-CPU machine the suite
  is flaky in both directions — the same command reported 80 and then 81
  failures on consecutive runs, and 14 tests that appeared only after the fixes
  pass cleanly when run serially. For calibration, the identical `-n 2`
  invocation reported **252 failures before this work and ~80 after**, with 185
  tests fixed and none genuinely broken; the residue is pre-existing
  parallel-execution interference plus a handful of long-standing failures in
  modules this transformation never touched (vision routing, welcome-tier copy,
  cron scheduler-provider resolution), each confirmed failing at the pre-work
  commit via a detached worktree.
- **It verifies absence of a name, not correctness of behaviour.** The
  functional regressions in this report were found *because* each string was
  read in context and asked what it did. The scan flags candidates; the tests
  decide. **124 test failures turned out to be real defects rather than rename
  churn** — 106 in the gateway lifecycle guard suite, 11 in the model-family
  detector, 2 in the desktop delivery suite, and one each in process-cmdline
  priority, systemd socket notification, code-kernel RPC authority and two
  process-holder recognition cases — plus one `windows_only` test that had been
  skipped into brokenness and one boundary probe that tested nothing at all.
  All are now passing.
