---
sidebar_position: 11
title: "ACP Host Integration"
description: "Use X19 inside ACP-compatible editors and collaboration platforms"
---

# ACP Host Integration

X19 can run as an ACP server, letting ACP-compatible hosts talk to
X19 over stdio. Editors can render:

- chat messages
- tool activity
- file diffs
- terminal commands
- approval prompts
- streamed thinking / response chunks

Other hosts can use the same protocol to route collaboration events into
X19. ACP is a good fit when you want X19 to keep its existing identity,
provider setup, memory, skills, and tools while another application owns the
conversation transport.

## What X19 exposes in ACP mode

X19 runs with a curated `x19-acp` toolset designed for editor workflows. It includes:

- file tools: `read_file`, `write_file`, `patch`, `search_files`
- terminal tools: `terminal`, `process`
- web/browser tools
- memory, todo, session search
- skills
- execute_code and delegate_task
- vision

It intentionally excludes things that do not fit typical editor UX, such as messaging delivery and cronjob management.

## Installation

Install X19 normally, then add the ACP extra from the install checkout:

```bash
cd ~/.x19/x19 && uv pip install -e '.[acp]'
```

This installs the `agent-client-protocol` dependency and enables:

- `x19 acp`
- `x19-acp`
- `python -m acp_adapter`

## Launching the ACP server

Any of the following starts X19 in ACP mode:

```bash
x19 acp
```

```bash
x19-acp
```

```bash
python -m acp_adapter
```

X19 logs to stderr so stdout remains reserved for ACP JSON-RPC traffic.

For non-interactive checks:

```bash
x19 acp --version
x19 acp --check
```

### Browser tools (optional)

Browser tools (`browser_navigate`, `browser_click`, etc.) depend on the
`agent-browser` npm package and Chromium, which aren't part of the Python
wheel. Install them with:

```bash
x19 acp --setup-browser           # interactive (prompts before ~400 MB download)
x19 acp --setup-browser --yes     # accept the download non-interactively
```

This is the standalone command. The terminal-auth flow (`x19 acp --setup`) also offers the browser bootstrap as a follow-up question after model selection, so most users never need to run `--setup-browser` directly.

What it does:

- Installs Node.js 26 into `~/.x19/node/` if missing
- `npm install -g agent-browser @askjo/camofox-browser` into that prefix (no sudo needed — `npm`'s `--prefix` points at the user-writable X19-managed Node)
- Installs Playwright Chromium, or uses a detected system Chrome/Chromium when available

The bootstrap is idempotent — re-running it is fast and skips work that's already done.

## Host setup

### Buzz channels (relay bridge)

[Buzz](https://github.com/block/buzz) is a Nostr-based collaboration platform
for people and agents. Its `buzz-acp` harness connects Buzz channels to any ACP
agent over stdio:

```text
Buzz relay <-- WebSocket --> buzz-acp <-- ACP over stdio --> X19
```

This is a transport integration, not a second X19 installation. The
subprocess launched by `buzz-acp` uses the same X19 configuration,
credentials, memory, skills, and state as `x19` on that host.

(This is distinct from [Buzz Desktop's managed runtime](#buzz-desktop), which
spawns X19 locally as a preset harness. The relay bridge is for joining Buzz
*channels* as an agent identity, typically on a server.)

Prerequisites:

- Complete the ACP installation and `x19 acp --check` above.
- Build `buzz-acp` and the `buzz` CLI from the
  [Buzz repository](https://github.com/block/buzz)
  (`cargo build --release -p buzz-acp`).
- Mint a dedicated Nostr keypair for X19 (`buzz-admin generate-key`) and
  register it as a relay member (`buzz-admin add-member`). Every agent needs
  its own identity — do not reuse a human keypair.
- Add that identity to the intended Buzz channels.

Start a bridge with:

```bash
export BUZZ_RELAY_URL="wss://community.example.com"
export BUZZ_PRIVATE_KEY="..."
export BUZZ_API_TOKEN="..."
export BUZZ_ACP_AGENT_COMMAND="x19"
export BUZZ_ACP_AGENT_ARGS="acp"

buzz-acp
```

`BUZZ_API_TOKEN` is needed only when the relay enforces token authentication.
Do not commit or paste the private key or API token.

For a persistent server deployment, run `buzz-acp` under a service manager as
the same operating-system user that owns the intended X19 home. Setup,
key generation, channel discovery, and per-agent options are documented in the
[buzz-acp README](https://github.com/block/buzz/tree/main/crates/buzz-acp).

The bridge discovers every Buzz channel where the X19 identity is a member
and automatically subscribes when it is added to another channel. Buzz channel
membership therefore remains the access boundary; X19 does not need a
separate channel list in its own configuration.

To expose X19 ACP activity in the owner's Buzz Desktop, add:

```bash
export BUZZ_ACP_RELAY_OBSERVER="true"
```

This publishes encrypted kind `24200` observer frames addressed to the agent's
owner (Buzz's NIP-AO). Desktop renders the live lifecycle, tool, response, and
usage stream in the agent's **Activity log**. The relay treats these frames as
ephemeral, so Desktop must be online before the turn starts; its local observer
archive is the durable owner-side history.

Headless bridges answer ACP permission requests themselves because no editor
is present to show approval dialogs — see
[Keep Buzz agents owner-only](#keep-buzz-agents-owner-only). Treat the bridge
as privileged automation: use a dedicated operating-system account, restrict
which Buzz users can prompt the agent (`buzz-acp` supports an owner-only
respond gate via `BUZZ_ACP_AGENT_OWNER`), and grant membership only in channels
where X19 is expected to work.

### VS Code

Install the [ACP Client](https://marketplace.visualstudio.com/items?itemName=formulahendry.acp-client) extension.

To connect:

1. Open the ACP Client panel from the Activity Bar.
2. Select **X19** from the built-in agent list.
3. Connect and start chatting.

If you want to define X19 manually, add it through VS Code settings under `acp.agents`:

```json
{
  "acp.agents": {
    "X19": {
      "command": "x19",
      "args": ["acp"]
    }
  }
}
```

### Zed

Configure X19 as a custom agent server in Zed settings:

1. Open the Agent Panel.
2. Add a custom agent server with the following configuration:

```json
{
  "agent_servers": {
    "x19": {
      "type": "custom",
      "command": "x19",
      "args": ["acp"]
    }
  }
}
```

3. Start a new X19 external-agent thread.

Prerequisites:

- Configure X19 provider credentials first with `x19 model`, or set them in `~/.x19/.env` / `~/.x19/config.yaml`.

### JetBrains

Use an ACP-compatible plugin and point it at `x19 acp` or `x19-acp`.

### Buzz Desktop

[Buzz](https://github.com/block/buzz) ships X19 as a preset runtime.
With X19 installed the normal way, Buzz discovers it automatically —
open **Settings → Runtimes** and X19 appears under your runtimes.

If discovery fails (older installs), make sure the ACP launcher resolves on a
login-shell PATH:

```bash
command -v x19-acp || command -v x19
```

Recent installs write both `x19` and `x19-acp` launchers into
`~/.local/bin`; running `x19 update` adds the `x19-acp` launcher to
older installs. As a manual fallback, configure Buzz's agent command as
`x19` with args `["acp"]`.

#### Model picker

Buzz Desktop (v0.5.1+) renders X19' full model menu in the agent's runtime
settings. The list comes from X19 itself over ACP: it shows every model
from providers you have authenticated in X19 (the same inventory behind
`x19 model` and the `/model` command), so a model missing from the menu
means its provider has no credentials configured on the X19 side.

Entry IDs take the form `provider:model` (e.g. `openrouter:z-ai/glm-5.1`), or
`custom:<name>:<model>` for custom OpenAI-compatible endpoints defined in
`config.yaml`. Picking a model applies to that agent's session; it does not
change your X19-wide default — use `x19 model` for that.

#### Keep Buzz agents owner-only

Buzz creates every agent with **Who can talk to this agent** set to `Owner only`.
Leave it there when the runtime is X19.

Two behaviors combine on this path. The `x19-acp` toolset includes `terminal`
and `execute_code`, and Buzz's ACP bridge answers X19' permission requests
itself with `allow_once` rather than surfacing them. An X19 in Buzz
therefore runs shell commands on the host without prompting. I asked one to run
`rm -rf` against a scratch directory and it deleted it, no prompt anywhere.

Selecting `Anyone` hands that same shell access to every author who can reach
the channel. Buzz does not warn when you pick it.

Neither of the obvious mitigations works today:

- `approvals.mode: manual` does make X19 raise the permission request, but
  Buzz auto-approves it and the command still runs.
- `platform_toolsets.acp` does not narrow the ACP toolset, so it cannot be used
  to drop `terminal`.

`!shutdown` from the owner stops the agent in any mode, and Buzz ignores that
command from everyone else.

## Configuration and credentials

ACP mode uses the same X19 configuration as the CLI:

- `~/.x19/.env`
- `~/.x19/config.yaml`
- `~/.x19/skills/`
- `~/.x19/state.db`

Provider resolution uses X19' normal runtime resolver, so ACP inherits the currently configured provider and credentials. X19 also advertises a terminal auth method (`--setup`) for first-run ACP clients; this opens X19' interactive model/provider setup.

## Host integration

These variables are set by an **ACP host process** (an editor or another agent
harness) on the X19 subprocess it spawns. They are not user configuration —
do not set them by hand in `.env` or `config.yaml`.

| Variable | Value | Effect |
|----------|-------|--------|
| `X19_ACP_SKIP_CONFIGURED_MCP` | `1` | Skip starting the **globally configured** MCP servers from `config.yaml` before the ACP JSON-RPC loop begins. |

X19 normally starts every MCP server configured in `config.yaml` before it
enters the ACP JSON-RPC loop. A host that owns MCP itself — passing the
session's servers explicitly through `session/new` — does not need that global
startup, and an unrelated slow or interactive MCP server would otherwise delay
`initialize`. Setting the marker to exactly `1` lets such a host skip it.

Only the global `config.yaml` discovery is skipped. **MCP servers supplied by
the ACP session through `session/new` are still registered**, so a host loses
no capability it asked for. Any other value (unset, empty, `0`, `false`) keeps
the default behavior, so an unrelated truthy-looking string cannot silently
disable MCP.

## Session behavior

ACP sessions are tracked by the ACP adapter's in-memory session manager while the server is running.

Each session stores:

- session ID
- working directory
- selected model
- current conversation history
- cancel event

Conversations are persisted to X19' session database and can be listed, loaded,
resumed, or forked after the ACP server restarts. Opening a new session without a
prompt keeps it in memory only: model-discovery probes do not create empty history
rows. A nonempty fork is persisted immediately, and existing session metadata can
still be updated even when its current history is empty.

Existing empty rows from older versions are not automatically deleted. An open ACP
row does not prove its client has disconnected. After closing the relevant editor
sessions, inspect unwanted rows with `x19 sessions show <id>` and remove only
confirmed unwanted sessions with `x19 sessions delete <id>`.

## Working directory behavior

ACP sessions bind the editor's cwd to the X19 task ID so file and terminal tools run relative to the editor workspace, not the server process cwd.

## Approvals

Dangerous terminal commands can be routed back to the editor as approval prompts. ACP approval options are simpler than the CLI flow:

- allow once
- allow always
- deny

Whether you actually see a prompt is up to the host. A host is free to answer the
request programmatically instead of showing it to you, in which case these
options exist on the wire but never reach a human. Buzz Desktop does this, so
treat that path as unattended execution regardless of your `approvals` setting.

On timeout or error, the approval bridge denies the request.

### Session-scoped edit auto-approval

ACP exposes a third tier between *allow once* and *allow always*: **Allow for session**. Picking it from the editor's permission prompt records the approval inside the current ACP session only — every subsequent matching command in that session goes through without prompting, but a new ACP session (or restarting the editor) resets the slate and re-prompts the first time.

| Option | Editor label | Scope | Persisted across restarts |
|---|---|---|---|
| `allow_once` | Allow once | This one tool call | No |
| `allow_session` | Allow for session | All matching calls in this ACP session | No — cleared when the session ends |
| `allow_always` | Allow always | All future sessions | Yes (written to the X19 permanent allowlist) |
| `deny` | Deny | This one tool call | No |

`allow_session` is the right default for an editor workflow where you trust an agent for the duration of a task but don't want to grant a long-lived allowlist entry. The safety trade-off is straightforward: the broader the scope, the less the editor will interrupt you, and the more damage a misbehaving agent (or prompt injection) can do before you notice. Start with `allow_once` for unfamiliar commands; promote to `allow_session` once you've seen the agent run the same pattern correctly a few times; reserve `allow_always` for truly idempotent commands you trust forever (e.g. `git status`).

The ACP bridge maps these options onto X19' internal approval semantics — `allow_always` writes a permanent allowlist entry the same way the CLI does, while `allow_session` only affects the in-process approval cache for the current ACP session.

## Troubleshooting

### ACP agent does not appear in the editor

Check:

- For manual/local development, verify the host command points to `x19 acp`.
- X19 is installed and on your PATH.
- The ACP extra is installed (`cd ~/.x19/x19 && uv pip install -e '.[acp]'`).

### ACP starts but immediately errors

Try these checks:

```bash
x19 acp --version
x19 acp --check
x19 doctor
x19 status
```

### Missing credentials

ACP mode uses X19' existing provider setup. Configure credentials with:

```bash
x19 model
```

or by editing `~/.x19/.env`. The terminal auth flow (`x19 acp --setup`) can also trigger the interactive provider/model setup.

## See also

- [Buzz ACP harness](https://github.com/block/buzz/tree/main/crates/buzz-acp)
- [ACP Internals](../../developer-guide/acp-internals.md)
- [Provider Runtime Resolution](../../developer-guide/provider-runtime.md)
- [Tools Runtime](../../developer-guide/tools-runtime.md)
