# X19 CLI Reference

Live sources when anything looks stale: `x19 --help`, `x19 <command> --help`,
https://anony-place.github.io/x19-refactored/docs/reference/cli-commands

### Global Flags

```
x19 [flags] [command]        (no subcommand = interactive chat)

  --version, -V             Show version
  -z, --oneshot PROMPT      One-shot: print ONLY the final response (for scripts/pipes)
  -m MODEL  --provider P    Model/provider override for this invocation
  -t, --toolsets LIST       Comma-separated toolsets for this invocation
  --resume, -r SESSION      Resume session by ID or title
  --continue, -c [NAME]     Resume by name, or most recent session
  --worktree, -w            Isolated git worktree mode (parallel agents)
  --skills, -s SKILL        Preload skills (comma-separate or repeat)
  --profile, -p NAME        Use a named profile
  --yolo                    Skip dangerous command approval
  --tui / --cli             Force the Ink TUI / classic REPL
  --ignore-rules            Skip AGENTS.md/SOUL.md/memory/skill injection
  --safe-mode               Disable ALL customizations (troubleshooting)
  --pass-session-id         Include session ID in system prompt
```

### Chat

```
x19 chat [flags]
  -q, --query TEXT          Single query, non-interactive
  --image PATH              Attach a local image to a single query
  -Q, --quiet               Suppress banner, spinner, tool previews
  --checkpoints             Enable filesystem checkpoints (/rollback)
  --max-turns N             Cap tool-calling iterations
  --source TAG              Session source tag (default: cli)
```
(plus the global flags above)

### Configuration

```
x19 setup [section]      Wizard (model|tts|terminal|gateway|tools|agent)
x19 model                Interactive model/provider picker
x19 fallback [add|remove|list]  Fallback provider chain
x19 config [show|edit|get|set|unset|path|env-path|check|migrate]
x19 login / logout       OAuth sign-in / clear stored auth
x19 doctor [--fix]       Check dependencies and config
x19 status [--all]       Component status
```

### Tools & Skills

```
x19 tools [list|enable NAME|disable NAME]   Per-platform toolsets (curses UI with no args)

x19 skills list|browse|search QUERY|inspect ID
x19 skills install ID    Hub identifier OR a direct https://…/SKILL.md URL
x19 skills config        Enable/disable skills per platform
x19 skills check|update|uninstall|publish PATH
x19 skills tap add REPO  Add a GitHub repo as a skill source
x19 bundles              Skill bundles (one /<name> alias loads several skills)
```

### MCP Servers

```
x19 mcp add NAME (--url or --command) | remove | list | test NAME
x19 mcp catalog | install NAME     Curated catalog install
x19 mcp configure NAME             Toggle tool selection
x19 mcp serve                      Run X19 as an MCP server
```
Details (transport, tool discovery, catalog): `references/native-mcp.md`.

### Gateway (Messaging Platforms)

```
x19 gateway run|install|start|stop|restart|status|setup
```

20+ platforms: Telegram, Discord, Slack, WhatsApp (Baileys + Business Cloud API), iMessage (Photon — `x19 photon setup`), Signal, Email, SMS, Matrix, Mattermost, Teams, LINE, SimpleX, ntfy, Google Chat, Home Assistant, DingTalk, Feishu, WeCom, Weixin, API Server, Webhooks. Open WebUI connects via the API Server adapter. Most adapters ship under `plugins/platforms/`.
Docs: https://anony-place.github.io/x19-refactored/docs/user-guide/messaging/

### Sessions

```
x19 sessions list|browse|rename ID TITLE|delete ID|export OUT|prune|stats
```

### Cron / Webhooks

```
x19 cron list|create SCHED|edit ID|pause|resume|run ID|remove|status
    Schedules: '30m', 'every 2h', '0 9 * * *', ISO timestamp
x19 webhook subscribe NAME|list|remove NAME|test NAME
```
Webhook payloads/routes: `references/webhooks.md`.

### Profiles

```
x19 profile list|create NAME (--clone|--clone-all|--clone-from)|use|show|delete
x19 profile rename A B | alias NAME | export NAME | import FILE
x19 profile migrate-identity A B   Retry a completed rename's session/routing identity migration
```

### Credentials & Pools

```
x19 auth                 Interactive credential manager
x19 auth add [PROVIDER]  Add OAuth or API-key credential (nous, openai-codex, qwen-oauth, …)
x19 auth list|remove P IDX|reset PROVIDER|status
```
Multiple credentials per provider form a pool that rotates automatically and skips exhausted keys.

### Other

```
x19 desktop / gui        Native desktop app
x19 dashboard            Web admin panel + embedded chat (--stop / --status)
x19 proxy                OpenAI-compatible local proxy backed by an OAuth provider
x19 portal               Quick setup / sign in via Nous Portal
x19 kanban <verb>        Multi-agent work-queue board
x19 project              Named multi-folder workspaces
x19 skin list|use|set    Switch/tweak skins (see references/themes.md)
x19 pets <verb>          Pet mascots (see references/petdex.md)
x19 memory setup|status|off|reset   Memory provider
x19 secrets bitwarden|onepassword   External secret stores
x19 moa                  Mixture-of-Agents slots
x19 hooks / security / backup / import / checkpoints / console
x19 logs [-f] [errors]   View agent/error logs
x19 send                 One-off message through a gateway platform
x19 pairing / plugins / insights / journey / computer-use
x19 acp                  ACP server (IDE integration)
x19 completion bash|zsh|fish
x19 update / uninstall / claw migrate
```

Plugin- and provider-supplied subcommands (e.g. `x19 photon setup`) only appear once their plugin is installed/active.

### Where to Find Things

| Looking for... | Location |
|---|---|
| Config options | `x19 config edit` · [Configuration docs](https://anony-place.github.io/x19-refactored/docs/user-guide/configuration) |
| Tools / toolsets | `x19 tools list` · [Tools reference](https://anony-place.github.io/x19-refactored/docs/reference/tools-reference) |
| Skills catalog | `x19 skills browse` · [Skills catalog](https://anony-place.github.io/x19-refactored/docs/reference/skills-catalog) |
| Provider setup | `x19 model` · [Providers guide](https://anony-place.github.io/x19-refactored/docs/integrations/providers) |
| Env variables | `x19 config env-path` · [Env vars reference](https://anony-place.github.io/x19-refactored/docs/reference/environment-variables) |
| Gateway logs | `~/.x19/logs/gateway.log` (or `x19 logs`) |
| Sessions | `x19 sessions browse` (reads state.db) |
