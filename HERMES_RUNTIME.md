# X19 runtime direction

X19 uses `run.py` as the only supported entry point.

## Operator surface

The normal path is plain terminal output:

- `x19` — concise status and commands
- `x19 setup` — provider/model discovery and live verification
- `x19 provider list`
- `x19 provider discover <provider>`
- `x19 provider test <provider>`
- `x19 provider use <provider> --model <model>`
- `x19 brain` — cognitive runtime health check
- `x19 run -t <target>` — assessment
- `x19 dash ...` — explicit legacy live dashboard only

The full-screen workspace is not part of the default control path.

## Provider principle

Model registries are hints, not truth. Provider setup discovers models from the
provider's live `/models` endpoint when supported, verifies the selected model
with a real request, and only then writes it as the active provider/model.
Local Ollama and custom OpenAI-compatible endpoints are handled without forcing
a cloud failover.

## Cognitive principle

The model follows a closed decision loop:

`state -> gap -> hypothesis -> action -> evidence -> update`

The cognitive runtime is advisory. Existing scope, policy and verification
components remain authoritative for actual security execution and findings.

The goal is not a bigger prompt or more autonomous commands. The goal is fewer
repeated scans, fewer invented facts, clearer hypothesis transitions, and a
defensible reason for every next action.
