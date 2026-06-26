# X19 Refactored

Autonomous AI pentesting framework — refactored architecture.

## What's here

- `brain/` — WorldModel, Planner, ContextBuilder, DecisionParser, ReflectionEngine
- `execution/` — CommandGateway, PolicyEngine, typed CommandRequest/CommandResult
- `parsers/` — Structured output parsers (nmap, httpx, gobuster, ffuf)
- `learning/` — Memory & self-improvement wrappers
- `reporting/` — Report generation wrappers
- `infrastructure/` — Config, storage, plugins
- `tests/` — 61 unit tests (gateway, parsers, world model, decision parsing, reflection)

## Setup

```bash
pip install -r requirements.txt
python run.py -t <target>
```

## Tests

```bash
python -m unittest discover -s tests -v
```
