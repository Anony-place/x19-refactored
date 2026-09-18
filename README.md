<p align="center">
  <strong>X19</strong><br>
  Autonomous Security Operations
</p>

# X19

X19 is the user-facing product built on a proven agent runtime. It keeps the runtime capabilities already present in this repository—real terminal execution, streaming, skills, memory, sessions, delegation, gateway/provider routing, approvals, and TUI infrastructure—and adds an X19 Boss/operator model for authorized security work.

**Product identity:** X19  
**Runtime foundation:** the existing agent runtime in this repository  
**Upstream attribution:** this repository retains upstream attribution and MIT licensing where required.

## Quick start

After installing the Python and Node dependencies used by the repository:

```bash
x19
x19 --tui
x19 --help
```

The `x19` entry point is the primary product command. The legacy `hermes` entry point remains only as a compatibility alias for existing installations and scripts.

## X19 operator model

The interactive operator talks to **X19 Boss**. Boss owns mission scope and state, creates the assessment plan, and dispatches ready work through the runtime's existing `delegate_task` mechanism. Managers coordinate specialist roles; specialists use the actual terminal/browser/tool surfaces available to them.

Mission state is persisted by the existing mission-state layer. Status is derived from persisted task, evidence, finding, timeline, and live delegation state—not from fabricated progress.

The evidence lifecycle is explicit:

`OBSERVATION → HYPOTHESIS → TEST → EVIDENCE → VERIFIED FINDING`

A candidate is never promoted to VERIFIED solely because a model thinks the evidence looks convincing. Verification requires a real verification result.

## Human controls and scope

Every X19 mission must use explicit authorization boundaries: target, authorized domains/IPs, exclusions, allowed/prohibited actions, and operational limits such as time, concurrency, and rate limits.

Human control remains authoritative. PAUSE, STOP, KILL ALL, RESET, and approval gates must remain available. X19 must fail closed when a task falls outside mission scope or when required runtime controls are unavailable.

## Knowledge and datasets

Public security knowledge is usable only with provenance metadata. Dataset entries must identify their source/licensing context and must not introduce secrets or private personal data. Synthetic examples are treated as synthetic examples; they are never presented as live observations or real scan results.

No production path should manufacture terminal output, reconnaissance discoveries, findings, verification results, or completion status.

## TUI

The terminal interface is intentionally minimal and operational. The visible product identity is **X19**; internal upstream module/package names may remain where changing them would break runtime compatibility.

The TUI retains real streaming output, tool-call rendering, sessions, gateway connectivity, interrupts, and terminal cleanup.

## Configuration

X19 is enabled by default in this repository. Explicit operator configuration still wins:

```yaml
x19:
  enabled: true
```

Set `x19.enabled: false` or `X19_ENABLED=0` only when intentionally running the legacy upstream identity. `X19_HOME` is not required for runtime operation; existing home/profile compatibility is preserved so stored sessions, skills, memory, and credentials are not silently relocated.

## Upstream compatibility

The `hermes-baseline` branch is the untouched reference baseline. Do not use it as the product identity.

The source retains internal `hermes_*` module names and compatibility environment variables where those names are part of the proven runtime contract. User-facing product copy and primary entry points use X19.

## License

MIT. See `LICENSE` for the repository license and preserved upstream attribution.
