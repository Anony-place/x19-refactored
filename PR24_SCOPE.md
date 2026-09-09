# Follow-up runtime fixes

This follow-up contains operator/runtime corrections after the plain-terminal merge:

- route natural `target <host>` input to the real X19 assessment loop instead of generic LLM chat
- expose multi-signal remote OS fingerprinting as a native X19 tool
- expose `x19 os <target>` in the plain control plane
- make the cognitive prompt explicitly recognize the native tool gateway
- add focused tests for OS fingerprinting and natural target routing
