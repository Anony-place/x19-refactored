# Next runtime integration

1. Move cognitive state updates from the prompt adapter into the main agent loop.
2. Expose provider/model selection through machine-readable `--json` output.
3. Add provider-specific structured error classification and retry policy.
4. Give subagents the existing scoped X19 tool gateway rather than analysis-only chat.
5. Add bounded persistent USER/MEMORY files with secret filtering.
6. Keep the dashboard opt-in; never make it the default operator surface.
