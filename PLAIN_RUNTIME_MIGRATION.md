# Plain runtime migration

The default `run.py` path no longer opens the full-screen workspace.

Use:

```text
x19
x19 setup
x19 provider list
x19 provider discover groq
x19 provider test groq
x19 provider use groq --model llama-3.3-70b-versatile
x19 run -t <target>
```

`x19 dash ...` remains an explicit opt-in for the existing live dashboard.
