# Petdex — Animated Pet Mascots

Browse, install, and select animated "pet" mascots from the public
[petdex](https://github.com/crafter-station/petdex) gallery. An installed pet
reacts to agent activity (idle, running a tool, reviewing, error, done) across
the X19 CLI, TUI, and desktop app. This skill drives the `x19 pets` CLI
and the `display.pet` config — it does not generate sprites.

## When to Use

- The user wants a desktop/terminal mascot or asks about "pets" / petdex.
- The user wants to change, preview, or disable the active pet.
- Diagnosing why a pet isn't showing (terminal graphics support, config).

## Prerequisites

- Network access to `petdex.dev` for the gallery/manifest (read-only, no auth).
- Pillow (a core X19 dependency) for sprite decoding — already installed.
- For full-fidelity terminal rendering: a graphics-capable terminal (kitty,
  Ghostty, WezTerm, iTerm2, or sixel). Otherwise a truecolor Unicode
  half-block fallback is used automatically.

## How to Run

Use the `terminal` tool to run `x19 pets <subcommand>`.

## Quick Reference

| Goal | Command |
| --- | --- |
| Browse the gallery | `x19 pets list` (add a substring to filter: `x19 pets list cat`) |
| List installed pets | `x19 pets list --installed` |
| Install a pet | `x19 pets install <slug>` (add `--select` to make it active) |
| Set the active pet | `x19 pets select <slug>` (omit slug for a picker) |
| Resize the pet everywhere | `x19 pets scale <factor>` (e.g. `0.5`, clamped 0.1–3.0) |
| Preview/animate in terminal | `x19 pets show [slug] [--cycle] [--state run]` |
| Disable the pet | `x19 pets off` |
| Remove a pet | `x19 pets remove <slug>` |
| Diagnose setup | `x19 pets doctor` |

## Procedure

1. Find a pet: `x19 pets list <query>` and note its `slug`.
2. Install + activate: `x19 pets install <slug> --select`.
3. Preview it: `x19 pets show` (Ctrl+C to stop).
4. Confirm setup: `x19 pets doctor` — shows the resolved pet, configured
   render mode, detected terminal graphics protocol, and effective mode.

Pets install into `<X19_HOME>/pets/<slug>/` (profile-aware). Selecting a pet
writes `display.pet.slug` + `display.pet.enabled` to `config.yaml`.

## Configuration

Under `display.pet` in `config.yaml`:

- `enabled` (bool) — master on/off.
- `slug` (str) — active pet; empty = first installed.
- `render_mode` — `auto` (detect) | `kitty` | `iterm` | `sixel` | `unicode` | `off`.
- `scale` (float) — on-screen size of the native 192×208 frames (default 0.33,
  clamped 0.1–3.0). One knob resizes every surface; set it with
  `x19 pets scale <factor>`, the `/pet scale` slash command, or the desktop
  Appearance slider.
- `unicode_cols` (int) — width in columns for the Unicode fallback.

## Pitfalls

- A pet only shows once one is installed AND selected (`enabled: true`).
- Inside a pipe/redirect (no TTY) terminal rendering is disabled by design.
- The petdex npm CLI installs to `~/.codex/pets`; X19 uses its own
  profile-scoped `<X19_HOME>/pets/` instead — install through `x19 pets`.

## Verification

- `x19 pets doctor` reports `✓ ready` when a pet is installed, selected,
  enabled, and Pillow is importable.
