# X19 Terminal UI Polish Directive

The X19 terminal interface must be clean, restrained, fast, and operational.

Design direction:
- dark, minimal, modern terminal UI
- no hacker/Matrix/neon aesthetic
- no oversized ASCII art
- no decorative panels that consume useful terminal space
- no fake activity/progress
- no excessive borders
- no unnecessary animations
- no "cute" Hermes branding in X19 mode
- X19 branding should be subtle and professional

Use the existing Hermes TUI architecture. Do not create a second UI framework.

Primary surfaces:
- ui-tui/src/theme.ts
- ui-tui/src/components/appLayout.tsx
- ui-tui/src/components/messageLine.tsx
- ui-tui/src/components/branding.tsx
- ui-tui/src/components/agentsPanel.tsx
- ui-tui/src/components/agentsOverlay.tsx
- ui-tui/src/components/textInput.tsx
- ui-tui/src/components/streamingAssistant.tsx

Target presentation:

X19
────────────────────────────────────────────────────────

operator message
  response text...

  tool · recon · 2.4s
  tool · httpx · 1.1s

X19 status: ACTIVE  |  phase: RECON  |  agents: 3

────────────────────────────────────────────────────────
› input...

Requirements:
- messages are visually primary
- tool activity is compact and secondary
- status is one compact line
- input area is simple
- avoid large hero/banner/session panels in the normal chat view
- remove/disable Hermes-specific welcome/banner decoration in X19 mode
- keep overlays for agents, sessions, help, and settings
- make agent activity understandable without turning the main transcript into a dashboard
- preserve scrolling, streaming, keyboard shortcuts, slash commands, approvals, tool output, and accessibility
- preserve light/dark compatibility, but X19 default should be dark
- maintain readable contrast
- terminal width must gracefully collapse without horizontal clutter
- no fake sample data

Do not redesign the entire Hermes TUI. Apply a focused X19 skin/layout layer.

Before modifying code:
1. trace which components actually render the standard X19 chat view;
2. determine whether a skin/branding mechanism can provide the changes;
3. prefer configuration/theme/skin changes over duplicated components;
4. only edit layout components where the current Hermes structure prevents the desired X19 presentation.

Validation:
- run the TUI build/typecheck/tests
- start the TUI in a real terminal
- verify a real operator message, streaming response, tool activity and input
- verify agent overlay still works
- verify no mock data was introduced
