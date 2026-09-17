# Security-agent patterns tracked for X19

This document records architecture patterns observed in public projects reviewed for X19. It is a design reference, not copied implementation code.

## CyberStrike

Key pattern: terminal-native TUI plus a large skill registry spanning established security frameworks. X19 should keep the terminal as the primary operator surface and expose skill/capability discovery without turning the UI into a dashboard.

## Pentest Copilot

Key patterns: explicit target/scope intake, autonomous tool loop, tool installation/capability registry, subagent coordination, browser automation, and multiple execution-consent modes. X19 should preserve its deterministic scope gate while making execution mode and agent activity visible in the terminal.

## Shannon

Key patterns: source-aware analysis before dynamic testing, parallel vulnerability analysis, exploit-proof requirement, resumable workspaces, authenticated testing, and CI/report integrations. X19 should connect its world model, coverage matrix, and finding verification into one resumable evidence graph; a speculative candidate must remain distinct from a proven finding.

## HackSynth

Key patterns: explicit planner/summarizer separation and benchmark-oriented evaluation of autonomous penetration-testing agents. X19 should retain compacted execution context and add repeatable evaluation fixtures for decision quality, loop avoidance, and evidence-to-finding correctness.

## pentest-ai-agents

Key patterns: specialist subagents organized by security domain, including recon, web, AD, cloud, mobile, wireless, payloads, exploitation, detection, forensics, and reporting. X19 should represent specialist capabilities as metadata-driven skills that can be delegated by the canonical decision engine rather than hard-coded attack sequences.

## X19 design rule

Borrow interfaces and architecture patterns, not payload recipes. Keep all execution behind the existing authorization/policy boundary. The terminal should show real state: target, provider, status, current objective, recent decision, tool activity, coverage, findings, and stop controls.
