---
name: innate-enforcer
description: Hardwired guardrail layer. Autonomic — refuses tool calls violating the 12 ship-with innate rules. v2.4 hosted-MCP variant — rule matching runs on server; wrapper renders red boxes.
---

## Preflight (MUST RUN BEFORE READING REST OF SKILL)

If `mcp__allostat-mcp__innate_enforcer_check` is not in your tool registry
for this session, STOP. Do not narrate what this skill "would" do. Tell
the operator: *"Allostat is degraded — the MCP server isn't registered
in this session. Re-run the installer from your install email link to
fix this."* Then end the turn. The capability described below is only
valid when the corresponding `mcp__allostat-mcp__*` tool is callable.

# Innate-enforcer pillar (v2.4 hosted MCP)

The innate-enforcer is Allostat's autonomic refusal layer. The 12
hardwired rules ship server-side as YAML; the wrapper calls
`innate_enforcer_check` with a signal_type + threshold (e.g.,
`usage_threshold_crossed` at 50000), and the server returns the
matching rule's red-box template body. The wrapper renders the red box
to the operator's session.

## Decision points

- `check_signal` — match a signal + threshold against the rule library;
  return `fire_red_box` + template body when matched, or `no_match`.
- `list_rules` — return rule metadata (id, name, severity) for diagnostic
  surfaces.

## The 12 rules

01-secrets-protection · 02-destructive-confirmation · 03-legacy-archival ·
04-canonical-verification · 05-handoff-checkpoints · 06-three-pass-workflow ·
07-memory-tree-hygiene · 08-purge-folder-lifecycle · 09-no-unprompted-sends ·
10-explicit-permissions · 11-workflow-gate-nudge ·
12-canonical-workspace-write-nudge.

θ migrates the YAML library to an MCP resource the wrapper can fetch;
until then the rules live as a snapshot in the server's `rules/innate/`
directory.

## Privacy

Server receives ONLY the signal_type + threshold. No prompt content, no
tool arguments. The full red-box template is server-emitted text; it's
not operator content.
