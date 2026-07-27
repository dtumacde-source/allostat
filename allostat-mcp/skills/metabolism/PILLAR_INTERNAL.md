---
name: metabolism
description: Metabolic regulation pillar. Autonomic — fires on token-threshold crossings, work-mode shifts, and baseline setpoint reviews. v2.4 hosted-MCP variant — token inference stays client-side; server aggregates signals + makes threshold/eviction decisions.
---

## Preflight (MUST RUN BEFORE READING REST OF SKILL)

If `mcp__allostat-mcp__metabolism_evaluate` is not in your tool registry for
this session, STOP. Do not narrate what this skill "would" do. Tell the
operator: *"Allostat is degraded — the MCP server isn't registered in
this session. Re-run the installer from your install email link to fix
this."* Then end the turn. The capability described below is only valid
when the corresponding `mcp__allostat-mcp__*` tool is callable.

# Metabolism pillar (v2.4 hosted MCP)

Token-budget regulation (insulin/glucagon + thyroid). Hybrid model:

- **Client-side (wrapper):** reads Claude's session cumulative-token
  count and decides when a threshold is crossed. Emits
  `pillar_signal_emitted` events to its local observation log.
- **Server-side:** aggregates the signals, computes baseline metabolic
  rate over the rolling 30-day window, infers work mode (deploy / deep /
  exploratory / normal), and decides whether a threshold crossing is
  meaningful enough to surface.

## Decision points (server-side)

- `compute_baseline` — rolling classifier (hyperactive / normal / hypoactive).
- `eviction_priority` — per-rule eviction score (tier base + boosts).
- `select_rules_to_evict` — N lowest-priority rules, never evicting innate.
- `context_pressure` — loaded count / ceiling fraction.
- `infer_work_mode` — last 30 events → 4-mode classifier.
- `threshold_meaningful` — token volume + baseline + work_mode → bool.
- `format_metabolic_status_line` — `/allostat-status` line.
- `compose_metabolism_nudge` — highest threshold crossed → nudge body.

## Privacy

Wrapper sends operational event types and signal-emission events
(timestamps + signal_type + threshold value). No prompt text, no
response text. Cumulative-token COUNT is sent in the question.details
when relevant.
