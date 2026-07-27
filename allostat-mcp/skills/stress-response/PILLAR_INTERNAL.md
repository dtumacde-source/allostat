---
name: stress-response
description: Anomaly cascade pillar. Autonomic — fires on threat-class events (repeated tool failures, contradictions, allostatic-load thresholds, operator distress). v2.4 hosted-MCP variant — drift detection, sensitization, KISS family, and nudge composer run on the server.
---

## Preflight (MUST RUN BEFORE READING REST OF SKILL)

If `mcp__allostat-mcp__stress_response_evaluate` is not in your tool registry
for this session, STOP. Do not narrate what this skill "would" do. Tell
the operator: *"Allostat is degraded — the MCP server isn't registered
in this session. Re-run the installer from your install email link to
fix this."* Then end the turn. The capability described below is only
valid when the corresponding `mcp__allostat-mcp__*` tool is callable.

# Stress-response pillar (v2.4 hosted MCP)

The stress-response pillar fires when threat patterns appear in the
operator's recent observations. The v2.4 wrapper sends the local
observation tail to the server's `stress_response_evaluate` MCP tool;
the server classifies threats, detects drift recurrence, runs the KISS
overcomplication detector, and returns a nudge if one fires.

## Decision points

- `drift_check` — classify observations by THREAT_SEVERITIES; return
  highest severity + cascade-pathway decision.
- `should_fire_cascade` — given severity, return (fast, slow) pathway.
- `detect_repeated_tool_failure` — same-operation failures ≥N synthesize
  a `tool_failure_repeated` threat.
- `compute_thriving_signal` — eustress detection over rolling 7-day window.
- `check_recovery` — N events since last threat → recovered.
- `detect_chronic_stress` — threats > N in 30 days → chronic.
- `compute_state_marker` — avatar state from current stress state.
- `detect_drift_recurrence` — sensitization (PATCH-087 / PATCH-095 /
  PATCH-048-salience-suppression all preserved).
- `detect_idle_resumption` — gap > 30 min since last event.
- `detect_kiss_drift` — overcomplication (plan_too_granular /
  too_many_edits / doc_for_tactical_work). too_many_new_files retired
  2026-07-04 (over-fired noise).
- `detect_completion_unverified` — completion claim without verification.
- `compose_stress_nudge` — integrator; priority-ordered cascade.

All decisions ported verbatim from v2.3 plugin
(plugin/lib/stress_response_runtime.py).

## Privacy

Wrapper sends recent observations as small metadata dicts (timestamp +
event type + non-content details). Operator prompt text and Claude
response text are NEVER included in the excerpt.
