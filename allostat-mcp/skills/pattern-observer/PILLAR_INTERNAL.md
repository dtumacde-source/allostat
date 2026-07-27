---
name: pattern-observer
description: Learning layer (Pro tier). Autonomic — proposes rule promotions when N=4 cross-session (N=2 in-session) same-pattern occurrences in observations log. Free tier observes only. v2.4 hosted-MCP variant — fingerprinting + counting + contradiction reset all run on the server.
---

## Preflight (MUST RUN BEFORE READING REST OF SKILL)

If `mcp__allostat-mcp__pattern_observer_evaluate` is not in your tool registry
for this session, STOP. Do not narrate what this skill "would" do. Tell
the operator: *"Allostat is degraded — the MCP server isn't registered
in this session. Re-run the installer from your install email link to
fix this."* Then end the turn. The capability described below is only
valid when the corresponding `mcp__allostat-mcp__*` tool is callable.

# Pattern-observer pillar (v2.4 hosted MCP)

Detects when the operator's behavior pattern crosses N=4 occurrences
across sessions, with contradiction reset (opposite direction zeros both
counters), and surfaces a learned-rule promotion proposal. v2.4 wrapper
sends the rolling observation buffer; server returns proposals. Geometric
ladder: N=2 in-session fast lane → N=2²=4 cross-session.

## Decision points

- `detect_proposals` — N=4 cross-session patterns (with contradiction
  reset), default threshold 4.
- `detect_in_session_overrides` — N=2 same-session override fast-promotion
  lane (no contradiction reset — operator chose this direction
  explicitly).
- `fingerprint_event` — compute one event's fingerprint hash.
- `format_proposal_surface` — render operator-facing proposal text.

## Privacy

Wrapper sends observation events with `details.subject` /
`details.operator_language` for fingerprint construction. The full
prompt text and Claude response text are NOT included. Server returns
proposal fingerprints + suggested rule wording; operator approves
via `/allostat-promote`.
