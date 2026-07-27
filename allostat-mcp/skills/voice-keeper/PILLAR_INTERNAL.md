---
name: voice-keeper
description: Voice fidelity cell. Autonomic — fires when producing operator-facing text and a *_prose.md / *_voice.md reference exists. v2.4 hosted-MCP variant — marker scans + nudge composer run on the server.
---

## Preflight (MUST RUN BEFORE READING REST OF SKILL)

If `mcp__allostat-mcp__voice_keeper_evaluate` is not in your tool registry
for this session, STOP. Do not narrate what this skill "would" do. Tell
the operator: *"Allostat is degraded — the MCP server isn't registered
in this session. Re-run the installer from your install email link to
fix this."* Then end the turn. The capability described below is only
valid when the corresponding `mcp__allostat-mcp__*` tool is callable.

# Voice-keeper pillar (v2.4 hosted MCP)

Heuristic voice-fidelity evaluation against the operator's voice
reference (e.g., `operator_prose.md` or `voice_reference.md`). BOTH the
voice reference AND the candidate text stay client-side: the autonomic
path evaluates locally via `lib/voice_keeper_local.py` (AI-slop, hedge,
corporate-boilerplate, banned-term markers + em-dash + passive-voice
ratios). Candidate text is NOT auto-transmitted to the server for
autonomic evaluation — the earlier "wrapper sends candidate text to
`voice_keeper_evaluate`" description was wrong (ultraswarm M-14,
2026-07-07); it overstated egress relative to the local-only path the
code runs.

## Decision points

- `evaluate_voice` — AI-slop / hedge / corporate / banned-term marker
  scan + em-dash and passive-voice ratio checks.
- `compose_voice_nudge` — priority-ordered nudge (sycophancy > ai_slop >
  cumulative_drift) over recent violation events.
- `format_eval_surface` — render an eval result as operator-facing text.

## Privacy

Operator's voice reference file (e.g., `operator_prose.md` or
`voice_reference.md`) lives client-side in the operator's memory tree
and is NEVER sent to the server. The wrapper sends candidate text to
evaluate, but only when the operator explicitly invokes voice
evaluation (e.g., via a wrapper-internal pre-publish check).
