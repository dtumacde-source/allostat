---
name: onboarding-interview
description: Imprinting layer. Autonomic — fires on /allostat-init, 90-day re-cal, or drift detection across 3+ topics. v2.4 hosted-MCP variant — question bank served as MCP resource; calibration prefill + architecture audit run CLIENT-SIDE; wrapper runs the interview state machine.
---

## Preflight (MUST RUN BEFORE READING REST OF SKILL)

If `mcp__allostat-mcp__onboarding_interview_evaluate` is not in your tool
registry for this session, STOP. Do not narrate what this skill "would"
do. Tell the operator: *"Allostat is degraded — the MCP server isn't
registered in this session. Re-run the installer from your install
email link to fix this."* Then end the turn. The capability described
below is only valid when the corresponding `mcp__allostat-mcp__*` tool is
callable.

# Onboarding-interview pillar (v2.4 hosted MCP)

The v2.4 wrapper runs the interview loop locally — it walks the operator
through behavioral-calibration questions, voice capture, and
architecture audit. The QUESTIONS themselves live server-side as the
`allostat://question-bank/calibration` MCP resource; the wrapper fetches
once at the start of `/allostat-init` (which runs the interview + calibration).

## Decision points (client-side)

Privacy retirement (AUDIT-D25 2026-05-24 + AUDIT-D37): the raw-content
server APIs below were retired because they accepted operator memory /
CLAUDE.md text over the wire. The server tools are **permanently inert**
(return `raw_content_refused`) and kept only for surface compatibility —
do NOT call them. The equivalent work now runs entirely client-side in
the wrapper.

- Calibration prefill — the wrapper scans the operator's existing
  CLAUDE.md / memory files **locally** to pre-fill answers from
  detectable patterns (the "dogfood lesson" — turns a 10-minute
  interview into a 30-second confirmation exchange). The former
  `precompute_calibration_answers` server call is inert.
- Architecture audit — tier classification and cross-cutting-feedback
  flagging run **locally** over the operator's rule sources. The former
  `audit_architecture` server call is inert.
- `generate_optimization_proposals` — convert local audit findings into
  concrete `promote-to-innate` proposals (proposals carry no raw operator
  content; safe to compute wherever the audit ran).

## Privacy

Raw operator content (CLAUDE.md / memory text) is **never** sent to the
server during onboarding. The wrapper fetches only the question bank
(`allostat://question-bank/calibration`) as an MCP resource; all scanning,
prefill, and architecture audit happen client-side. The resulting
imprinted-rules YAML is written to `.allostat/imprinted/` client-side —
the server never holds operator state. See `commands/allostat-init.md`
for the operator-facing contract.
