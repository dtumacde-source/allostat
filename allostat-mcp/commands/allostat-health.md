---
name: allostat-health
description: System health check. Pillar firing status, memory tree state, silo state, banner state, error checks. "Is everything working?" command.
---

# /allostat-health

Operator-issued health check. Surfaces:

1. **Pillar firing status** — which pillars fired recently, which are silent, last-fire timestamps per pillar
2. **Memory tree state** — MEMORY.md present + non-empty, feedback/project/reference counts, last-write timestamps
3. **Silo state** — all 5 silos present (drift/voice/customization/workflow/confidence_recovery), entry counts per silo
4. **Banner state** — banner rendered correctly this session, no degraded-mode warnings
5. **Error checks** — recent hook errors, MCP connectivity, install validation state

Server-side slash command — calls these MCP tools and combines results:

1. `metabolism_evaluate` with `question_type=format_metabolic_status_line`
2. `stress_response_evaluate` with `question_type=compute_state_marker`
3. `hypothalamic_axis_route` with `question_type=recalibration_due`

Wrapper combines into a status block with health indicators per subsystem.

## Multi-project view

For an archipelago view across ALL registered projects (from
`~/.claude/.allostat/archipelago.json`):

```bash
python "$ALLOSTAT_PLUGIN_DIR/lib/memory_lifecycle.py" archipelago
```

Renders per-project state marker + rule counts + umbrella memberships.

## Health indicators

- ✅ **Healthy** — all subsystems firing, memory tree populated, no errors
- ⚠ **Degraded** — some pillars silent, partial memory tree, recoverable errors
- ❌ **Broken** — MCP not registered, banner not rendering, install validation failing → run `/allostat-fix`
