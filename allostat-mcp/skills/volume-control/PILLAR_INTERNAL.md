---
name: volume-control
description: Filesystem hygiene effector pillar. Autonomic — fires on writes, rollouts, LEGACY archival, and PURGE lifecycle. v2.4 hosted-MCP variant — server decides; wrapper applies (mv to _PURGE folder).
---

## Preflight (MUST RUN BEFORE READING REST OF SKILL)

If `mcp__allostat-mcp__volume_control_evaluate` is not in your tool registry
for this session, STOP. Do not narrate what this skill "would" do. Tell
the operator: *"Allostat is degraded — the MCP server isn't registered
in this session. Re-run the installer from your install email link to
fix this."* Then end the turn. The capability described below is only
valid when the corresponding `mcp__allostat-mcp__*` tool is callable.

# Volume-control pillar (v2.4 hosted MCP)

Filesystem hygiene gland (kidney axis). v2.4 hosts the decision logic
on the server: detect rollout-unrecorded, topology-change-unrecorded,
canonical-check-pending, legacy-aging conditions over the wrapper-
supplied observation slice + the wrapper's locally-aggregated
`_LEGACY_*` file count. Wrapper executes any `mv` operations
client-side.

## Decision points

- `detect_rollout_unrecorded` — rollout event without matching
  migration_recorded follow-up.
- `detect_topology_change_unrecorded` — topology_change_detected without
  matching migration_recorded.
- `detect_canonical_check_pending` — multi_folder_edit without
  canonical_verified.
- `should_nudge_legacy_aging` — wrapper-supplied file count ≥ 5.
- `compose_volume_control_nudge` — priority-ordered integrator.
- `decide_archive_targets` — server names which `_LEGACY_*` files the
  wrapper should `mv` to `_PURGE/` based on age + is_legacy flags.

## Privacy

Wrapper sends only event metadata (event type, timestamps) and
aggregated file counts. Filenames are NOT sent in bulk — only the
specific candidate paths the operator asks the server to evaluate for
archival (and even then, only the slug, not full path).
