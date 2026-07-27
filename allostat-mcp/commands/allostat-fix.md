---
name: allostat-fix
description: Repair operations. Re-scaffold missing files, re-sync MEMORY.md, run repair-install, clear stale locks. The "something's broken, fix it" command.
---

# /allostat-fix

Operator-issued repair. Runs diagnostic + auto-repair across all Allostat subsystems.

## What it does

1. **Re-scaffold missing files** — runs first-run scaffolder logic; creates any missing Bucket B templates, sandbox folders, memory tree dir, MEMORY.md header, `_PURPOSE.md` template. **Does NOT overwrite existing files** (per `feedback_migration_never_destroys_existing_files.md`).

2. **Re-sync MEMORY.md index** — regenerates MEMORY.md index from on-disk feedback/project/reference files. Preserves operator-curated content; only updates the auto-generated index section.

3. **Run install repair** — invokes `repair-install.ps1` (Windows) or `repair-install.sh` (Mac/Linux) to verify plugin registry, MCP registration, bearer token, install_validation state.

4. **Clear stale locks** — removes any orphaned `.lock` files from prior crashed sessions (in `~/.allostat/`, `~/.claude/.allostat/`).

5. **Verify silo integrity** — checks all 5 silos (drift/voice/customization/workflow/confidence_recovery) are present and parseable. Creates empty silo files if absent.

6. **Verify archipelago.json** — creates empty `{}` if absent.

## When to use

Symptoms that warrant `/allostat-fix`:
- Banner not rendering
- Pillars silent that used to fire
- `/allostat-health` shows degraded or broken indicators
- MCP server connection errors
- Memory tree missing files that were there before
- Install validation state stuck at non-OK

## What it does NOT do

- Does NOT overwrite operator's existing content (memory files, preferences, appendices, sandboxes)
- Does NOT delete files (only adds missing structure)
- Does NOT modify operator's CLAUDE.md
- Does NOT trigger any prod-side or server-side actions
- Does NOT require operator-side credentials or config

## Output

Surfaces a per-subsystem report:

```
✅ Bucket B templates: 6/6 present (0 created)
✅ Memory tree: dir present, MEMORY.md present (re-synced 12 entries)
✅ Install repair: registry OK, MCP OK, bearer OK
⚠  Silos: 4/5 present (created empty confidence_recovery.jsonl)
✅ archipelago.json: present
```

If any step fails, surfaces error + manual-fix instructions (no silent failures).
