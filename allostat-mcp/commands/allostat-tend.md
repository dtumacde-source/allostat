---
name: allostat-tend
description: Memory-tree hygiene umbrella. Drives the memory_lifecycle engine — audit, retire/retain rules, list/finalize retirement, find orphans, reorder/rebuild the index, merge candidates, audit tiers, and the check-symlinks Downloads-junction failsafe.
---

# /allostat-tend [verb] [args]

Umbrella command for memory-tree lifecycle hygiene. Every verb DRIVES the
engine at `lib/memory_lifecycle.py` — run the matching command below; do
not hand-edit the tree or hand-roll the audit.

General form:

```bash
python "$ALLOSTAT_PLUGIN_DIR/lib/memory_lifecycle.py" <verb> [memory_dir] [opts]
```

`memory_dir` is optional for the tree verbs — when omitted it resolves to
the active project's memory tree from cwd. Pass it explicitly when you are
not inside the target project. One verb (`check-symlinks`) operates on a
different state surface (filesystem roots) and takes no `memory_dir`.

Default (no verb / `/allostat-tend` alone): run `tend` — the audit report
below — and surface it.

## Verbs

### `tend` — hygiene audit (the default)

```bash
python "$ALLOSTAT_PLUGIN_DIR/lib/memory_lifecycle.py" tend [memory_dir] [--projects a,b] [--json]
```

Manual hygiene pass. Reports tier distribution of the tree, low-confidence
/ unknown-pattern files (tier-integrity issues), the retirement status of
every rule currently in the deprecation window, and the count of files
awaiting finalization. `--projects` is a comma-separated list of known
project names; `--json` emits machine-readable output.

### `retire <rule_id>` — start a rule's deprecation window

```bash
python "$ALLOSTAT_PLUGIN_DIR/lib/memory_lifecycle.py" retire <rule_id> [memory_dir] [--reason "..."]
```

Marks the rule (filename stem, e.g. `feedback_no_jargon`) as retiring. It
enters a 5-session deprecation window and is auto-finalized when the
counter reaches zero. Cancel with `retain`.

### `retain <rule_id>` — cancel a retirement

```bash
python "$ALLOSTAT_PLUGIN_DIR/lib/memory_lifecycle.py" retain <rule_id> [memory_dir]
```

Strips the retirement frontmatter so the rule stays active.

### `list` — show rules in the deprecation window

```bash
python "$ALLOSTAT_PLUGIN_DIR/lib/memory_lifecycle.py" list [memory_dir]
```

JSON list of every retiring rule with `sessions_remaining` and retrieval
priority multiplier.

### `finalize` — move counter-zero rules to `_RETIRED/`

```bash
python "$ALLOSTAT_PLUGIN_DIR/lib/memory_lifecycle.py" finalize [memory_dir]
```

Moves every `retirement_state=retired` file to `_RETIRED/<YYYYMMDD>/`.
Returns the list of finalized rule ids.

### `orphans` — find unindexed `.md` files

```bash
python "$ALLOSTAT_PLUGIN_DIR/lib/memory_lifecycle.py" orphans [memory_dir]
```

Lists `.md` files on disk that MEMORY.md does not link to (archive folders
and the index itself are skipped). Use before `rebuild-index` to see what
would get pulled in.

### `reorder <age|tier>` — re-sort MEMORY.md entries

```bash
python "$ALLOSTAT_PLUGIN_DIR/lib/memory_lifecycle.py" reorder age   [memory_dir]
python "$ALLOSTAT_PLUGIN_DIR/lib/memory_lifecycle.py" reorder tier  [memory_dir]
```

Rewrites the MEMORY.md entry list sorted oldest→newest (`age`) or grouped
by tier (`tier`). Writes a `.PRE_REORDER` backup first.

### `legacy <rule_id>` — operator-explicit LEGACY supersession

```bash
python "$ALLOSTAT_PLUGIN_DIR/lib/memory_lifecycle.py" legacy <rule_id> [memory_dir]
```

Moves the rule into `_LEGACY/` with the v2.3 naming convention. Use when
the operator explicitly supersedes a rule (vs. the timed `retire` path).

### `rebuild-index` — regenerate MEMORY.md from disk

```bash
python "$ALLOSTAT_PLUGIN_DIR/lib/memory_lifecycle.py" rebuild-index [memory_dir]
```

Regenerates MEMORY.md from the files on disk, preserving any hand-curated
hook already in the index and otherwise pulling each entry's one-line hook
from its frontmatter `description:` (or first prose line). Link targets are
emitted memory-tree-relative, so entries in subdirectories stay resolvable.
Cold storage (`_archived_*/`, `_LEGACY*/`, `_PURGE*/`, `_RETIRED*/`) and
`handoffs/` are skipped — a rebuild never resurrects a pruned file as a live
index entry. Writes a timestamped `MEMORY.md.PRE_REBUILD_<stamp>` backup
first (one per run, so a second rebuild cannot eat the first backup). Run
`orphans` first to preview.

### `merge-candidates` — surface near-duplicate files

```bash
python "$ALLOSTAT_PLUGIN_DIR/lib/memory_lifecycle.py" merge-candidates [memory_dir]
```

Reports pairs of files with high term-signature overlap that may be worth
merging. Advisory only — does not merge anything.

### `audit-tiers` — tier-integrity audit

```bash
python "$ALLOSTAT_PLUGIN_DIR/lib/memory_lifecycle.py" audit-tiers [memory_dir] [--projects a,b]
```

Runs the hierarchy validator: flags files whose frontmatter tier doesn't
match their inferred tier, plus files missing a tier. Exit code is nonzero
when the audit fails.

### `check-symlinks` — Downloads-junction failsafe

```bash
python "$ALLOSTAT_PLUGIN_DIR/lib/memory_lifecycle.py" check-symlinks
```

Scans the default roots for STALE symlinks / junctions — the failsafe for
the Windows `Downloads` Known-Folder junction (the redirect that points the
in-profile `Downloads` folder at a folder on another drive). That junction
has broken silently before, sending writes to a real, invisible folder back
on the system drive. Run this when deliverables seem to vanish or land in
the wrong place. Takes no `memory_dir` (it scans configured roots, not the
memory tree).

## Notes

- These verbs were orphaned before this command shipped: the engine
  existed at `lib/memory_lifecycle.py` but no slash command surfaced them.
- `tick` is a session-start internal (counter decrement) and is fired by
  the hook, not invoked here.
- `promote-candidates` is intentionally NOT exposed — that path is being
  removed.

Client-side only. No server round-trip.
