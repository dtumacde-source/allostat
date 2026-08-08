---
name: allostat-forget
description: Retract something from memory — purges every store Allostat can reach and reports, per store, what it removed and what it could not. Preview by default.
---

# /allostat-forget

Remove a fact from Allostat's memory and say honestly where it went.

## Why this exists

"Forget X" used to delete the memory file, report success, and leave the same
text sitting verbatim in the observation log and the audit files. That is not a
deletion. `Custody and Constraint` (2026-07-31) requires the record be held in
storage you "can read in full, can amend, and can destroy" — so a command that
claims destruction has to deliver it, or say precisely where it fell short.

## Usage

```
/allostat-forget <text>              # preview: shows what WOULD be removed, changes nothing
/allostat-forget <text> --execute    # actually remove it
/allostat-forget <text> --regex      # treat <text> as a regular expression
```

Preview is the default deliberately. A deletion is not reversible and you are
entitled to see its blast radius first.

## What it reaches

Every store is listed in the report, whether or not it held anything:

- the memory tree, including cold storage and `_processed/` derivatives
- the `MEMORY.md` index and the harness-side mirror of it
- session handoffs
- the observation log, nudge history, pending surfaces, server-instructed writes
- local silos and canonical resolutions
- audit files
- rotated `.jsonl.gz` archives of any of the above

Each store reports what was removed, rewritten, or deleted — and every store is
re-read afterwards. A store that still matches is reported as **STILL PRESENT**,
not as done.

## What it does NOT reach, and says so every time

- **Claude Code's own session transcripts.** They belong to the harness, not to
  Allostat, and your 10-year retention rule governs them. Purging those is a
  decision about the harness, made deliberately — not a side effect of this
  command.
- **Server-side silos**, until the 0.2.9 purge endpoint is deployed. Reported as
  queued, never as forgotten.

## Accountability

Every execution appends a line to `.allostat/retraction_log.jsonl` recording
when it ran, what pattern, and the per-store counts — not the removed content.
A deletion nobody can account for is its own custody problem.
