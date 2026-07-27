---
name: allostat
description: Allostat entry point + help. Lists active commands and pillar firing status.
---

# /allostat

## Subverb: `record-migration`

If invoked as `/allostat record-migration [note]` (or `record migration`),
do NOT print the help below. Instead record the migration so volume-control
stops nagging.

**Do not reference `${CLAUDE_PLUGIN_ROOT}` or `$ALLOSTAT_PLUGIN_DIR` here.**
`${CLAUDE_PLUGIN_ROOT}` only expands inside JSON hook/MCP configs, NOT in a
command doc's body text — it is a documented, open upstream bug
(anthropics/claude-code#9354) — and `$ALLOSTAT_PLUGIN_DIR` is never set in a
tool-spawned shell. Both collapse to an empty string, which resolves the
script path to a nonexistent drive-root path. Instead, run this to discover
the install and invoke it, entirely at runtime, no injected variable required:

<!-- rb8:record-migration-resolve:start -->
```bash
plugins_root="$HOME/.claude/plugins"
root=""
best=""
while IFS= read -r f; do
  vdir="$(dirname "$(dirname "$f")")"
  pdir="$(dirname "$vdir")"
  ver="$(basename "$vdir")"
  case "$ver" in ''|*[!0-9.]*) continue ;;   # skip non-numeric dirs (e.g. "unknown")
  esac
  [ "$(basename "$pdir")" = "allostat-mcp" ] || continue
  if [ -z "$best" ] || [ "$(printf '%s\n%s\n' "$best" "$ver" | sort -V | tail -1)" = "$ver" ]; then
    best="$ver"; root="$vdir"
  fi
done < <(find "$plugins_root" -type f -name "record_migration.py" 2>/dev/null)
if [ -z "$root" ]; then
  echo "allostat-mcp plugin (with record_migration.py) not found under $plugins_root" >&2
  exit 1
fi
python "$root/lib/record_migration.py" --note "<note>"
```
<!-- rb8:record-migration-resolve:end -->

(drop `--note "<note>"` if the operator gave no note). This searches the
standard Claude Code plugins tree (`$HOME/.claude/plugins`), finds every
installed `allostat-mcp` version that ships `record_migration.py`, and picks
the HIGHEST version by semantic-version sort (`sort -V`, not a lexical
sort — there can be multiple installed versions side by side, e.g.
`1.4.9` and `1.4.62`, and a lexical sort would wrongly rank `1.4.9` higher).
No marketplace name is hard-coded — it globs across whatever marketplace(s)
exist. Appends a `migration_recorded` event to the project's
`.allostat/observations.jsonl`.

After running it, confirm to the operator in one line that the migration is
recorded and the `topology_change_unrecorded` / `rollout_unrecorded` nudge
will clear on the next prompt.

This is the producer for the event volume-control waits on
(`detect_topology_change_unrecorded` / `detect_rollout_unrecorded`). Client-side
only — the event ships to the server in the normal dispatch excerpt; no server
change involved.

## Subverb: `update`

If invoked as `/allostat update` or `/allostat update now`, do NOT print the
help below. Update Allostat to the latest version using the credential already
on this machine — no install code needed.

**Do not reference `${CLAUDE_PLUGIN_ROOT}` or `$ALLOSTAT_PLUGIN_DIR` here**
(same reason as `record-migration` above — #9354, and the env var is never
set in a tool-spawned shell). Discover the install and invoke it at runtime
instead:

<!-- rb8:update-resolve:start -->
```powershell
$pluginsRoot = Join-Path $env:USERPROFILE ".claude\plugins"
$versionDirs = Get-ChildItem -Path $pluginsRoot -Recurse -Filter "allostat-update.ps1" -ErrorAction SilentlyContinue |
    ForEach-Object { $_.Directory.Parent } |
    Where-Object { $_.Parent.Name -eq "allostat-mcp" -and $_.Name -match '^\d+(\.\d+)*$' }
$root = $versionDirs | Sort-Object -Property @{Expression = { [version]$_.Name }} -Descending | Select-Object -First 1
if (-not $root) { throw "allostat-mcp plugin (with allostat-update.ps1) not found under $pluginsRoot" }
& (Join-Path $root.FullName "scripts\allostat-update.ps1")
```
<!-- rb8:update-resolve:end -->

This searches the standard Claude Code plugins tree
(`"$env:USERPROFILE\.claude\plugins"`), finds every installed `allostat-mcp`
version that ships `allostat-update.ps1`, and picks the HIGHEST version by
semantic-version sort (`[version]` cast compares components numerically, so
`1.4.62` correctly outranks `1.4.9` — a plain string/lexical sort would get
this backwards). No marketplace name is hard-coded — `-Recurse` globs across
whatever marketplace(s) exist. The resolved script downloads the current
installer and runs it in `-Refresh` mode (uses the saved `ALLOSTAT_MCP_TOKEN`
bearer against `/install/refresh`; verifies the bundle SHA; stages the new
version). It does NOT change the running session.

When it finishes, tell the operator to **fully quit and reopen Claude Code**
to load the new version (the version-skew banner will also remind them).

Windows-only for now (a Mac/Linux code-free update path is post-soft-launch).
Automatic background updates are NOT enabled — updating is this explicit command.

## Help (default — no recognized subverb)

Active commands (S2 surface):

- `/allostat-init` — first-run setup
- `/allostat-health` — system health check
- `/allostat-fix` — repair / re-scaffold / sync issues
- `/allostat-handoff-status` — handoff watchdog visibility
- `/allostat-prune` — memory tree pruning to cold storage; subverbs `preview` / `execute` / `restore`
- `/allostat-tend` — memory-tree hygiene umbrella (audit, retire, orphans, index rebuild, check-symlinks)
- `/allostat-promote` — review pending pattern-observer proposals; promote approved ones to learned rules
- `/allostat-manage-billing` — securely open the customer billing portal to manage or cancel a subscription
- `/allostat record-migration [note]` — record a topology/rollout migration to clear the volume-control nudge
- `/allostat update [now]` — update to the latest version using your saved credential (no install code; Windows)
- `/loadhandoff` — load a prior session handoff into context
- `/recall <keywords>` — search handoffs + pruning archives + pruning log

Autonomic pillars (no operator invocation; fire via hooks):
hypothalamic-axis, innate-enforcer, recall-silos, pattern-observer, voice-keeper, stress-response, metabolism, volume-control, onboarding-interview.

Retired commands from prior surfaces preserved at `commands/_RETIRED_*.md` for reference only.
