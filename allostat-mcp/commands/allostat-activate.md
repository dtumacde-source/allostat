---
name: allostat-activate
description: Activate your Allostat subscription. Exchanges a one-time install code for your access token and sets it up so the plugin can connect. Use after installing from the plugin marketplace.
argument-hint: <install-code>
---

# /allostat-activate

Activates an Allostat subscription for a plugin-marketplace install.

When Allostat is installed from the Claude Code plugin marketplace, the plugin
code is present but not yet connected to the regulator server — it needs the
subscriber's access token. This command performs that one-step activation:
it exchanges the operator's one-time install code for their token and persists
it so the plugin's MCP connection can authenticate.

## What it does

Runs the activation helper with the code the operator supplied as `$ARGUMENTS`.

**Do not reference `${CLAUDE_PLUGIN_ROOT}` or `$ALLOSTAT_PLUGIN_DIR` here.**
`${CLAUDE_PLUGIN_ROOT}` only expands inside JSON hook/MCP configs, NOT in a
command doc's body text — it is a documented, open upstream bug
(anthropics/claude-code#9354) — and `$ALLOSTAT_PLUGIN_DIR` is never set in a
tool-spawned shell. Both collapse to an empty string, which resolves the
script path to a nonexistent drive-root path. Instead, run this to discover
the install and invoke it, entirely at runtime, no injected variable required
(same pattern as `/allostat record-migration`, RB-8 / #9354):

<!-- rb9:activate-resolve:start -->
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
done < <(find "$plugins_root" -type f -name "activate.py" 2>/dev/null)
if [ -z "$root" ]; then
  echo "allostat-mcp plugin (with activate.py) not found under $plugins_root" >&2
  exit 1
fi
python "$root/lib/activate.py" $ARGUMENTS
```
<!-- rb9:activate-resolve:end -->

This searches the standard Claude Code plugins tree (`$HOME/.claude/plugins`),
finds every installed `allostat-mcp` version that ships `activate.py`, and
picks the HIGHEST version by semantic-version sort (`sort -V`, not a lexical
sort — there can be multiple installed versions side by side, e.g. `1.4.9`
and `1.4.62`, and a lexical sort would wrongly rank `1.4.9` higher). No
marketplace name is hard-coded — it globs across whatever marketplace(s)
exist.

The helper:
1. Sends the code to `https://mcp.allostat.ai/install/resolve` and receives the
   subscriber bearer token. (This consumes the one-time code and rotates the
   bearer server-side — it is single-use.)
2. Saves the token to a persistent User-scope environment variable
   `ALLOSTAT_MCP_TOKEN` (on Windows via the registry, never `setx`; on
   macOS/Linux it prints the one line to add to your shell profile).
3. Writes a recovery copy of the token to `<wrapper>/.env` (resolved from
   `activate.py`'s own file location, not any injected variable — it prefers
   `CLAUDE_PLUGIN_ROOT` only as a same-process convenience when that variable
   happens to be non-empty, and otherwise falls back to
   `Path(__file__).resolve().parent.parent`).

## After activation

Tell the operator, in plain language: **fully quit and reopen Claude Code.**
The MCP connection reads the environment only at launch, so a running instance
won't see the new token until it restarts. After the restart, Allostat connects
and begins regulating.

## If no code was given

If `$ARGUMENTS` is empty, ask the operator for their install code (it arrived in
their Allostat welcome email), then run the helper with it. Do not invent a code.

## If activation fails

The helper prints the reason (code expired after 24h, already used, invalid, or
no network). Relay it plainly and, for an expired/used code, tell the operator to
request a fresh install code.
