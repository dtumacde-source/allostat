# Allostat MCP

Hosted-MCP wrapper plugin for [Claude Code](https://claude.com/claude-code). Routes hook events to the Allostat regulator at `mcp.allostat.ai` while keeping all operator memory client-side.

## What this gives you

After installation + Claude Code restart, Allostat runs silently in the background. When you return to a project with a recent handoff, the session opens already knowing where you left off — the wrapper auto-loads your last handoff into context and shows a one-line cue:

```
📋 Continuity: loaded last handoff (1.5h ago).
```

No "read the handoff" step — continuity just happens. (Genuine, actionable issues still surface as their own one-line cues, e.g. an auth-stale warning or an available update.)

Behind the cue: the wrapper fires hooks on each tool call, sends minimal excerpts (NOT full text content) to the regulator server, and surfaces back any guardrail or pattern-detection signals.

## Installation

The standard path is the one-click email link from your operator. If you're reading this from inside the bundle after a successful install, you're done — just restart Claude Code.

Manual install (for development or repair):

```powershell
# Windows PowerShell
.\install.ps1 -Code <16-char install code>

# Mac / Linux
bash install.sh <16-char install code>
```

The installer:

1. Detects Claude Code (`~/.claude/` must exist)
2. Resolves your install code to a bearer token + bundle URL
3. Downloads + SHA256-verifies the wrapper bundle
4. Copies the wrapper into `~/.claude/plugins/allostat-mcp/` + cache path
5. Sets `ALLOSTAT_MCP_TOKEN` as a user-scope env var
6. Registers the native MCP server in `.mcp.json`
7. Enables `allostat-mcp@local` in your `settings.json`
8. Runs a smoke test against `mcp.allostat.ai`
9. Prints success + restart instructions

## Configuration

### Required

| Env var | Purpose |
|---|---|
| `ALLOSTAT_MCP_TOKEN` | Bearer token. Installer sets this for you; you only need to know it exists in case you need to rotate it. |

### Optional

| Env var | Default | Purpose |
|---|---|---|
| `ALLOSTAT_MCP_ENDPOINT` | `https://mcp.allostat.ai/mcp` | Override the MCP endpoint (useful for local server testing). |
| `ALLOSTAT_HANDOFF_DIR` | auto-discovered | Override the handoff folder. Auto-discovery walks parent dirs of the session cwd and falls back to a home-relative default; set this only when your handoffs live somewhere off the beaten path. |
| `ALLOSTAT_DISABLED` | unset | Set to `1` to turn the wrapper off without uninstalling. Useful for differential debugging. |
| `ALLOSTAT_STATE_DIR_NAME` | `.allostat` | Override the per-project state-dir name (rarely needed). |

### Handoff folder — auto-discovered

The wrapper finds your session-end handoff folder in this order:

1. **`ALLOSTAT_HANDOFF_DIR`** env var, if you set one (override for non-standard layouts)
2. **Parent-dir walk** from your current working directory — looks for any ancestor with an `allostat_handoffs/` or `.allostat/handoffs/` subfolder
3. **Home-relative default** — `~/Desktop/Allostat/session_journals/allostat_handoffs/` on Windows, `~/Allostat/session_journals/allostat_handoffs/` on Mac/Linux. The installer creates this folder for you.

For most setups you don't need to set anything — auto-discovery covers the freshly-installed case. If your handoffs live somewhere else (e.g., a different drive), set the env var:

**Windows** (only if your handoffs aren't under `~/Desktop/Allostat/session_journals/`):
```powershell
[Environment]::SetEnvironmentVariable("ALLOSTAT_HANDOFF_DIR", "$env:USERPROFILE\path\to\your\handoffs", "User")
```

**Mac / Linux** (only if your handoffs aren't under `~/Allostat/session_journals/`):
```bash
export ALLOSTAT_HANDOFF_DIR="$HOME/path/to/your/handoffs"
```

Restart Claude Code after changing env vars for them to take effect.

## What you can do once installed

Slash commands (all start with `/`):

| Command | What it does |
|---|---|
| `/allostat status` | Shows current project's regulatory state — allostatic load, adaptivity, rule counts, last calibration. |
| `/allostat why-fired` | Lists which Allostat nudges fired this session and why. Useful for understanding what the regulator is doing on your behalf. |
| `/allostat tend` | Runs hygiene on the current project: archives aging files, validates canonical markers, sweeps purge candidates. |
| `/loadhandoff` | Lists recent handoffs (across `ALLOSTAT_HANDOFF_DIR` and project-relative folders) and loads the most recent into context. |

Full command list: 20 commands across `commands/*.md` in the bundle. Run `/allostat status` first to orient.

## Tips

The session-start banner includes a rotating tip from a curated catalog of ~90 tips covering memory hygiene, slash-command discovery, concept explainers (allostatic load, adaptivity, rule tiers, archipelago), and workflow patterns (sandboxing, _LEGACY archival, PURGE lifecycle, three-pass workflow).

Tips cycle with cooldown — you won't see the same tip twice within 7 days (or 14 days for some). Per-persona tagging exists in the catalog (coder, writer, webdev, data, marketing, admin, legal, support, product, edu) but session-start currently draws from the `general` pool; persona-routing for session-start activates in v2.5.

## Troubleshooting

**Banner doesn't show up**

1. Confirm Claude Code restarted after installation.
2. Check `~/.claude/settings.json` has `"allostat-mcp@local": true` under `enabledPlugins`.
3. Make sure a Python 3 interpreter is on PATH (`python3 --version` or
   `python --version`). Hooks run through `hooks/run_hook`, which resolves
   `python3` then `python`; if neither works, the session banner is replaced
   by a `[allostat] BROKEN INSTALL` notice naming the fix.
4. Run the session-start hook manually to see what it would emit
   (use `python` instead of `python3` on Windows):
   ```
   echo '{"hook_event_name":"SessionStart","session_id":"test","cwd":"."}' | python3 ~/.claude/plugins/allostat-mcp/hooks/session-start.py
   ```

**Server unreachable / 401 / 429**

The wrapper degrades silently when the server is unreachable — your Claude Code session continues to work, you just don't see pillar nudges. Check server health:

```bash
curl https://mcp.allostat.ai/healthz
```

If your bearer token gets rejected (401), email support to rotate. If you hit rate limits (429), you've made >30 requests per second OR >5000 per day; the default rate limits cover normal use, so 429s usually indicate runaway-loop code firing many hooks.

**Different project not surfacing tips**

The wrapper is project-aware. Make sure the project's `.allostat/` directory exists; if not, the wrapper falls back to silent mode for that project. Run `/allostat init <project-name>` to initialize.

**Nothing in the recent-handoff line**

Either `ALLOSTAT_HANDOFF_DIR` isn't set, or no handoff in that folder is under 48 hours old. The line silently omits in both cases — it's not an error.

## Support

For installation problems, configuration questions, or feature requests:

📧 **support@allostat.ai**

Please include:
- Your OS + Claude Code version
- The exact behavior you're seeing (or NOT seeing)
- Any error messages from `~/.claude/logs/` if relevant

## Architecture

The wrapper is a thin Streamable-HTTP MCP client. Operator memory stays on your filesystem (`<project>/.allostat/`). Your prompt is sent to the server only for in-the-moment regulation — held in memory while a decision is made, then released: **never written to disk, never logged as a body**. The server persists **no** operator content; its `request_log` schema forbids content columns, enforced by regression tests (`test_ram_only_invariant`, `test_no_operator_content_logged`) that fail if a future contributor adds one. The privacy moat is *never stored or logged server-side* — not *never transmitted* (see `docs/INVARIANTS.md` #1).

For developers: see `pyproject.toml` for dependencies (stdlib only — no httpx, no MCP SDK on the wrapper side). The lib/ modules are pure logic and unit-testable; hooks call into them via the standard Claude Code hook protocol.

---

**Allostat MCP — v0.1.0**
Built by Health Professions Data, LLC.
