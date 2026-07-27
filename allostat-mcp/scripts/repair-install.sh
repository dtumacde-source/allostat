#!/usr/bin/env bash
# repair-install.sh -- In-place repair for degraded Allostat MCP install
# (Linux/Mac). PATCH-103.
#
# SCOPE: Config drift on a successful install.
# INCOMPLETE INSTALLS (H-07, 2026-07-14): an install that CONSUMED its one-time
#   code but failed before the plugin finished extracting/wiring leaves a saved
#   recovery bearer in $WRAPPER_DIR/.env but no runnable plugin. Such installs
#   are no longer dead-ended here — they're routed to the code-free
#   `install.sh --refresh` recovery (which reuses that saved bearer). Config
#   drift on a fully-installed plugin is still repaired in place below.
#
# What it does (idempotent):
#   - Rewrites marketplace.json to canonical shape
#   - Rewrites .mcp.json without MCP-Protocol-Version
#   - Corrects installed_plugins.json "unknown" entries
#   - Re-runs `claude mcp remove + add --scope user` with stored bearer
#   - Runs 4-layer validation
#
# Usage:
#   bash ~/.claude/plugins/marketplaces/local/allostat-mcp/scripts/repair-install.sh

set -euo pipefail

# PATCH-106 (POSIX parity): the plugin is deployed INSIDE the local marketplace
# at ~/.claude/plugins/marketplaces/local/allostat-mcp/ (parity with the Windows
# Get-PluginRoot), so the bare-string marketplace source "./allostat-mcp"
# resolves against the marketplace root. This repair script ships inside that
# dir, so the default targets it directly.
WRAPPER_DIR="${WRAPPER_DIR:-$HOME/.claude/plugins/marketplaces/local/allostat-mcp}"
CLAUDE_DIR="${CLAUDE_DIR:-$HOME/.claude}"
SERVER_BASE="${ALLOSTAT_MCP_ENDPOINT_BASE:-https://mcp.allostat.ai}"
INSTALLER_BASE="${ALLOSTAT_INSTALLER_BASE_URL:-https://installer.allostat.ai}"

RESET="$(printf '\033[0m')"
CYAN="$(printf '\033[36m')"
GREEN="$(printf '\033[32m')"
YELLOW="$(printf '\033[33m')"
RED="$(printf '\033[31m')"

step() { printf "%s==> %s%s\n" "$CYAN" "$1" "$RESET"; }
ok()   { printf "%s[ok] %s%s\n"  "$GREEN" "$1" "$RESET"; }
warn() { printf "%s[warn] %s%s\n" "$YELLOW" "$1" "$RESET"; }
err()  { printf "%s[error] %s%s\n" "$RED" "$1" "$RESET"; }

step "Allostat MCP repair script (PATCH-103)"
echo

if [ ! -d "$WRAPPER_DIR" ]; then
    err "Allostat MCP plugin dir not found at $WRAPPER_DIR."
    echo "Repair script fixes a degraded install; there's nothing to repair here."
    echo "Run the full installer from your install email link."
    exit 1
fi

PLUGIN_JSON="$WRAPPER_DIR/plugin.json"
VERSION="unknown"
if [ -f "$PLUGIN_JSON" ]; then
    VERSION=$(python3 -c "import json; print(json.load(open('$PLUGIN_JSON')).get('version','unknown'))" 2>/dev/null || echo "unknown")
fi
ok "Plugin install detected at $WRAPPER_DIR (version $VERSION)"

CLAUDE_EXE="$(command -v claude || true)"
if [ -z "$CLAUDE_EXE" ]; then
    err "claude CLI not found on PATH."
    exit 1
fi
ok "claude CLI detected: $CLAUDE_EXE"

ENV_FILE="$WRAPPER_DIR/.env"
BEARER=""
if [ -f "$ENV_FILE" ]; then
    BEARER=$(grep '^ALLOSTAT_MCP_TOKEN=' "$ENV_FILE" | head -n 1 | cut -d= -f2- | tr -d '\r\n')
fi
if [ -z "$BEARER" ]; then
    err "No bearer token found in $ENV_FILE."
    echo "Re-run the full installer from your install email link."
    exit 1
fi
ok "Bearer read from .env backup"

# H-07 (2026-07-14): incomplete-install detection. A saved bearer with no
# runnable plugin (hooks/hooks.json absent) means the install failed after
# consuming its code but before extract/wire finished. In-place config repair
# below assumes an extracted plugin, so it would fail here. Route to the
# code-free `install.sh --refresh` recovery instead of dead-ending — it reuses
# this saved bearer to re-fetch + re-wire, no new install code required.
if [ ! -f "$WRAPPER_DIR/hooks/hooks.json" ]; then
    warn "Incomplete install: a recovery credential is present but the plugin is"
    warn "not fully installed (missing $WRAPPER_DIR/hooks/hooks.json)."
    echo
    echo "Recover WITHOUT a new install code by re-running the installer with --refresh:"
    case "$(uname -s 2>/dev/null)" in
        Darwin) echo "  curl -fsSL $INSTALLER_BASE/install/mac/install.sh   | bash -s -- --refresh" ;;
        *)      echo "  curl -fsSL $INSTALLER_BASE/install/linux/install.sh | bash -s -- --refresh" ;;
    esac
    echo "(This reuses the saved bearer in $ENV_FILE — no new code needed.)"
    exit 0
fi

# Step 1: Rewrite marketplace.json
MARKETPLACE_DIR="$CLAUDE_DIR/plugins/marketplaces/local/.claude-plugin"
MARKETPLACE_MANIFEST="$MARKETPLACE_DIR/marketplace.json"
mkdir -p "$MARKETPLACE_DIR"

step "Rewriting marketplace.json (upsert; preserves co-resident plugins)..."
VERSION="$VERSION" \
python3 - "$MARKETPLACE_MANIFEST" <<'PY'
import json, os, sys, time
path = sys.argv[1]
# ultraswarm (2026-07-07): UPSERT, don't clobber. Pre-fix this rewrote
# marketplace.json wholesale (dropping co-resident third-party plugins —
# invariant #4) and re-appended the legacy v2.3 `allostat` entry PATCH-106
# deliberately removed. Now: preserve top-level metadata + all UNRELATED
# plugins, upsert only allostat-mcp, drop the legacy `allostat` entry, and back
# up before writing.
#
# PATCH-106 (ultraswarm CRITICAL, fixed 2026-07-07): the `source` is the BARE
# STRING "./allostat-mcp" relative to the marketplace root, NOT the object form
# {type:"local", path:<abs>}. Claude Code's plugin-loader schema rejects the
# object form for a local plugin, so a "repaired" install would fail Layer 1
# (plugin not loaded) — repair made it worse, not better. The .sh installers
# now deploy the plugin at <marketplace>/allostat-mcp/ so the bare string
# resolves against the marketplace root.
allostat_entry = {
    "name": "allostat-mcp",
    "description": "Hosted-MCP wrapper for Allostat.",
    "source": "./allostat-mcp",
    "version": os.environ["VERSION"],
}
name = "local"
description = "Local plugin marketplace for Allostat."
owner = {"name": "Allostat", "email": "support@allostat.ai"}
others = []
if os.path.exists(path):
    try:
        with open(path) as f:
            existing = json.load(f)
        name = existing.get("name", name)
        description = existing.get("description", description)
        owner = existing.get("owner", owner)
        others = [p for p in existing.get("plugins", [])
                  if isinstance(p, dict) and p.get("name") not in ("allostat-mcp", "allostat")]
        import shutil
        shutil.copy2(path, path + "." + time.strftime("%Y%m%dT%H%M%S") + ".bak")
    except Exception:
        others = []
marketplace = {
    "name": name,
    "description": description,
    "owner": owner,
    "plugins": others + [allostat_entry],
}
with open(path, "w") as f:
    json.dump(marketplace, f, indent=2)
PY
ok "marketplace.json rewritten (upsert)"

# Step 2: Rewrite .mcp.json without MCP-Protocol-Version
step "Rewriting .mcp.json (no MCP-Protocol-Version header)..."
mode_of() {
    stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1" 2>/dev/null
}
MCP_JSON="$WRAPPER_DIR/.mcp.json"
MCP_TMP="$(mktemp "${MCP_JSON}.tmp.XXXXXX")" || {
    err "Could not create protected temporary .mcp.json."
    exit 1
}
if ! SERVER_BASE="$SERVER_BASE" VERSION="$VERSION" BEARER="$BEARER" MCP_JSON="$MCP_TMP" python3 - <<'PY'
import json, os
# ITEM C (2026-05-29): write the RESOLVED bearer, not the literal
# "${ALLOSTAT_MCP_TOKEN}" placeholder. Claude Code does NOT reliably expand
# ${VAR} in .mcp.json header values (the lesson PATCH-122 established for the
# .ps1 path); the placeholder produced a non-functional bearer on .sh repairs.
# $BEARER is already read from .env at the top of this script + used for the
# `claude mcp add` step — use the same value here.
with open(os.environ["MCP_JSON"], "w") as f:
    json.dump({
        "allostat-mcp": {
            "type": "http",
            "url": f"{os.environ['SERVER_BASE']}/mcp",
            "headers": {
                "Authorization": f"Bearer {os.environ['BEARER']}",
                "Accept": "application/json, text/event-stream",
                "Content-Type": "application/json",
                "User-Agent": f"allostat-mcp-wrapper/{os.environ['VERSION']} (+https://allostat.ai)",
            },
        }
    }, f, indent=2)
PY
then
    rm -f "$MCP_TMP"
    err "Could not render protected .mcp.json."
    exit 1
fi
if ! chmod 600 "$MCP_TMP" 2>/dev/null; then
    rm -f "$MCP_TMP"
    err "Could not set owner-only permissions on .mcp.json; credential not installed."
    exit 1
fi
MCP_MODE="$(mode_of "$MCP_TMP")"
if [ "$MCP_MODE" != "600" ]; then
    rm -f "$MCP_TMP"
    err ".mcp.json temporary mode is ${MCP_MODE:-unknown}, expected 600; credential not installed."
    exit 1
fi
if ! mv -f "$MCP_TMP" "$MCP_JSON"; then
    rm -f "$MCP_TMP"
    err "Could not atomically install protected .mcp.json."
    exit 1
fi

# .env also carries the live bearer. Repair must not report success unless its
# existing recovery credential is verifiably owner-only.
if ! chmod 600 "$ENV_FILE" 2>/dev/null || [ "$(mode_of "$ENV_FILE")" != "600" ]; then
    err "Could not verify owner-only permissions on .env; rotate the credential."
    exit 1
fi
ok ".mcp.json rewritten"

# Step 3: Correct installed_plugins.json
IP_PATH="$CLAUDE_DIR/plugins/installed_plugins.json"
if [ -f "$IP_PATH" ]; then
    step "Correcting installed_plugins.json (if 'unknown' entries present)..."
    IP_PATH="$IP_PATH" VERSION="$VERSION" WRAPPER_DIR="$WRAPPER_DIR" python3 - <<'PY'
import json, os, datetime
path = os.environ["IP_PATH"]
try:
    with open(path) as f:
        ip = json.load(f)
except Exception:
    raise SystemExit(0)
entry = ip.get("plugins", {}).get("allostat-mcp@local")
if not entry:
    raise SystemExit(0)
record = entry[0]
# ultraswarm (2026-07-07): parity with the Windows Repair-InstalledPluginsJson —
# correct not just the literal "unknown" case but ANY stale/wrong installPath or
# version (e.g. a post-upgrade stale-but-concrete version), and only rewrite when
# something actually changed.
want_path = os.environ["WRAPPER_DIR"]
want_version = os.environ["VERSION"]
cur_path = str(record.get("installPath", ""))
cur_version = record.get("version")
if cur_path != want_path or cur_version != want_version:
    record["installPath"] = want_path
    record["version"] = want_version
    record["lastUpdated"] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    with open(path, "w") as f:
        json.dump(ip, f, indent=2)
    print("corrected")
PY
    ok "installed_plugins.json checked"
fi

# Step 4: Re-register MCP server
step "Re-registering MCP server at user scope..."
"$CLAUDE_EXE" mcp remove allostat-mcp --scope user >/dev/null 2>&1 || true
# NOTE (ultraswarm argv review): the bearer rides `mcp add --header` on the child
# argv, briefly readable via ps/`/proc/<pid>/cmdline`. INHERENT to the Claude CLI
# — `claude mcp add` exposes only `--header` for HTTP auth (no env/file/stdin
# option; confirmed via `claude mcp add --help`), so it can't be moved off argv
# here. One-shot at repair; not fixable our side. Revisit if the CLI adds one.
if "$CLAUDE_EXE" mcp add allostat-mcp \
    --scope user \
    --transport http "$SERVER_BASE/mcp" \
    --header "Authorization: Bearer $BEARER" 2>&1 | sed 's/^/    /'; then
    ok "MCP server registered at user scope"
else
    warn "claude mcp add returned non-zero -- continuing with validation"
fi

# Step 5: Validate
step "Running validation..."
# set -e would abort on a non-zero doctor exit before we can capture and
# report it -- suspend it around the capture so the final branch runs.
set +e
bash "$WRAPPER_DIR/scripts/allostat-doctor.sh"
EXIT_CODE=$?
set -e

echo
if [ $EXIT_CODE -eq 0 ]; then
    echo "Repair complete. Restart Claude Code to pick up the rewritten config."
fi

exit $EXIT_CODE
