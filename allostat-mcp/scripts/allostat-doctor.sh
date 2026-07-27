#!/usr/bin/env bash
# allostat-doctor.sh -- Standalone Allostat MCP health check (Linux/Mac).
# PATCH-103.
#
# Read-only diagnostic. Wraps hooks/install_validation.py with the same
# 4-layer + 1-callable-probe checks as the install.ps1's Step 12b.
#
# Usage:
#   bash ~/.claude/plugins/allostat-mcp/scripts/allostat-doctor.sh
#   bash ~/.claude/plugins/allostat-mcp/scripts/allostat-doctor.sh --verbose

set -euo pipefail

VERBOSE=0
for arg in "$@"; do
    case "$arg" in
        --verbose|-v) VERBOSE=1 ;;
    esac
done

WRAPPER_DIR="${WRAPPER_DIR:-$HOME/.claude/plugins/allostat-mcp}"
SERVER_BASE="${ALLOSTAT_MCP_ENDPOINT_BASE:-https://mcp.allostat.ai}"
INSTALL_VALIDATION="$WRAPPER_DIR/hooks/install_validation.py"

if [ ! -f "$INSTALL_VALIDATION" ]; then
    echo "[error] install_validation.py not found at $INSTALL_VALIDATION"
    echo "Plugin may be incompletely installed. Re-run the full installer."
    exit 5
fi

CLAUDE_EXE="$(command -v claude || true)"
if [ -z "$CLAUDE_EXE" ]; then
    echo "[error] claude CLI not found on PATH."
    exit 5
fi

# Read bearer from .env backup for Layer 5 callable probe.
BEARER=""
ENV_FILE="$WRAPPER_DIR/.env"
if [ -f "$ENV_FILE" ]; then
    BEARER=$(grep '^ALLOSTAT_MCP_TOKEN=' "$ENV_FILE" | head -n 1 | cut -d= -f2- | tr -d '\r\n')
fi

# Run install_validation.py (Layer 1-4 only — Python module doesn't have bearer access).
echo "==> Allostat health check"
echo

# set -e would abort on a non-zero validation exit before we can capture and
# report it -- suspend it around the capture so the diagnostic branch runs.
set +e
PY_OUTPUT="$(python3 "$INSTALL_VALIDATION" 2>&1 | tail -n 1)"
PY_EXIT=$?
set -e

# Parse the JSON output.
STATE=$(echo "$PY_OUTPUT" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("state","unknown"))' 2>/dev/null || echo "unknown")
PLUGIN_LOADED=$(echo "$PY_OUTPUT" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("plugin_loaded"))' 2>/dev/null || echo "unknown")
MCP_STATUS=$(echo "$PY_OUTPUT" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("mcp_status"))' 2>/dev/null || echo "unknown")
SERVER_REACHABLE=$(echo "$PY_OUTPUT" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("server_reachable"))' 2>/dev/null || echo "unknown")
FIX_HINT=$(echo "$PY_OUTPUT" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("fix_hint") or "")' 2>/dev/null || echo "")

# Layer 5: authenticated MCP probe (if bearer available).
MCP_CALLABLE="skipped"
if [ -n "$BEARER" ]; then
    # Bearer via curl's stdin config (-K -), NOT -H on argv: a process command
    # line is world-readable via /proc/<pid>/cmdline and `ps -ww`, so a bearer
    # on argv leaks to any local user for the probe's lifetime (ultraswarm). The
    # heredoc feeds the Authorization header through stdin, keeping it off argv.
    PROBE_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "$SERVER_BASE/mcp" \
        -K - \
        -H "Accept: application/json, text/event-stream" \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"allostat-installer-probe","version":"0.1.7"}}}' \
        --max-time 10 2>/dev/null <<CURL_AUTH || echo "000"
header = "Authorization: Bearer ${BEARER}"
CURL_AUTH
)
    if [ "$PROBE_STATUS" = "200" ]; then
        MCP_CALLABLE="✓"
    else
        MCP_CALLABLE="✗ (HTTP $PROBE_STATUS)"
        # Downgrade state if probe failed but Python module reported healthy.
        if [ "$STATE" = "healthy" ]; then
            STATE="degraded_mcp_failed_connect"
            FIX_HINT="MCP callable probe failed (HTTP $PROBE_STATUS). Re-run installer with fresh code."
            PY_EXIT=3
        fi
    fi
fi

# Status line
if [ "$STATE" = "healthy" ]; then
    echo "================================================"
    echo "  Allostat health: ✓ HEALTHY"
    echo "================================================"
else
    STATE_UPPER=$(echo "$STATE" | tr '[:lower:]' '[:upper:]')
    echo "================================================"
    echo "  Allostat health: ⚠ $STATE_UPPER"
    echo "================================================"
fi
echo

# Layer summary
echo "Layer 1 (plugin loaded):     $([ "$PLUGIN_LOADED" = "True" ] && echo ✓ || echo ✗)"
echo "Layer 2 (MCP registered):    $([ "$MCP_STATUS" = "connected" ] || [ "$MCP_STATUS" = "failed" ] && echo ✓ || echo ✗)"
echo "Layer 3 (server reachable):  $([ "$SERVER_REACHABLE" = "True" ] && echo ✓ || echo ✗)"
echo "Layer 4 (MCP connected):     $([ "$MCP_STATUS" = "connected" ] && echo ✓ || echo ✗)"
echo "Layer 5 (MCP callable):      $MCP_CALLABLE"
echo

if [ "$STATE" != "healthy" ] && [ -n "$FIX_HINT" ]; then
    echo "Fix:"
    echo "  $FIX_HINT"
    echo
fi

if [ "$VERBOSE" = "1" ]; then
    echo "---"
    echo "Raw validation output:"
    echo "$PY_OUTPUT"
    echo
fi

exit $PY_EXIT
