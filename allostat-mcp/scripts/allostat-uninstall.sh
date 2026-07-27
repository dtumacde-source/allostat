#!/usr/bin/env bash
# Uninstall Allostat — the in-terminal command (mac/linux).
#
# Removes THIS install's wrapper machinery and DISABLES Allostat for THIS
# surface only (Claude Code plugin + marketplace entry + MCP registration when
# run from the Claude install; config.toml block + standalone wrapper when run
# from the Codex install). Leaves ALL your data — memory, handoffs, .allostat
# state — and your ALLOSTAT_MCP_TOKEN untouched, so a reinstall resumes from
# where you left off.
#
# Run from any terminal:
#   bash "$HOME/.claude/plugins/marketplaces/local/allostat-mcp/scripts/allostat-uninstall.sh"
#   bash "$HOME/.allostat/codex/allostat-mcp/scripts/allostat-uninstall.sh"
#
# Removal logic lives in wrapper/lib/uninstall.py; this shim copies it (plus
# codex_wiring.py for the Codex surface) to a temp dir and runs it FROM there,
# so it can remove its own plugin directory cleanly.
set -euo pipefail

# Surface + removal library are derived ONLY from where THIS script lives
# (Sol P1-2/P2, operator requirement 2026-07-18). This shim ships in BOTH the
# Claude install ($HOME/.claude/...) and the standalone Codex install
# ($HOME/.allostat/codex/...). It must run ONLY its own install's removal code:
# never probe or execute the other surface's library (version skew there must
# not be able to break THIS uninstall), and ABORT when ownership can't be
# classified -- unknown ownership must never broaden into wider removal.
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
case "$SELF_DIR" in
    *"/.allostat/codex/"*) SURFACE="codex" ;;
    *"/.claude/"*)         SURFACE="claude" ;;
    *)
        echo "Cannot determine which Allostat install owns this uninstaller:" >&2
        echo "  $SELF_DIR" >&2
        echo "It is not under ~/.claude or ~/.allostat/codex. Nothing was removed." >&2
        echo "Run the copy inside the install you want to remove. To remove BOTH" >&2
        echo "installs, run each install's own uninstall script." >&2
        exit 2
        ;;
esac

PLUGIN_LIB="$(cd "$SELF_DIR/.." && pwd)/lib"
if [ ! -f "$PLUGIN_LIB/uninstall.py" ]; then
    echo "This install's removal logic is missing: $PLUGIN_LIB/uninstall.py" >&2
    echo "Nothing was removed. Reinstall (or --refresh) first, then uninstall." >&2
    exit 1
fi

PY="$(command -v python3 || command -v python || true)"
if [ -z "$PY" ]; then
    echo "No Python interpreter found on PATH — cannot run the uninstaller." >&2
    exit 1
fi

TMP="$(mktemp -d)"
# allostat:destructive-ok removes only this script's own mktemp -d scratch dir on exit.
trap 'rm -rf "$TMP"' EXIT
cp "$PLUGIN_LIB/uninstall.py" "$TMP/"
# The Codex helper is only needed for the Codex surface (loaded lazily); a
# Claude uninstall never imports it.
if [ "$SURFACE" = "codex" ]; then
    cp "$PLUGIN_LIB/codex_wiring.py" "$TMP/"
fi
"$PY" "$TMP/uninstall.py" --surface "$SURFACE"
