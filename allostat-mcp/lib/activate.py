#!/usr/bin/env python3
"""Activate an Allostat install code into ALLOSTAT_MCP_TOKEN.

Purpose
-------
Plugin-marketplace installs deliver the plugin CODE via git (`/plugin install`),
but they do NOT run the Windows installer (`install.ps1`) that normally mints the
subscriber bearer and sets the `ALLOSTAT_MCP_TOKEN` environment variable. Without
that token the plugin's `.mcp.json` (`Authorization: Bearer ${ALLOSTAT_MCP_TOKEN}`)
has nothing to send, so the server stays dormant (silent-on-no-subscription).

This script is the store-install activation step. It exchanges a one-time install
code for the bearer at `/install/resolve` — the SAME endpoint install.ps1 uses —
then persists the bearer and sets `ALLOSTAT_MCP_TOKEN` as a persistent User-scope
env var. It deliberately does NOT download a bundle (the store already delivered
the code) — it is the token-only slice of the installer's resolve step.

IMPORTANT
---------
* `/install/resolve` CONSUMES the one-time code and rotates the bearer server-side.
  Do not call it speculatively — `--dry-run` therefore does NOT hit the network.
* After a successful activation the user MUST fully restart Claude Code: MCP server
  env is read at launch, so a running instance won't see the new variable.

Usage
-----
    python activate.py <CODE>
    python activate.py --dry-run <CODE>   # show what would happen; no network, no writes

Endpoint override (testing): set ALLOSTAT_MCP_ENDPOINT (default https://mcp.allostat.ai).
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

DEFAULT_ENDPOINT = "https://mcp.allostat.ai"
ENV_VAR = "ALLOSTAT_MCP_TOKEN"


def _endpoint() -> str:
    return os.environ.get("ALLOSTAT_MCP_ENDPOINT", DEFAULT_ENDPOINT).rstrip("/")


def _resolve_url() -> str:
    return _endpoint() + "/install/resolve"


def resolve_code(code: str) -> dict:
    """POST the code to /install/resolve; return the parsed JSON.

    Consumes the one-time code and rotates the bearer server-side.
    """
    body = json.dumps({"code": code}).encode("utf-8")
    req = urllib.request.Request(
        _resolve_url(),
        data=body,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "allostat-activate/1.0 (+https://allostat.ai)",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = e.read().decode("utf-8")[:400]
        except Exception:
            # Best-effort: the error body is a diagnostic nicety appended to the
            # SystemExit message below; if it can't be read we still raise the
            # HTTP-code error, so swallowing here loses nothing actionable.
            pass
        raise SystemExit(
            f"ERROR: server rejected the code (HTTP {e.code}). {detail}\n"
            "Common causes: code expired (24h limit), already used, or invalid.\n"
            "Ask for a fresh install code and try again."
        )
    except urllib.error.URLError as e:
        raise SystemExit(
            f"ERROR: could not reach {_endpoint()} ({e.reason}).\n"
            "Check your internet connection and try again."
        )


def wrapper_dir() -> Path:
    """Best-effort location of the plugin dir for the recovery .env file.

    Prefer CLAUDE_PLUGIN_ROOT (set by Claude Code for plugin commands); fall back
    to this file's parent-of-parent (…/wrapper/lib/activate.py -> …/wrapper).
    """
    root = os.environ.get("CLAUDE_PLUGIN_ROOT")
    if root:
        return Path(root)
    return Path(__file__).resolve().parent.parent


def persist_env_file(bearer: str) -> Path:
    """Write the bearer to <wrapper>/.env (recovery copy, matches installer)."""
    env_path = wrapper_dir() / ".env"
    # ultraswarm: create the file owner-only FROM THE START. write_text() would
    # create it world-readable and only then chmod, leaving a window where the
    # bearer is exposed. os.open with 0o600 closes that window (on POSIX; on
    # Windows the mode is advisory and the chmod below is the best-effort belt).
    data = f"{ENV_VAR}={bearer}\r\n"
    try:
        fd = os.open(env_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
            f.write(data)
    except OSError:
        env_path.write_text(data, encoding="utf-8")  # fallback
    try:
        os.chmod(env_path, 0o600)
    except Exception:
        pass  # best-effort on Windows
    return env_path


def _set_windows_user_env(name: str, value: str) -> None:
    """Persist a User-scope env var on Windows WITHOUT exposing it on any process
    argv. Writes HKCU\\Environment via the registry API (never a `setx name value`
    command line, whose value is readable by any local process, Task Manager, or
    EDR process-creation log) and broadcasts WM_SETTINGCHANGE so already-running
    shells pick it up without a logoff. Raises on failure so the caller falls
    back to the manual hint. Windows-only (imports are lazy for POSIX safety)."""
    import ctypes
    import winreg

    with winreg.OpenKey(
        winreg.HKEY_CURRENT_USER, "Environment", 0, winreg.KEY_SET_VALUE
    ) as key:
        winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)
    # Best-effort broadcast so new/refreshed processes see it; failure here does
    # not undo the persisted write, so it is not fatal.
    try:
        HWND_BROADCAST = 0xFFFF
        WM_SETTINGCHANGE = 0x1A
        SMTO_ABORTIFHUNG = 0x0002
        ctypes.windll.user32.SendMessageTimeoutW(
            HWND_BROADCAST, WM_SETTINGCHANGE, 0, "Environment",
            SMTO_ABORTIFHUNG, 5000, ctypes.byref(ctypes.c_ulong()),
        )
    except Exception:
        # Best-effort: a failed WM_SETTINGCHANGE broadcast does not undo the
        # persisted registry write — new shells inherit it on next launch — so
        # swallowing it here is not fatal (H3 audit-gate intent marker).
        pass


def set_user_env(bearer: str) -> tuple[bool, str]:
    """Set ALLOSTAT_MCP_TOKEN as a persistent User-scope env var.

    Returns (persisted, human_message). On Windows writes HKCU\\Environment via
    the registry API (NOT `setx`, whose argv would expose the bearer to any
    local process / EDR process-creation log). On POSIX we cannot reliably set
    an env var that the Claude Code app will inherit, so we report the manual
    step instead of pretending it worked.
    """
    # Update this process's env either way, so a same-process check can see it.
    os.environ[ENV_VAR] = bearer

    if platform.system() == "Windows":
        try:
            _set_windows_user_env(ENV_VAR, bearer)
            return True, (
                f"Set {ENV_VAR} as a persistent User environment variable."
            )
        except Exception:
            # Never interpolate the exception: it could render the value.
            # Report only the failure, with a placeholder for the manual hint.
            return False, (
                "Could not set the environment variable automatically.\n"
                "Set it manually, then restart Claude Code:\n"
                f'    setx {ENV_VAR} "<your token>"'
            )

    # POSIX: no universally-inherited persistent env. Guide the user.
    return False, (
        f"On macOS/Linux, add this to your shell profile (e.g. ~/.zshrc, ~/.bashrc),\n"
        f"then fully restart Claude Code:\n"
        f'    export {ENV_VAR}="<your token>"\n'
        f"(The token has also been saved to {wrapper_dir() / '.env'} for reference.)"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Activate an Allostat install code.")
    parser.add_argument("code", help="Your install code (from your Allostat email).")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would happen without hitting the network or writing anything.",
    )
    args = parser.parse_args(argv)

    code = args.code.strip()
    if not code:
        print("ERROR: no install code provided.", file=sys.stderr)
        return 2

    if args.dry_run:
        print("DRY RUN -- no network call, no changes made.")
        print(f"  Would POST the code to: {_resolve_url()}")
        print(f"  Would set env var:      {ENV_VAR} (User scope)")
        print(f"  Would write .env at:    {wrapper_dir() / '.env'}")
        print(f"  Platform:               {platform.system()}")
        return 0

    print(f"Resolving install code at {_endpoint()} ...")
    resolved = resolve_code(code)
    bearer = resolved.get("bearer")
    if not bearer:
        raise SystemExit("ERROR: server response did not include a bearer token.")

    user_email = resolved.get("user_email", "(unknown)")
    persist_env_file(bearer)
    persisted, message = set_user_env(bearer)

    print(f"OK: Code resolved (user: {user_email}).")
    print(f"  {message}")
    print("")
    if persisted:
        print("ACTIVATED. Now fully quit and reopen Claude Code so the plugin picks up")
        print("your token — the MCP connection reads the environment at launch.")
    else:
        print("Once the variable is set, fully quit and reopen Claude Code.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
