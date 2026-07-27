"""Shared hook scaffolding for the allostat-mcp wrapper plugin.

Common patterns:
  - parse stdin JSON payload
  - resolve the project root + state dir
  - opt-out via ALLOSTAT_DISABLED=1 (bench harness flag)
  - opt-out via missing ALLOSTAT_MCP_TOKEN (silent degrade if no auth)
  - format additionalContext output for UserPromptSubmit etc.
  - log to stderr on errors (visible in operator's session if hook
    troubleshooting is needed) but never raise — hooks must not break
    the operator's session
"""
from __future__ import annotations

import atexit
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


# v0.2.0 audit-hardening (W3/W4/W38/W47): force stdout + stderr to UTF-8
# regardless of OS default encoding (Windows defaults to cp1252 which
# corrupts the box-drawing characters in handoff-checkpoint red boxes
# and the ✅/⚠/❌ markers in the install-state banner). reconfigure()
# only exists on Python 3.7+ TextIOWrapper; guard for older runtimes
# even though we require 3.12+.
#
# H-24 (2026-07-11): stdin MUST be reconfigured too. It defaults to the OS
# locale codepage (cp1252 on Windows), so a piped hook JSON payload carrying
# a non-cp1252 byte (non-English username/path, certain smart punctuation)
# fails to decode inside read_payload() — the bare except there swallows it
# to {}, discarding cwd/session_id/transcript_path for EVERY hook fire.
# Test stdins (StringIO) have no .reconfigure; the AttributeError guard skips
# them harmlessly.
for _stream in (sys.stdin, sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
    except (AttributeError, ValueError):
        pass


# Add the wrapper's lib/ to sys.path so hooks can import local_state,
# mcp_client, client_state_writer, etc.
_HOOK_DIR = Path(__file__).resolve().parent
_PLUGIN_ROOT = _HOOK_DIR.parent
_LIB_DIR = _PLUGIN_ROOT / "lib"
if str(_LIB_DIR) not in sys.path:
    sys.path.insert(0, str(_LIB_DIR))


def disabled() -> bool:
    """ALLOSTAT_DISABLED=1 turns the regulator off (bench harness opt-out)."""
    return os.environ.get("ALLOSTAT_DISABLED") == "1"


def has_mcp_token() -> bool:
    """Without a Bearer token the wrapper cannot reach the MCP server.

    On missing token, hooks degrade silently (return 0, no additionalContext)
    so an unconfigured plugin install doesn't break the operator's session.

    Audit #6 (2026-07-06): this preflight MUST mirror the same token sources
    MCPClientConfig.from_env() consults — OS env *and* the plugin .env file.
    Before this fix the gate checked only os.environ, so a bearer installed
    (or rotated) into the plugin .env — which the client would happily use —
    still failed the gate closed, silently suppressing every hook's dispatch
    and all server-side regulation. Check OS env first (cheap), then fall
    back to the .env resolver the client itself uses.
    """
    if os.environ.get("ALLOSTAT_MCP_TOKEN", "").strip():
        return True
    try:
        from mcp_client import _read_bearer_from_env_file  # noqa: E402
        return bool(_read_bearer_from_env_file())
    except Exception:  # noqa: BLE001 — never let a preflight import break the hook
        return False


def should_inject(state_dir: Path | None) -> bool:
    """S2 Block 3a (2026-05-27) — deactivation lifecycle guard.

    Returns True iff the wrapper should inject rules + run regulation this
    hook fire. Reads the subscription_state cache populated at SessionStart
    by `subscription_gate.refresh_subscription_state`.

    Fail-CLOSED semantics (2026-07-20 — see the note below):
      - state_dir is None → **False**. Nothing to read entitlement from.
      - Cache absent / malformed / unreadable → False (F-04, 2026-07-10: per
        `subscription_gate.is_active_subscription`, fail-CLOSED — a
        missing/corrupt cache no longer grants entitlement; SessionStart writes
        a real state before any hook reads it).
      - Cached state in {'active', 'trial'} → True.
      - Cached state in {'lapsed', 'canceled'} → False.
      - **Any exception → False.** Import failure, read failure, anything.

    The guard is read-only — populating the cache is SessionStart's job.
    Downstream hooks (UserPromptSubmit, PreToolUse, PostToolUse, Stop)
    consult this and early-noop when False.

    Operator's locked directive 2026-05-27 PM: silent removal on lapse.
    "A message would be intrusive — Allostat's presence on their machine
    after they manually went into their account and unsubscribed."

    WHY BOTH BRANCHES FLIPPED (2026-07-20). This function is the gate every
    downstream hook consults, and it used to answer True on `state_dir is None`
    and True on ANY exception. So the F-04 hardening below it — which made
    `is_active_subscription` fail closed on a missing or corrupt cache — was
    only ever consulted when the import and the read both SUCCEEDED. A broken
    plugin update, a missing module, a syntax error in `subscription_gate.py`:
    all of them landed in the `except` and resolved to *entitled*.

    That is why the same directive was issued five times between 2026-05-27 and
    2026-07-20 without the behaviour changing. Each round hardened the predicate
    under inspection while this caller kept answering True. The operator's
    words: "There is no world where allowing any part of allostat to run
    without the regulator is safe."

    `state_dir is None` was justified as "don't degrade sessions where state
    can't be resolved". But `resolve_state_dir()` falls back to `Path.cwd()`
    and never returns None, so the branch is defensive-only — and if it ever
    does fire, there is by definition no cache to read, which is precisely the
    case that must deny.

    The cost of this direction is real and accepted: if entitlement cannot be
    read, regulation stops. That is the *pro-customer* outcome. A customer whose
    Allostat goes inert still has a fully working Claude Code and recovers on
    the next SessionStart. A customer whose Allostat runs unregulated gets
    unmetered memory injection — the 75k-tokens-on-a-3-word-prompt failure.
    """
    if state_dir is None:
        return False
    try:
        import subscription_gate  # noqa: E402
        return subscription_gate.is_active_subscription(state_dir)
    except Exception as e:  # noqa: BLE001
        # Fail CLOSED. "I could not determine entitlement" must never resolve
        # to "entitled" — that equivalence is the whole defect.
        try:
            emit_stderr(f"should_inject lookup failed (regulation OFF): {e}")
        except Exception:  # noqa: BLE001  # H3 audit fix: stderr-print itself raised
            pass
        return False


def is_terminally_inactive(state_dir: Path | None) -> bool:
    """Decouple SAFETY from entitlement (item #5, 2026-07-14).

    Returns True ONLY when entitlement is a server-CONFIRMED terminal-inactive
    state (`lapsed`/`canceled`) — the sole case where the deactivation guard
    fully silences the wrapper INCLUDING its local safety rules (the operator's
    locked silent-removal-on-lapse: after they unsubscribed, Allostat's presence
    on their machine — safety refusals included — goes quiet).

    An INDETERMINATE state returns False so the SAFETY floor still runs:
      - `"unknown"` — the fail-closed sentinel a 300s control-plane outage
        produces for a still-PAYING user (this is the blocker being closed:
        an outage must NOT strip the 12 destructive-command/sandbox guards).
      - missing / malformed cache — can't confirm a terminal state → protect.

    state_dir None → False (can't confirm terminal state; run safety).
    Any lookup error → False (fail-safe: keep safety on).

    Distinct from `should_inject` (active/trial → value-add regulation). Safety
    runs whenever this is False; value-add runs only when should_inject is True.
    """
    if state_dir is None:
        return False
    try:
        import subscription_gate  # noqa: E402
        return subscription_gate.is_terminally_inactive(state_dir)
    except Exception as e:  # noqa: BLE001
        try:
            emit_stderr(
                f"is_terminally_inactive lookup failed (fail-safe: safety on): {e}"
            )
        except Exception:  # noqa: BLE001
            pass
        return False


def read_payload() -> dict[str, Any]:
    """Read the hook's stdin JSON payload. Returns {} on parse failure."""
    try:
        raw = sys.stdin.read()
    except Exception:
        return {}
    if not raw:
        return {}
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return {"prompt": raw}  # UserPromptSubmit fallback
    return payload if isinstance(payload, dict) else {}


def resolve_project_root_from_payload(payload: dict[str, Any]) -> Path | None:
    """Use the harness-provided transcript path / cwd to pick a project
    root. Falls back to cwd."""
    cwd_hint = payload.get("cwd") or payload.get("workspaceRoot")
    if cwd_hint:
        try:
            return Path(cwd_hint).resolve()
        except Exception:
            pass
    transcript = payload.get("transcript_path") or payload.get("transcriptPath")
    if transcript:
        try:
            tp = Path(transcript)
            # The transcript folder lives at .claude/projects/<encoded>/.
            # Fall back to that as a project_root proxy when no .allostat/.
            if tp.parent.exists():
                return tp.parent
        except Exception:
            pass
    return Path.cwd()


_pending_codex_context: list[str] = []
_codex_flush_registered = False


def wrap_pending_context(prefix: str, suffix: str) -> None:
    """Bracket everything buffered for the single Codex flush.

    Codex wall-of-text fix (2026-07-05): all SessionStart payloads travel in
    ONE combined object under Codex, so session-start wraps them in an
    <allostat_internal_context> envelope before flushing (data, not display
    text). No-op when nothing is buffered (Claude never buffers).
    """
    if _pending_codex_context:
        _pending_codex_context.insert(0, prefix)
        _pending_codex_context.append(suffix)


_post_flush_callbacks: list = []


def run_after_physical_flush(callback) -> None:
    """Register a callback to run ONLY after buffered Codex context has
    physically reached stdout. Round-7 inversion (advisor 2026-07-23): a
    successful return from emit_additional_context proves only that text
    entered a list; presentation state may be committed exclusively on proof
    of physical output. Callbacks run at most once, in registration order,
    and never at all if the flush fails."""
    _post_flush_callbacks.append(callback)


def flush_pending_context(hook_event: str = "SessionStart") -> bool:
    """Codex accepts only ONE JSON object per hook. Emit all buffered
    additionalContext as a single combined object.

    Returns True only when the payload PHYSICALLY reached stdout (print +
    flush both succeeded) — or when nothing was buffered. Round-7: this
    result is the only failure signal the Codex path has; it is returned,
    not swallowed. On failure the buffer is KEPT so the atexit-registered
    retry still has the payload, and post-flush callbacks do NOT run."""
    global _post_flush_callbacks
    if not _pending_codex_context:
        return True
    combined = "\n\n".join(_pending_codex_context)
    try:
        print(json.dumps({
            "hookSpecificOutput": {"hookEventName": hook_event, "additionalContext": combined}
        }))
        sys.stdout.flush()
    except Exception as e:
        emit_stderr(f"flush_pending_context failed — buffered context NOT delivered: {e}")
        return False
    _pending_codex_context.clear()
    callbacks, _post_flush_callbacks = _post_flush_callbacks, []
    for cb in callbacks:
        try:
            cb()
        except Exception as e:
            emit_stderr(f"post-flush callback failed: {e}")
    return True


def emit_additional_context(
    text: str,
    *,
    hook_event: str = "UserPromptSubmit",
) -> None:
    """Print the JSON envelope Claude Code expects for hook
    additionalContext output.

    Claude Code's hook protocol requires `hookEventName` to match the
    actual event slot the hook is registered for. Each hook script must
    pass its event name explicitly via `hook_event` — defaults to
    `UserPromptSubmit` for back-compat, but callers should always set it.

    Codex accepts only ONE JSON object on a hook's stdout — so under Codex
    we buffer emissions and flush a single combined object at process exit
    (via `flush_pending_context`, registered with `atexit` on first use).
    The Claude path is unchanged: immediate one-object-per-call.
    """
    if not text:
        return
    if detect_harness() == "codex":
        global _codex_flush_registered
        _pending_codex_context.append(text)
        if not _codex_flush_registered:
            atexit.register(flush_pending_context, hook_event)
            _codex_flush_registered = True
        return
    output = {
        "hookSpecificOutput": {
            "hookEventName": hook_event,
            "additionalContext": text,
        }
    }
    print(json.dumps(output))
    # Round-7: physical output is the proof callers key presentation state on.
    # Flush now so a closed/dead stdout raises HERE, to the caller, instead of
    # sitting in libc's buffer while the caller records "shown".
    sys.stdout.flush()


def emit_stderr(msg: str) -> None:
    sys.stderr.write(f"[allostat-mcp] {msg}\n")


def refuse_tool_call(message: str, *, hook_event: str = "PreToolUse") -> int:
    """Harness-aware tool-call refusal. Returns the exit code the hook must
    return.

    Claude Code: red-box via additionalContext + exit 2 (today's behavior,
    unchanged — the caller adds its own stderr line where it always did).

    Codex (probe-proven 2026-07-06): exit 2 does NOT block — Codex denies on
    the JSON decision object `hookSpecificOutput.permissionDecision: "deny"`,
    surfacing the reason to the model verbatim (holds even under
    bypassPermissions). The red-box text rides as the reason; any buffered
    additionalContext is dropped so the deny is the SINGLE stdout object
    (Codex one-object contract).
    """
    if detect_harness() == "codex":
        _pending_codex_context.clear()
        print(json.dumps({
            "hookSpecificOutput": {
                "hookEventName": hook_event,
                "permissionDecision": "deny",
                "permissionDecisionReason": message,
            }
        }))
        return 0
    emit_additional_context(message, hook_event=hook_event)
    return 2


@dataclass(frozen=True)
class HarnessProfile:
    """Per-harness injection tuning. Claude = today's behavior; Codex leaner
    because it compresses hard ~250k tokens (keep session-start inject small)."""
    name: str
    handoff_max_chars: int
    memory_max_chars: int | None  # None = uncapped
    # Slice 2 (write-loop): granular per-file mute of the always-on/universal
    # appendices, replacing slice 1's coarse all-or-nothing bool. Inject the
    # appendices MINUS any filename in this set. Both shipped profiles now
    # exclude nothing — slice 2 wired the write loop (handoff protocol
    # backed), slice 3 wired UserPromptSubmit's per-turn `now:` line
    # (livetime protocol backed). The mechanism stays for future harnesses
    # or per-file mutes.
    always_on_exclude: frozenset[str] = frozenset()


_PROFILES: dict[str, HarnessProfile] = {
    "claude": HarnessProfile(
        "claude", handoff_max_chars=8000, memory_max_chars=None,
        always_on_exclude=frozenset(),
    ),
    "codex": HarnessProfile(
        "codex", handoff_max_chars=3000, memory_max_chars=4000,
        always_on_exclude=frozenset(),
    ),
}


def detect_harness(argv: list[str] | None = None) -> str:
    """Explicit-only detection. Codex iff `--harness codex` in argv (CODEX_HOME
    is NOT in the hook env — probe 2026-07-05). Default → claude."""
    argv = sys.argv if argv is None else argv
    try:
        i = argv.index("--harness")
    except ValueError:
        return "claude"
    if i + 1 < len(argv):
        val = argv[i + 1].strip().lower()
        if val in _PROFILES:
            return val
    return "claude"


def get_profile(harness: str | None = None) -> HarnessProfile:
    if harness is None:
        harness = detect_harness()
    return _PROFILES.get(harness, _PROFILES["claude"])
