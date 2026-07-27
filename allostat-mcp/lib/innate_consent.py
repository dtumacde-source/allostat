"""Single-use, file-based consent for innate-rule overrides (2026-07-04).

The env-var override (ALLOSTAT_INNATE_OVERRIDES) cannot reach the hook under
the desktop app. This token lives in the project's .allostat/ dir, so the
UserPromptSubmit hook (which sees the phrase) and the PreToolUse hook (which
enforces the guard) share it in the same environment — works everywhere.

FAIL-SAFE: any read problem returns False (guard stays on). SINGLE-USE:
check_and_consume deletes the token so the next destructive command re-fires.
"""
from __future__ import annotations

import json
import os
import re
import time
import uuid
from pathlib import Path

OVERRIDE_PHRASE = "allostat: override"
CONSENT_FILENAME = "innate_consent.json"

# H-04 (Wave-2 2026-07-11): anchored, whole-line invocation. The phrase must
# BE a line of the prompt — optional surrounding whitespace, optional wrapping
# BACKTICK pair (rule 02's red box renders `allostat: override`, so a faithful
# copy of the documented invocation still arms), and at most one trailing '.'
# or '!'. The pre-fix unanchored substring match armed the 300s token whenever
# the phrase appeared ANYWHERE — pasting a log/doc/transcript that merely
# QUOTED the phrase silently disarmed the destructive-command guard. Whole-line
# is the tightest anchor that keeps the documented UX ("Type
# `allostat: override` in your next message") working, including the phrase on
# its own line inside a longer message.
#
# Wrapping restricted to BACKTICK only (adversarial-verify tightening,
# 2026-07-11): the documented invocation uses backticks; accepting `'`/`"`
# also armed the common quoted-log / JSON-string shape ("allostat: override")
# with no UX benefit.
_ANCHORED_OVERRIDE_RE = re.compile(
    r"^\s*(`)?" + re.escape(OVERRIDE_PHRASE) + r"`?\s*[.!]?\s*$",
    re.IGNORECASE,
)


def _override_lines(prompt: str) -> list[str]:
    """Split the prompt on GENUINE newlines only (adversarial-verify tightening,
    2026-07-11). str.splitlines() also breaks on VT/FF/FS/GS/RS/NEL/LS/PS, so a
    pasted printout embedding one of those control chars immediately before the
    phrase armed the token with no real line break. Restrict to \\n (stripping a
    trailing \\r for CRLF)."""
    return [line.rstrip("\r") for line in prompt.split("\n")]


def _ttl_backstop() -> float:
    return float(os.environ.get("ALLOSTAT_CONSENT_TTL", "300"))


def _path(state_dir) -> Path:
    return Path(state_dir) / CONSENT_FILENAME


def prompt_grants_override(prompt: str) -> bool:
    """True iff the operator DELIBERATELY typed the override phrase (H-04).

    Anchored to a whole line (see _ANCHORED_OVERRIDE_RE): pasted content that
    merely CONTAINS the phrase mid-line — logs, docs, transcripts, the rule's
    own red-box instructions — no longer arms the token."""
    if not prompt:
        return False
    return any(_ANCHORED_OVERRIDE_RE.match(line) for line in _override_lines(prompt))


def grant(state_dir, now: float | None = None) -> None:
    now = time.time() if now is None else now
    p = _path(state_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        json.dumps({
            "granted_at": now,
            "expires_at": now + _ttl_backstop(),
            "phrase": OVERRIDE_PHRASE,
        }),
        encoding="utf-8",
    )


def peek(state_dir, now: float | None = None) -> bool:
    """True iff a valid unexpired token exists, WITHOUT consuming it.

    DIAGNOSTICS/TESTS ONLY. A peek must never GATE a destructive allow:
    H-05 (Wave-2 2026-07-11) showed two parallel PreToolUse processes could
    both peek one token and both bypass a lethal refusal. Decision points use
    `consume_atomically` (first-wins) instead; a downstream block hands the
    claimed payload to `restore`. Any read error → False (fail-safe)."""
    now = time.time() if now is None else now
    p = _path(state_dir)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (FileNotFoundError, ValueError, OSError):
        return False
    expires = data.get("expires_at")
    return isinstance(expires, (int, float)) and now < expires


def consume_atomically(state_dir, now: float | None = None) -> dict | None:
    """Atomically CLAIM the single-use token at the decision point (H-05,
    Wave-2 2026-07-11).

    The old design peeked here and burned the token at the end of the hook;
    in the peek→burn window two PARALLEL PreToolUse processes could both see
    the token and both bypass a lethal refusal. `os.replace` to a
    caller-unique claim file is atomic on a single filesystem: exactly one of
    any number of concurrent callers wins the rename; every loser gets
    FileNotFoundError and returns None (the guard stays armed for them).

    Returns the token payload dict iff a valid, unexpired token was claimed —
    the caller can hand it to `restore` when a DOWNSTREAM guard blocks the
    same command (the grant wasn't spent on an executed action). Returns
    None on: no token, lost the race, malformed, expired, any OS error.
    The token file is gone either way (single-use + stale cleanup)."""
    now = time.time() if now is None else now
    p = _path(state_dir)
    claim = p.with_name(f"{CONSENT_FILENAME}.claim.{os.getpid()}.{uuid.uuid4().hex}")
    try:
        os.replace(p, claim)  # atomic: first consumer wins
    except OSError:  # FileNotFoundError included — no token / lost the race
        return None
    data: object = None
    try:
        data = json.loads(claim.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        data = None
    try:
        claim.unlink()
    except OSError:
        # Best-effort: a leftover claim file is inert (nothing reads it).
        pass
    if not isinstance(data, dict):
        return None
    expires = data.get("expires_at")
    if isinstance(expires, (int, float)) and now < expires:
        return data
    return None


def restore(state_dir, token: dict) -> bool:
    """Put an atomically-claimed but UNSPENT token back (H-05 companion).

    Used when the consent gate claimed the token but a DOWNSTREAM guard
    (sandbox, MEMORY.md cap) blocked the command — the operator's grant was
    never spent on an executed action, so it survives for the retry (the
    ultraswarm-med behavior the old late-burn point provided).

    Create-only (`open(..., "x")`): never clobbers a token granted after the
    claim. The original `expires_at` is preserved — a restore never extends
    the TTL. Any error → False (fail-safe: the guard just stays armed and
    the operator re-types the phrase)."""
    if not isinstance(token, dict):
        return False
    p = _path(state_dir)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "x", encoding="utf-8") as f:
            f.write(json.dumps(token))
        return True
    except (OSError, TypeError, ValueError):
        return False


def check_and_consume(state_dir, now: float | None = None) -> bool:
    """True iff a valid unexpired token exists. Deletes the token either way
    (single-use + stale cleanup). Any read error → False (fail-safe).

    H-05: reimplemented on `consume_atomically` so every consumer shares the
    same race-safe first-wins semantics."""
    return consume_atomically(state_dir, now=now) is not None
