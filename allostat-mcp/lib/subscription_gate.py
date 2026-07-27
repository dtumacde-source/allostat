"""Subscription-state gate — S2 Block 2b (2026-05-27).

Wrapper-side helper that resolves the current subscription_state from the
hosted MCP server and caches it per-session. Backs Block 3's deactivation
lifecycle: hooks check `is_active_subscription(state_dir)` and early-noop
when False.

Design (per v3.2 action plan; fail-closed hardened by RB-10 2026-07-09):
  - Single GET against the server's `/user/state` endpoint (read-only, no
    side effects — endpoint added in same Block 2b).
  - Result cached at `state_dir / "subscription_state.json"` with ISO
    timestamp.
  - Fail CLOSED (bounded) on ANY error (network, server non-200, missing
    bearer, unparseable payload). RB-10 (client side of RB-6/C-05) reversed
    the old fail-OPEN default: a server outage or a stale bearer must NOT
    grant entitlement, or a lapsed user (or anyone during an outage) rides
    for free. To avoid hard-locking the operator on a single transient blip
    we honor last-known-good WITHIN a bounded grace window
    (`CLIENT_GRACE_SECONDS`, aligned with the server's 300s), anchored to the
    last SUCCESSFUL validation (`validated_at`), never re-armed by fault
    reads. Within grace → serve last-known state. Beyond grace, or no good
    cache → resolve to a non-entitled `"unknown"` state (hooks gate on it).
    Recovery is automatic: the next SessionStart re-validates.
  - SessionStart calls `refresh_subscription_state()`; downstream hooks
    read the cache via `is_active_subscription()`.
  - Observation event `subscription_state_resolved` is emitted on every
    refresh attempt with the resolved state value (faults recorded honestly
    — never emits "active" on a fault).

The cache is per-session — SessionStart writes; UserPromptSubmit /
PreToolUse / PostToolUse / Stop read. Mid-session subscription changes
take effect on the next SessionStart, intentional per v3.2 plan §5b
(documented behavior).
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# Subscription states that grant entitlement. Anything NOT in this set
# (including the fail-closed "unknown" sentinel) gates.
ACTIVE_STATES: frozenset[str] = frozenset({"active", "trial"})
ALL_KNOWN_STATES: frozenset[str] = frozenset(
    {"active", "trial", "lapsed", "canceled"}
)

# RB-10 (2026-07-09) — fail CLOSED. On a fault we no longer default to
# "active". We resolve to this non-entitled sentinel unless a last-known-good
# validation is still within grace. "unknown" is deliberately NOT in
# ALL_KNOWN_STATES nor ACTIVE_STATES, so `is_active_subscription` gates on it.
FAIL_CLOSED_STATE: str = "unknown"

# Bounded grace window for serving last-known-good on a fault. Aligned with
# the server's RB-6 300s grace so client + server tolerate the same transient
# window. Anchored to the last SUCCESSFUL validation (`validated_at`), never
# re-armed by a fault read — so a persistent outage exhausts grace and gates.
CLIENT_GRACE_SECONDS: int = 300

# R1 (2026-07-20) — the entitlement staleness horizon. A cached state older
# than this has not been confirmed by any server recently enough to BE an
# entitlement, no matter what string it holds.
#
# Deliberately much wider than CLIENT_GRACE_SECONDS, because it is a BACKSTOP,
# not a second grace window. Grace answers "the server just blipped, keep
# working"; this answers "no server has confirmed you in three days, so a
# cached word is not proof of anything". Because it is strictly looser than the
# refresh path's own behavior (which decays to `unknown` 300s after a fault),
# it cannot gate any customer the current design already serves — it can only
# catch a cache that `refresh_subscription_state` never got to touch.
#
# Sized to cover any plausible single session plus a couple of days offline.
# It is a module constant and NOT readable from the environment: the defect
# this whole change exists to close was an ambient variable on the money path,
# and a configurable expiry would be the same defect wearing a different name.
ENTITLEMENT_MAX_VALIDATION_AGE_SECONDS: int = 72 * 60 * 60

# Tolerance for a `validated_at` that reads slightly ahead of the local clock.
# The stamp and the read come from the SAME clock, so a future anchor means the
# clock moved or the file was written by hand. A few minutes absorbs ordinary
# jitter; beyond that we fail closed rather than honor an entitlement whose
# expiry is under the holder's control.
_FUTURE_ANCHOR_TOLERANCE_SECONDS: int = 300

_CACHE_FILENAME = "subscription_state.json"

# R1 — the test seam that replaced the retired ambient refresh-skip variable.
# The variable's name is deliberately not written here: a guard test greps the
# shipped trees for it, and a mention in a comment is indistinguishable from a
# mention in a code path to that test. The history is in git and in
# `tests/test_entitlement_freshness_boundary.py`.
#
# `None` in the shipped artifact. Tests that drive the resolver in-process pass
# `fetch_fn=` directly; tests that launch a hook as its own process set this
# attribute from the suite's `sitecustomize` shim, which lives under
# `wrapper/tests/` and is not part of the built plugin.
#
# Why this is not the same thing as the variable it replaced: setting a module
# attribute requires code already executing inside this interpreter. At that
# point an attacker could patch `is_active_subscription` itself, and no gate
# defends against arbitrary in-process code execution. An environment variable
# needed one line in a shell profile. The claim this design supports is the one
# that is actually worth making: **nothing in the shipped artifact grants
# entitlement from ambient configuration.**
_STATE_FETCHER: Any = None


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """H-10 defense in depth: refuse to follow 3xx on the bearer-carrying
    /user/state GET. urllib's default redirect handler retains the
    `Authorization` header across redirects (cross-host and https->http
    downgrade), so a validated origin answering 3xx could exfiltrate the
    subscription Bearer to an attacker target. Returning None surfaces the 3xx
    as an HTTPError instead of transparently re-requesting — the Bearer only
    ever reaches the pre-validated origin."""

    def redirect_request(self, *args, **kwargs):  # noqa: D401
        return None


def _urlopen_no_redirect(req, *, timeout):
    """Open the bearer request with redirects refused, WITHOUT mutating
    urllib's process-global opener.

    H-10 (concurrency): the previous implementation swapped urllib's GLOBAL
    opener via `install_opener(opener)` for the duration of the call and
    restored the prior opener in a finally. Under concurrency that swap RACES —
    a forced two-thread interleave issued one bearer request through the
    baseline (redirect-following) opener and left the process with another
    call's opener installed. We instead build a LOCAL `OpenerDirector` carrying
    the no-redirect handler and call its `.open()` directly, so redirect refusal
    is per-call and thread-safe and the global opener is never touched (other
    urllib users keep their default redirect behavior). This module-level
    function is the seam the test-suite mocks."""
    opener = urllib.request.build_opener(_NoRedirectHandler())
    return opener.open(req, timeout=timeout)


def _state_cache_path(state_dir: Path) -> Path:
    return Path(state_dir) / _CACHE_FILENAME


# H-10 (bearer exfil, SEVERE — 2026-07-14). The prod https default the
# resolver falls back to whenever an override is unsafe or unverifiable. Every
# /user/state request carries a live Bearer, so a remote plaintext override
# would leak the subscription token in cleartext; we never return one.
_SAFE_DEFAULT_ENDPOINT = "https://mcp.allostat.ai/mcp"


def _shared_endpoint_validator():
    """Return mcp_client's shared endpoint validator + loopback predicate.

    H-10: the subscription gate MUST resolve its endpoint through the SAME
    validator the MCP client uses (`mcp_client._resolve_endpoint`), so a
    remote plaintext `http://` override is rejected here exactly as it is on
    the MCP call path — one source of truth, no drift. Both modules live in
    `wrapper/lib`, which is on `sys.path` at runtime (and in tests), so a plain
    import resolves. On any import failure we return `(None, None)` and the
    caller fails SAFE to the prod https default (never leaks the bearer).
    """
    try:
        import mcp_client
        return mcp_client._resolve_endpoint, mcp_client._is_loopback_http
    except Exception:  # noqa: BLE001 — fail safe to prod https default
        return None, None


def _strip_mcp_suffix(endpoint: str) -> str:
    """Strip the `/mcp` (or `/mcp/`) suffix + trailing slashes to get the API
    base. `/user/state` lives at the base, not under `/mcp`."""
    if endpoint.endswith("/mcp"):
        return endpoint[:-4]
    if endpoint.endswith("/mcp/"):
        return endpoint[:-5]
    return endpoint.rstrip("/")


def _resolve_base_url() -> str:
    """Resolve the API base (no `/mcp` suffix) for `/user/state`.

    H-10 (2026-07-14): delegates endpoint resolution to the shared
    `mcp_client._resolve_endpoint` validator. That validator honors https
    overrides and loopback-http (local dev), but REFUSES any remote plaintext
    `http://` override and falls back to the prod https default — so the live
    Bearer can never be aimed at an attacker-controlled cleartext host via
    ALLOSTAT_MCP_URL / ALLOSTAT_MCP_ENDPOINT. If mcp_client can't be imported,
    we fail safe to the prod https default rather than trust the raw env value.
    """
    resolve_endpoint, _ = _shared_endpoint_validator()
    endpoint = resolve_endpoint() if resolve_endpoint is not None else _SAFE_DEFAULT_ENDPOINT
    return _strip_mcp_suffix(endpoint)


def _endpoint_safe_for_bearer(url: str) -> bool:
    """True iff it is safe to attach the subscription Bearer to `url`.

    H-10 defense in depth: https is always safe; plaintext http is safe ONLY
    for a loopback host (local dev), checked via mcp_client's shared
    `_is_loopback_http`. Anything else — remote http, unknown scheme, or an
    unverifiable state (mcp_client import failed) — is refused so the token
    never crosses the wire in cleartext to a non-loopback host.
    """
    if url.startswith("https://"):
        return True
    if url.startswith("http://"):
        _, is_loopback_http = _shared_endpoint_validator()
        if is_loopback_http is None:
            return False
        return bool(is_loopback_http(url))
    return False


def _resolve_bearer() -> str | None:
    """Look up the bearer the wrapper already uses for MCP calls.

    Phase 3 (2026-05-28) — reversed lookup order. The installer rewrites
    `.env` files atomically on every install. The env var (`ALLOSTAT_MCP_TOKEN`)
    depends on a TRUE process restart (Windows scope quirks: closing Claude
    Code's window often preserves env, only logout/reboot guarantees refresh).
    Freshest source wins: check `.env` files FIRST, env var fallback.

    Pre-Phase-3, env var was checked first. When operator ran the installer
    + restarted Claude Code via the window-close-reopen pattern, the wrapper
    subprocess inherited the OLD env-var bearer; .env had the new one. Wrapper
    polled /user/state with stale bearer → 401 → fail-safe-to-active masking
    the auth failure. Empirical evidence: 152 401s observed in operator's
    session post-v1.4.32 install.

    Returns None on miss (caller falls back to fail-safe-to-active).
    """
    import re
    pattern = re.compile(r'(?m)^\s*ALLOSTAT_MCP_TOKEN\s*=\s*"?([^"\n]+)"?\s*$')
    # .env file candidates FIRST (freshest source — rewritten by installer).
    candidates: list[Path] = []
    try:
        candidates.append(Path(__file__).resolve().parent.parent / ".env")
    except (OSError, ValueError):
        pass
    try:
        candidates.append(
            Path.home() / ".claude" / "plugins" / "marketplaces"
            / "local" / "allostat-mcp" / ".env"
        )
    except (OSError, ValueError):
        pass
    for env_path in candidates:
        try:
            if not env_path.is_file():
                continue
            content = env_path.read_text(encoding="utf-8", errors="replace")
            m = pattern.search(content)
            if m:
                bearer = m.group(1).strip()
                if bearer:
                    return bearer
        except (OSError, ValueError):
            continue
    # Fallback: env var. May be stale if Claude Code process pre-dates the
    # latest installer run — `.env` above is preferred precisely because
    # of this.
    bearer = (os.environ.get("ALLOSTAT_MCP_TOKEN") or "").strip()
    if bearer:
        return bearer
    return None


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(ts: Any) -> datetime | None:
    """Parse a cache timestamp. Returns None on any failure.

    Accepts the module's own canonical `%Y-%m-%dT%H:%M:%SZ` first, then any
    ISO-8601 spelling `datetime.fromisoformat` understands (offsets,
    microseconds), normalizing a trailing `Z` and treating a naive stamp as
    UTC — which is what every writer in this codebase means by it.

    R1 (2026-07-20): the strict-only version silently returned None for
    `datetime.now(timezone.utc).isoformat()`, the exact spelling the suite's
    own cache-seeding helper produced. None means "never validated", which is
    the fail-closed answer — so the strictness was safe but wrong, and it hid
    the fact that seeded caches carried no usable validation anchor at all.
    Broadening it is safe here only because the age of the parsed anchor is now
    bounded at the entitlement boundary; before that bound existed, a
    permissive parser would have widened the hole.
    """
    if not isinstance(ts, str):
        return None
    try:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc,
        )
    except (ValueError, TypeError):
        pass
    try:
        parsed = datetime.fromisoformat(ts.strip().replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _validation_anchor(cache: dict[str, Any] | None) -> datetime | None:
    """When was the state in `cache` last CONFIRMED by the server?

    RB-10 grace is anchored to a real successful validation, not to the
    per-refresh `resolved_at` (which advances even on fault reads and would
    otherwise re-arm the window). Prefer the explicit `validated_at`; fall
    back to `resolved_at` only for a legacy cache whose `source == "server"`
    (pre-RB-10 successful writes stamped `resolved_at` at validation time).
    """
    if not isinstance(cache, dict):
        return None
    anchor = _parse_iso(cache.get("validated_at"))
    if anchor is not None:
        return anchor
    if cache.get("source") == "server":
        return _parse_iso(cache.get("resolved_at"))
    return None


def _last_known_good_within_grace(
    prior: dict[str, Any] | None, *, now: datetime,
) -> dict[str, Any] | None:
    """Return the prior cache iff it holds a known state validated within
    `CLIENT_GRACE_SECONDS`. Otherwise None (grace unavailable/exhausted)."""
    if not isinstance(prior, dict):
        return None
    state = prior.get("subscription_state")
    if not isinstance(state, str) or state not in ALL_KNOWN_STATES:
        return None
    anchor = _validation_anchor(prior)
    if anchor is None:
        return None
    age_seconds = (now - anchor).total_seconds()
    if age_seconds <= CLIENT_GRACE_SECONDS:
        return prior
    return None


def _prior_confirmed_terminal(prior: dict[str, Any] | None) -> str | None:
    """Return the prior cache's subscription_state iff it is a server-CONFIRMED
    terminal-inactive state (`lapsed`/`canceled`), else None.

    N-M-01 part (a) (2026-07-15): a confirmed cancellation/lapse is a SETTLED
    FACT. On a control-plane outage that has EXHAUSTED grace, the fault branch
    used to decay ANY prior state to the `"unknown"` fail-closed sentinel —
    which flips `is_terminally_inactive` back to False and silently RE-ENABLES
    the local safety layer for someone who genuinely unsubscribed (reversing the
    operator's locked "safety off on cancel"). We instead carry the confirmed
    terminal state forward across the outage. Only an unvalidated ACTIVE user
    earns the benefit-of-the-doubt decay to `"unknown"`.

    "Genuinely confirmed" = `source` in {"server", "cache_grace",
    "terminal_sticky"}: a fresh 200, a terminal already served via grace from a
    prior 200, or a terminal already carried across a previous outage. A prior
    `"fail_closed"`/`"unknown"` GUESS never promotes itself to a sticky terminal
    (it was never confirmed). Including `"terminal_sticky"` is what lets the
    settled fact survive MORE than one consecutive outage, rather than decaying
    on the second fault because the source is no longer the literal "server".

    A later server-CONFIRMED `active`/re-subscribe (server reachable) still
    overrides everything via the authoritative `server_state` path, so terminal
    never becomes permanent against a fresh confirmation.
    """
    if not isinstance(prior, dict):
        return None
    state = prior.get("subscription_state")
    if not isinstance(state, str) or state not in TERMINAL_INACTIVE_STATES:
        return None
    if prior.get("source") not in ("server", "cache_grace", "terminal_sticky"):
        return None
    return state


def _fetch_state_from_server(
    *, base_url: str, bearer: str, timeout_seconds: float = 5.0,
) -> str:
    """Single HTTP GET against /user/state. Returns the resolved state
    string. Raises on transport or response shape errors so the caller
    can fail-safe-to-active uniformly.

    H-10 (2026-07-14) defense in depth: refuse to attach the Bearer to a
    remote plaintext endpoint even when handed such a `base_url` directly
    (bypassing `_resolve_base_url`). The token must never leave over cleartext
    to a non-loopback host. Raises RuntimeError before any request is made."""
    url = base_url + "/user/state"
    if not _endpoint_safe_for_bearer(url):
        raise RuntimeError(
            "refusing to attach subscription bearer to a remote plaintext "
            "endpoint (would transmit the token in cleartext)"
        )
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {bearer}",
            "User-Agent": "allostat-mcp-wrapper/subscription_gate",
            "Accept": "application/json",
        },
        method="GET",
    )
    with _urlopen_no_redirect(req, timeout=timeout_seconds) as response:
        if response.status != 200:
            raise RuntimeError(f"non-200 from /user/state: {response.status}")
        body = response.read()
    payload = json.loads(body.decode("utf-8", errors="replace"))
    if not isinstance(payload, dict):
        raise RuntimeError("non-dict payload from /user/state")
    state = payload.get("subscription_state")
    if not isinstance(state, str):
        raise RuntimeError("missing or non-string subscription_state in response")
    return state


def _default_fetcher(
    *, base_url: str, bearer: str, timeout_seconds: float, **_ignored: Any,
) -> str:
    """The production fetcher. Kept separate from `_fetch_state_from_server` so
    the injectable seam has a stable keyword signature without widening the
    signature of the function that actually carries the bearer."""
    return _fetch_state_from_server(
        base_url=base_url, bearer=bearer, timeout_seconds=timeout_seconds,
    )


def refresh_subscription_state(
    state_dir: Path,
    *,
    timeout_seconds: float = 5.0,
    append_observation_fn: Any = None,
    fetch_fn: Any = None,
) -> dict[str, Any]:
    """Query the server and write the cache. Returns the cache dict.

    Called by SessionStart only. Other hooks read the cache via
    `is_active_subscription()` and never query the server.

    Fail-CLOSED behavior (RB-10): ANY error (missing bearer, network
    failure, timeout, non-200, malformed/unknown payload) does NOT resolve
    to `'active'` and does NOT overwrite the cache with `'active'`. Instead
    the resolver serves the last-known-good state WHILE it is still within
    `CLIENT_GRACE_SECONDS` of its last successful validation (so a single
    transient blip cannot lock the operator out); once grace is exhausted,
    or when there is no good cache, it resolves to the non-entitled
    `'unknown'` sentinel and the `error` field records the fault. Recovery
    is automatic on the next SessionStart refresh.

    `append_observation_fn` is optional. When provided (signature
    `(state_dir, event_type, details)`), an event
    `subscription_state_resolved` is appended. Hook callers pass
    `local_state.append_observation` here.

    Test seam: pass `fetch_fn` to supply the server's answer directly. There is
    no environment variable that alters this function's behavior — see the
    `_STATE_FETCHER` comment for why the previous one had to be deleted rather
    than gated.
    """
    state_dir = Path(state_dir)
    state_dir.mkdir(parents=True, exist_ok=True)

    now = datetime.now(timezone.utc)
    now_iso = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    # Last-known-good candidate BEFORE we overwrite the cache. Grace is
    # measured against this prior validation, never re-armed by fault reads.
    prior = read_cached_state(state_dir)

    # RB-10 — start fail-CLOSED. Only a fresh successful validation, or a
    # prior good validation still within grace, upgrades off "unknown".
    cache: dict[str, Any] = {
        "subscription_state": FAIL_CLOSED_STATE,
        "resolved_at": now_iso,
        # `validated_at` = last time the SERVER confirmed the state. Set only
        # on a fresh 200, or carried forward (never advanced) on a fault so
        # grace is not re-armed. None when never validated.
        "validated_at": None,
        "source": "fail_closed",
        "error": None,
        # Phase 3 (2026-05-28) — bearer_status distinguishes 401 from other
        # URLErrors. Values:
        #   "valid"     — server returned 200; bearer authenticated
        #   "rejected"  — server returned 401; bearer is stale/bad
        #   "unknown"   — couldn't determine (missing bearer, network down,
        #                 non-200 non-401 response).
        "bearer_status": "unknown",
    }

    base_url = _resolve_base_url()
    bearer = _resolve_bearer()

    # Outcome of the server call: a validated state string, or a fault.
    server_state: str | None = None

    # Resolution order: explicit argument, then the module attribute a test
    # shim may have installed, then production. A bearer is required only for
    # the production fetcher — an injected one IS the source of truth, and the
    # suite deliberately runs with no token and an isolated home.
    fetcher = fetch_fn or _STATE_FETCHER or _default_fetcher

    if fetcher is _default_fetcher and not bearer:
        cache["error"] = "missing_bearer"
    else:
        try:
            state = fetcher(
                state_dir=state_dir,
                base_url=base_url,
                bearer=bearer,
                timeout_seconds=timeout_seconds,
            )
            if state in ALL_KNOWN_STATES:
                server_state = state
                # Server returned 200 + a valid state value → bearer worked.
                cache["bearer_status"] = "valid"
            else:
                cache["error"] = f"unknown_state_value:{state!r}"
                # Server responded but with unexpected payload; treat
                # bearer as valid (auth layer passed) — issue is downstream.
                cache["bearer_status"] = "valid"
        except urllib.error.HTTPError as e:
            # Phase 3: distinguish 401 from other HTTPErrors. Must catch
            # BEFORE URLError since HTTPError subclasses URLError.
            if e.code == 401:
                # Bearer was rejected by server. Mark stale; SessionStart
                # banner composer surfaces the auth-stale fix-hint. Still
                # eligible for grace below so a single transient 401 (e.g. a
                # momentarily stale bearer) does not lock the operator out.
                cache["error"] = "http_401_bearer_rejected"
                cache["bearer_status"] = "rejected"
            else:
                cache["error"] = f"HTTPError:{e.code}:{e.reason}"
        except urllib.error.URLError as e:
            cache["error"] = f"urlerror:{e.reason}"
        except (
            json.JSONDecodeError,
            RuntimeError,
            TimeoutError,
            OSError,
        ) as e:
            cache["error"] = f"{type(e).__name__}:{e}"
        except Exception as e:  # noqa: BLE001 — fail-closed envelope
            cache["error"] = f"unexpected:{type(e).__name__}:{e}"

    if server_state is not None:
        # Fresh successful validation — the authoritative path.
        cache["subscription_state"] = server_state
        cache["source"] = "server"
        cache["validated_at"] = now_iso
        cache["error"] = None
    else:
        # Fault path — fail CLOSED, but honor last-known-good within grace so
        # a single transient error can't hard-lock the operator.
        grace = _last_known_good_within_grace(prior, now=now)
        terminal = _prior_confirmed_terminal(prior)
        if grace is not None:
            cache["subscription_state"] = grace["subscription_state"]
            # Carry the ORIGINAL validation anchor forward (do not advance it),
            # so a persistent outage exhausts grace instead of riding forever.
            carried = _validation_anchor(grace)
            cache["validated_at"] = (
                carried.strftime("%Y-%m-%dT%H:%M:%SZ")
                if carried is not None else None
            )
            cache["source"] = "cache_grace"
        elif terminal is not None:
            # N-M-01 part (a): grace is exhausted, but the prior state was a
            # server-CONFIRMED terminal-inactive (lapsed/canceled). That is a
            # SETTLED FACT — carry it forward instead of decaying to "unknown",
            # which would silently re-enable the local safety layer for a user
            # who genuinely unsubscribed. A fresh server-confirmed active still
            # overrides above (server_state path). Grace is intentionally
            # checked FIRST so a within-grace terminal keeps its "cache_grace"
            # source and existing observability; terminal-sticky only owns the
            # beyond-grace case grace can no longer serve.
            cache["subscription_state"] = terminal
            cache["source"] = "terminal_sticky"
            # Preserve the (now stale) validation anchor for observability only;
            # it can no longer arm grace, but records when the terminal state was
            # last actually confirmed.
            sticky_anchor = _validation_anchor(prior)
            cache["validated_at"] = (
                sticky_anchor.strftime("%Y-%m-%dT%H:%M:%SZ")
                if sticky_anchor is not None else None
            )
        else:
            # No usable cache within grace → remain non-entitled "unknown".
            # Preserve a stale (beyond-grace) validated_at only for
            # observability; it can no longer grant entitlement.
            cache["subscription_state"] = FAIL_CLOSED_STATE
            cache["source"] = "fail_closed"
            stale_anchor = _validation_anchor(prior)
            cache["validated_at"] = (
                stale_anchor.strftime("%Y-%m-%dT%H:%M:%SZ")
                if stale_anchor is not None else None
            )

    # Write the cache atomically (write to temp, rename).
    cache_path = _state_cache_path(state_dir)
    try:
        tmp_path = cache_path.with_suffix(".json.tmp")
        tmp_path.write_text(
            json.dumps(cache, indent=2), encoding="utf-8",
        )
        tmp_path.replace(cache_path)
    except OSError as e:
        # Cache write failed — surface but don't crash. The session still
        # runs (the in-memory `cache` value is the truth for this call).
        cache["cache_write_error"] = str(e)
        try:
            print(
                f"allostat-mcp: subscription_state cache write failed: {e}",
                file=sys.stderr,
            )
        except Exception:  # noqa: BLE001  # H3 audit fix: stderr-print itself raised; nothing else to try
            pass

    if callable(append_observation_fn):
        try:
            append_observation_fn(
                state_dir,
                "subscription_state_resolved",
                details={
                    "subscription_state": cache["subscription_state"],
                    "source": cache["source"],
                    "error": cache.get("error"),
                    "bearer_status": cache.get("bearer_status"),
                },
            )
            # Phase 3 (2026-05-28) — second, distinct observation when the
            # bearer was rejected. Pattern-observer + operator-facing
            # `/allostat-handoff-status` can surface this without scanning
            # subscription_state_resolved for the bearer_status field.
            if cache.get("bearer_status") == "rejected":
                append_observation_fn(
                    state_dir,
                    "subscription_gate_bearer_rejected",
                    details={
                        "resolved_at": cache.get("resolved_at"),
                        # NO bearer value itself — privacy invariant.
                        # Just the marker that 401 was observed.
                    },
                )
        except Exception as obs_err:  # noqa: BLE001
            # Best-effort: observation logging must not break the SessionStart
            # hook chain. Surface to stderr so the failure is visible without
            # crashing the caller (matches H3 audit-fix pattern from S1).
            try:
                print(
                    f"allostat-mcp: subscription_gate observation emit failed: {obs_err}",
                    file=sys.stderr,
                )
            except Exception:  # noqa: BLE001  # H3 audit fix: stderr-only fallback
                pass

    return cache


def read_cached_state(state_dir: Path) -> dict[str, Any] | None:
    """Read the cached subscription_state dict. Returns None if absent or
    malformed. Caller must apply fail-safe-to-active when None."""
    cache_path = _state_cache_path(state_dir)
    try:
        if not cache_path.is_file():
            return None
        content = cache_path.read_text(encoding="utf-8", errors="replace")
        data = json.loads(content)
        if not isinstance(data, dict):
            return None
        return data
    except (OSError, json.JSONDecodeError):
        return None


def is_active_subscription(state_dir: Path) -> bool:
    """Return True iff the cached subscription_state is in ACTIVE_STATES.

    Fail CLOSED (F-04, 2026-07-10): a MISSING or MALFORMED cache returns
    False, not True. The old "defensive net" returned True in both cases — a
    monetization hole: deleting or corrupting `subscription_state.json` read as
    entitled. That net's only legitimate trigger (a paying operator whose cache
    was never written) is already covered upstream — SessionStart's
    `refresh_subscription_state` writes a real state, or the fail-closed
    `"unknown"` sentinel, BEFORE any hook calls this reader — so a missing or
    unparseable cache at read time means an absent/deleted/corrupt file, which
    must gate. Recovery is automatic: the next SessionStart repopulates it.

    The fault-handling that decides entitlement still lives in
    `refresh_subscription_state` (RB-10): on a server error it writes the
    last-known-good state within grace or the non-entitled `"unknown"`
    sentinel — never "active". This reader gates correctly on every non-active
    value: `"unknown"`, `"lapsed"`, `"canceled"`, and now missing/malformed.

    Called by Block 3's hook guards. NOT called by SessionStart (which
    instead invokes `refresh_subscription_state` to populate the cache).

    R1 (2026-07-20) — FRESHNESS IS PART OF THIS DECISION, not a separate one.
    The paragraph above says entitlement fault-handling "still lives in
    `refresh_subscription_state`". That sentence was the defect. It is true
    only while the refresh actually runs, and the refresh is exactly what an
    attacker (or a crash, or a disabled hook) removes. Codex reproduced a cache
    last validated on 2000-01-01 resolving entitled, with no network at all.

    So the reader no longer trusts an upstream writer to have bounded the age
    of what it is reading. A state string and its validation age are resolved
    together, here, at the boundary where entitlement is actually granted.
    """
    return _resolve_entitlement(state_dir, now=datetime.now(timezone.utc))


def _resolve_entitlement(state_dir: Path, *, now: datetime) -> bool:
    """The single entitlement decision: known-active AND recently validated.

    Split out with an injectable `now` so the staleness edges are testable
    without sleeping, and so there is exactly one place that says yes.
    """
    cache = read_cached_state(state_dir)
    if cache is None:
        return False
    state = cache.get("subscription_state")
    if not isinstance(state, str):
        return False
    if state not in ACTIVE_STATES:
        return False

    # A state string with no successful validation behind it is not an
    # entitlement. This covers `validated_at: null`, an unparseable stamp, and
    # any hand-written cache — all of which previously read as entitled.
    anchor = _validation_anchor(cache)
    if anchor is None:
        return False

    age_seconds = (now - anchor).total_seconds()
    if age_seconds > ENTITLEMENT_MAX_VALIDATION_AGE_SECONDS:
        return False
    # Stamped ahead of the clock that reads it: moved clock or forged file.
    if age_seconds < -_FUTURE_ANCHOR_TOLERANCE_SECONDS:
        return False
    return True


# Server-CONFIRMED terminal non-entitlement: the operator went to their account
# and unsubscribed, and the server told us so. This is DISTINCT from the
# fail-closed "unknown" sentinel, which means "we couldn't determine" (a
# control-plane outage, a missing bearer, a network fault) — NOT a known
# unsubscribe. The distinction matters for decoupling safety from entitlement
# (item #5, 2026-07-14): only a confirmed terminal-inactive state triggers the
# operator's silent-removal-on-lapse dormancy; an indeterminate state keeps the
# local safety rules running so a 300s outage can't strip a paying user's
# destructive-command guards.
TERMINAL_INACTIVE_STATES: frozenset[str] = frozenset({"lapsed", "canceled"})


def is_terminally_inactive(state_dir: Path) -> bool:
    """Return True iff the cache holds a server-CONFIRMED terminal-inactive
    state (`lapsed`/`canceled`).

    Missing/malformed cache → False. The fail-closed `"unknown"` sentinel →
    False. Only an explicit lapsed/canceled value (which `refresh_subscription_state`
    writes solely on a successful server validation) returns True. Callers use
    this to decide whether the deactivation DORMANCY (silent removal, no safety)
    applies — everything else runs the safety floor."""
    cache = read_cached_state(state_dir)
    if cache is None:
        return False
    state = cache.get("subscription_state")
    if not isinstance(state, str):
        return False
    return state in TERMINAL_INACTIVE_STATES


def is_bearer_rejected(state_dir: Path) -> bool:
    """Return True iff the cached bearer_status is 'rejected'.

    Phase 3 (2026-05-28). Used by SessionStart banner composer to surface
    the degraded auth-stale banner with fix-hint. Distinct from
    `is_active_subscription` so the two concerns stay separable:
      - subscription_state = what the operator is paying for (active/lapsed)
      - bearer_status = whether the wrapper can talk to the server at all

    Both checks: missing/malformed cache returns False (don't false-positive
    the banner). Only an explicit `"rejected"` value surfaces.
    """
    cache = read_cached_state(state_dir)
    if cache is None:
        return False
    status = cache.get("bearer_status")
    if not isinstance(status, str):
        return False
    return status == "rejected"


def bearer_rejected_fix_hint() -> str:
    """Operator-facing message surfaced in the degraded banner when bearer
    is rejected. Lives here as a constant so wrapper/tests reference one
    source-of-truth."""
    return (
        "Allostat auth stale — fully exit Claude Code "
        "(not just close the window), then run the installer again."
    )
