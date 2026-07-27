"""Operator-correction classifier — PATCH-189.

Classifies an operator prompt as correction vs non-correction (task /
authorization / brainstorming / Claude Code internal event). Used by
the UserPromptSubmit hook to decide whether to append an
`operator_correction` observation that pattern-observer can fingerprint.

Pre-PATCH-189 the classifier lived inline in the hook with a broad
``\\b(prefer|please|always)\\s+\\w+`` pattern that matched every task prompt
("please check X", "please make Y"). Phase 2 Investigation 1 empirical:
11 events tagged `operator_correction` in a 5-hour autonomous-run window,
only 1 was an actual correction. Pool was poisoned → pattern-observer
couldn't cluster real corrections at the N=5 threshold.

Post-PATCH-189: precision over recall. Each pattern is high-precision —
we'd rather miss some real corrections than admit task prompts. Plus a
blacklist filter for Claude Code internal events (task notifications,
system reminders).

Mirrors server-side `dispatch_tools._CORRECTION_PATTERNS` +
`_is_operator_correction`. If either side updates, update BOTH; the two
sides ship through different pipelines (wrapper bundle vs server
staging→prod) so no shared source. Test coverage on both sides asserts
equivalent behavior.
"""
from __future__ import annotations

import re


# High-precision correction patterns. Each one is chosen to minimize
# false positives at the cost of some recall. New patterns added here
# need to be mirrored to `allostat-mcp/allostat_server/dispatch_tools.py`.
#
# Phase 3.1 refinement (2026-05-24): tightened patterns 1 + 2 to anchor
# at clause boundaries (start of prompt or after sentence-end punctuation).
# Pre-Phase-3.1 the negation imperatives matched anywhere — "stop button",
# "don't worry about that detail" embedded mid-paragraph, "reset the
# database" as a task instruction all classified as corrections. The
# anchor requires the imperative to OPEN a clause, which is the natural
# position for an operator correction.
CORRECTION_PATTERNS: tuple[re.Pattern, ...] = (
    # Negation imperatives anchored to clause start. Eliminates "don't
    # worry" embedded mid-prompt, "stop button" in code discussion,
    # "reset the DB" as task instruction.
    re.compile(
        r"(?:^|[\.\!\?]\s+)\s*(don'?t|do not|stop|never|avoid)\s+\w+",
        re.IGNORECASE | re.MULTILINE,
    ),
    # Reset / undo / revert / scratch that — Phase 3.1: anchored to
    # clause start AND require correction-anaphor suffix (that / the
    # last / the change / etc.) or bare-verb-at-clause-end-punctuation.
    # Pre-Phase-3.1 bare `\b(reset|undo|revert)\b` caught task instructions
    # like "revert PR #123", "reset the database", "undo migration 042" —
    # all of which are TASKS not corrections of Claude's prior turn.
    # Note: bare "reset" dropped entirely as correction signal — too
    # ambiguous with task verbs (reset DB, reset state, reset branch).
    re.compile(
        r"(?:^|[\.\!\?]\s+)\s*("
        r"scratch that"
        r"|undo(?=[\.\!\?,]|$)"
        r"|undo\s+(?:that|the\s+(?:last|change|commit|edit))"
        r"|revert(?=[\.\!\?,]|$)"
        r"|revert\s+(?:that|the\s+(?:last|change|commit|edit))"
        r")\b",
        re.IGNORECASE | re.MULTILINE,
    ),
    # Polite correction wrappers (narrow — "please stop", "please avoid").
    # Replaces pre-PATCH-189 broad `please\s+\w+` which matched every task
    # prompt ("please check X", "please make Y").
    re.compile(
        r"\bplease\s+(stop|don'?t|do not|avoid|never|use less|use fewer|cut|remove|skip)\b",
        re.IGNORECASE,
    ),
    # Explicit-correction language directed at Claude.
    re.compile(
        r"\b(you should have|you shouldn'?t|you should not|you'?re wrong|that'?s incorrect|wrong about|not what i)\b",
        re.IGNORECASE,
    ),
    # First-person preference assertion ("I prefer X", "I'd prefer X").
    # Narrower than pre-PATCH-189 bare `prefer\s+\w+` which caught any
    # third-party reporting of preferences.
    re.compile(r"\bi(?:'?d)?\s+prefer\b", re.IGNORECASE),
    # Standalone "no," / "no." at prompt start (correction marker). Requires
    # terminating PUNCTUATION after "no" (deep-audit 2026-07-02): the prior
    # `no[,.\s]+` also matched a bare space, firing on ordinary task-affirming
    # prose ("no rush", "no need to", "no hurry") that is not a correction.
    # "no, X is wrong" / "no. use Y instead" still classify.
    re.compile(
        r"^\s*no[,.]\s*(?!problem|worry|worries|big deal)\w+",
        re.IGNORECASE,
    ),
)


# Blacklist filter for Claude Code internal events. These look like operator
# prompts at the hook boundary (UserPromptSubmit fires for them) but are
# harness-generated — task notifications, system reminders, slash-command
# boilerplate. Should NEVER be classified as operator behavior.
#
# Phase 2 Investigation 1: 3 of 11 false-positive `operator_correction`
# events were `<task-notification>` blocks. Filter handles those + similar
# Claude Code internal-event wrappers.
NON_CORRECTION_PREFIX_BLACKLIST: tuple[str, ...] = (
    "<task-notification>",
    "<system-reminder>",
    "<command-message>",
    "<command-name>",
    "<bash-",
    "<local-command-stdout>",
    "<local-command-stderr>",
    "[Request interrupted by user]",
)


def is_operator_correction(prompt: str) -> bool:
    """True iff the prompt looks like an operator correction.

    Two-stage gate:
      1. Blacklist check — Claude Code internal events (task notifications,
         system reminders, etc.) are NEVER corrections regardless of what
         text they contain.
      2. Pattern match — high-precision correction markers (PATCH-189
         refined; see module docstring for evidence trail).

    Mirrors server-side `dispatch_tools._is_operator_correction`.
    """
    if not prompt:
        return False
    p_lstrip = prompt.lstrip()
    if any(p_lstrip.startswith(prefix) for prefix in NON_CORRECTION_PREFIX_BLACKLIST):
        return False
    return any(p.search(prompt) for p in CORRECTION_PATTERNS)
