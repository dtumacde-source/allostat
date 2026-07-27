"""Allostat memory reader — PATCH-138 / v0.6.0 Slice 5.

Read-only pillar accessor that pulls operator-memory context for the
post-tool-use hook to interpolate INTO pillar nudges CLIENT-SIDE.

Privacy lock (per advisor brief 2026-05-20 §1.2 + ship contract
pillar_post_processing_contract.md):
  - Memory CONTENT is read locally only
  - ZERO snippet ever crosses to server
  - Server returns abstract nudge metadata (template ID + interpolation
    targets); wrapper reads the operator's memory, extracts the snippet
    via this module, interpolates into final nudge text BEFORE rendering
    to operator

Ported from the v2.3 plugin's memory_reader.py into the v2.4 wrapper.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path


VOICE_REFERENCE_FILENAMES = (
    "operator_prose.md",
    "operator_voice.md",
    "voice_reference.md",
    "prose.md",
)


@dataclass
class ProjectMemorySnapshot:
    memory_index_text: str = ""
    project_files: list[Path] = field(default_factory=list)
    feedback_files: list[Path] = field(default_factory=list)
    voice_reference_path: Path | None = None
    memory_root: Path | None = None


def _safe_mtime(p: Path) -> float:
    """File mtime, or 0.0 if it can't be stat'd (so a vanished/locked file
    sorts last instead of breaking the sort)."""
    try:
        return p.stat().st_mtime
    except OSError:
        return 0.0


def read_project_memory(memory_root: Path) -> ProjectMemorySnapshot:
    """Return a snapshot of the operator's project memory tree.

    Args:
        memory_root: path to ~/.claude/projects/<sanitized-cwd>/memory/

    Returns:
        ProjectMemorySnapshot with file lists + index text + voice path.
    """
    snap = ProjectMemorySnapshot()
    if not memory_root.is_dir():
        return snap
    snap.memory_root = memory_root

    index = memory_root / "MEMORY.md"
    if index.exists():
        try:
            snap.memory_index_text = index.read_text(encoding="utf-8-sig", errors="replace")
        except OSError:
            pass

    try:
        # Sort project files most-recent-first: glob order is filesystem-
        # arbitrary (nondeterministic across platforms), but consumers such as
        # nudge_context_from_memory document "the most-recent project_*.md's
        # first locked decision." mtime desc, filename as a stable tiebreak.
        project_files = [
            p for p in memory_root.glob("project_*.md") if p.is_file()
        ]
        project_files.sort(key=lambda p: (-_safe_mtime(p), p.name))
        snap.project_files.extend(project_files)
        for p in memory_root.glob("feedback_*.md"):
            if p.is_file():
                snap.feedback_files.append(p)
    except OSError:
        pass

    snap.voice_reference_path = get_voice_reference_path(memory_root)
    return snap


def get_voice_reference_path(memory_root: Path) -> Path | None:
    if not memory_root.is_dir():
        return None
    for name in VOICE_REFERENCE_FILENAMES:
        candidate = memory_root / name
        if candidate.is_file():
            return candidate
    try:
        for p in memory_root.iterdir():
            if not p.is_file():
                continue
            if p.suffix != ".md":
                continue
            if p.name.endswith("_prose.md") or p.name.endswith("_voice.md"):
                return p
    except OSError:
        pass
    return None


# B1 (2026-06-26) — core-view formatter. Hard cap so the injected memory index
# has a context backstop. NOTE (2026-07-08): the memory index is still injected
# in full here and, unlike the handoff (now a lean resume core + pointer), still
# rides the oversized session-start payload past the ~2KB inline cap. Trimming
# this to rule-headers + a pointer is the queued follow-up to the handoff fix.
_CORE_INDEX_MAX_CHARS = 8000

# Section headers whose BODIES collapse to count+pointer in the core view (G5:
# behavioral-vs-reference split — behavioral stays always-on, these collapse).
_COLLAPSIBLE_SECTIONS = ("Project", "Reference")

# B2 (G6 — keep behavioral rules individually addressable, tightened): each
# behavioral entry keeps its `[title](file)` link but the post-em-dash hook tail
# trims to this many words. The full hook stays in the leaf file frontmatter
# (lossless); the core just carries enough to recognize the rule.
_BEHAVIORAL_HOOK_MAX_WORDS = 8

# Long human titles dominate the always-on layer's size. The leaf FILENAME is
# the canonical addressable id (every rule stays named); the human title in the
# core caps to this many chars so the behavioral layer fits the session-start
# budget. The full title stays in MEMORY.md on disk (lossless).
_BEHAVIORAL_TITLE_MAX_CHARS = 50


def _trim_link_title(head: str, max_chars: int = _BEHAVIORAL_TITLE_MAX_CHARS) -> str:
    """Trim the `[title]` portion of a `- [title](file.md)` head to max_chars,
    leaving the `(file.md)` link target intact so the rule stays addressable."""
    import re
    m = re.match(r"^(\s*[-*+]\s*\**\[)(.*?)(\]\([^)]*\.md\)\**.*)$", head, re.DOTALL)
    if not m:
        return head
    prefix, title, suffix = m.group(1), m.group(2), m.group(3)
    if len(title) <= max_chars:
        return head
    return prefix + title[:max_chars].rstrip() + "…" + suffix


def _compress_behavioral_line(line: str, max_hook_words: int = _BEHAVIORAL_HOOK_MAX_WORDS) -> str:
    """B2 — trim the hook tail of a behavioral bullet line to max_hook_words,
    preserving the leading indent and the `[title](file)` link verbatim so the
    rule stays individually addressable. Non-entry lines (not a bullet, or no
    recognizable hook tail) pass through unchanged.

    The hook tail is whatever follows the closing `)` of the `(file)` link, then
    the first separator (em-dash `—` or a spaced hyphen ` - `). Handles both the
    plain `- [t](f) — hook` and bold `- **[t](f)** — hook` / `- **[t](f)** - hook`
    entry forms found in the live index.
    """
    stripped = line.lstrip()
    if not stripped.startswith(("- ", "* ", "+ ")):
        return line
    indent = line[: len(line) - len(stripped)]

    # Locate the LINK close — the `)` that closes `](<file>.md)`. Titles can
    # contain their own parens/em-dashes (e.g. "(2026-05-18 P3 standing rule)"),
    # so we must anchor on the `.md)` link terminator, NOT the first `)`.
    import re
    m = re.search(r"\]\([^)]*\.md\)", stripped)
    if not m:
        return line
    link_close = m.end() - 1  # index of the closing ")"
    head = stripped[: link_close + 1]
    rest = stripped[link_close + 1:]  # e.g. "** — hook" or " — hook" or " - hook"

    # Always trim an over-long human title (filename stays intact → still named).
    head = _trim_link_title(head)

    # Find the first separator in the rest: em-dash, or a spaced hyphen.
    em = rest.find("—")
    hy = rest.find(" - ")
    candidates = [c for c in (em, hy) if c >= 0]
    if not candidates:
        # No hook tail — keep the (possibly title-trimmed) head as the entry.
        return f"{indent}{head}{rest.rstrip()}"
    sep_idx = min(candidates)
    sep_len = 1 if rest[sep_idx] == "—" else 3  # "—" vs " - "
    head_extra = rest[:sep_idx]  # bold-close markers etc. between link and sep
    hook = rest[sep_idx + sep_len:]

    words = hook.strip().split()
    if len(words) > max_hook_words:
        hook_render = " ".join(words[:max_hook_words]).rstrip(".,;: ") + "…"
    else:
        hook_render = hook.strip()
    return f"{indent}{head}{head_extra.rstrip()} — {hook_render}"


def _count_entry_lines(section_body: str) -> int:
    """Count bullet entry lines (`- ...`) in a collapsed section body."""
    return sum(
        1 for ln in section_body.splitlines()
        if ln.lstrip().startswith(("-", "*", "+"))
    )


def _render_core_index(
    memory_text: str,
    memory_root: Path,
    max_chars: int = _CORE_INDEX_MAX_CHARS,
) -> str:
    """B1 — collapse the Project/Reference layers of MEMORY.md to count+pointer.

    G5 (behavioral-vs-reference split): the behavioral layer (everything up to
    and including the `## Feedback` section) injects verbatim — those rules are
    always-on and lazy-loading them reinstates the drift they prevent. The
    `## Project` and `## Reference` sections collapse to a single
    `## <Name> (N) — full list in MEMORY.md (read on demand)` header so their
    bodies (project/reference filenames) load on demand instead of every session.

    Caveat #1 (advisor signoff, NON-NEGOTIABLE): an explicit on-disk pointer line
    is appended — agents don't read files they don't know exist. If the rendered
    core exceeds max_chars, it is truncated WITH the pointer preserved.

    Lossless: nothing is dropped from MEMORY.md on disk; this only changes what
    is INJECTED. The full list stays a Read away at the pointer path.
    """
    on_disk_path = memory_root / "MEMORY.md"
    pointer_line = (
        f"\n> Full index on disk: `{on_disk_path}` — read it for the full "
        "project/reference entries (collapsed above).\n"
    )

    lines = memory_text.splitlines()
    n = len(lines)

    # Collapse the leading PREAMBLE — the orientation prose between the H1 title
    # and the first `## ` section header. It's non-load-bearing narration (tree
    # description, consolidation notes, repo list) that costs hundreds of chars
    # every session; the behavioral RULES live in the sections below. Keep the
    # H1 title (+ any first-line title) and replace the rest of the preamble
    # with a one-line on-disk note. Lossless — full preamble stays in MEMORY.md.
    first_section = next(
        (k for k, ln in enumerate(lines)
         if ln.lstrip().startswith("## ") and not ln.lstrip().startswith("### ")),
        None,
    )
    out: list[str] = []
    i = 0
    if first_section is not None and first_section > 0:
        # Keep the leading H1 title line(s) only (up to the first blank line).
        kept_preamble: list[str] = []
        for k in range(first_section):
            if lines[k].startswith("# ") and not lines[k].startswith("## "):
                kept_preamble.append(lines[k])
            elif kept_preamble and not lines[k].strip():
                break
        out.extend(kept_preamble)
        out.append(
            "_(orientation preamble omitted from the injected core — read the "
            "full MEMORY.md on disk)_"
        )
        i = first_section

    while i < n:
        line = lines[i]
        stripped = line.strip()
        # Is this a collapsible top-level section header?
        collapsed_name = None
        if stripped.startswith("## "):
            heading = stripped[3:].strip()
            for name in _COLLAPSIBLE_SECTIONS:
                # Match "## Project" / "## Project (8)" / "## Reference ..." etc.
                if heading == name or heading.startswith(name + " ") or heading.startswith(name + "("):
                    collapsed_name = name
                    break
        if collapsed_name is not None:
            # Gather this section's body up to the next top-level "## " header.
            j = i + 1
            body_lines: list[str] = []
            while j < n:
                nxt = lines[j].lstrip()
                if nxt.startswith("## ") and not nxt.startswith("### "):
                    break
                body_lines.append(lines[j])
                j += 1
            count = _count_entry_lines("\n".join(body_lines))
            out.append(
                f"## {collapsed_name} ({count}) — full list in MEMORY.md "
                "(read on demand)"
            )
            i = j
            continue
        # Behavioral layer (everything not in a collapsed section): keep the
        # rule individually addressable but tighten the hook tail (B2 / G6).
        out.append(_compress_behavioral_line(line))
        i += 1

    core = "\n".join(out).rstrip() + "\n" + pointer_line
    if len(core) > max_chars:
        # Truncate the behavioral block but ALWAYS keep the pointer line so the
        # agent can recover the full index on disk (caveat #1).
        budget = max_chars - len(pointer_line) - len("\n... [truncated]\n")
        if budget < 0:
            budget = 0
        core = core[:budget].rstrip() + "\n... [truncated]\n" + pointer_line
    return core


def build_memory_index_context(memory_root: Path) -> str | None:
    """Labeled additionalContext block for the project MEMORY.md INDEX.

    Injects the CORE VIEW (B1, 2026-06-26): the behavioral layer verbatim, with
    the Project/Reference sections collapsed to count+pointer and an explicit
    on-disk pointer to the full index. Leaf files (feedback_*/project_*/
    reference_*) live in the same folder and load on demand. Returns None when
    there is no MEMORY.md or it is empty. Never raises on a missing dir
    (resolve_memory_dir may point at a not-yet-scaffolded folder;
    read_project_memory returns an empty snapshot).
    """
    snap = read_project_memory(memory_root)
    text = (snap.memory_index_text or "").strip()
    if not text:
        return None
    core_view = _render_core_index(text, memory_root)
    return (
        f"=== Allostat project memory (index) - {memory_root} ===\n"
        "The project's MEMORY.md index (core view — behavioral rules in full; "
        "project/reference collapsed to a count + on-disk pointer). Leaf files "
        "(feedback_*/project_*/reference_*) live in this folder and load on "
        "demand.\n\n"
        f"{core_view}"
    )


# ---------- locked decisions extractor ----------

_LOCKED_HEADINGS = (
    "locked decisions", "locked", "settled decisions",
    "decisions locked", "lock", "do not change",
)
_INLINE_LOCK_RE = re.compile(
    r"\([^)]*?(?:locked|do not change|do not edit)[^)]*?\)",
    re.IGNORECASE,
)


def extract_locked_decisions(file_path: Path) -> list[str]:
    """Find bullet items under 'Locked decisions' headings, plus inline
    lines with (locked YYYY-MM-DD) markers. Returns deduped list, order
    preserved.
    """
    if not file_path.is_file():
        return []
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    decisions: list[str] = []
    in_locked_section = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            heading = stripped.lstrip("#").strip().lower()
            in_locked_section = any(h in heading for h in _LOCKED_HEADINGS)
            continue
        if in_locked_section and stripped.startswith(("-", "*", "+")):
            item = stripped[1:].strip()
            if item:
                decisions.append(item)
            continue
        if _INLINE_LOCK_RE.search(stripped) and stripped:
            decisions.append(stripped)

    seen: set = set()
    out: list[str] = []
    for d in decisions:
        if d not in seen:
            seen.add(d)
            out.append(d)
    return out


# ---------- pillar context surface ----------

_DECISION_AWARE_PILLARS = ("volume-control", "stress-response", "confidence-gate",
                            "volume_control", "stress_response", "confidence_gate")
_VOICE_AWARE_PILLARS = ("voice-keeper", "voice_keeper")


def nudge_context_from_memory(
    memory_root: Path,
    pillar: str,
    max_chars: int = 180,
) -> str | None:
    """Return a one-line context fragment to interpolate into a pillar's
    nudge. None when nothing relevant lives in memory.

    Voice-aware pillars get a voice-reference hint.
    Decision-aware pillars get the most-recent project_*.md's first locked
    decision.

    Bounded by max_chars (180 per v2.3 default).
    """
    snap = read_project_memory(memory_root)
    if snap.memory_root is None:
        return None

    if pillar in _VOICE_AWARE_PILLARS:
        if snap.voice_reference_path is not None:
            hint = f"voice reference: {snap.voice_reference_path.name} — match cadence + register"
            return hint[:max_chars]
        return None

    if pillar in _DECISION_AWARE_PILLARS:
        for project_file in snap.project_files:
            decisions = extract_locked_decisions(project_file)
            if decisions:
                snippet = decisions[0]
                hint = f"locked: {snippet}"
                return hint[:max_chars]
        return None

    return None


# ---------- pillar-post-processing interpolation ----------

def interpolate_nudge(
    nudge_text: str,
    memory_root: Path,
    pillar: str,
) -> str:
    """Take server-returned nudge text and interpolate operator-memory
    context client-side. Looks for the marker `{{memory_context}}` and
    substitutes the memory snippet.

    If no marker, returns nudge_text unchanged (server didn't request
    interpolation for this nudge).

    Per advisor §1.2: this happens WRAPPER-SIDE. Server never sees the
    interpolation result; operator's memory content never crosses to server.
    """
    marker = "{{memory_context}}"
    if marker not in nudge_text:
        return nudge_text
    snippet = nudge_context_from_memory(memory_root, pillar) or ""
    return nudge_text.replace(marker, snippet)
