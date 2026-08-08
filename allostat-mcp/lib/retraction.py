"""Allostat retraction — "forget X" that tells the truth about what it forgot.

The defect this closes (2026-08-07): the operator asked for something to be
forgotten. The memory leaf was deleted. The product reported success. The same
content remained, verbatim, in 66 rows of `observations.jsonl` and in 42 audit
files.

That is not a severity question, it is a truthfulness one. It contradicts
principle 1 of `Custody and Constraint`, published under the operator's name on
2026-07-31, which requires the record be held in storage the operator "can read
in full, can amend, and can destroy" — and principle 2, full legibility. A
deletion that leaves verbatim copies in two other stores is not destruction,
and the operator has argued in public that a system claiming this and not
delivering it is the specific failure that paper exists to name.

So this module is built around three rules:

  1. **Enumerate every store first.** A retraction can only be honest about
     stores it knows exist. `inventory()` is the list, and it is the thing to
     extend when a new store is added — not the purge code.
  2. **Report PER STORE, never in aggregate.** "Forgotten" is not a summary; it
     is a claim about each place the fact could live. Each store reports what
     was removed, what was rewritten, and what could not be reached.
  3. **Verify, then claim.** Every store is re-scanned after the purge. A store
     that still matches is reported as FAILED, however the write went. No store
     is described as purged on the strength of having attempted it.

Two categories are deliberately never purged, and both say so at request time
rather than being quietly counted as done:

  - **Claude Code's own transcripts** (`~/.claude/projects/**/*.jsonl`). These
    are the harness's records, not Allostat's store, and the operator's own
    10-year retention rule governs them. Allostat does not reach into them.
  - **Server-side silos.** Until the 0.2.9 purge endpoint is deployed there is
    no client-side path to them, so they are reported as queued, not as done.
"""
from __future__ import annotations

import gzip
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from local_state import jsonl_lock, utc_iso  # noqa: E402

# Stores that exist but are NOT Allostat's to purge. Named explicitly so they
# appear in every report rather than being silently absent from it.
OUT_OF_SCOPE_NOTE_TRANSCRIPTS = (
    "Claude Code's own session transcripts (~/.claude/projects/**/*.jsonl). "
    "These are the harness's records, not Allostat's store, and your 10-year "
    "retention rule governs them. Allostat does not touch them — if you want "
    "them purged, that is a decision about the harness, made deliberately."
)
UNREACHABLE_NOTE_SERVER_SILOS = (
    "Server-side silos. The purge endpoint exists on the server axis (0.2.9) "
    "but is not deployed yet, so there is no path to them from here. Queued, "
    "not done."
)

AUDIT_LOG_NAME = "retraction_log.jsonl"


@dataclass
class StoreResult:
    """What actually happened in one store."""

    store: str
    location: str
    matches_before: int = 0
    lines_removed: int = 0
    files_deleted: int = 0
    files_rewritten: int = 0
    matches_after: int = 0
    status: str = "clean"  # clean|purged|FAILED|unreachable|out_of_scope
    note: str = ""

    @property
    def honest_line(self) -> str:
        if self.status == "out_of_scope":
            return f"  [not Allostat's] {self.store}: {self.note}"
        if self.status == "unreachable":
            return f"  [CANNOT REACH]   {self.store}: {self.note}"
        if self.status == "clean":
            return f"  [nothing there]  {self.store}"
        if self.status == "FAILED":
            return (
                f"  [STILL PRESENT]  {self.store}: {self.matches_after} match(es) "
                f"remain after the purge — NOT forgotten. {self.note}".rstrip()
            )
        bits = []
        if self.lines_removed:
            bits.append(f"{self.lines_removed} line(s) removed")
        if self.files_deleted:
            bits.append(f"{self.files_deleted} file(s) deleted")
        if self.files_rewritten:
            bits.append(f"{self.files_rewritten} file(s) rewritten")
        return f"  [purged]         {self.store}: " + ", ".join(bits or ["done"])


@dataclass
class RetractionReport:
    pattern: str
    dry_run: bool
    stores: list[StoreResult] = field(default_factory=list)
    #: True when the retraction ran but could not write its own audit line.
    #: Surfaced, never swallowed: a deletion nobody can account for is the
    #: mirror image of the custody problem this module closes, so the operator
    #: is told the removal happened without a record of it.
    audit_write_failed: bool = False

    @property
    def fully_purged(self) -> bool:
        """True only when every reachable store verified clean.

        An unreachable store makes this False — that is the point. A retraction
        that could not reach a store has not forgotten the fact, whatever it
        managed elsewhere.
        """
        return all(
            s.status in ("clean", "purged", "out_of_scope") for s in self.stores
        ) and not any(s.status == "unreachable" for s in self.stores)

    def format(self) -> str:
        verb = "WOULD REMOVE" if self.dry_run else "REMOVED"
        lines = [
            f"=== Retraction: {self.pattern!r} ({verb}) ===",
            "",
        ]
        lines.extend(s.honest_line for s in self.stores)
        lines.append("")
        touched = sum(s.matches_before for s in self.stores)
        unreachable = [s for s in self.stores if s.status == "unreachable"]
        if self.dry_run:
            lines.append(f"{touched} match(es) across {len(self.stores)} store(s) inspected.")
            lines.append("Nothing was changed — this was a preview.")
            if unreachable:
                # Say it BEFORE the operator commits, not after. Learning that
                # a deletion was incomplete once it is already irreversible is
                # the worst possible order.
                lines.append(
                    "NOT fully forgotten even if you run this: "
                    + ", ".join(s.store for s in unreachable)
                    + " cannot be reached from here."
                )
        elif self.fully_purged:
            lines.append(
                "Every store Allostat can reach is verified clean. "
                "The stores listed above as out-of-scope are unchanged and are "
                "not Allostat's to change."
            )
        else:
            lines.append(
                "NOT fully forgotten. The stores marked above still hold it, or "
                "could not be reached. Do not treat this as a completed deletion."
            )
        if self.audit_write_failed:
            lines.append(
                "WARNING: the removal happened but its audit line could not be "
                f"written to {AUDIT_LOG_NAME}. This deletion is unrecorded."
            )
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# inventory — the list a retraction is honest about
# ---------------------------------------------------------------------------


def inventory(memory_dir: Path | None, state_dir: Path | None) -> list[tuple[str, Path, str]]:
    """Every store a remembered fact can live in.

    Returns (store_name, path, kind) where kind is "md" | "jsonl" | "gz".
    Extend THIS when a new store is added; the purge code is generic over it,
    so a store added here is purged and reported automatically, and a store
    NOT added here is the exact failure mode this module exists to prevent.
    """
    out: list[tuple[str, Path, str]] = []

    if memory_dir and memory_dir.is_dir():
        for p in sorted(memory_dir.rglob("*.md")):
            if p.name == "MEMORY.md":
                store = "memory index"
            elif "handoffs" in p.relative_to(memory_dir).parts:
                store = "session handoffs"
            elif "_processed" in p.relative_to(memory_dir).parts:
                store = "processed derivatives"
            elif any(
                part.startswith(("_archived_", "_LEGACY", "_PURGE", "_RETIRED"))
                for part in p.relative_to(memory_dir).parts
            ):
                store = "cold storage (archived memory)"
            else:
                store = "memory tree"
            out.append((store, p, "md"))
        for p in sorted(memory_dir.rglob("*.json")):
            out.append(("memory machinery", p, "jsonl"))

    if state_dir and state_dir.is_dir():
        for name, store in (
            ("observations.jsonl", "observation log"),
            ("nudge_history.jsonl", "nudge history"),
            ("pending_dusk_surface.jsonl", "pending surfaces"),
            ("server_instructed_writes.jsonl", "server-instructed write log"),
            ("canonical_resolutions.jsonl", "canonical resolutions"),
        ):
            p = state_dir / name
            if p.is_file():
                out.append((store, p, "jsonl"))
        silos = state_dir / "silos"
        if silos.is_dir():
            for p in sorted(silos.glob("*.jsonl")):
                out.append((f"local silo ({p.stem})", p, "jsonl"))
            for p in sorted(silos.glob("*.json")):
                out.append((f"local silo ({p.stem})", p, "jsonl"))
        audit = state_dir / "audit"
        if audit.is_dir():
            for p in sorted(audit.rglob("*")):
                if p.is_file() and p.suffix in (".md", ".txt"):
                    out.append(("audit files", p, "md"))
        # Rotated archives of any of the above — a fact rotated out of the hot
        # file is still a copy of the fact.
        for p in sorted(state_dir.rglob("*.jsonl.gz")):
            out.append(("rotated archives", p, "gz"))

    return out


def _harness_pointer_paths(memory_dir: Path | None) -> list[Path]:
    """The harness-side mirror of the index, if this project has one.

    `_root_project_memory` regenerates it as a thin pointer, but a pointer
    written before a retraction can still carry the retracted text.
    """
    if memory_dir is None:
        return []
    try:
        import local_state  # noqa: E402
        import session_handoff  # noqa: E402

        project_root = local_state.resolve_project_root(memory_dir) or memory_dir.parent
        harness = session_handoff._harness_memory_root(project_root)
    except Exception:  # noqa: BLE001
        return []
    if not harness or not Path(harness).is_dir():
        return []
    return [p for p in Path(harness).rglob("*.md") if p.is_file()]


# ---------------------------------------------------------------------------
# purge
# ---------------------------------------------------------------------------


def _compile(pattern: str, *, regex: bool) -> re.Pattern[str]:
    return re.compile(pattern if regex else re.escape(pattern), re.IGNORECASE)


def _count_matches_text(text: str, rx: re.Pattern[str]) -> int:
    return sum(1 for line in text.splitlines() if rx.search(line))


#: Files that are STRUCTURE, not content. Emptying one of these must never
#: delete it — `MEMORY.md` is the index every session reads and `_PURPOSE.md`
#: is scaffolding, so removing them because the last entry was retracted would
#: break the tree to honour a request about one fact. Caught by an end-to-end
#: smoke test: retracting the only project deleted the operator's index.
_NEVER_DELETED = frozenset({"MEMORY.md", "_PURPOSE.md", "README.md"})


def _purge_text_file(path: Path, rx: re.Pattern[str], *, dry_run: bool) -> tuple[int, bool, bool]:
    """Drop matching lines. Returns (lines_removed, file_deleted, rewritten).

    A leaf left with nothing but frontmatter and whitespace is deleted: the
    remains of a retracted memory are not a memory, and leaving a hollow file
    behind is how a "deleted" fact stays discoverable by name. Structural files
    (`_NEVER_DELETED`) are rewritten instead — emptied, but still there.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return 0, False, False
    lines = text.splitlines()
    kept = [ln for ln in lines if not rx.search(ln)]
    removed = len(lines) - len(kept)
    if removed == 0:
        return 0, False, False
    if dry_run:
        return removed, False, False

    remainder = "\n".join(kept)
    if _is_hollow(remainder) and path.name not in _NEVER_DELETED:
        try:
            path.unlink()
            return removed, True, False
        except OSError:
            return removed, False, False
    try:
        path.write_text(remainder + ("\n" if text.endswith("\n") else ""), encoding="utf-8")
        return removed, False, True
    except OSError:
        return removed, False, False


def _is_hollow(text: str) -> bool:
    """True when what's left is frontmatter, headings and whitespace only."""
    body = re.sub(r"(?s)\A---\n.*?\n---\n", "", text)
    for line in body.splitlines():
        s = line.strip()
        if s and not s.startswith("#"):
            return False
    return True


def _purge_jsonl(path: Path, rx: re.Pattern[str], *, dry_run: bool) -> tuple[int, bool]:
    """Drop matching JSONL rows. Returns (rows_removed, rewritten).

    Matching is on the raw line, so a fact reaches this whether it sits in a
    payload field, a nested detail, or a free-text excerpt. Taken under the
    same lock the appenders hold.
    """
    try:
        with jsonl_lock(path):
            raw = path.read_text(encoding="utf-8", errors="replace")
            lines = [ln for ln in raw.splitlines() if ln.strip()]
            kept = [ln for ln in lines if not rx.search(ln)]
            removed = len(lines) - len(kept)
            if removed == 0 or dry_run:
                return removed, False
            path.write_text("\n".join(kept) + ("\n" if kept else ""), encoding="utf-8")
            return removed, True
    except OSError:
        return 0, False


def _purge_gz(path: Path, rx: re.Pattern[str], *, dry_run: bool) -> tuple[int, bool]:
    """Same, for a rotated gzip archive."""
    try:
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
            lines = [ln for ln in f.read().splitlines() if ln.strip()]
    except OSError:
        return 0, False
    kept = [ln for ln in lines if not rx.search(ln)]
    removed = len(lines) - len(kept)
    if removed == 0 or dry_run:
        return removed, False
    try:
        with gzip.open(path, "wt", encoding="utf-8") as f:
            f.write("\n".join(kept) + ("\n" if kept else ""))
        return removed, True
    except OSError:
        return removed, False


def _scan_after(path: Path, kind: str, rx: re.Pattern[str]) -> int:
    """Re-read a store and count what survived. This is what turns an attempt
    into a claim."""
    if not path.exists():
        return 0
    try:
        if kind == "gz":
            with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
                return _count_matches_text(f.read(), rx)
        return _count_matches_text(path.read_text(encoding="utf-8", errors="replace"), rx)
    except OSError:
        return 0


def retract(
    pattern: str,
    *,
    memory_dir: Path | None,
    state_dir: Path | None,
    dry_run: bool = True,
    regex: bool = False,
    server_purge_available: bool = False,
) -> RetractionReport:
    """Purge `pattern` from every reachable store and report per store.

    `dry_run=True` (the default) inspects and reports without changing
    anything — a retraction should be previewable, because the operator is
    entitled to see the blast radius of a deletion before it happens.
    """
    rx = _compile(pattern, regex=regex)
    report = RetractionReport(pattern=pattern, dry_run=dry_run)

    grouped: dict[str, StoreResult] = {}

    def _result(store: str, location: str) -> StoreResult:
        if store not in grouped:
            grouped[store] = StoreResult(store=store, location=location)
            report.stores.append(grouped[store])
        return grouped[store]

    targets = inventory(memory_dir, state_dir)
    targets += [("harness index mirror", p, "md") for p in _harness_pointer_paths(memory_dir)]

    for store, path, kind in targets:
        res = _result(store, str(path.parent))
        before = _scan_after(path, kind, rx)
        if before == 0:
            continue
        res.matches_before += before
        if kind == "md":
            removed, deleted, rewritten = _purge_text_file(path, rx, dry_run=dry_run)
            res.lines_removed += removed
            res.files_deleted += int(deleted)
            res.files_rewritten += int(rewritten)
        elif kind == "gz":
            removed, rewritten = _purge_gz(path, rx, dry_run=dry_run)
            res.lines_removed += removed
            res.files_rewritten += int(rewritten)
        else:
            removed, rewritten = _purge_jsonl(path, rx, dry_run=dry_run)
            res.lines_removed += removed
            res.files_rewritten += int(rewritten)
        res.matches_after += _scan_after(path, kind, rx)

    for res in report.stores:
        if res.matches_before == 0:
            res.status = "clean"
        elif dry_run:
            res.status = "purged"  # preview: what WOULD be removed
        elif res.matches_after == 0:
            res.status = "purged"
        else:
            res.status = "FAILED"

    # The two stores that are never silently counted as done.
    report.stores.append(StoreResult(
        store="Claude Code transcripts",
        location="~/.claude/projects",
        status="out_of_scope",
        note=OUT_OF_SCOPE_NOTE_TRANSCRIPTS,
    ))
    report.stores.append(StoreResult(
        store="server-side silos",
        location="(remote)",
        status="purged" if server_purge_available else "unreachable",
        note="" if server_purge_available else UNREACHABLE_NOTE_SERVER_SILOS,
    ))

    if not dry_run:
        report.audit_write_failed = not _append_audit(state_dir, report)
    return report


def _append_audit(state_dir: Path | None, report: RetractionReport) -> bool:
    """Record the retraction itself.

    A deletion with no record of who deleted what, when, is unaccountable — and
    an unaccountable deletion is its own custody problem, the mirror image of
    the one this module closes. The line names the pattern and the counts; it
    does not carry the purged content.
    """
    if state_dir is None:
        return False
    try:
        state_dir.mkdir(parents=True, exist_ok=True)
        path = state_dir / AUDIT_LOG_NAME
        entry = {
            "timestamp": utc_iso(),
            "action": "retraction",
            "pattern": report.pattern,
            "fully_purged": report.fully_purged,
            "stores": [
                {
                    "store": s.store,
                    "status": s.status,
                    "matches_before": s.matches_before,
                    "lines_removed": s.lines_removed,
                    "files_deleted": s.files_deleted,
                    "matches_after": s.matches_after,
                }
                for s in report.stores
            ],
        }
        with jsonl_lock(path):
            with path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        return True
    except OSError:
        # NOT silenced: the caller sets `audit_write_failed` and the report
        # tells the operator the removal happened with no record of it. An
        # unaccountable deletion is the mirror image of the custody problem
        # this module exists to close, so it is surfaced rather than swallowed.
        return False


# ---------------------------------------------------------------------------
# CLI (/allostat-forget)
# ---------------------------------------------------------------------------


def _cli(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="allostat-forget")
    parser.add_argument("pattern", help="text to retract (literal unless --regex)")
    parser.add_argument("--execute", action="store_true",
                        help="actually purge; default is a preview")
    parser.add_argument("--regex", action="store_true")
    parser.add_argument("--memory-dir")
    parser.add_argument("--state-dir")
    args = parser.parse_args(argv)

    import local_state  # noqa: E402
    import memory_lifecycle  # noqa: E402

    memory_dir = Path(args.memory_dir) if args.memory_dir else memory_lifecycle.resolve_memory_dir()
    state_dir = Path(args.state_dir) if args.state_dir else local_state.resolve_state_dir()

    report = retract(
        args.pattern,
        memory_dir=memory_dir,
        state_dir=state_dir,
        dry_run=not args.execute,
        regex=args.regex,
    )
    print(report.format())
    return 0 if (report.dry_run or report.fully_purged) else 1


if __name__ == "__main__":
    raise SystemExit(_cli())
