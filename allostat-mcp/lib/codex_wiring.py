"""Codex install/uninstall — marker-fenced block writer for ~/.codex/config.toml.

The Codex adapter (1.4.56) routes hook events + the MCP server into Codex via a
block in `~/.codex/config.toml`. This module owns that block: it writes it on
install and removes it on uninstall, symmetrically, using a single pair of fence
markers so the two operations can never drift apart.

Design invariants (advisor 2026-07-06 installer asks):

  1. MARKER-FENCED, never a TOML reformat. We only ever add/remove the text
     BETWEEN the fences; every other line in config.toml is byte-preserved. A
     partial or hand-edited config is never corrupted — worst case the block is
     re-appended fresh. (install is idempotent: any existing fenced block is
     replaced, not duplicated.)
  2. ENV-ONLY TOKEN, structurally. render_block() accepts only the env-var NAME
     (token_env_var) — there is no parameter to pass a raw secret, so the
     installer physically cannot write a plaintext token into config.toml. Codex
     reads the bearer from the environment via `bearer_token_env_var`.
  3. WRAPPER-ONLY on uninstall. remove_block() strips exactly this managed block
     (the MCP registration + the four hooks). It touches nothing else — no user
     memory, no state, no other config. Removing the block fully disables the
     Codex integration; the user's files are never in scope here.

All functions are pure text transforms (no I/O) except read_config/write_config,
so the logic is unit-testable without a real config.toml. Output is verified to
parse as TOML by the tests (tomllib).
"""
from __future__ import annotations

import json
import os
import re
import shlex
import stat
import tempfile
from pathlib import Path
from pathlib import PurePosixPath
import tomllib

# The fence pair. Stable forever — install and uninstall both key on these, and
# they double as a human "managed, do not edit" signal. Never change the text of
# an already-shipped marker or old installs become un-uninstallable.
_BEGIN = "# >>> allostat (managed block — `allostat uninstall` removes this; do not edit) >>>"
_END = "# <<< allostat <<<"

# The four harness-agnostic hooks the Codex adapter wires (same wrapper hooks
# Claude Code uses, invoked with --harness codex).
_HOOKS = ("SessionStart", "Stop", "PreToolUse", "UserPromptSubmit")
_HOOK_SCRIPT = {
    "SessionStart": "session-start.py",
    "Stop": "stop.py",
    "PreToolUse": "pre-tool-use.py",
    "UserPromptSubmit": "user-prompt-submit.py",
}

_DEFAULT_SERVER_URL = "https://mcp.allostat.ai/mcp"
_DEFAULT_TOKEN_ENV_VAR = "ALLOSTAT_MCP_TOKEN"

# C-01: Codex documents hook timeouts in seconds.  Fifteen seconds is the
# backstop above the wrapper's internal ~12s MCP retry budget, so a hung network
# call cannot block a Codex turn indefinitely.
_HOOK_TIMEOUT_SECONDS = 15


def _toml_literal(s: str) -> str:
    """Emit `s` as a valid TOML string, preferring backslash-free literals.

    - No apostrophe → single-quoted literal `'...'` (the common case; matches the
      official Codex config example and needs no escaping).
    - Apostrophe present → a single-quoted literal would terminate early, so use
      a multi-line literal `'''...'''`, which permits stray `'` and `"` (only a
      run of `'''` terminates it). Still backslash-free.
    - Pathological `'''` in the path → fall back to a TOML basic string with
      backslash/quote escaping (correctness over prettiness).
    """
    if any(ord(char) < 32 or ord(char) == 127 for char in s):
        return json.dumps(s, ensure_ascii=False)
    if "'" not in s:
        return f"'{s}'"
    if "'''" not in s and not s.startswith("'") and not s.endswith("'"):
        return f"'''{s}'''"
    esc = s.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{esc}"'


class CodexPathNotExpressible(ValueError):
    """A path cannot be written into a Codex hook command string.

    Raised instead of emitting a command Codex would silently fail to run. The
    message is operator-facing: the installer surfaces it verbatim and aborts.
    """


def _get_short_name(native_path: str) -> str | None:
    """Raw GetShortPathNameW. Returns None unless it yields a DIFFERENT name.

    The Win32 call only succeeds for a path that already exists, and a volume
    with 8.3 generation disabled returns the long name unchanged — both are
    reported as None so the caller can fall back or fail loudly.
    """
    if os.name != "nt":
        return None
    try:
        import ctypes
        from ctypes import wintypes

        get_short = ctypes.windll.kernel32.GetShortPathNameW
        get_short.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
        get_short.restype = wintypes.DWORD
        needed = get_short(native_path, None, 0)
        if not needed:
            return None
        buf = ctypes.create_unicode_buffer(needed)
        if not get_short(native_path, buf, needed):
            return None
        short = buf.value
    except Exception:
        return None
    if not short or short == native_path:
        return None
    return short


def _windows_short_path(value: str) -> str | None:
    """Return a space-free Windows 8.3 rendering of `value`, or None.

    8.3 short names are space-free by construction (`C:\\Program Files` →
    `C:\\PROGRA~1`), which is the only way to name a whitespace-bearing path in a
    command string Codex splits on whitespace.

    GetShortPathNameW only works on paths that EXIST, and the config block is
    written for hook scripts that may not be on disk yet (or at all, in tests).
    So we shorten the longest existing ANCESTOR and re-append the remaining
    components verbatim. The hook filenames Allostat ships contain no spaces, so
    the result is space-free whenever the existing part could be shortened.

    Returns None — never raises — when this is not Windows, nothing in the chain
    exists, or 8.3 generation is disabled on the volume (`fsutil 8dot3name`).
    """
    if os.name != "nt":
        return None
    native = value.replace("/", "\\")
    current = Path(native)
    tail: list[str] = []
    while True:
        try:
            exists = current.exists()
        except OSError:
            return None
        if exists:
            break
        if current.parent == current:
            return None
        tail.append(current.name)
        current = current.parent
    short = _get_short_name(str(current))
    if short is None:
        return None
    for name in reversed(tail):
        short = f"{short}\\{name}"
    return short


def _codex_command_token(value: str) -> str:
    """Return `value` as one token Codex's hook-command splitter can recover.

    Codex does NOT perform shell quote processing on a hook `command`. Measured
    against codex-cli 0.145.0 on 2026-07-26 (see
    `audits/20260726_codex_hook_failure_measured_corrections.md`): the string is split on
    whitespace and quote characters are kept LITERALLY, so

      * quoting a path corrupts it — the quote characters land in the filename
        and the hook process never launches, and
      * a path containing whitespace cannot be expressed as one token at all.

    (A `command` + `args` array was also tested: Codex ignores `args` silently
    and reports the hook Completed while running nothing. Never emit that form.)

    So tokens are emitted BARE. Whitespace is first retried as the Windows 8.3
    short form; if that is unavailable the path is not expressible and we raise
    rather than write a config that cannot work.
    """
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise CodexPathNotExpressible(
            f"Path contains a control character and cannot be used in a Codex "
            f"hook command: {value!r}"
        )
    if _codex_token_is_clean(value):
        return value

    # Only whitespace and a double quote get here (see _codex_token_is_clean),
    # and 8.3 shortening is the one escape hatch for either: `C:\Program Files`
    # becomes `C:\PROGRA~1`. It cannot help with an apostrophe — that is a legal
    # 8.3 character, so `O'Brien` shortens to itself — which is exactly why the
    # apostrophe is handled by parser tolerance instead of being refused here.
    short = _windows_short_path(value)
    if short is not None:
        short = short.replace("\\", "/")
        if _codex_token_is_clean(short):
            return short

    offender = "whitespace" if any(c.isspace() for c in value) else "a quote character"
    raise CodexPathNotExpressible(
        f"Codex splits a hook command on whitespace and never unquotes it, so a "
        f"path containing {offender} cannot be wired:\n"
        f"    {value}\n"
        "Windows 8.3 short-name generation would normally solve this but is "
        "unavailable here (the path may not exist yet, or 8.3 names are disabled "
        "on this volume — check `fsutil 8dot3name query`).\n"
        "Fix: install Allostat and Python under a path with no spaces or quotes, "
        "or re-enable 8.3 name generation, then re-run the installer."
    )


def _codex_token_is_clean(value: str) -> bool:
    """True when `value` can be emitted bare AND parsed back symmetrically.

    An APOSTROPHE is permitted: Codex keeps it literally, and `_parse_hook_command`
    falls back to whitespace splitting when shlex chokes on the unbalanced quote,
    so `C:/Users/O'Brien/...` round-trips. 8.3 shortening cannot help there — an
    apostrophe is a legal 8.3 character, so `O'Brien` is left as-is — and refusing
    would lock a legitimately-named user out of the product entirely.

    A DOUBLE quote is still refused: illegal in Windows filenames, and genuinely
    ambiguous to recover on POSIX.
    """
    return not any(char.isspace() for char in value) and '"' not in value


_SANDBOX_HEADER = "[sandbox_workspace_write]"


def has_foreign_sandbox_table(config_text: str) -> bool:
    """True if config.toml declares `[sandbox_workspace_write]` OUTSIDE our fence.

    `sandbox_workspace_write` is a single top-level TOML table, so emitting our
    own while the user already has one produces a duplicate-key file that Codex
    refuses to load — strictly worse than not writing it. When this returns True
    the installer must leave the user's table alone and tell them what to add,
    which also honours the invariant that nothing outside the fences is touched.
    """
    remainder = _strip_existing(config_text)
    return any(line.strip() == _SANDBOX_HEADER for line in remainder.splitlines())


def render_sandbox_table(writable_root: str | Path) -> list[str]:
    """The `[sandbox_workspace_write]` lines granting hooks what they need.

    Codex runs hooks with `writable_roots: []` and `network_access: false`
    unless told otherwise. Allostat's hooks persist state under the install root
    and call the MCP server, so BOTH fail silently without this table.

    Scope is exactly the Allostat state directory — never a wider root, and
    never `sandbox_mode = danger-full-access`. The path is emitted as a TOML
    LITERAL string: a basic string would read `C:\\Users\\...` as an escape and
    `\\U` is a unicode escape, which breaks the file outright.
    """
    # Use the path exactly as given: str(Path) already yields the platform's
    # native separators, and rewriting separators here would corrupt a POSIX
    # path when the installer happens to run on Windows.
    return [
        "",
        _SANDBOX_HEADER,
        "network_access = true",
        f"writable_roots = [{_toml_literal(str(writable_root))}]",
    ]


def render_block(
    hooks_dir: str | Path,
    python_exe: str | Path,
    *,
    server_url: str = _DEFAULT_SERVER_URL,
    token_env_var: str = _DEFAULT_TOKEN_ENV_VAR,
    sandbox_writable_root: str | Path | None = None,
) -> str:
    """Render the managed config.toml block (between the fences, inclusive).

    hooks_dir is the directory that directly contains the hook .py files — the
    caller supplies it so this module is agnostic to install layout (the INSTALLED
    plugin flattens to <plugin>/hooks/, while the monorepo is <repo>/wrapper/hooks/).

    NOTE the signature: there is NO raw-token parameter, only token_env_var
    (a NAME). The block wires Codex to read the bearer from the environment —
    a plaintext secret can never be written here (env-only-token invariant).

    The Codex hook `command` is a single TOML STRING that Codex splits on
    WHITESPACE, with no shell quote processing whatsoever (measured against
    codex-cli 0.145.0; see `_codex_command_token`). Each path is therefore
    emitted BARE — quoting it would put literal quote characters into the
    filename and the hook would never launch — and the whole value is emitted as
    a TOML *literal* string (single quotes; no backslash escaping, and Windows
    paths are forward-slash-normalized). A path that cannot be expressed without
    whitespace raises CodexPathNotExpressible so the installer aborts instead of
    writing a config that silently does nothing. (H-23, corrected 1.4.74.)
    """
    hd = str(hooks_dir).replace("\\", "/").rstrip("/")
    py = str(python_exe).replace("\\", "/")
    lines = [
        _BEGIN,
        "[mcp_servers.allostat]",
        f'url = "{server_url}"',
        f'bearer_token_env_var = "{token_env_var}"',
    ]
    py_token = _codex_command_token(py)
    for hook in _HOOKS:
        script = _HOOK_SCRIPT[hook]
        # Bare tokens: Codex splits on whitespace and never unquotes.
        cmd = (
            f"{py_token} "
            f"{_codex_command_token(f'{hd}/{script}')} --harness codex"
        )
        lines += [
            "",
            f"[[hooks.{hook}]]",
            f"[[hooks.{hook}.hooks]]",
            'type = "command"',
            f"command = {_toml_literal(cmd)}",
            f"timeout = {_HOOK_TIMEOUT_SECONDS}",
        ]
    if sandbox_writable_root is not None:
        lines += render_sandbox_table(sandbox_writable_root)
    lines.append(_END)
    return "\n".join(lines)


# --- unfenced-orphan cleanup (dual-hook self-heal) -------------------------
#
# Before the fences existed (codex-adapter dev slices), the installer wrote
# Allostat's four Codex hooks UNFENCED. The fence-keyed strip below is blind to
# those, so a re-install stacked a fresh fenced set on top of the orphan and
# every Codex event fired TWICE. We now also remove any [[hooks.*]] table group
# whose command invokes one of Allostat's hook scripts with `--harness codex`,
# fenced or not — never touching genuine third-party hooks (different command).

# A top-level Codex hook parent header, e.g. `[[hooks.SessionStart]]` — no
# further dotted key (that would be the nested `.hooks` child, absorbed below).
_HOOK_PARENT_RE = re.compile(r"^\[\[hooks\.[^.\[\]]+\]\]$")
_HOOK_CHILD_RE = re.compile(r"^\[\[hooks\.[^.\[\]]+\.hooks\]\]$")


def _parse_hook_command(stripped: str) -> list[str] | None:
    """Parse one TOML ``command = ...`` line into argv.

    Invalid or multi-line values are not claimed.  Cleanup must prefer leaving
    ambiguous foreign configuration in place over deleting it.
    """
    if not re.match(r"^command\s*=", stripped):
        return None
    try:
        value = tomllib.loads(f"x = {stripped.split('=', 1)[1].strip()}")["x"]
        if not isinstance(value, str):
            return None
        try:
            argv = shlex.split(value, posix=True)
        except ValueError:
            # An unbalanced quote — e.g. the apostrophe in a bare
            # `C:/Users/O'Brien/...` path, which 1.4.74 emits deliberately.
            # Codex itself just splits on whitespace, so do the same rather than
            # decline to recognise a command we wrote. Ownership is still gated
            # by _is_owned_hook_path, so this cannot claim a foreign hook.
            return value.split()
        # Pre-fence Windows documentation emitted unquoted backslash paths.
        # POSIX shlex treats those backslashes as escapes; retry with Windows-
        # compatible tokenization only when that loss is observable.
        if "\\" in value and not any("\\" in token for token in argv):
            argv = shlex.split(value, posix=False)
            argv = [
                token[1:-1]
                if len(token) >= 2
                and token[0] == token[-1]
                and token[0] in {'"', "'"}
                else token
                for token in argv
            ]
        return argv
    except (KeyError, TypeError, ValueError, tomllib.TOMLDecodeError):
        return None


def _is_owned_hook_path(raw_path: str) -> bool:
    """Return True only for hook locations Allostat has actually shipped.

    A script basename plus ``--harness codex`` is not an ownership marker: a
    third party can legitimately use the same basename and flag.  Recognized
    paths are restricted to the public plugin/install roots and the historical
    monorepo development root used by the pre-fence adapter.
    """
    normalized = raw_path.replace("\\", "/")
    parts = tuple(part.casefold() for part in PurePosixPath(normalized).parts)
    if len(parts) < 2 or parts[-2] != "hooks":
        return False
    if parts[-1] not in {script.casefold() for script in _HOOK_SCRIPT.values()}:
        return False

    # Current Claude marketplace and standalone Codex install roots.
    if "allostat-mcp" in parts[:-2]:
        return True

    # Earliest public documentation used ~/.claude/plugins/allostat/hooks.
    joined = "/".join(parts)
    if "/.claude/plugins/allostat/hooks/" in f"/{joined}/":
        return True

    # Pre-fence development adapters ran directly from allostat-mono*/wrapper.
    return (
        parts[-3:-1] == ("wrapper", "hooks")
        and any(part.startswith("allostat-mono") for part in parts[:-3])
    )


def _is_allostat_hook_command(stripped: str) -> bool:
    """True only for an owned, exact Codex hook invocation.

    Fenced blocks are owned by their markers.  This predicate is intentionally
    narrower because it is used to delete *unfenced* legacy groups.
    """
    argv = _parse_hook_command(stripped)
    if argv is None or len(argv) < 4:
        return False
    if argv[-2:] != ["--harness", "codex"]:
        return False
    return _is_owned_hook_path(argv[-3])


def _filter_hook_parent_group(group: list[str]) -> list[str]:
    """Return `group` with only its Allostat-owned `[[hooks.<Name>.hooks]]` child
    sub-groups removed, keeping the parent header and any third-party siblings.

    A parent `[[hooks.<Name>]]` may hold MULTIPLE nested `[[hooks.<Name>.hooks]]`
    children. Dropping the whole parent because ONE child is ours would delete
    unrelated third-party sibling handlers, so we filter at child granularity:

      - No owned command anywhere in the group → return it byte-for-byte.
      - Otherwise keep the parent header + preamble + every non-owned child, and
        drop each child sub-group that carries an Allostat hook command.
      - If EVERY child is owned (the pure pre-fence orphan shape), return [] so
        the caller drops the now-empty parent too (no stranded `[[hooks.*]]`)."""
    if not any(_is_allostat_hook_command(g.strip()) for g in group):
        return group  # no Allostat residue here — byte-preserve

    # Lines between the parent header and its first child stay with the parent.
    first_child = 1
    while first_child < len(group) and not _HOOK_CHILD_RE.match(group[first_child].strip()):
        first_child += 1
    preamble = group[:first_child]

    # Split the remainder into child sub-groups, each headed by a `.hooks` table.
    children: list[list[str]] = []
    k = first_child
    while k < len(group):
        m = k + 1
        while m < len(group) and not _HOOK_CHILD_RE.match(group[m].strip()):
            m += 1
        children.append(group[k:m])
        k = m

    kept = [c for c in children if not any(_is_allostat_hook_command(g.strip()) for g in c)]
    if not kept:
        # Owned command lives in the preamble (no children) or every child is
        # ours — nothing third-party survives, so drop the whole parent group.
        return []
    result = list(preamble)
    for child in kept:
        result.extend(child)
    return result


def _strip_unfenced_allostat_hooks(config_text: str) -> str:
    """Remove Allostat-owned hook entries, preserving genuine third-party hooks
    and every other line byte-for-byte.

    A parent group runs from a `[[hooks.<Name>]]` header through its nested
    `[[hooks.<Name>.hooks]]` children + keys, up to the next parent header, any
    other top-level table header, or EOF. Removal is at CHILD granularity: only
    the `[[hooks.<Name>.hooks]]` sub-groups whose command is an Allostat hook are
    dropped. A third-party child under the SAME parent survives (the parent is
    retained while any sibling remains); a parent whose children are all ours is
    dropped entirely so no empty `[[hooks.*]]` is stranded. A third-party
    `[[hooks.SessionStart]]` with a different command is left byte-for-byte."""
    lines = config_text.splitlines()
    out: list[str] = []
    i, n = 0, len(lines)
    while i < n:
        if _HOOK_PARENT_RE.match(lines[i].strip()):
            j = i + 1
            while j < n:
                s = lines[j].strip()
                if _HOOK_PARENT_RE.match(s):
                    break
                if s.startswith("[") and not _HOOK_CHILD_RE.match(s):
                    break
                j += 1
            kept = _filter_hook_parent_group(lines[i:j])
            if kept:
                out.extend(kept)
            else:
                # whole group removed — drop the blank line(s) it owned above it
                while out and out[-1].strip() == "":
                    out.pop()
            i = j
            continue
        out.append(lines[i])
        i += 1
    return "\n".join(out)


_MCP_ALLOSTAT_HEADER = "[mcp_servers.allostat]"


def _has_allostat_orphan(config_text: str) -> bool:
    """True if config_text carries any Allostat Codex residue that cleanup owns.

    Two shapes, either of which is ours to remove: (1) an Allostat hook command
    (fenced or unfenced), and (2) an MCP-only wiring — the `[mcp_servers.allostat]`
    table on its own, with no fence and no hooks (a partially-applied install, or
    one whose hooks were hand-deleted). `allostat` is our reserved MCP namespace,
    so any such table is Allostat's. Detecting the table here is what lets
    remove_block/uninstall SEE an MCP-only install as something to strip — the
    strip side (_strip_orphan_mcp_table) already knew how to remove it. (M-05.)"""
    for line in config_text.splitlines():
        s = line.strip()
        if _is_allostat_hook_command(s):
            return True
        if s == _MCP_ALLOSTAT_HEADER:
            return True
    return False


def _find_fence_end(lines: list[str], start: int) -> int | None:
    """Index of the next _END fence at or after `start`, or None if unterminated."""
    for k in range(start, len(lines)):
        if lines[k].strip() == _END:
            return k
    return None


def _strip_orphan_mcp_table(config_text: str) -> str:
    """Remove an UNFENCED `[mcp_servers.allostat]` table — the residue a partial
    (missing-_END) block leaves once its dangling fence marker is dropped.
    `allostat` is our reserved MCP namespace, so any such table is ours to remove;
    leaving it would collide with the fresh table a re-install appends (a
    duplicate-key TOML error).

    Table scope follows TOML semantics: the table runs from its header until the
    NEXT `[header]` (or EOF) — blank lines and comments interspersed among its
    keys are INSIDE the table, not its end (M-05). The prior version broke on the
    first blank/comment, so a comment among the keys stranded every later key,
    which then re-attached to the PRECEDING third-party table (neighbor
    pollution) and left Allostat residue behind. We remove the header through the
    LAST key line before the next header; any trailing blanks/comments after that
    last key belong to the following table and are preserved. Third-party tables
    and every other line are byte-preserved."""
    lines = config_text.splitlines()
    out: list[str] = []
    i, n = 0, len(lines)
    while i < n:
        if lines[i].strip() == _MCP_ALLOSTAT_HEADER:
            # drop the blank line(s) this table owned above it
            while out and out[-1].strip() == "":
                out.pop()
            # Scan to the next table header; track the last KEY line so trailing
            # blanks/comments (owned by the following table) are not swallowed.
            j = i + 1
            last_key = i  # at minimum remove the header itself
            while j < n:
                s = lines[j].strip()
                if s.startswith("["):
                    break  # next table header ends this table's scope
                if s != "" and not s.startswith("#"):
                    last_key = j  # a key line extends the removed region
                j += 1
            i = last_key + 1  # resume after the last removed key
            continue
        out.append(lines[i])
        i += 1
    return "\n".join(out)


def _strip_existing(config_text: str) -> str:
    """Remove existing Allostat Codex wiring, returning the remainder.

    Passes, in order: the fenced managed block(s); any orphan `[mcp_servers.allostat]`
    table; then any UNFENCED orphan Allostat hook groups (pre-fence installs — the
    dual-hook self-heal). Tolerant of: no block, one block, (defensively) multiple
    blocks from a buggy prior write, and a PARTIAL block whose closing _END fence is
    missing (an interrupted write or a user who deleted the "do not edit" line). An
    unterminated _BEGIN never swallows to EOF — only the dangling marker is dropped,
    and the orphan passes then clean our tables — so trailing third-party config is
    preserved (M-05). Trims surrounding blank lines the wiring owned so repeated
    install/uninstall cycles don't accrete whitespace. Third-party content is
    byte-preserved.
    """
    lines = config_text.splitlines()
    out: list[str] = []
    i, n = 0, len(lines)
    while i < n:
        stripped = lines[i].strip()
        if stripped == _BEGIN:
            # drop a single trailing blank line we may have added before the block
            while out and out[-1].strip() == "":
                out.pop()
            end = _find_fence_end(lines, i + 1)
            if end is not None:
                i = end + 1  # skip the whole fenced block, inclusive of _END
            else:
                # Missing _END: do NOT latch to EOF (the M-05 corruption). Drop
                # only this dangling marker; the orphan passes below strip our
                # residual tables and every foreign line survives.
                i += 1
            continue
        if stripped == _END:
            # a stray closing fence with no opening _BEGIN — drop the marker only
            i += 1
            continue
        out.append(lines[i])
        i += 1
    text = _strip_orphan_mcp_table("\n".join(out))
    return _strip_unfenced_allostat_hooks(text)


def install_block(config_text: str, block: str) -> str:
    """Idempotently install `block` into config_text.

    Removes any prior managed block first (so re-install replaces, never
    duplicates), then appends the fresh block separated by exactly one blank
    line, with a single trailing newline. Every non-block line is preserved.
    """
    base = _strip_existing(config_text).rstrip("\n")
    if base:
        return base + "\n\n" + block + "\n"
    return block + "\n"


def remove_block(config_text: str) -> tuple[str, bool]:
    """Remove the managed block. Returns (new_text, removed?).

    removed=False means there was no Allostat wiring at all — no fenced block and
    no unfenced orphan hooks (already uninstalled / never installed) — the caller
    treats that as a benign no-op, not an error.
    """
    had = _BEGIN in config_text or _has_allostat_orphan(config_text)
    if not had:
        return config_text, False
    new_text = _strip_existing(config_text).rstrip("\n") + "\n"
    return new_text, True


# --- thin file I/O wrappers (the only impure functions) ---------------------


def read_config(config_path: str | Path) -> str:
    """Read config.toml text, or '' if it doesn't exist yet (fresh Codex)."""
    p = Path(config_path)
    if not p.is_file():
        return ""
    return p.read_text(encoding="utf-8")


def _config_path_kind(path: Path) -> str:
    """Classify `path` WITHOUT following links — mirrors the standalone
    installer's `_lstat_kind` (install/codex/install.py). Returns one of
    "missing", "file", "directory", "symlink", or "special". A Windows directory
    junction is reported as "symlink" so it is refused on the same footing as a
    POSIX symlink."""
    is_junction = getattr(path, "is_junction", None)
    if callable(is_junction):
        try:
            if is_junction():
                return "symlink"
        except OSError:
            return "special"
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return "missing"
    except OSError:
        return "special"
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISREG(mode):
        return "file"
    return "special"


def write_config(config_path: str | Path, text: str) -> None:
    """Write config.toml text atomically, creating parent dirs if needed.

    Stages to a temp file in the SAME directory, then os.replace() onto the
    destination — a same-filesystem rename, atomic on POSIX and Windows. An
    interrupted write (crash, full disk, kill) can never leave a half-written
    config.toml: the live file is only ever the complete old bytes or the complete
    new bytes. This is the write side of the M-05 fix — the strip side tolerates a
    partial block; this side stops one from being produced. (Default newline
    handling matches the prior Path.write_text — `\\n` → os.linesep on write.)

    REFUSE symlink/junction (and other non-regular) config paths (M-12). A
    config.toml that is a symlink is externally managed — it points at a target
    the operator owns elsewhere. os.replace() onto the link path would swap the
    LINK for a fresh regular file, silently severing that external management and
    leaving the real target stale. The standalone installer already refuses this
    (install/codex/install.py:875-877, which rejects any config whose lstat kind
    is not "missing"/"file"); the unified install/uninstall path must match. Both
    install() and uninstall() route through here, so this one gate covers both.
    """
    p = Path(config_path)
    kind = _config_path_kind(p)
    if kind not in {"missing", "file"}:
        raise ValueError(
            f"Refusing to write Codex config at {p}: path is a {kind}, not a "
            "regular file. A symlink/junction config is externally managed; "
            "os.replace would sever the link instead of updating its target. "
            "(M-12.)"
        )
    p.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=str(p.parent), prefix=".allostat-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.replace(tmp_name, p)
    except BaseException:
        # Best-effort: on a failed commit, drop the temp file so no partial write
        # lingers; a cleanup error here must not mask the original write error,
        # which we re-raise. The live config is never touched (the atomic swap).
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def install(config_path: str | Path, hooks_dir: str | Path, python_exe: str | Path,
            *, server_url: str = _DEFAULT_SERVER_URL,
            token_env_var: str = _DEFAULT_TOKEN_ENV_VAR,
            sandbox_writable_root: str | Path | None = None) -> bool:
    """Install the Codex block into config.toml (idempotent, marker-fenced).

    hooks_dir directly contains the hook .py files (installed: <plugin>/hooks).

    Returns True when the `[sandbox_workspace_write]` table was written inside
    the fence. Returns False when `sandbox_writable_root` was requested but the
    user already declares that table themselves: we then leave THEIR table
    untouched (a second one would make config.toml unparseable) and the caller
    tells them what to add. With `sandbox_writable_root=None` the return is
    False and means only "not requested".
    """
    existing = read_config(config_path)
    wrote_sandbox = (
        sandbox_writable_root is not None
        and not has_foreign_sandbox_table(existing)
    )
    block = render_block(
        hooks_dir,
        python_exe,
        server_url=server_url,
        token_env_var=token_env_var,
        sandbox_writable_root=sandbox_writable_root if wrote_sandbox else None,
    )
    write_config(config_path, install_block(existing, block))
    return wrote_sandbox


def uninstall(config_path: str | Path) -> bool:
    """Remove the Codex block from config.toml. Returns True if a block was
    removed, False if none was present (benign). Never touches other config."""
    text = read_config(config_path)
    new_text, removed = remove_block(text)
    if removed:
        write_config(config_path, new_text)
    return removed


def _cli(argv: list[str]) -> int:
    """Thin CLI so the PowerShell/shell installers can invoke this module:
        codex_wiring.py install   <config> <hooks_dir> <python_exe> [token_env_var]
        codex_wiring.py uninstall <config>
    hooks_dir directly contains the hook .py files (installed: <plugin>/hooks).
    Note: no raw-token argument exists — install only ever takes the env-var name."""
    if len(argv) >= 4 and argv[0] == "install":
        env_var = argv[4] if len(argv) > 4 else _DEFAULT_TOKEN_ENV_VAR
        install(argv[1], argv[2], argv[3], token_env_var=env_var)
        print(f"Codex block installed in {argv[1]}")
        return 0
    if len(argv) == 2 and argv[0] == "uninstall":
        print(f"Codex block removed: {uninstall(argv[1])}")
        return 0
    print("usage: codex_wiring.py {install <config> <plugin_root> <python> [env_var] "
          "| uninstall <config>}", file=__import__("sys").stderr)
    return 2


if __name__ == "__main__":
    import sys
    sys.exit(_cli(sys.argv[1:]))
