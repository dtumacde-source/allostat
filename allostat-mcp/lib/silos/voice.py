"""Voice silo — recurring voice-drift patterns + canonical voice samples.

Ported from the v2.3 plugin's lib/silos/voice.py into the v2.4 wrapper.
Second silo class (after drift). Follows the same shape as drift.py.

Signal class: a voice violation pattern keeps recurring (operator
strikes the same kind of phrasing repeatedly). Resolution: a canonical
sample of how the operator's voice should sound for this class.
On future generation, recall this silo before producing similar prose.

Token construction MUST mirror server-side
`recall_silos.compute_class_tokens` for class_name="voice" exactly:

    return [violation_type, sample_text[:60].lower()]

Drift between wrapper + server breaks recall — keep in lockstep.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from silo_base import SiloEntry, SiloFingerprint, query_silo, write_entry


@dataclass
class VoiceFingerprint:
    """Inputs that identify a voice-drift pattern."""

    violation_type: str  # e.g., "ai_slop", "hedge", "sycophancy"
    sample_text: str  # the offending snippet (first 60 chars used for token)


@dataclass
class VoiceResolution:
    """Canonical voice sample + source for a violation type."""

    canonical_sample: str  # the right way to phrase it
    canonical_source: str  # voice-reference file or memory ref


def _to_silo_fp(fp: VoiceFingerprint) -> SiloFingerprint:
    """Build the SiloFingerprint for a voice case.

    Token construction MUST mirror server's compute_class_tokens("voice")
    exactly: [violation_type, sample_text[:60].lower()].
    """
    return SiloFingerprint(
        class_name="voice",
        key_tokens=[fp.violation_type, fp.sample_text[:60].lower()],
        raw_excerpt=fp.sample_text,
    )


def record_voice_resolution(
    silo_path: Path,
    fingerprint: VoiceFingerprint,
    resolution: VoiceResolution,
    session_id: str,
) -> None:
    """Inscribe a resolved voice-drift case to the silo.

    Args:
        silo_path: Path to voice.jsonl (use silo_base.resolve_silo_path).
        fingerprint: The voice case being recorded.
        resolution: The canonical voice correction.
        session_id: The session in which the resolution landed.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    entry = SiloEntry(
        fingerprint=_to_silo_fp(fingerprint),
        resolution={
            "canonical_sample": resolution.canonical_sample,
            "canonical_source": resolution.canonical_source,
        },
        success_marker="voice_corrected",
        timestamp=now,
        session_id=session_id,
        fire_count=1,
        last_fire=now,
    )
    write_entry(silo_path, entry)


def query_voice(
    silo_path: Path,
    fingerprint: VoiceFingerprint,
    top_n: int = 5,
) -> list[SiloEntry]:
    """Local wrapper-side query against the voice silo."""
    return query_silo(silo_path, _to_silo_fp(fingerprint), top_n=top_n)
