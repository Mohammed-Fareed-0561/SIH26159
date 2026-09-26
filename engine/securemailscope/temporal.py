"""
Temporal security analysis for Phase 4.

Tracks how an asset's security posture evolves across multiple captures over time.

Uses capture timestamps where available.  When timestamps are missing or
unreliable, temporal comparisons are marked as `NOT_OBSERVABLE`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from .evidence import Confidence
from .posture import (
    DriftResult,
    DriftSeverity,
    PostureSnapshot,
    build_posture_snapshot,
    compare_snapshots,
)


@dataclass
class TemporalPoint:
    """One point in a temporal sequence."""
    capture_id: str
    capture_time: Optional[datetime]
    snapshot: PostureSnapshot
    time_reliable: bool = True


@dataclass
class TemporalAnalysis:
    """
    Temporal analysis of an asset's security posture over time.

    Contains the ordered sequence of posture snapshots and the drift
    results between consecutive snapshots.
    """
    asset_key: str
    points: list[TemporalPoint] = field(default_factory=list)
    drifts: list[DriftResult] = field(default_factory=list)
    temporal_confidence: Confidence = Confidence.HIGH
    limitations: list[str] = field(default_factory=list)

    @property
    def has_temporal_order(self) -> bool:
        """Whether the points are ordered by reliable timestamps."""
        return all(p.time_reliable and p.capture_time is not None for p in self.points)

    @property
    def time_span(self) -> Optional[tuple[datetime, datetime]]:
        """Return (earliest, latest) capture times if available."""
        times = [p.capture_time for p in self.points if p.capture_time is not None]
        if not times:
            return None
        return (min(times), max(times))

    @property
    def overall_severity(self) -> DriftSeverity:
        """Worst drift severity across all temporal points."""
        if not self.drifts:
            return DriftSeverity.NO_MEANINGFUL_CHANGE
        order = {
            DriftSeverity.DEGRADATION: 0,
            DriftSeverity.CONFIGURATION_CHANGE: 1,
            DriftSeverity.IMPROVEMENT: 2,
            DriftSeverity.INCONCLUSIVE: 3,
            DriftSeverity.NO_MEANINGFUL_CHANGE: 4,
        }
        return min(
            (d.overall_severity for d in self.drifts),
            key=lambda s: order.get(s, 5),
        )


def build_temporal_analysis(
    snapshots: list[PostureSnapshot],
    capture_ids: list[str],
    capture_times: list[Optional[datetime]],
    capture_times_suspect: list[bool] = None,
) -> TemporalAnalysis:
    """
    Build a temporal analysis from ordered posture snapshots.

    Parameters
    ----------
    snapshots : ordered list of PostureSnapshot (by capture order)
    capture_ids : corresponding capture IDs
    capture_times : corresponding capture timestamps
    capture_times_suspect : whether each timestamp is suspect (default: all False)
    """
    if capture_times_suspect is None:
        capture_times_suspect = [False] * len(snapshots)

    if len(snapshots) != len(capture_ids) or len(snapshots) != len(capture_times):
        raise ValueError(
            f"Mismatched lengths: {len(snapshots)} snapshots, "
            f"{len(capture_ids)} capture_ids, {len(capture_times)} capture_times"
        )

    analysis = TemporalAnalysis(asset_key=snapshots[0].asset_key if snapshots else "unknown")

    # Build temporal points
    for i, snap in enumerate(snapshots):
        time_reliable = not capture_times_suspect[i]
        point = TemporalPoint(
            capture_id=capture_ids[i],
            capture_time=capture_times[i],
            snapshot=snap,
            time_reliable=time_reliable,
        )
        analysis.points.append(point)

    # Check timestamp reliability
    if not analysis.has_temporal_order:
        analysis.temporal_confidence = Confidence.LOW
        analysis.limitations.append(
            "Capture timestamps are missing or suspect — temporal ordering "
            "may not be accurate. Use 'NOT_OBSERVABLE' as the basis for "
            "time-based conclusions."
        )
    elif len(analysis.points) < 2:
        analysis.temporal_confidence = Confidence.UNKNOWN
        analysis.limitations.append("Only one capture available — no temporal comparison possible.")

    # Compute drift between consecutive points
    for i in range(1, len(analysis.points)):
        before = analysis.points[i - 1].snapshot
        after = analysis.points[i].snapshot

        drift = compare_snapshots(before, after)

        # If timestamps are unreliable, downgrade confidence
        if not analysis.has_temporal_order:
            drift.confidence = Confidence.LOW

        analysis.drifts.append(drift)

    return analysis


def summarize_temporal_changes(analysis: TemporalAnalysis) -> list[str]:
    """
    Produce human-readable summary of temporal changes.

    Each entry describes one drift between consecutive captures.
    """
    summaries = []
    for i, drift in enumerate(analysis.drifts):
        before_cap = analysis.points[i].capture_id
        after_cap = analysis.points[i + 1].capture_id

        if drift.overall_severity == DriftSeverity.NO_MEANINGFUL_CHANGE:
            summaries.append(
                f"Capture {before_cap} → {after_cap}: "
                f"No meaningful posture change."
            )
        else:
            summaries.append(
                f"Capture {before_cap} → {after_cap}: "
                f"{drift.overall_severity.value.upper()} — "
                f"{drift.summary}"
            )
    return summaries
