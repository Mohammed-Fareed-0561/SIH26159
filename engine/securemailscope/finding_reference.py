"""
Finding-to-evidence reference linkage.

Phase 2 produces a state machine with transitions that carry evidence. Phase 3
connects *findings* (from the rule engine) to *transitions*, so every security
finding can be traced:

    Finding → State Transition → EvidenceRef → Observation → Packet/Frame

A ``FindingReference`` is a lightweight, backward-compatible pointer that lives
on a ``Finding`` without altering its existing ``evidence`` field.  Legacy
findings that were produced before transition IDs existed simply leave the new
fields empty — their original ``evidence`` (frames, excerpts) is preserved.

The model never fabricates IDs.  A reference is only created when the
state-machine result for the session can actually tie the finding's rule to a
security-relevant transition.  When the linkage is imprecise we record *why*:
``link_confidence`` explains the gap instead of hiding it.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class LinkConfidence(str, Enum):
    """How precisely a finding maps to a state-machine transition."""

    EXACT = "exact"           # the finding's rule maps 1:1 to a transition
    TRANSITION_INFERRED = "transition_inferred"  # finding is implied by a transition
    NO_TRANSITION = "no_transition"  # finding exists but no transition covers it
    NOT_ATTEMPTED = "not_attempted"  # linkage was not run (legacy / pre-Phase-3)


@dataclass
class FindingReference:
    """
    Structured back-link from a finding to the state-machine evidence that
    supports it.

    Fields are deliberately sparse: only what can be *proven* from the
    state-machine result is populated.  ``link_confidence`` documents the
    quality of the linkage itself.
    """

    finding_id: str                # the rule_id, e.g. SMS-STRIP-002
    rule_id: str
    transition_ids: list[str] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    observation_ids: list[str] = field(default_factory=list)
    packet_refs: list[dict[str, Any]] = field(default_factory=list)
    link_confidence: LinkConfidence = LinkConfidence.NOT_ATTEMPTED
    link_notes: list[str] = field(default_factory=list)


def finding_reference_to_dict(ref: FindingReference) -> dict[str, Any]:
    from .models import _encode
    return _encode(ref)
