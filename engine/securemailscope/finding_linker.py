"""
Finding-to-transition linker.

Connects rule-engine findings to the Phase 2 state-machine transitions that
produced them.  Each finding gets a ``FindingReference`` that traces:

    Finding -> State Transition -> EvidenceRef -> Observation -> Packet/Frame

Legacy findings that cannot be linked precisely retain their existing
``evidence`` field — the linkage is purely additive.
"""
from __future__ import annotations

from typing import Optional

from .finding_reference import FindingReference, LinkConfidence
from .models import Finding, Session


# Maps rule_id patterns to the state-machine transitions that produced them.
# This is a heuristic mapping — not every finding has a unique transition,
# and the engine documents the confidence of each link.
_RULE_TRANSITION_MAP: dict[str, list[tuple[str, str]]] = {
    # STARTTLS offered but not requested
    "SMS-STRIP-002": [("STARTTLS_OFFERED", "AUTH"),
                       ("STARTTLS_OFFERED", "MAIL_FROM"),
                       ("STARTTLS_OFFERED", "QUIT")],
    # STARTTLS requested but not established
    "SMS-STRIP-003": [("TLS_NEGOTIATING", "ERROR"),
                       ("TLS_NEGOTIATING", "INCOMPLETE")],
    # Server does not advertise STARTTLS
    "SMS-STRIP-004": [("CAPABILITIES", "STARTTLS_OFFERED")],
    # AUTH before TLS
    "SMS-AUTH-001": [("CAPABILITIES", "AUTH"),
                       ("STARTTLS_OFFERED", "AUTH")],
    # TLS handshake failure
    "SMS-STRIP-001": [("TLS_NEGOTIATING", "TLS_ESTABLISHED")],
    # Weak cipher
    "SMS-CIPH-001": [("TLS_ESTABLISHED", "AUTH")],
    "SMS-CIPH-002": [("TLS_ESTABLISHED", "AUTH")],
    # Weak TLS version
    "SMS-PROTO-001": [("TLS_ESTABLISHED", "AUTH")],
    "SMS-PROTO-002": [("TLS_ESTABLISHED", "AUTH")],
    # Certificate issues
    "SMS-CERT-001": [("TLS_ESTABLISHED", "AUTH")],
    "SMS-CERT-002": [("TLS_ESTABLISHED", "AUTH")],
    "SMS-CERT-003": [("TLS_ESTABLISHED", "AUTH")],
    "SMS-CERT-004": [("TLS_ESTABLISHED", "AUTH")],
    "SMS-CERT-005": [("TLS_ESTABLISHED", "AUTH")],
    "SMS-CERT-006": [("TLS_ESTABLISHED", "AUTH")],
    "SMS-CERT-007": [("TLS_ESTABLISHED", "AUTH")],
    "SMS-CERT-008": [("TLS_ESTABLISHED", "AUTH")],
    # OK finding (secure configuration)
    "SMS-OK-001": [("TLS_ESTABLISHED", "AUTH")],
    # Protocol security
    "SMS-PROTO-003": [("CONNECT", "BANNER")],
    "SMS-PROTO-004": [("STARTTLS_OFFERED", "AUTH")],
    # Key exchange
    "SMS-KEX-001": [("TLS_ESTABLISHED", "AUTH")],
    # Key strength
    "SMS-KEY-001": [("TLS_ESTABLISHED", "AUTH")],
    "SMS-KEY-002": [("TLS_ESTABLISHED", "AUTH")],
    # Policy
    "SMS-POL-001": [("CONNECT", "BANNER")],
    "SMS-POL-002": [("CONNECT", "BANNER")],
    # Forward secrecy
    "SMS-FS-001": [("TLS_ESTABLISHED", "AUTH")],
}


def link_finding_to_transitions(
    finding: Finding,
    session: Session,
    state_result: Optional[object] = None,
) -> FindingReference:
    """
    Create a FindingReference linking a finding to state-machine transitions.

    Parameters
    ----------
    finding : the Finding to link
    session : the Session containing findings and state machine results
    state_result : the StateMachineResult for this session (may be None)

    Returns
    -------
    FindingReference — backward compatible; legacy fields are preserved on the
    Finding object, this is a parallel pointer.
    """
    ref = FindingReference(finding_id=finding.rule_id, rule_id=finding.rule_id)

    if state_result is None:
        ref.link_confidence = LinkConfidence.NOT_ATTEMPTED
        ref.link_notes.append("No state machine result available for this session")
        return ref

    # Collect transition IDs and their evidence
    transitions = getattr(state_result, "transitions", [])
    sec_transitions = getattr(state_result, "security_relevant_transitions", [])

    # Map rule_id to expected transition pairs
    expected_pairs = _RULE_TRANSITION_MAP.get(finding.rule_id, [])

    if not expected_pairs:
        # Unknown rule — try to infer from security-relevant transitions
        ref.link_confidence = LinkConfidence.TRANSITION_INFERRED
        ref.link_notes.append(
            f"Rule {finding.rule_id} has no explicit transition mapping; "
            f"linking to security-relevant transitions by inference"
        )
        for tr in sec_transitions:
            ref.transition_ids.append(tr.transition_id)
            for obs_ref in tr.observation_refs:
                ref.evidence_ids.append(obs_ref.evidence_id)
                ref.observation_ids.append(obs_ref.evidence_id)
                if obs_ref.excerpt:
                    ref.packet_refs.append({"frame": None, "excerpt": obs_ref.excerpt[:80]})
        if not ref.transition_ids:
            ref.link_confidence = LinkConfidence.NO_TRANSITION
            ref.link_notes.append("No security-relevant transitions found to link")
        return ref

    # Try to find exact matching transitions
    matched = False
    for tr in transitions:
        for exp_from, exp_to in expected_pairs:
            if tr.from_state == exp_from and tr.to_state == exp_to:
                ref.transition_ids.append(tr.transition_id)
                for obs_ref in tr.observation_refs:
                    ref.evidence_ids.append(obs_ref.evidence_id)
                    ref.observation_ids.append(obs_ref.evidence_id)
                    ref.packet_refs.append({
                        "frame": tr.frame,
                        "frame_precision": getattr(tr, "frame_precision", "UNKNOWN"),
                        "excerpt": obs_ref.excerpt[:80] if obs_ref.excerpt else None,
                    })
                matched = True

    if matched:
        ref.link_confidence = LinkConfidence.EXACT
    else:
        # The transition exists in the state machine but doesn't match the
        # expected pair — e.g. rule fired but the state sequence is different.
        ref.link_confidence = LinkConfidence.TRANSITION_INFERRED
        ref.link_notes.append(
            f"Finding {finding.rule_id} fired but no exact matching transition "
            f"({expected_pairs}) was found in the observed state sequence"
        )
        # Still link to any security-relevant transition that covers this area
        for tr in sec_transitions:
            if any(et in (tr.from_state, tr.to_state) for et, _ in expected_pairs):
                ref.transition_ids.append(tr.transition_id)

    return ref


def link_all_findings(
    session: Session,
    state_result: Optional[object] = None,
) -> list[FindingReference]:
    """Link every finding on a session to its state-machine evidence."""
    refs: list[FindingReference] = []
    for finding in session.findings:
        ref = link_finding_to_transitions(finding, session, state_result)
        refs.append(ref)
    return refs
