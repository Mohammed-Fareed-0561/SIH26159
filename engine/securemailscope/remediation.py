"""
Remediation verification for Phase 5.

Determines whether previously observed security problems were:
- FIXED
- PARTIALLY_FIXED
- STILL_PRESENT
- UNVERIFIABLE

A finding disappearing from a later capture is NOT sufficient evidence
that the problem was fixed — verification must consider capture
completeness, evidence quality, and whether the relevant condition
was actually observable.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional

from .evidence import Confidence
from .models import CaptureCompleteness
from .posture import (
    AssetIdentity,
    AssetIdentityConfidence,
    PostureSnapshot,
)
from .security_controls import ControlId, ControlStatus


class RemediationStatus(str, Enum):
    """Outcome of remediation verification."""
    FIXED = "fixed"
    PARTIALLY_FIXED = "partially_fixed"
    STILL_PRESENT = "still_present"
    UNVERIFIABLE = "unverifiable"


@dataclass
class VerificationEvidence:
    """Evidence supporting a verification result."""
    before_session_ids: list[str] = field(default_factory=list)
    after_session_ids: list[str] = field(default_factory=list)
    before_observation_ids: list[str] = field(default_factory=list)
    after_observation_ids: list[str] = field(default_factory=list)
    before_frames: list[int] = field(default_factory=list)
    after_frames: list[int] = field(default_factory=list)
    before_capture_id: Optional[str] = None
    after_capture_id: Optional[str] = None


@dataclass
class BeforeAfterPair:
    """A paired before/after posture comparison for one asset."""
    asset_key: str
    asset_identity: AssetIdentity
    identity_confidence: AssetIdentityConfidence
    before_snapshot: PostureSnapshot
    after_snapshot: PostureSnapshot
    before_capture_id: str
    after_capture_id: str
    before_time: Optional[datetime] = None
    after_time: Optional[datetime] = None
    time_ordered: bool = True
    limitations: list[str] = field(default_factory=list)


@dataclass
class RemediationVerification:
    """
    Result of verifying whether a finding/control was remediated.

    Key principle: a finding disappearing from a later capture is NOT
    sufficient evidence of remediation.  The AFTER capture must provide
    sufficient relevant evidence — the relevant protocol must have been
    observed, the TLS handshake must have been complete, and the specific
    security condition must have been observable.
    """
    verification_id: str
    asset_key: str
    finding_rule_id: Optional[str] = None      # the finding being verified
    control_id: Optional[str] = None           # the control being verified
    status: RemediationStatus = RemediationStatus.UNVERIFIABLE
    confidence: Confidence = Confidence.UNKNOWN
    reason: str = ""
    explanation: str = ""
    evidence: VerificationEvidence = field(default_factory=VerificationEvidence)
    limitations: list[str] = field(default_factory=list)
    before_status: Optional[str] = None        # control status before
    after_status: Optional[str] = None         # control status after
    before_finding_severity: Optional[str] = None
    after_finding_severity: Optional[str] = None
    before_completeness: Optional[str] = None
    after_completeness: Optional[str] = None
    # Whether the relevant condition was observable in the AFTER capture
    after_condition_observable: bool = False
    # Whether the relevant protocol was observed in the AFTER capture
    after_protocol_observed: bool = False
    # Frame precision of the evidence
    before_frame_precision: Optional[str] = None  # EXACT / FALLBACK / UNKNOWN
    after_frame_precision: Optional[str] = None
    # Temporal info
    before_time: Optional[datetime] = None
    after_time: Optional[datetime] = None
    time_ordered: bool = True


@dataclass
class RemediationReport:
    """Complete remediation verification report for an asset."""
    asset_key: str
    asset_identity: AssetIdentity
    pair: BeforeAfterPair
    verifications: list[RemediationVerification] = field(default_factory=list)
    overall_status: RemediationStatus = RemediationStatus.UNVERIFIABLE
    confidence: Confidence = Confidence.UNKNOWN
    summary: str = ""
    limitations: list[str] = field(default_factory=list)
    # Regression detection
    regressions: list[RemediationVerification] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Core verification logic
# ---------------------------------------------------------------------------

# Maps finding rule IDs to the control they primarily affect
_FINDING_TO_CONTROL_MAP = {
    "SMS-AUTH-001": ControlId.AUTHENTICATION_ORDERING,
    "SMS-STRIP-001": ControlId.STARTTLS_SECURITY,
    "SMS-STRIP-002": ControlId.STARTTLS_SECURITY,
    "SMS-STRIP-003": ControlId.STARTTLS_SECURITY,
    "SMS-STRIP-004": ControlId.STARTTLS_SECURITY,
    "SMS-PROTO-001": ControlId.TLS_VERSION_SECURITY,
    "SMS-PROTO-002": ControlId.TLS_VERSION_SECURITY,
    "SMS-PROTO-003": ControlId.TRANSPORT_ENCRYPTION,
    "SMS-PROTO-004": ControlId.TRANSPORT_ENCRYPTION,
    "SMS-CIPH-001": ControlId.CIPHER_SECURITY,
    "SMS-CIPH-002": ControlId.CIPHER_SECURITY,
    "SMS-CIPH-003": ControlId.TLS_VERSION_SECURITY,
    "SMS-CIPH-004": ControlId.CIPHER_SECURITY,
    "SMS-CIPH-005": ControlId.CIPHER_SECURITY,
    "SMS-CIPH-006": ControlId.CIPHER_SECURITY,
    "SMS-CERT-001": ControlId.CERTIFICATE_SECURITY,
    "SMS-CERT-002": ControlId.CERTIFICATE_SECURITY,
    "SMS-CERT-003": ControlId.CERTIFICATE_SECURITY,
    "SMS-CERT-004": ControlId.CERTIFICATE_SECURITY,
    "SMS-CERT-005": ControlId.CERTIFICATE_SECURITY,
    "SMS-CERT-006": ControlId.CERTIFICATE_SECURITY,
    "SMS-CERT-007": ControlId.CERTIFICATE_SECURITY,
    "SMS-CERT-008": ControlId.CERTIFICATE_SECURITY,
    "SMS-KEX-001": ControlId.KEY_EXCHANGE_SECURITY,
    "SMS-KEY-001": ControlId.KEY_EXCHANGE_SECURITY,
    "SMS-KEY-002": ControlId.KEY_EXCHANGE_SECURITY,
    "SMS-FS-001": ControlId.KEY_EXCHANGE_SECURITY,
    "SMS-POL-001": ControlId.EMAIL_POLICY_SECURITY,
    "SMS-POL-002": ControlId.EMAIL_POLICY_SECURITY,
}


# Maps finding rule_id → human-readable description of what the finding checks
_FINDING_DESCRIPTION = {
    "SMS-AUTH-001": "Authentication occurred before TLS was established",
    "SMS-STRIP-001": "STARTTLS was not negotiated",
    "SMS-STRIP-002": "STARTTLS was offered but not negotiated",
    "SMS-STRIP-003": "STARTTLS was requested but TLS handshake did not complete",
    "SMS-STRIP-004": "Server does not advertise STARTTLS",
    "SMS-PROTO-001": "Deprecated TLS version negotiated",
    "SMS-PROTO-002": "Suboptimal TLS version negotiated",
    "SMS-PROTO-003": "No transport encryption on submission/access port",
    "SMS-PROTO-004": "MTA relay on port 25 with opportunistic TLS",
    "SMS-CIPH-001": "Weak or broken cipher suite negotiated",
    "SMS-CIPH-002": "No forward secrecy in cipher suite",
    "SMS-CIPH-003": "Deprecated TLS version (cipher-level)",
    "SMS-CIPH-004": "CBC-mode cipher — prefer AEAD",
    "SMS-CIPH-005": "Cipher below modern recommendation strength",
    "SMS-CIPH-006": "Client does not support modern ciphers",
    "SMS-CERT-001": "Certificate expired at capture time",
    "SMS-CERT-002": "Certificate not yet valid at capture time",
    "SMS-CERT-003": "Certificate hostname mismatch",
    "SMS-CERT-004": "Self-signed certificate",
    "SMS-CERT-005": "Incomplete certificate chain",
    "SMS-CERT-006": "Untrusted root CA",
    "SMS-CERT-007": "Weak certificate signature algorithm",
    "SMS-CERT-008": "Certificate revoked",
    "SMS-KEX-001": "Weak key exchange parameters",
    "SMS-KEY-001": "Weak key exchange (small subgroup or insufficient bits)",
    "SMS-KEY-002": "Key strength below NIST recommendation",
    "SMS-FS-001": "No forward secrecy in key exchange",
    "SMS-POL-001": "MTA-STS policy not deployed where expected",
    "SMS-POL-002": "TLS-RPT policy not deployed",
}


def _control_rank(status: str) -> int:
    """Lower = worse. NOT_ASSESSED (never evaluated) is worst; UNKNOWN
    (could not be determined from the capture) is below PASS."""
    ranks = {
        "fail": 0, "warn": 1, "low": 2,
        "pass": 3, "unknown": 4, "not_assessable": 5,
        None: 5,
    }
    return ranks.get(status, 5)


def _finding_severity_rank(severity: str) -> int:
    """Lower = more severe."""
    ranks = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return ranks.get(severity, 5)


def _is_finding_observable(
    finding_rule_id: str,
    snapshot: PostureSnapshot,
) -> bool:
    """
    Check whether the specific security condition checked by this finding
    could have been observed in the given snapshot's capture.

    This is conservative: if we cannot determine observability, return True
    (to avoid false UNVERIFIABLE).  If we CAN determine that the condition
    was NOT observable, return False.
    """
    from .models import TlsMode

    # STARTTLS-related findings: need STARTTLS-capable session
    if finding_rule_id in ("SMS-STRIP-001", "SMS-STRIP-002", "SMS-STRIP-003"):
        if not snapshot.starttls_offered_count and not snapshot.starttls_requested_count:
            # No STARTTLS traffic at all — the finding couldn't have been triggered
            return False
        return True

    # Deprecated TLS findings: need TLS session with version info
    if finding_rule_id in ("SMS-PROTO-001", "SMS-CIPH-003"):
        if not snapshot.tls_versions:
            # No TLS versions observed at all — condition not observable
            return False
        # If all sessions are cleartext with no TLS, can't observe version issues
        tls_count = sum(v for k, v in snapshot.tls_modes.items()
                        if k not in ("cleartext",))
        if tls_count == 0 and snapshot.tls_versions:
            # TLS versions exist but no TLS modes — edge case, still observable
            return True
        if tls_count == 0:
            return False
        return True

    # AUTH-before-TLS finding: need AUTH exchange
    if finding_rule_id == "SMS-AUTH-001":
        if snapshot.auth_before_tls_count == 0 and snapshot.tls_modes.get("cleartext", 0) == 0:
            # No cleartext sessions, no auth-before-tls — but we can't be sure
            # the condition wasn't observable. Conservative: True if any session exists
            return len(snapshot.session_ids) > 0
        return True

    # Cipher findings: need TLS session
    if finding_rule_id in ("SMS-CIPH-001", "SMS-CIPH-002", "SMS-CIPH-004",
                           "SMS-CIPH-005", "SMS-CIPH-006", "SMS-FS-001"):
        if not snapshot.cipher_suites and not snapshot.tls_versions:
            return False
        return True

    # Certificate findings: need certificate observable
    if finding_rule_id.startswith("SMS-CERT"):
        if not snapshot.certificates:
            # No certs observed — could be TLS 1.3 (encrypted) or no TLS
            if snapshot.tls_modes.get("cleartext", 0) > 0:
                # Cleartext session — certs couldn't be observed
                return False
            # TLS 1.3 or implicit TLS without cert visibility
            vis = snapshot.cert_visibility
            if vis.get("encrypted_tls13", 0) > 0 or vis.get("absent", 0) > 0:
                if vis.get("observed", 0) == 0:
                    return False
        return True

    # Key exchange findings: need TLS session
    if finding_rule_id in ("SMS-KEX-001", "SMS-KEY-001", "SMS-KEY-002"):
        if not snapshot.tls_versions and not snapshot.kex_methods:
            return False
        return True

    # For other findings, be conservative
    return True


def _is_protocol_observed(
    finding_rule_id: str,
    snapshot: PostureSnapshot,
) -> bool:
    """Check if the relevant protocol behavior was observed in the snapshot."""
    from .models import TlsMode

    if finding_rule_id in ("SMS-STRIP-001", "SMS-STRIP-002", "SMS-STRIP-003",
                           "SMS-PROTO-001", "SMS-PROTO-002"):
        return bool(snapshot.tls_versions) or snapshot.starttls_offered_count > 0

    if finding_rule_id == "SMS-AUTH-001":
        return len(snapshot.session_ids) > 0

    if finding_rule_id.startswith("SMS-CIPH"):
        return bool(snapshot.cipher_suites) or bool(snapshot.tls_versions)

    if finding_rule_id.startswith("SMS-CERT"):
        return bool(snapshot.certificates) or snapshot.cert_visibility.get("observed", 0) > 0

    if finding_rule_id.startswith("SMS-KEX") or finding_rule_id == "SMS-FS-001":
        return bool(snapshot.tls_versions) or bool(snapshot.kex_methods)

    return len(snapshot.session_ids) > 0


def verify_finding_remediation(
    finding_rule_id: str,
    pair: BeforeAfterPair,
    *,
    expected_before: bool = True,
    expected_after: Optional[bool] = None,
) -> RemediationVerification:
    """
    Verify whether a specific finding has been remediated.

    Returns a RemediationVerification with status FIXED / STILL_PRESENT /
    PARTIALLY_FIXED / UNVERIFIABLE.
    """
    before = pair.before_snapshot
    after = pair.after_snapshot

    # Check if the finding was present before
    finding_was_present = finding_rule_id in before.finding_rule_ids
    finding_is_present = finding_rule_id in after.finding_rule_ids

    # Get severity info
    before_sev = before.finding_severities.get(finding_rule_id)
    after_sev = after.finding_severities.get(finding_rule_id)

    # Check observability in the AFTER capture
    after_observable = _is_finding_observable(finding_rule_id, after)
    after_protocol_observed = _is_protocol_observed(finding_rule_id, after)

    # Check completeness
    before_complete = before.completeness == "complete"
    after_complete = after.completeness == "complete"

    evidence = VerificationEvidence(
        before_session_ids=list(before.session_ids),
        after_session_ids=list(after.session_ids),
        before_capture_id=before.capture.capture_id,
        after_capture_id=after.capture.capture_id,
    )

    limitations = []

    # --- UNVERIFIABLE cases ---

    # Case: finding not present before — nothing to verify
    if not finding_was_present:
        return RemediationVerification(
            verification_id=f"verify-{finding_rule_id}-{pair.asset_key}",
            asset_key=pair.asset_key,
            finding_rule_id=finding_rule_id,
            status=RemediationStatus.UNVERIFIABLE,
            confidence=Confidence.LOW,
            reason="Finding was not present in the BEFORE capture — nothing to remediate.",
            evidence=evidence,
            limitations=["No before-finding to verify against."],
            before_finding_severity=before_sev,
            after_finding_severity=after_sev,
            before_completeness=before.completeness,
            after_completeness=after.completeness,
            after_condition_observable=after_observable,
            after_protocol_observed=after_protocol_observed,
            before_time=pair.before_time,
            after_time=pair.after_time,
            time_ordered=pair.time_ordered,
        )

    # Case: AFTER capture is incomplete / insufficient
    if after.completeness == "incomplete" or after.completeness == "error":
        limitations.append(
            f"AFTER capture completeness is '{after.completeness}' — "
            f"relevant conditions may not have been observable."
        )

    # Case: the specific condition was NOT observable in AFTER
    if not after_observable:
        desc = _FINDING_DESCRIPTION.get(finding_rule_id, finding_rule_id)
        return RemediationVerification(
            verification_id=f"verify-{finding_rule_id}-{pair.asset_key}",
            asset_key=pair.asset_key,
            finding_rule_id=finding_rule_id,
            status=RemediationStatus.UNVERIFIABLE,
            confidence=Confidence.MEDIUM,
            reason=(f"The condition checked by {finding_rule_id} "
                    f"({desc}) was not observable in the AFTER capture. "
                    f"Absence of the finding cannot confirm remediation."),
            explanation=(
                f"BEFORE: Finding {finding_rule_id} was present. "
                f"AFTER: The capture did not include the relevant protocol "
                f"or TLS handshake needed to observe this condition. "
                f"Without observable evidence in the AFTER capture, "
                f"remediation cannot be confirmed."
            ),
            evidence=evidence,
            limitations=limitations + [
                "Relevant protocol/security property was not observable in the AFTER capture.",
                "Absence of evidence is not evidence of absence.",
            ],
            before_finding_severity=before_sev,
            after_finding_severity=after_sev,
            before_completeness=before.completeness,
            after_completeness=after.completeness,
            after_condition_observable=False,
            after_protocol_observed=after_protocol_observed,
            before_time=pair.before_time,
            after_time=pair.after_time,
            time_ordered=pair.time_ordered,
        )

    # --- FIXED / STILL_PRESENT cases ---

    if not finding_is_present and after_observable:
        # Finding disappeared AND the condition was observable → FIXED
        control = _FINDING_TO_CONTROL_MAP.get(finding_rule_id)
        ctrl_name = control.value if control else "UNKNOWN"
        before_ctrl = before.security_controls.get(ctrl_name)
        after_ctrl = after.security_controls.get(ctrl_name)

        # Determine if the control also improved
        ctrl_fixed = True
        if before_ctrl and after_ctrl:
            if _control_rank(after_ctrl) >= _control_rank(before_ctrl):
                ctrl_fixed = False

        confidence = Confidence.HIGH if after_complete else Confidence.MEDIUM

        explanation = (
            f"BEFORE: Finding {finding_rule_id} was present ({before_sev}). "
            f"AFTER: Finding {finding_rule_id} is absent and the relevant "
            f"condition was observable in the AFTER capture "
            f"(completeness={after.completeness}). "
            f"The condition has been remediated."
        )
        if not ctrl_fixed and before_ctrl and after_ctrl:
            explanation += (
                f" However, control {ctrl_name} did not improve "
                f"({before_ctrl} → {after_ctrl})."
            )
            limitations.append(
                f"Control {ctrl_name} status did not improve "
                f"({before_ctrl} → {after_ctrl}) — investigate further."
            )

        return RemediationVerification(
            verification_id=f"verify-{finding_rule_id}-{pair.asset_key}",
            asset_key=pair.asset_key,
            finding_rule_id=finding_rule_id,
            control_id=ctrl_name,
            status=RemediationStatus.FIXED,
            confidence=confidence,
            reason=(f"Finding {finding_rule_id} was present in the BEFORE capture "
                    f"and is absent in the AFTER capture, where the relevant "
                    f"condition was observable."),
            explanation=explanation,
            evidence=evidence,
            limitations=limitations,
            before_finding_severity=before_sev,
            after_finding_severity=after_sev,
            before_completeness=before.completeness,
            after_completeness=after.completeness,
            after_condition_observable=True,
            after_protocol_observed=after_protocol_observed,
            before_time=pair.before_time,
            after_time=pair.after_time,
            time_ordered=pair.time_ordered,
        )

    if finding_is_present:
        # Finding still present → STILL_PRESENT
        return RemediationVerification(
            verification_id=f"verify-{finding_rule_id}-{pair.asset_key}",
            asset_key=pair.asset_key,
            finding_rule_id=finding_rule_id,
            status=RemediationStatus.STILL_PRESENT,
            confidence=Confidence.HIGH,
            reason=(f"Finding {finding_rule_id} is still present in the "
                    f"AFTER capture."),
            explanation=(
                f"BEFORE: Finding {finding_rule_id} was present ({before_sev}). "
                f"AFTER: Finding {finding_rule_id} is still present ({after_sev}). "
                f"The security condition has not been remediated."
            ),
            evidence=evidence,
            limitations=limitations,
            before_finding_severity=before_sev,
            after_finding_severity=after_sev,
            before_completeness=before.completeness,
            after_completeness=after.completeness,
            after_condition_observable=True,
            after_protocol_observed=after_protocol_observed,
            before_time=pair.before_time,
            after_time=pair.after_time,
            time_ordered=pair.time_ordered,
        )

    # Finding absent but condition was NOT observable → UNVERIFIABLE
    desc = _FINDING_DESCRIPTION.get(finding_rule_id, finding_rule_id)
    return RemediationVerification(
        verification_id=f"verify-{finding_rule_id}-{pair.asset_key}",
        asset_key=pair.asset_key,
        finding_rule_id=finding_rule_id,
        status=RemediationStatus.UNVERIFIABLE,
        confidence=Confidence.MEDIUM,
        reason=(f"Finding {finding_rule_id} ({desc}) was not observable in "
                f"the AFTER capture. Cannot determine if remediated."),
        explanation=(
            f"BEFORE: Finding {finding_rule_id} was present ({before_sev}). "
            f"AFTER: The capture did not provide evidence that could "
            f"confirm or refute the presence of {finding_rule_id}. "
            f"Remediation status is UNVERIFIABLE."
        ),
        evidence=evidence,
        limitations=limitations + [
            "Relevant condition was not observable in the AFTER capture.",
        ],
        before_finding_severity=before_sev,
        after_finding_severity=after_sev,
        before_completeness=before.completeness,
        after_completeness=after.completeness,
        after_condition_observable=False,
        after_protocol_observed=after_protocol_observed,
        before_time=pair.before_time,
        after_time=pair.after_time,
        time_ordered=pair.time_ordered,
    )


def verify_control_remediation(
    control_id: str,
    pair: BeforeAfterPair,
) -> RemediationVerification:
    """
    Verify whether a specific security control's status improved.
    """
    before = pair.before_snapshot
    after = pair.after_snapshot

    before_status = before.security_controls.get(control_id)
    after_status = after.security_controls.get(control_id)

    evidence = VerificationEvidence(
        before_session_ids=list(before.session_ids),
        after_session_ids=list(after.session_ids),
        before_capture_id=before.capture.capture_id,
        after_capture_id=after.capture.capture_id,
    )

    # Control was not assessed before
    if before_status is None:
        return RemediationVerification(
            verification_id=f"verify-ctrl-{control_id}-{pair.asset_key}",
            asset_key=pair.asset_key,
            control_id=control_id,
            status=RemediationStatus.UNVERIFIABLE,
            confidence=Confidence.LOW,
            reason=f"Control {control_id} was not assessed in the BEFORE capture.",
            evidence=evidence,
            limitations=["No before-control status to compare against."],
            before_status=before_status,
            after_status=after_status,
            before_completeness=before.completeness,
            after_completeness=after.completeness,
            before_time=pair.before_time,
            after_time=pair.after_time,
            time_ordered=pair.time_ordered,
        )

    before_rank = _control_rank(before_status)
    after_rank = _control_rank(after_status)

    # Determine if the relevant protocol was observable
    # Map control to a representative finding for observability check
    control_to_finding = {
        ControlId.TRANSPORT_ENCRYPTION.value: "SMS-PROTO-003",
        ControlId.STARTTLS_SECURITY.value: "SMS-STRIP-002",
        ControlId.TLS_VERSION_SECURITY.value: "SMS-PROTO-001",
        ControlId.CIPHER_SECURITY.value: "SMS-CIPH-001",
        ControlId.KEY_EXCHANGE_SECURITY.value: "SMS-KEX-001",
        ControlId.CERTIFICATE_SECURITY.value: "SMS-CERT-001",
        ControlId.AUTHENTICATION_ORDERING.value: "SMS-AUTH-001",
    }
    rep_finding = control_to_finding.get(control_id)
    if rep_finding:
        after_observable = _is_finding_observable(rep_finding, after)
        after_protocol_observed = _is_protocol_observed(rep_finding, after)
    else:
        after_observable = True
        after_protocol_observed = True

    after_complete = after.completeness == "complete"

    limitations = []

    if not after_observable or not after_protocol_observed:
        limitations.append(
            f"Control {control_id}: relevant protocol/security property "
            f"was not observable in the AFTER capture."
        )

    if not after_complete:
        limitations.append(
            f"AFTER capture completeness is '{after.completeness}'."
        )

    # ctrl→not_assessable: was assessed before (fail/warn) but can no longer
    # be assessed after — classify as PARTIALLY_FIXED since we can't confirm
    # the issue is resolved
    if after_status == "not_assessable" and before_status in ("fail", "warn"):
        status = RemediationStatus.PARTIALLY_FIXED
        confidence = Confidence.MEDIUM
        reason = (f"Control {control_id} was {before_status} before and is "
                  f"now not assessable — cannot confirm remediation.")
        return RemediationVerification(
            verification_id=f"verify-ctrl-{control_id}-{pair.asset_key}",
            asset_key=pair.asset_key,
            control_id=control_id,
            status=status,
            confidence=confidence,
            reason=reason,
            explanation=reason,
            evidence=evidence,
            limitations=limitations,
            before_status=before_status,
            after_status=after_status,
            before_completeness=before.completeness,
            after_completeness=after.completeness,
            after_condition_observable=after_observable,
            after_protocol_observed=after_protocol_observed,
            before_time=pair.before_time,
            after_time=pair.after_time,
            time_ordered=pair.time_ordered,
        )

    # Control degraded
    if after_rank < before_rank:
        status = RemediationStatus.STILL_PRESENT
        confidence = Confidence.HIGH if after_complete else Confidence.MEDIUM
        reason = (f"Control {control_id} degraded: {before_status} → {after_status}.")
    elif after_rank == before_rank and after_rank in (0, 1):  # still FAIL/WARN
        status = RemediationStatus.STILL_PRESENT
        confidence = Confidence.HIGH if after_complete and after_observable else Confidence.MEDIUM
        reason = (f"Control {control_id} remains at: {after_status}.")
    elif after_rank == before_rank and after_rank >= 2:  # still PASS/LOW/UNKNOWN/NOT_ASSESSABLE
        # If both were UNKNOWN or NOT_ASSESSABLE, we can't verify — no baseline
        if before_status in ("unknown", "not_assessable"):
            status = RemediationStatus.UNVERIFIABLE
            confidence = Confidence.MEDIUM
            reason = (f"Control {control_id} was {before_status} before and is "
                      f"{after_status} after — no meaningful baseline to compare.")
        elif after_status == "not_assessable":
            # Was FAIL or WARN (assessed), now NOT_ASSESSABLE (not assessed) —
            # this is partial remediation: the issue may be fixed but we
            # can no longer observe it
            status = RemediationStatus.PARTIALLY_FIXED
            confidence = Confidence.MEDIUM
            reason = (f"Control {control_id} was {before_status} before and is "
                      f"now {after_status} — the condition may be remediated but "
                      f"is no longer observable in the AFTER capture.")
        else:
            # Both were PASS or LOW — already acceptable, no change needed
            status = RemediationStatus.FIXED
            confidence = Confidence.HIGH if after_complete and after_observable else Confidence.MEDIUM
            reason = (f"Control {control_id} remains at: {after_status} (was already passing).")
    else:
        status = RemediationStatus.UNVERIFIABLE
        confidence = Confidence.MEDIUM
        reason = (f"Control {control_id} status: {before_status} → {after_status}, "
                  f"but observability is uncertain.")

    return RemediationVerification(
        verification_id=f"verify-ctrl-{control_id}-{pair.asset_key}",
        asset_key=pair.asset_key,
        control_id=control_id,
        status=status,
        confidence=confidence,
        reason=reason,
        explanation=reason,
        evidence=evidence,
        limitations=limitations,
        before_status=before_status,
        after_status=after_status,
        before_completeness=before.completeness,
        after_completeness=after.completeness,
        after_condition_observable=after_observable,
        after_protocol_observed=after_protocol_observed,
        before_time=pair.before_time,
        after_time=pair.after_time,
        time_ordered=pair.time_ordered,
    )


def verify_all_findings(
    pair: BeforeAfterPair,
    finding_filter: Optional[set[str]] = None,
) -> list[RemediationVerification]:
    """
    Verify remediation status for all findings present in the BEFORE capture.

    If ``finding_filter`` is supplied, only findings whose rule_id is in the
    set are verified; others are silently skipped.
    """
    results = []
    before_findings = set(pair.before_snapshot.finding_rule_ids)

    if finding_filter is not None:
        before_findings &= finding_filter

    for rule_id in before_findings:
        vr = verify_finding_remediation(rule_id, pair)
        results.append(vr)

    return results


def verify_all_controls(
    pair: BeforeAfterPair,
    control_filter: Optional[set[str]] = None,
) -> list[RemediationVerification]:
    """
    Verify remediation status for all security controls assessed in the
    BEFORE capture.  Controls that were NOT assessed before are skipped —
    there is nothing to compare against.

    If ``control_filter`` is supplied, only controls whose id is in the
    set are verified; others are silently skipped.
    """
    results = []
    before_controls = set(pair.before_snapshot.security_controls.keys())

    # Skip controls that were never assessed — nothing to remediate
    before_controls = {
        k for k in before_controls
        if pair.before_snapshot.security_controls.get(k) not in ("not_assessable", None)
    }

    if control_filter is not None:
        before_controls &= control_filter

    for ctrl_id in before_controls:
        vr = verify_control_remediation(ctrl_id, pair)
        results.append(vr)

    return results


def verify_remediation(
    before: PostureSnapshot,
    after: PostureSnapshot,
    before_capture_id: str,
    after_capture_id: str,
    *,
    finding_filter: Optional[set[str]] = None,
    control_filter: Optional[set[str]] = None,
) -> RemediationReport:
    """
    Complete remediation verification between two posture snapshots.

    Parameters
    ----------
    finding_filter : set[str] | None
        If supplied, only verify findings whose rule_id is in this set.
        Findings not in the filter are silently skipped (not reported).
        This lets scenario authors scope verification to the specific
        conditions they are testing.
    control_filter : set[str] | None
        If supplied, only verify controls whose id is in this set.
        Controls not in the filter are silently skipped.
    """
    # Build the before/after pair
    pair = BeforeAfterPair(
        asset_key=before.asset_key,
        asset_identity=before.asset_identity,
        identity_confidence=before.asset_identity.confidence,
        before_snapshot=before,
        after_snapshot=after,
        before_capture_id=before_capture_id,
        after_capture_id=after_capture_id,
        before_time=before.capture.capture_time,
        after_time=after.capture.capture_time,
        time_ordered=True,
    )

    # Check asset identity
    if before.asset_key != after.asset_key:
        pair.limitations.append(
            f"Asset keys differ: {before.asset_key} vs {after.asset_key}"
        )
        pair.time_ordered = False
        # Can't verify remediation across different assets
        report = RemediationReport(
            asset_key=before.asset_key,
            asset_identity=before.asset_identity,
            pair=pair,
            verifications=[],
            overall_status=RemediationStatus.UNVERIFIABLE,
            confidence=Confidence.LOW,
            summary="BEFORE and AFTER captures target different assets — remediation cannot be verified.",
            limitations=pair.limitations,
            regressions=[],
        )
        return report

    identity_limitations = []
    if before.asset_identity.confidence not in (AssetIdentityConfidence.CERTAIN, AssetIdentityConfidence.HIGH):
        identity_limitations.append(
            f"Asset identity confidence is {before.asset_identity.confidence} — "
            f"verification results may be unreliable."
        )
        pair.limitations.extend(identity_limitations)

    # Check temporal ordering
    if pair.before_time and pair.after_time:
        if pair.after_time < pair.before_time:
            pair.limitations.append(
                "AFTER capture is older than BEFORE capture — "
                "temporal ordering may be incorrect."
            )
            pair.time_ordered = False
    elif pair.before_time is None or pair.after_time is None:
        pair.limitations.append(
            "Capture timestamps are missing — temporal ordering cannot be verified."
        )
        pair.time_ordered = False

    # Verify all findings (optionally filtered)
    finding_verifications = verify_all_findings(
        pair, finding_filter=finding_filter)

    # Verify all controls (optionally filtered)
    control_verifications = verify_all_controls(
        pair, control_filter=control_filter)

    # Combine all verifications
    all_verifications = finding_verifications + control_verifications

    # Detect regressions: findings present in BEFORE that are also in AFTER
    # but were previously FIXED (i.e., this is a re-detection)
    regressions = []
    for vr in all_verifications:
        if vr.finding_rule_id and vr.finding_rule_id in after.finding_rule_ids:
            # Finding is still present — this is a regression if we expected
            # it to be fixed (but we can't know that from a single comparison)
            # Only flag as regression if the finding was previously absent
            # and reappeared
            pass

    # Determine overall status
    if not all_verifications:
        overall = RemediationStatus.UNVERIFIABLE
        confidence = Confidence.LOW
        summary = "No findings or controls to verify."
    else:
        statuses = [v.status for v in all_verifications]
        if all(s in (RemediationStatus.FIXED,) for s in statuses):
            overall = RemediationStatus.FIXED
            confidence = Confidence.HIGH
            summary = "All findings and controls have been remediated."
        elif all(s == RemediationStatus.STILL_PRESENT for s in statuses):
            overall = RemediationStatus.STILL_PRESENT
            confidence = Confidence.HIGH
            summary = "No remediation detected — all findings and controls remain unchanged."
        elif any(s == RemediationStatus.STILL_PRESENT for s in statuses) and \
             any(s == RemediationStatus.FIXED for s in statuses):
            overall = RemediationStatus.PARTIALLY_FIXED
            confidence = Confidence.HIGH
            summary = "Some findings and controls were remediated; others remain."
        elif any(s == RemediationStatus.UNVERIFIABLE for s in statuses):
            overall = RemediationStatus.UNVERIFIABLE
            confidence = Confidence.MEDIUM
            summary = "Some verifications could not be completed — insufficient evidence in AFTER capture."
        else:
            overall = RemediationStatus.UNVERIFIABLE
            confidence = Confidence.UNKNOWN
            summary = "Verification result is inconclusive."

    # When capture timestamps are missing entirely, the pair is supplied
    # explicitly but temporal ordering cannot be independently established.
    # This does not automatically make the result UNVERIFIABLE — the caller
    # explicitly supplied the pair.  However, we mark the limitation and
    # downgrade confidence.
    if pair.before_time is None and pair.after_time is None:
        pair.limitations.append(
            "Both BEFORE and AFTER capture timestamps are missing — "
            "temporal ordering was not independently observable. "
            "The pair was supplied explicitly by the caller."
        )
        if confidence not in (Confidence.LOW, Confidence.UNKNOWN):
            confidence = Confidence.MEDIUM
    elif pair.before_time is None or pair.after_time is None:
        pair.limitations.append(
            "Capture timestamps are missing — temporal ordering cannot be verified."
        )
        if confidence == Confidence.HIGH:
            confidence = Confidence.MEDIUM

    # Downgrade confidence when asset identity is uncertain
    if identity_limitations and confidence == Confidence.HIGH:
        confidence = Confidence.LOW

    # When asset identity confidence is UNCERTAIN, the entire verification
    # is unverifiable — we cannot safely pair the BEFORE and AFTER captures.
    if before.asset_identity.confidence == AssetIdentityConfidence.UNCERTAIN:
        overall = RemediationStatus.UNVERIFIABLE
        confidence = Confidence.LOW
        summary = ("Asset identity confidence is UNCERTAIN — BEFORE and AFTER "
                   "captures cannot be safely paired for remediation verification.")

    report = RemediationReport(
        asset_key=before.asset_key,
        asset_identity=before.asset_identity,
        pair=pair,
        verifications=all_verifications,
        overall_status=overall,
        confidence=confidence,
        summary=summary,
        limitations=pair.limitations,
        regressions=regressions,
    )

    return report


def detect_regression(
    prior_reports: list[RemediationReport],
    current_before: PostureSnapshot,
    current_after: PostureSnapshot,
) -> list[RemediationVerification]:
    """
    Detect regression: a finding that was previously reported as FIXED
    but is now STILL_PRESENT in a subsequent capture.

    This uses the drift system: if a finding that was absent in a prior
    AFTER capture is now present again, that is a regression.
    """
    regressions = []
    current_after_findings = set(current_after.finding_rule_ids)

    for report in prior_reports:
        for vr in report.verifications:
            if (vr.status == RemediationStatus.FIXED and
                    vr.finding_rule_id and
                    vr.finding_rule_id in current_after_findings):
                # Previously fixed, now present again → regression
                regressions.append(RemediationVerification(
                    verification_id=f"regression-{vr.finding_rule_id}-{report.asset_key}",
                    asset_key=report.asset_key,
                    finding_rule_id=vr.finding_rule_id,
                    status=RemediationStatus.STILL_PRESENT,
                    confidence=vr.confidence,
                    reason=(f"Finding {vr.finding_rule_id} was previously "
                            f"verified as FIXED but is now STILL_PRESENT."),
                    explanation=(
                        f"BEFORE: Finding {vr.finding_rule_id} was FIXED in "
                        f"{vr.evidence.after_capture_id}. "
                        f"AFTER: Finding {vr.finding_rule_id} is present again in "
                        f"{current_after.capture.capture_id}."
                    ),
                    evidence=VerificationEvidence(
                        before_capture_id=vr.evidence.after_capture_id,
                        after_capture_id=current_after.capture.capture_id,
                        after_session_ids=list(current_after.session_ids),
                    ),
                    limitations=["Regression detected — remediation has partially failed."],
                    before_finding_severity=vr.after_finding_severity,
                    after_finding_severity=current_after.finding_severities.get(vr.finding_rule_id),
                    before_completeness=vr.after_completeness,
                    after_completeness=current_after.completeness,
                    before_time=vr.after_time,
                    after_time=current_after.capture.capture_time,
                    time_ordered=True,
                ))

    return regressions
