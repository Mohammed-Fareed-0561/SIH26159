"""
Security control model.

A **security control** is a named, auditable property of an email-security
configuration.  Each finding maps to one or more controls, and each control
reports a status that is always explainable: PASS / WARN / FAIL / UNKNOWN /
NOT_ASSESSABLE.

Controls are first-class data: they are evaluated deterministically from
observations, never merely cosmetic labels.  The status of a control is
derived from the findings and state-machine transitions that affect it in
this capture.

Design rules
------------
* Controls are enumerated here, not in the rule base.  The rule base
  (kb/rules.yaml) cites standards; the control model groups findings into
  operator-facing buckets.
* Every control status carries a human-readable ``reason`` and a list of
  ``limitations`` — the same pattern used by ``EvidenceRef.status``.
* A finding can affect multiple controls (e.g. AUTH-before-TLS affects both
  TRANSPORT_ENCRYPTION and AUTHENTICATION_ORDERING).
* Backward compatible: controls are an additive field on Session/Report.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from .models import TlsMode


class ControlId(str, Enum):
    """Named security controls.  Stable keys, never renamed."""
    TRANSPORT_ENCRYPTION = "TRANSPORT_ENCRYPTION"
    STARTTLS_SECURITY = "STARTTLS_SECURITY"
    TLS_VERSION_SECURITY = "TLS_VERSION_SECURITY"
    CIPHER_SECURITY = "CIPHER_SECURITY"
    KEY_EXCHANGE_SECURITY = "KEY_EXCHANGE_SECURITY"
    CERTIFICATE_SECURITY = "CERTIFICATE_SECURITY"
    AUTHENTICATION_ORDERING = "AUTHENTICATION_ORDERING"
    EMAIL_POLICY_SECURITY = "EMAIL_POLICY_SECURITY"
    SESSION_SECURITY = "SESSION_SECURITY"


class ControlStatus(str, Enum):
    """Outcome for a control evaluation."""
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"
    LOW = "low"
    UNKNOWN = "unknown"
    NOT_ASSESSABLE = "not_assessable"


@dataclass
class ControlEvaluation:
    """The result of evaluating one control for one session or asset."""

    control_id: ControlId
    status: ControlStatus
    reason: str
    # Which finding rule_ids contributed to this status
    contributing_finding_ids: list[str] = field(default_factory=list)
    # Security-relevant transition IDs that bear on this control
    transition_ids: list[str] = field(default_factory=list)
    # Evidence IDs that substantiate the evaluation
    evidence_ids: list[str] = field(default_factory=list)
    # Frame numbers that can be pointed at in the capture
    frames: list[int] = field(default_factory=list)
    # Capture-level limitations that constrain the evaluation
    limitations: list[str] = field(default_factory=list)
    # Standards this control maps to (from kb/standards.yaml)
    standards: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        from .models import _encode
        return _encode(self)


# ---------------------------------------------------------------------------
# Control evaluation engine
# ---------------------------------------------------------------------------
# Maps finding rule_id → (control_id, contributing_status, reason_template)
_FINDING_TO_CONTROL: dict[str, list[tuple[ControlId, ControlStatus, str]]] = {
    "SMS-AUTH-001": [(ControlId.AUTHENTICATION_ORDERING, ControlStatus.FAIL,
                       "Credentials were transmitted before TLS was established."),
		      (ControlId.TRANSPORT_ENCRYPTION, ControlStatus.FAIL,
                       "Transport encryption was not in place during authentication.")],
    "SMS-STRIP-001": [(ControlId.STARTTLS_SECURITY, ControlStatus.WARN,
                       "STARTTLS was not negotiated.")],
    "SMS-STRIP-002": [(ControlId.STARTTLS_SECURITY, ControlStatus.FAIL,
                       "STARTTLS was offered but not negotiated."),
		      (ControlId.AUTHENTICATION_ORDERING, ControlStatus.WARN,
                       "Authentication occurred without STARTTLS.")],
    "SMS-STRIP-003": [(ControlId.STARTTLS_SECURITY, ControlStatus.FAIL,
                       "STARTTLS was requested but the TLS handshake did not complete.")],
    "SMS-STRIP-004": [(ControlId.STARTTLS_SECURITY, ControlStatus.FAIL,
                       "Server does not advertise STARTTLS on this port."),
		      (ControlId.TRANSPORT_ENCRYPTION, ControlStatus.FAIL,
                       "No encryption available on this port.")],
    "SMS-PROTO-001": [(ControlId.TLS_VERSION_SECURITY, ControlStatus.FAIL,
                       "Deprecated TLS version negotiated.")],
    "SMS-PROTO-002": [(ControlId.TLS_VERSION_SECURITY, ControlStatus.WARN,
                       "Suboptimal TLS version negotiated.")],
    "SMS-PROTO-003": [(ControlId.TRANSPORT_ENCRYPTION, ControlStatus.FAIL,
                       "No transport encryption on a submission/access port."),
		      (ControlId.AUTHENTICATION_ORDERING, ControlStatus.FAIL,
                       "Authentication on cleartext channel.")],
    "SMS-PROTO-004": [(ControlId.TRANSPORT_ENCRYPTION, ControlStatus.WARN,
                       "MTA relay on port 25 — opportunistic TLS only."),
		      (ControlId.STARTTLS_SECURITY, ControlStatus.WARN,
                       "STARTTLS not negotiated for MTA relay.")],
    "SMS-CIPH-001": [(ControlId.CIPHER_SECURITY, ControlStatus.FAIL,
                       "Weak or broken cipher suite negotiated.")],
    "SMS-CIPH-002": [(ControlId.CIPHER_SECURITY, ControlStatus.FAIL,
                       "No forward secrecy in cipher suite.")],
    "SMS-CIPH-003": [(ControlId.TLS_VERSION_SECURITY, ControlStatus.FAIL,
                       "Deprecated TLS version.")],
    "SMS-CIPH-004": [(ControlId.CIPHER_SECURITY, ControlStatus.WARN,
                       "CBC-mode cipher — prefer AEAD.")],
    "SMS-CIPH-005": [(ControlId.CIPHER_SECURITY, ControlStatus.WARN,
                       "Cipher below modern recommendation strength.")],
    "SMS-CIPH-006": [(ControlId.CIPHER_SECURITY, ControlStatus.LOW,
                       "Client does not support modern ciphers.")],
    "SMS-CERT-001": [(ControlId.CERTIFICATE_SECURITY, ControlStatus.FAIL,
                       "Certificate expired at capture time.")],
    "SMS-CERT-002": [(ControlId.CERTIFICATE_SECURITY, ControlStatus.FAIL,
                       "Certificate not yet valid at capture time.")],
    "SMS-CERT-003": [(ControlId.CERTIFICATE_SECURITY, ControlStatus.FAIL,
                       "Certificate hostname mismatch.")],
    "SMS-CERT-004": [(ControlId.CERTIFICATE_SECURITY, ControlStatus.WARN,
                       "Self-signed certificate.")],
    "SMS-CERT-005": [(ControlId.CERTIFICATE_SECURITY, ControlStatus.WARN,
                       "Incomplete certificate chain.")],
    "SMS-CERT-006": [(ControlId.CERTIFICATE_SECURITY, ControlStatus.WARN,
                       "Untrusted root CA.")],
    "SMS-CERT-007": [(ControlId.CERTIFICATE_SECURITY, ControlStatus.LOW,
                       "Weak certificate signature algorithm.")],
    "SMS-CERT-008": [(ControlId.CERTIFICATE_SECURITY, ControlStatus.FAIL,
                       "Certificate revoked.")],
    "SMS-KEX-001": [(ControlId.KEY_EXCHANGE_SECURITY, ControlStatus.FAIL,
                       "Weak key exchange parameters.")],
    "SMS-KEY-001": [(ControlId.KEY_EXCHANGE_SECURITY, ControlStatus.FAIL,
                       "Weak key exchange (small subgroup or insufficient bits).")],
    "SMS-KEY-002": [(ControlId.KEY_EXCHANGE_SECURITY, ControlStatus.WARN,
                       "Key strength below NIST recommendation.")],
    "SMS-FS-001": [(ControlId.KEY_EXCHANGE_SECURITY, ControlStatus.WARN,
                       "No forward secrecy in key exchange.")],
    "SMS-POL-001": [(ControlId.EMAIL_POLICY_SECURITY, ControlStatus.FAIL,
                       "MTA-STS policy not deployed where expected.")],
    "SMS-POL-002": [(ControlId.EMAIL_POLICY_SECURITY, ControlStatus.WARN,
                       "TLS-RPT policy not deployed.")],
    "SMS-OK-001": [(ControlId.TRANSPORT_ENCRYPTION, ControlStatus.PASS,
                       "Secure TLS configuration observed."),
		      (ControlId.STARTTLS_SECURITY, ControlStatus.PASS,
                       "STARTTLS negotiated successfully."),
		      (ControlId.CERTIFICATE_SECURITY, ControlStatus.PASS,
                       "Certificate is valid and trusted."),
		      (ControlId.CIPHER_SECURITY, ControlStatus.PASS,
                       "Modern cipher suite with forward secrecy."),
		      (ControlId.TLS_VERSION_SECURITY, ControlStatus.PASS,
                       "Modern TLS version negotiated."),
		      (ControlId.AUTHENTICATION_ORDERING, ControlStatus.PASS,
                       "Authentication occurred after TLS establishment."),],
}


def evaluate_security_controls(session: "Session", state_result: Optional[object] = None) -> list["ControlEvaluation"]:
    """
    Evaluate all security controls for a session based on its findings
    and state-machine transitions.

    The evaluation is deterministic: each finding maps to one or more
    controls, and the most severe status wins.  Controls with no
    contributing findings are reported as PASS (if the session is encrypted)
    or UNKNOWN (if there is no relevant evidence).
    """
    from .models import Session as _S

    evaluations: list[ControlEvaluation] = []
    # Track the worst status per control
    per_control: dict[str, list[tuple[ControlStatus, str, str, list[int], list[str]]]] = {}

    for finding in session.findings:
        rule_id = finding.rule_id
        mappings = _FINDING_TO_CONTROL.get(rule_id, [])
        for ctrl, status, reason in mappings:
            ctrl_key = ctrl.value
            if ctrl_key not in per_control:
                per_control[ctrl_key] = []
            frames = list(finding.evidence.frames) if finding.evidence else []
            perf_rank = status.value  # for sorting
            per_control[ctrl_key].append((status, reason, rule_id, frames, []))

    # Also check session state for implicit control status
    _add_session_level_controls(per_control, session, state_result)

    # Build ControlEvaluation for each control
    all_controls = [c for c in ControlId]
    for ctrl in all_controls:
        ctrl_key = ctrl.value
        entries = per_control.get(ctrl_key, [])
        if entries:
            # Pick the worst status
            status_rank = {"fail": 0, "warn": 1, "low": 2, "pass": 3, "unknown": 4, "not_assessable": 5}
            entries.sort(key=lambda e: status_rank.get(e[0].value, 5))
            worst = entries[0]
            status = worst[0]
            reason = worst[1]
            finding_ids = [e[2] for e in entries]
            frames = list(set(f for e in entries for f in e[3]))
            limitations = list(set(l for e in entries for l in e[4]))
        else:
            # No findings affecting this control — determine default
            if ctrl == ControlId.TRANSPORT_ENCRYPTION:
                if session.tls_mode != TlsMode.CLEARTEXT and session.encrypted:
                    status = ControlStatus.PASS
                    reason = "Transport encryption observed (TLS established)."
                elif session.tls_mode == TlsMode.CLEARTEXT:
                    status = ControlStatus.FAIL
                    reason = "No transport encryption observed."
                else:
                    status = ControlStatus.UNKNOWN
                    reason = "Transport encryption status could not be determined."
            elif ctrl == ControlId.STARTTLS_SECURITY:
                if session.starttls_offered:
                    if session.starttls_accepted:
                        status = ControlStatus.PASS
                        reason = "STARTTLS was offered and successfully negotiated."
                    else:
                        status = ControlStatus.FAIL
                        reason = "STARTTLS was offered but not negotiated."
                else:
                    status = ControlStatus.NOT_ASSESSABLE
                    reason = "STARTTLS was not offered on this port."
            elif ctrl == ControlId.TLS_VERSION_SECURITY:
                if session.tls_version:
                    v = session.tls_version
                    if v in ("1.0", "1.1", "SSLv3", "SSLv2"):
                        status = ControlStatus.FAIL
                        reason = f"Deprecated TLS version {v} negotiated."
                    elif v in ("1.2", "1.3"):
                        status = ControlStatus.PASS
                        reason = f"Modern TLS version {v} negotiated."
                    else:
                        status = ControlStatus.WARN
                        reason = f"TLS version {v} — review for currency."
                else:
                    status = ControlStatus.UNKNOWN
                    reason = "No TLS version observed."
            elif ctrl == ControlId.CIPHER_SECURITY:
                if session.cipher_suite:
                    status = ControlStatus.UNKNOWN
                    reason = f"Cipher suite {session.cipher_suite} observed — review against current guidance."
                else:
                    status = ControlStatus.UNKNOWN
                    reason = "No cipher suite observed (no TLS or TLS not visible)."
            elif ctrl == ControlId.KEY_EXCHANGE_SECURITY:
                if session.kex:
                    if session.forward_secrecy:
                        status = ControlStatus.PASS
                        reason = f"Key exchange {session.kex} provides forward secrecy."
                    elif session.kex in ("RSA",):
                        status = ControlStatus.FAIL
                        reason = f"Key exchange {session.kex} does not provide forward secrecy."
                    else:
                        status = ControlStatus.WARN
                        reason = f"Key exchange {session.kex} — review for forward secrecy."
                else:
                    status = ControlStatus.UNKNOWN
                    reason = "Key exchange not observed."
            elif ctrl == ControlId.CERTIFICATE_SECURITY:
                if session.cert_visibility.value == "encrypted_tls13":
                    status = ControlStatus.NOT_ASSESSABLE
                    reason = "TLS 1.3 encrypts the certificate message; cannot assess."
                elif session.cert_visibility.value == "observed" and session.chain:
                    if session.chain_valid and session.name_match is not False:
                        status = ControlStatus.PASS
                        reason = "Certificate chain is valid and hostname matches."
                    else:
                        status = ControlStatus.FAIL
                        reason = "Certificate chain or hostname mismatch."
                else:
                    status = ControlStatus.UNKNOWN
                    reason = "No certificate observed."
            elif ctrl == ControlId.EMAIL_POLICY_SECURITY:
                if session.tlsa_records or session.mta_sts_published:
                    if session.tlsa_records:
                        status = ControlStatus.PASS
                        reason = "DANE TLSA records observed."
                    elif session.mta_sts_published:
                        status = ControlStatus.PASS
                        reason = "MTA-STS policy published."
                else:
                    status = ControlStatus.NOT_ASSESSABLE
                    reason = "No DNS policy records observed in this capture."
            else:
                status = ControlStatus.NOT_ASSESSABLE
                reason = f"Control {ctrl.value} not yet assessed for this protocol."
            entries = []
            finding_ids = []
            frames = []

        # Collect transition IDs from state machine
        transition_ids = []
        evidence_ids = []
        if state_result:
            for tr in getattr(state_result, "security_relevant_transitions", []):
                transition_ids.append(tr.transition_id)
                for obs_ref in tr.observation_refs:
                    evidence_ids.append(obs_ref.evidence_id)

        evaluations.append(ControlEvaluation(
            control_id=ctrl,
            status=status,
            reason=reason,
            contributing_finding_ids=finding_ids,
            transition_ids=transition_ids,
            evidence_ids=evidence_ids,
            frames=frames,
            limitations=[],  # filled from findings if needed
            standards=_control_standards(ctrl),
        ))

    return evaluations


def _control_standards(ctrl: ControlId) -> list[str]:
    """Return the standards list for a control from the KB."""
    try:
        from .kb import load_standards
        stds = load_standards()
        entry = stds.get(ctrl.value, {})
        return entry.get("standards", [])
    except Exception:
        return []


def _add_session_level_controls(
    per_control: dict, session: Session, state_result: Optional[object]
) -> None:
    """Add implicit control statuses derived from session state (not findings)."""
    # This is where session-level observations that don't produce a finding
    # could still inform a control.  For now, findings drive most controls;
    # the per-control loop above handles defaults.
    pass


# ---------------------------------------------------------------------------
# Control → finding rule mapping
# ---------------------------------------------------------------------------
# Each control is associated with the set of rule_ids (and transition
# conditions) that it tracks.  This is the authoritative mapping used by the
# evaluation engine.
def control_rule_map() -> dict[str, list[str]]:
    """Return {control_id_value: [rule_id, ...]} for all controls."""
    return {
        ControlId.TRANSPORT_ENCRYPTION.value: [
            "SMS-PROTO-003", "SMS-PROTO-004", "SMS-STRIP-002", "SMS-STRIP-003",
            "SMS-STRIP-004", "SMS-AUTH-001", "SMS-POL-001", "SMS-POL-002",
        ],
        ControlId.STARTTLS_SECURITY.value: [
            "SMS-STRIP-001", "SMS-STRIP-002", "SMS-STRIP-003", "SMS-STRIP-004",
        ],
        ControlId.TLS_VERSION_SECURITY.value: [
            "SMS-PROTO-001", "SMS-PROTO-002",
        ],
        ControlId.CIPHER_SECURITY.value: [
            "SMS-CIPH-001", "SMS-CIPH-002", "SMS-CIPH-003", "SMS-CIPH-004",
            "SMS-CIPH-005", "SMS-CIPH-006",
        ],
        ControlId.KEY_EXCHANGE_SECURITY.value: [
            "SMS-FS-001", "SMS-KEX-001",
        ],
        ControlId.CERTIFICATE_SECURITY.value: [
            "SMS-CERT-001", "SMS-CERT-002", "SMS-CERT-003", "SMS-CERT-004",
            "SMS-CERT-005", "SMS-CERT-006", "SMS-CERT-007", "SMS-CERT-008",
            "SMS-KEY-001", "SMS-KEY-002",
        ],
        ControlId.AUTHENTICATION_ORDERING.value: [
            "SMS-STRIP-002", "SMS-AUTH-001", "SMS-PROTO-003",
        ],
        ControlId.EMAIL_POLICY_SECURITY.value: [
            "SMS-POL-001", "SMS-POL-002",
        ],
        # SMS-VIS-001 and SMS-VIS-002 are visibility notes, not control failures
        ControlId.SESSION_SECURITY.value: [],
    }


def control_descriptions() -> dict[str, str]:
    """Short human-readable description per control."""
    return {
        ControlId.TRANSPORT_ENCRYPTION.value:
            "Email protocol traffic must be protected by TLS — either implicit "
            "TLS on the dedicated port or a STARTTLS upgrade before any "
            "application data.",
        ControlId.STARTTLS_SECURITY.value:
            "When STARTTLS is offered, it must be negotiated.  Advertised "
            "capabilities that are silently removed or ignored leave the "
            "session exposed to downgrade or stripping.",
        ControlId.TLS_VERSION_SECURITY.value:
            "Negotiated TLS version must be 1.2 or higher.  TLS 1.0, 1.1 and "
            "SSLv2/v3 are deprecated and insecure.",
        ControlId.CIPHER_SECURITY.value:
            "The negotiated cipher suite must be modern, AEAD, and free of "
            "broken or export-grade primitives.",
        ControlId.KEY_EXCHANGE_SECURITY.value:
            "Key exchange must provide forward secrecy and meet the NIST-bit "
            "strength floor (≥ 2048 for finite-field, ≥ P-256 for elliptic).",
        ControlId.CERTIFICATE_SECURITY.value:
            "The server certificate must be valid at capture time, issued by "
            "a trusted CA, chain to a known root, and match the hostname.",
        ControlId.AUTHENTICATION_ORDERING.value:
            "Authentication must occur only after encryption is established.  "
            "Credentials sent before TLS are exposed to interception.",
        ControlId.EMAIL_POLICY_SECURITY.value:
            "Domain-level policy (MTA-STS / DANE / SMTP-TLSRPT) must be "
            "consistent with the observed encryption state.",
        ControlId.SESSION_SECURITY.value:
            "Session-level properties: renegotiation, session resumption, "
            "session tickets.  Not yet fully assessed in this phase.",
    }
