"""
Ground-truth test scenarios for Phase 4.

Each scenario defines a controlled, synthetic email security situation with
known ground truth. These are NOT real captures — they are synthetic Session
objects constructed to validate the evidence chain.

Every scenario specifies:
  - protocol
  - expected state transitions
  - expected observations
  - expected findings
  - expected security controls
  - expected evidence status
  - expected confidence
  - whether an attack can actually be confirmed from the capture

The STARTTLS-stripping-like scenario MUST remain "possible/suspicious" —
never "confirmed" — unless the evidence actually proves an attack.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from securemailscope.models import (
    AuthExposure,
    CertInfo,
    Endpoint,
    Evidence,
    Finding,
    Protocol,
    Role,
    Severity,
    Session,
    TlsMode,
    CertVisibility,
    Revocation,
)
from securemailscope.evidence import ObservationStatus, Confidence
from securemailscope.posture import AssetIdentityConfidence
from securemailscope.remediation import RemediationStatus


@dataclass
class GroundTruthScenario:
    """A controlled scenario with known expected outcomes."""
    name: str
    description: str
    protocol: Protocol
    role: Role

    # Session construction
    banner: Optional[str] = None
    capability_line: Optional[str] = None
    starttls_offered: bool = False
    starttls_requested: bool = False
    starttls_accepted: bool = False
    tls_mode: TlsMode = TlsMode.CLEARTEXT
    tls_version: Optional[str] = None
    cipher_suite: Optional[str] = None
    kex: Optional[str] = None
    forward_secrecy: Optional[bool] = None
    cleartext_auth: Optional[AuthExposure] = None
    command_transcript: list[str] = field(default_factory=list)
    cert_visibility: CertVisibility = CertVisibility.ABSENT
    chain: list = field(default_factory=list)
    chain_valid: Optional[bool] = None
    name_match: Optional[bool] = None
    revocated: bool = False
    capture_time: Optional[datetime] = None
    first_frame: int = 0
    last_frame: int = 50

    # Expected outcomes
    expected_findings: list[str] = field(default_factory=list)
    expected_finding_count: int = 0
    expected_controls: dict[str, str] = field(default_factory=dict)  # control_id -> status
    expected_evidence_status: ObservationStatus = ObservationStatus.OBSERVED
    expected_confidence: Confidence = Confidence.HIGH
    attack_confirmable: bool = False  # whether an attack can be confirmed from capture alone
    notes: list[str] = field(default_factory=list)


def _cert(subject="CN=mail.example", issuer="CN=Example CA",
          not_before=None, not_after=None,
          self_signed=False, sha256_fingerprint="abc123",
          key_algorithm="RSA", key_bits=2048,
          signature_hash="SHA256", expired_at_capture=None,
          not_yet_valid_at_capture=None):
    if not_before is None:
        not_before = datetime(2020, 1, 1, tzinfo=timezone.utc)
    if not_after is None:
        not_after = datetime(2030, 1, 1, tzinfo=timezone.utc)
    return CertInfo(
        subject=subject,
        issuer=issuer,
        serial="1234567890",
        not_before=not_before,
        not_after=not_after,
        key_algorithm=key_algorithm,
        key_bits=key_bits,
        signature_hash=signature_hash,
        self_signed=self_signed,
        sha256_fingerprint=sha256_fingerprint,
        expired_at_capture=expired_at_capture,
        not_yet_valid_at_capture=not_yet_valid_at_capture,
    )


def _make_session(scenario: GroundTruthScenario, session_id: str = "scn-0",
                  tcp_stream: int = 0,
                  capture_time: Optional[datetime] = None,
                  server_name: Optional[str] = None) -> Session:
    """Build a Session from a ground-truth scenario.

    ``server_name`` overrides the default ``mail.example`` so that scenarios
    representing *different* assets can be modelled (e.g. a remediation pair
    where BEFORE and AFTER target different hosts).
    """
    if capture_time is None:
        capture_time = scenario.capture_time  # may be None — caller decides
    if server_name is None:
        server_name = "mail.example"
    return Session(
        session_id=session_id,
        tcp_stream=tcp_stream,
        client=Endpoint("192.168.1.50", 40000 + tcp_stream),
        server=Endpoint("10.0.0.2", 25 if scenario.protocol == Protocol.SMTP else
                        143 if scenario.protocol == Protocol.IMAP else 110),
        first_frame=scenario.first_frame,
        last_frame=scenario.last_frame,
        capture_time=capture_time,
        protocol=scenario.protocol,
        role=scenario.role,
        tls_mode=scenario.tls_mode,
        server_name=server_name,
        banner=scenario.banner,
        capability_line=scenario.capability_line,
        starttls_offered=scenario.starttls_offered,
        starttls_requested=scenario.starttls_requested,
        starttls_accepted=scenario.starttls_accepted,
        cleartext_auth=scenario.cleartext_auth,
        command_transcript=scenario.command_transcript,
        tls_version=scenario.tls_version,
        cipher_suite=scenario.cipher_suite,
        kex=scenario.kex,
        forward_secrecy=scenario.forward_secrecy,
        cert_visibility=scenario.cert_visibility,
        chain=scenario.chain,
        chain_valid=scenario.chain_valid,
        name_match=scenario.name_match,
        revocation=Revocation.REVOKED if scenario.revocated else Revocation.UNKNOWN_OFFLINE,
    )


# ---------------------------------------------------------------------------
# Scenario definitions
# ---------------------------------------------------------------------------
# Scenarios 1-15 cover the required ground-truth cases.
# Each scenario has a well-defined expected set of findings and controls.

SCENARIOS = {}


def _register(name, **kwargs):
    scenario = GroundTruthScenario(name=name, **kwargs)
    SCENARIOS[name] = scenario
    return scenario


# 1. Secure SMTP STARTTLS + TLS 1.2
_register(
    name="smtp_secure_starttls_tls12",
    description="SMTP submission with STARTTLS negotiated, TLS 1.2, modern cipher, auth after TLS",
    protocol=Protocol.SMTP,
    role=Role.SUBMISSION_ACCESS,
    banner="220 mail.example.com ESMTP",
    capability_line="250-mail.example.com Hello client, SIZE 35882573, AUTH PLAIN LOGIN, STARTTLS",
    starttls_offered=True,
    starttls_requested=True,
    starttls_accepted=True,
    tls_mode=TlsMode.STARTTLS,
    tls_version="1.2",
    cipher_suite="ECDHE-RSA-AES128-GCM-SHA256",
    kex="ECDHE",
    forward_secrecy=True,
    command_transcript=["EHLO client", "STARTTLS", "EHLO client", "AUTH PLAIN"],
    cert_visibility=CertVisibility.OBSERVED,
    chain=[_cert()],
    chain_valid=True,
    name_match=True,
    expected_findings=[],
    expected_controls={},  # All PASS
    expected_confidence=Confidence.HIGH,
    attack_confirmable=False,
    notes=["Secure configuration — no findings expected"],
)


# 2. SMTP AUTH after TLS
_register(
    name="smtp_auth_after_tls",
    description="SMTP with STARTTLS then AUTH PLAIN after TLS established",
    protocol=Protocol.SMTP,
    role=Role.SUBMISSION_ACCESS,
    banner="220 mail.example.com",
    capability_line="250-STARTTLS",
    starttls_offered=True,
    starttls_requested=True,
    starttls_accepted=True,
    tls_mode=TlsMode.STARTTLS,
    tls_version="1.3",
    cipher_suite="TLS_AES_128_GCM_SHA256",
    kex="ECDHE",
    forward_secrecy=True,
    command_transcript=["EHLO", "STARTTLS", "EHLO", "AUTH PLAIN"],
    cert_visibility=CertVisibility.ENCRYPTED_TLS13,
    expected_findings=[],
    expected_controls={},  # All PASS
    expected_confidence=Confidence.HIGH,
    attack_confirmable=False,
    notes=["TLS 1.3 encrypts certificate — cert not assessable, but no failure"],
)


# 3. SMTP AUTH before TLS
_register(
    name="smtp_auth_before_tls",
    description="SMTP with cleartext AUTH before STARTTLS — credentials exposed",
    protocol=Protocol.SMTP,
    role=Role.SUBMISSION_ACCESS,
    banner="220 mail.example.com",
    capability_line="250-STARTTLS",
    starttls_offered=True,
    starttls_requested=False,
    starttls_accepted=False,
    tls_mode=TlsMode.CLEARTEXT,
    cleartext_auth=AuthExposure(
        mechanism="PLAIN", username="user", secret_sha256="abc",
        frame=10,
    ),
    command_transcript=["EHLO", "AUTH PLAIN"],
    expected_findings=["SMS-AUTH-001", "SMS-STRIP-002"],
    expected_controls={
        "AUTHENTICATION_ORDERING": "fail",
        "TRANSPORT_ENCRYPTION": "fail",
    },
    expected_confidence=Confidence.HIGH,
    attack_confirmable=False,
    notes=["Credentials exposed — this is a finding, not an attack"],
)


# 4. STARTTLS advertised but not successfully negotiated
_register(
    name="smtp_starttls_not_negotiated",
    description="STARTTLS offered but client did not request it — falls back to cleartext auth",
    protocol=Protocol.SMTP,
    role=Role.SUBMISSION_ACCESS,
    banner="220 mail.example.com",
    capability_line="250-STARTTLS",
    starttls_offered=True,
    starttls_requested=False,
    starttls_accepted=False,
    tls_mode=TlsMode.CLEARTEXT,
    cleartext_auth=AuthExposure(
        mechanism="LOGIN", username="user", secret_sha256="abc",
        frame=15,
    ),
    command_transcript=["EHLO", "AUTH LOGIN"],
    expected_findings=["SMS-STRIP-002"],
    expected_controls={"STARTTLS_SECURITY": "fail"},
    expected_confidence=Confidence.MEDIUM,
    attack_confirmable=False,  # Could be client misconfiguration, not an attack
    notes=["STARTTLS stripping is only ONE possible explanation"],
)


# 5. STARTTLS not advertised
_register(
    name="smtp_starttls_not_advertised",
    description="Server does not offer STARTTLS — cleartext only",
    protocol=Protocol.SMTP,
    role=Role.MTA_RELAY,
    banner="220 mail.example.com",
    capability_line="250-AUTH PLAIN LOGIN",
    starttls_offered=False,
    starttls_requested=False,
    starttls_accepted=False,
    tls_mode=TlsMode.CLEARTEXT,
    command_transcript=["EHLO", "AUTH PLAIN"],
    expected_findings=["SMS-STRIP-004"],
    expected_controls={"STARTTLS_SECURITY": "not_assessable"},
    expected_confidence=Confidence.HIGH,
    attack_confirmable=False,
    notes=["No STARTTLS advertised — server configuration issue"],
)


# 6. Deprecated TLS version
_register(
    name="smtp_deprecated_tls",
    description="SMTP with STARTTLS using deprecated TLS 1.0",
    protocol=Protocol.SMTP,
    role=Role.SUBMISSION_ACCESS,
    banner="220 mail.example.com",
    capability_line="250-STARTTLS",
    starttls_offered=True,
    starttls_requested=True,
    starttls_accepted=True,
    tls_mode=TlsMode.STARTTLS,
    tls_version="1.0",
    cipher_suite="AES128-SHA",
    kex="RSA",
    forward_secrecy=False,
    command_transcript=["EHLO", "STARTTLS", "EHLO", "AUTH PLAIN"],
    cert_visibility=CertVisibility.OBSERVED,
    chain=[_cert()],
    chain_valid=True,
    name_match=True,
    expected_findings=["SMS-PROTO-001", "SMS-CIPH-002", "SMS-FS-001"],
    expected_controls={
        "TLS_VERSION_SECURITY": "fail",
        "CIPHER_SECURITY": "fail",
        "KEY_EXCHANGE_SECURITY": "warn",
    },
    expected_confidence=Confidence.HIGH,
    attack_confirmable=False,
    notes=["Deprecated TLS is a misconfiguration, not an attack"],
)


# 7. Weak/deprecated cipher
_register(
    name="smtp_weak_cipher",
    description="SMTP with STARTTLS using a broken cipher suite (RC4 or EXPORT)",
    protocol=Protocol.SMTP,
    role=Role.SUBMISSION_ACCESS,
    banner="220 mail.example.com",
    capability_line="250-STARTTLS",
    starttls_offered=True,
    starttls_requested=True,
    starttls_accepted=True,
    tls_mode=TlsMode.STARTTLS,
    tls_version="1.1",
    cipher_suite="RC4-SHA",
    kex="RSA",
    forward_secrecy=False,
    command_transcript=["EHLO", "STARTTLS", "EHLO", "AUTH PLAIN"],
    cert_visibility=CertVisibility.OBSERVED,
    chain=[_cert()],
    chain_valid=True,
    name_match=True,
    expected_findings=["SMS-CIPH-001"],
    expected_controls={"CIPHER_SECURITY": "fail"},
    expected_confidence=Confidence.HIGH,
    attack_confirmable=False,
    notes=["Weak cipher is a finding, not an attack"],
)


# 8. Certificate validation problem
_register(
    name="smtp_cert_expired",
    description="SMTP with expired certificate",
    protocol=Protocol.SMTP,
    role=Role.SUBMISSION_ACCESS,
    banner="220 mail.example.com",
    capability_line="250-STARTTLS",
    starttls_offered=True,
    starttls_requested=True,
    starttls_accepted=True,
    tls_mode=TlsMode.STARTTLS,
    tls_version="1.2",
    cipher_suite="ECDHE-RSA-AES128-GCM-SHA256",
    kex="ECDHE",
    forward_secrecy=True,
    command_transcript=["EHLO", "STARTTLS", "EHLO", "AUTH PLAIN"],
    cert_visibility=CertVisibility.OBSERVED,
    chain=[_cert(
        not_before=datetime(2020, 1, 1, tzinfo=timezone.utc),
        not_after=datetime(2023, 6, 1, tzinfo=timezone.utc),
        expired_at_capture=True,
    )],
    chain_valid=False,
    name_match=True,
    expected_findings=["SMS-CERT-001"],
    expected_controls={"CERTIFICATE_SECURITY": "fail"},
    expected_confidence=Confidence.HIGH,
    attack_confirmable=False,
    notes=["Expired cert is misconfiguration — certificate validity judged against capture clock"],
)


# 9. TLS negotiation failure
_register(
    name="smtp_tls_handshake_failure",
    description="STARTTLS requested but TLS handshake did not complete",
    protocol=Protocol.SMTP,
    role=Role.SUBMISSION_ACCESS,
    banner="220 mail.example.com",
    capability_line="250-STARTTLS",
    starttls_offered=True,
    starttls_requested=True,
    starttls_accepted=False,
    tls_mode=TlsMode.CLEARTEXT,
    command_transcript=["EHLO", "STARTTLS"],
    expected_findings=["SMS-STRIP-003"],
    expected_controls={"STARTTLS_SECURITY": "fail"},
    expected_confidence=Confidence.HIGH,
    attack_confirmable=False,
    notes=["STARTTLS requested but negotiation failed — could be server error, not attack"],
)


# 10. Incomplete TCP capture
_register(
    name="smtp_incomplete_capture",
    description="Capture ends before the session completes — INCOMPLETE state",
    protocol=Protocol.SMTP,
    role=Role.SUBMISSION_ACCESS,
    banner="220 mail.example.com",
    capability_line="250-STARTTLS",
    starttls_offered=True,
    starttls_requested=False,
    starttls_accepted=False,
    tls_mode=TlsMode.CLEARTEXT,
    cleartext_auth=AuthExposure(
        mechanism="PLAIN", username="user", secret_sha256="abc",
        frame=5,
    ),
    command_transcript=["EHLO"],
    first_frame=0,
    last_frame=3,
    expected_findings=[],  # Findings may be partial — INCOMPLETE captures may miss data
    expected_controls={},
    expected_evidence_status=ObservationStatus.INSUFFICIENT_CAPTURE,
    expected_confidence=Confidence.LOW,
    attack_confirmable=False,
    notes=["Capture is incomplete — conclusions are limited"],
)


# 11. IMAP STARTTLS
_register(
    name="imap_starttls",
    description="IMAP with STARTTLS negotiated successfully",
    protocol=Protocol.IMAP,
    role=Role.SUBMISSION_ACCESS,
    banner="* OK [CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN] mail.example",
    capability_line="* CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN",
    starttls_offered=True,
    starttls_requested=True,
    starttls_accepted=True,
    tls_mode=TlsMode.STARTTLS,
    tls_version="1.3",
    cipher_suite="TLS_AES_256_GCM_SHA384",
    kex="ECDHE",
    forward_secrecy=True,
    command_transcript=["a1 CAPABILITY", "a2 STARTTLS", "a3 AUTHENTICATE PLAIN"],
    cert_visibility=CertVisibility.ENCRYPTED_TLS13,
    expected_findings=[],
    expected_controls={},
    expected_confidence=Confidence.HIGH,
    attack_confirmable=False,
    notes=["IMAP STARTTLS with TLS 1.3 — secure configuration"],
)


# 12. POP3 STLS
_register(
    name="pop3_stls",
    description="POP3 with STLS negotiated successfully",
    protocol=Protocol.POP3,
    role=Role.SUBMISSION_ACCESS,
    banner="+OK POP3 server ready",
    capability_line="+OK Capability list follows",
    starttls_offered=True,
    starttls_requested=True,
    starttls_accepted=True,
    tls_mode=TlsMode.STARTTLS,
    tls_version="1.2",
    cipher_suite="ECDHE-RSA-AES128-GCM-SHA256",
    kex="ECDHE",
    forward_secrecy=True,
    command_transcript=["STLS", "USER test", "PASS secret"],
    cert_visibility=CertVisibility.OBSERVED,
    chain=[_cert()],
    chain_valid=True,
    name_match=True,
    expected_findings=[],
    expected_controls={},
    expected_confidence=Confidence.HIGH,
    attack_confirmable=False,
    notes=["POP3 STLS with TLS 1.2 — secure configuration"],
)


# 13. Simulated STARTTLS-stripping-like sequence
_register(
    name="smtp_stripping_simulation",
    description="STARTTLS offered, client does not request it, AUTH occurs in cleartext. Simulates stripping-like sequence but is only SUSPICIOUS, not confirmed attack.",
    protocol=Protocol.SMTP,
    role=Role.SUBMISSION_ACCESS,
    banner="220 mail.example.com",
    capability_line="250-STARTTLS",
    starttls_offered=True,
    starttls_requested=False,
    starttls_accepted=False,
    tls_mode=TlsMode.CLEARTEXT,
    cleartext_auth=AuthExposure(
        mechanism="PLAIN", username="user", secret_sha256="abc",
        frame=10,
    ),
    command_transcript=["EHLO", "AUTH PLAIN"],
    expected_findings=["SMS-STRIP-002"],
    expected_controls={"STARTTLS_SECURITY": "fail"},
    expected_confidence=Confidence.LOW,  # Stripping explanation is LOW confidence
    attack_confirmable=False,
    notes=[
        "STARTTLS stripping is ONE possible explanation",
        "Could also be client misconfiguration or incomplete capture",
        "The reasoning engine must NOT claim 'confirmed attack'",
    ],
)


# 14. Mixed behavior across sessions (same asset, different security posture)
_register(
    name="smtp_mixed_behavior_1",
    description="Same server, different clients — one uses STARTTLS, one doesn't",
    protocol=Protocol.SMTP,
    role=Role.MTA_RELAY,
    banner="220 mail.example.com",
    capability_line="250-STARTTLS",
    starttls_offered=True,
    starttls_requested=True,
    starttls_accepted=True,
    tls_mode=TlsMode.STARTTLS,
    tls_version="1.2",
    cipher_suite="ECDHE-RSA-AES128-GCM-SHA256",
    kex="ECDHE",
    forward_secrecy=True,
    command_transcript=["EHLO", "STARTTLS", "EHLO", "MAIL FROM"],
    cert_visibility=CertVisibility.OBSERVED,
    chain=[_cert()],
    chain_valid=True,
    name_match=True,
    expected_findings=[],
    expected_controls={},
    expected_confidence=Confidence.HIGH,
    attack_confirmable=False,
)

# Companion scenario for mixed behavior — same server, insecure client
_register(
    name="smtp_mixed_behavior_2",
    description="Same server as smtp_mixed_behavior_1, but a different client doesn't use STARTTLS",
    protocol=Protocol.SMTP,
    role=Role.MTA_RELAY,
    banner="220 mail.example.com",
    capability_line="250-STARTTLS",
    starttls_offered=True,
    starttls_requested=False,
    starttls_accepted=False,
    tls_mode=TlsMode.CLEARTEXT,
    command_transcript=["EHLO", "MAIL FROM"],
    expected_findings=["SMS-STRIP-002"],
    expected_controls={"STARTTLS_SECURITY": "fail"},
    expected_confidence=Confidence.MEDIUM,
    attack_confirmable=False,
)


# 15. Same asset before/after a configuration change
# This scenario pair shows TLS version downgrade
_register(
    name="smtp_before_config_change",
    description="Server supports TLS 1.2 and 1.3 — secure baseline",
    protocol=Protocol.SMTP,
    role=Role.SUBMISSION_ACCESS,
    banner="220 mail.example.com",
    capability_line="250-STARTTLS",
    starttls_offered=True,
    starttls_requested=True,
    starttls_accepted=True,
    tls_mode=TlsMode.STARTTLS,
    tls_version="1.3",
    cipher_suite="TLS_AES_128_GCM_SHA256",
    kex="ECDHE",
    forward_secrecy=True,
    command_transcript=["EHLO", "STARTTLS", "EHLO", "AUTH PLAIN"],
    cert_visibility=CertVisibility.ENCRYPTED_TLS13,
    capture_time=datetime(2024, 1, 1, tzinfo=timezone.utc),
    expected_findings=[],
    expected_controls={},
    expected_confidence=Confidence.HIGH,
    attack_confirmable=False,
)

_register(
    name="smtp_after_config_change",
    description="Server now only supports TLS 1.0 — config change caused regression",
    protocol=Protocol.SMTP,
    role=Role.SUBMISSION_ACCESS,
    banner="220 mail.example.com",
    capability_line="250-STARTTLS",
    starttls_offered=True,
    starttls_requested=True,
    starttls_accepted=True,
    tls_mode=TlsMode.STARTTLS,
    tls_version="1.0",
    cipher_suite="AES128-SHA",
    kex="RSA",
    forward_secrecy=False,
    command_transcript=["EHLO", "STARTTLS", "EHLO", "AUTH PLAIN"],
    cert_visibility=CertVisibility.OBSERVED,
    chain=[_cert()],
    chain_valid=True,
    name_match=True,
    capture_time=datetime(2024, 3, 1, tzinfo=timezone.utc),
    expected_findings=["SMS-PROTO-001", "SMS-CIPH-002", "SMS-FS-001"],
    expected_controls={
        "TLS_VERSION_SECURITY": "fail",
        "CIPHER_SECURITY": "fail",
        "KEY_EXCHANGE_SECURITY": "warn",
    },
    expected_confidence=Confidence.HIGH,
    attack_confirmable=False,
    notes=["Configuration change caused TLS version downgrade — DEGRADATION, not attack"],
)


# ---------------------------------------------------------------------------
# Phase 5 helpers: pipeline runner and PostureSnapshot builder
# ---------------------------------------------------------------------------
def _apply_full_pipeline(session: Session):
    """Run the full analysis pipeline on a single session.

    This mirrors the test harness in ``test_posture_drift_phase4.py``:
    rules → grade → state machine → finding links → reasoning → controls.

    Returns ``(sm_result, session)`` so callers can inspect the state machine
    result if needed.
    """
    from securemailscope.scoring.rules import apply_rules
    from securemailscope.scoring.grade import grade_session
    from securemailscope.smtp_state_machine import SmtpStateMachine
    from securemailscope.imap_state_machine import ImapStateMachine
    from securemailscope.pop3_state_machine import Pop3StateMachine
    from securemailscope.finding_linker import link_all_findings
    from securemailscope.reasoning import ReasoningEngine
    from securemailscope.security_controls import evaluate_security_controls

    session.features = {}
    session.findings = apply_rules(session)
    session.grade = grade_session(session, session.findings)
    sm_result = (
        SmtpStateMachine(session).build_states()
        if session.protocol == Protocol.SMTP
        else (ImapStateMachine(session).build_states()
              if session.protocol == Protocol.IMAP
              else Pop3StateMachine(session).build_states())
    )
    if sm_result:
        refs = link_all_findings(session, sm_result)
        session.finding_references = refs
        engine = ReasoningEngine()
        for f in session.findings:
            ref = next((r for r in refs if r.finding_id == f.rule_id), None)
            reasoning = engine.reason(session, sm_result, f.rule_id, f, ref)
            session.reasoning.append(reasoning)
    controls = evaluate_security_controls(session, sm_result)
    session.security_controls = controls
    return sm_result, session


def _build_snapshot(
    scenario: GroundTruthScenario,
    capture_id: str,
    server_name: Optional[str] = None,
    capture_time: Optional[datetime] = None,
    identity_override_key: Optional[str] = None,
    identity_override_confidence: Optional[AssetIdentityConfidence] = None,
):
    """Build a ``PostureSnapshot`` from a ground-truth scenario.

    *server_name* overrides the default ``mail.example`` so that
    remediation scenarios targeting different assets are modelled
    correctly (used by ``different_asset``).

    *identity_override_key* lets a test set a different asset key.
    When supplied the resulting snapshot's ``asset_identity.key`` and
    ``host`` are set to this value — used by ``different_asset``.

    *identity_override_confidence* overrides the AssetIdentityConfidence
    derived from the session — used by ``uncertain_asset_identity``.
    """
    # Determine capture time for this snapshot — preserve explicit None so
    # the missing_timestamps scenario can represent captures without timestamps.
    if capture_time is not None:
        cap_time = capture_time
    elif scenario.capture_time is not None:
        cap_time = scenario.capture_time
    else:
        cap_time = None

    session = _make_session(
        scenario,
        server_name=server_name or "mail.example",
        capture_time=cap_time,
    )
    _apply_full_pipeline(session)

    from securemailscope.posture import build_posture_snapshot

    snapshot = build_posture_snapshot([session], capture_id, cap_time)

    # Apply overrides requested by the caller
    if identity_override_key:
        snapshot.asset_identity.key = identity_override_key
        snapshot.asset_identity.host = identity_override_key.split(":")[0]
    if identity_override_confidence is not None:
        snapshot.asset_identity.confidence = identity_override_confidence

    return snapshot


def _pair_to_snapshots(
    pair: dict,
    before_capture_id: str = "capt-before",
    after_capture_id: str = "capt-after",
):
    """Convert a remediation scenario pair dict into two PostureSnapshots.

    Reads identity overrides (after_server_name, before/after identity keys
    and confidence) directly from the pair dict so callers don't need to
    pass them separately.
    """
    before_scn = pair["before"]
    after_scn = pair["after"]

    before = _build_snapshot(
        before_scn,
        before_capture_id,
        identity_override_key=pair.get("before_identity_key"),
        identity_override_confidence=pair.get("before_identity_confidence"),
    )
    after = _build_snapshot(
        after_scn,
        after_capture_id,
        server_name=pair.get("after_server_name"),
        identity_override_key=pair.get("after_identity_key"),
        identity_override_confidence=pair.get("after_identity_confidence"),
    )
    return before, after


# ---------------------------------------------------------------------------
# Phase 5: Remediation verification scenarios
# ---------------------------------------------------------------------------
# These are BEFORE/AFTER pairs that test remediation verification logic.
# Each pair registers two GroundTruthScenario objects (into SCENARIOS) and a
# summary entry in REMEDIATION_SCENARIOS. The test harness builds PostureSnapshots
# from the scenarios, runs the full pipeline, and verifies each pair through the
# real remediation engine (verify_remediation).
#
# Each entry maps a stable key to:
#   before:  GroundTruthScenario
#   after:   GroundTruthScenario
#   expected_finding:  the finding rule_id being verified (for finding-level tests)
#   expected_control:  the control_id being verified (for control-level tests)
#   expected_status:   RemediationStatus the engine should report
#   expected_confidence: Confidence the engine should report (approximate)
#   notes:   human-readable description of the ground-truth expectation

REMEDIATION_SCENARIOS: dict[str, dict] = {}


def _pair(name, before, after, expected_status, expected_confidence=Confidence.HIGH,
          expected_finding=None, expected_control=None, notes=None,
          after_server_name=None, before_identity_key=None,
          after_identity_key=None, before_identity_confidence=None,
          after_identity_confidence=None, **extra):
    """Register a before/after remediation scenario pair.

    ``before`` and ``after`` are GroundTruthScenario kwargs dicts; they are
    registered into SCENARIOS under ``{name}__before`` / ``{name}__after`` so
    the test harness can build PostureSnapshots from them.

    Optional identity overrides for special scenarios:
      *after_server_name* — different server_name for the AFTER scenario
      (used by the "different_asset" pair where AFTER targets a different host).

      *before_identity_key / after_identity_key* — explicit asset keys
      (used by "different_asset" where the two captures target distinct hosts).

      *before_identity_confidence / after_identity_confidence* — override the
      AssetIdentityConfidence (used by "uncertain_asset_identity").
    """
    b = SCENARIOS[f"{name}__before"] = GroundTruthScenario(
        name=f"{name}__before", **before
    )
    a = SCENARIOS[f"{name}__after"] = GroundTruthScenario(
        name=f"{name}__after", **after
    )
    entry = {
        "before": b,
        "after": a,
        "expected_finding": expected_finding,
        "expected_control": expected_control,
        "expected_status": expected_status,
        "expected_confidence": expected_confidence,
        "notes": notes or [],
    }
    # Store optional identity overrides used by _pair_to_snapshots
    if after_server_name is not None:
        entry["after_server_name"] = after_server_name
    if before_identity_key is not None:
        entry["before_identity_key"] = before_identity_key
    if after_identity_key is not None:
        entry["after_identity_key"] = after_identity_key
    if before_identity_confidence is not None:
        entry["before_identity_confidence"] = before_identity_confidence
    if after_identity_confidence is not None:
        entry["after_identity_confidence"] = after_identity_confidence
    entry.update(extra)
    REMEDIATION_SCENARIOS[name] = entry


# A. TLS 1.0 → TLS 1.2/1.3  (FIXED)
_pair(
    "deprecated_tls_fixed",
    expected_finding="SMS-PROTO-001",
    expected_status=RemediationStatus.FIXED,
    expected_confidence=Confidence.HIGH,
    notes=["TLS 1.0 replaced by TLS 1.3; finding disappears AND condition observable"],
    before=dict(
        description="Before: TLS 1.0 with weak cipher and no forward secrecy",
        protocol=Protocol.SMTP,
        role=Role.SUBMISSION_ACCESS,
        banner="220 mail.example.com",
        capability_line="250-STARTTLS",
        starttls_offered=True, starttls_requested=True, starttls_accepted=True,
        tls_mode=TlsMode.STARTTLS,
        tls_version="1.0",
        cipher_suite="AES128-SHA",
        kex="RSA", forward_secrecy=False,
        command_transcript=["EHLO", "STARTTLS", "EHLO", "AUTH PLAIN"],
        cert_visibility=CertVisibility.OBSERVED,
        chain=[_cert()], chain_valid=True, name_match=True,
        capture_time=datetime(2024, 1, 1, tzinfo=timezone.utc),
        expected_findings=["SMS-PROTO-001", "SMS-CIPH-002", "SMS-FS-001"],
    ),
    after=dict(
        description="After: TLS 1.3 with strong AEAD cipher, ECDHE, forward secrecy",
        protocol=Protocol.SMTP,
        role=Role.SUBMISSION_ACCESS,
        banner="220 mail.example.com",
        capability_line="250-STARTTLS",
        starttls_offered=True, starttls_requested=True, starttls_accepted=True,
        tls_mode=TlsMode.STARTTLS,
        tls_version="1.3",
        cipher_suite="TLS_AES_128_GCM_SHA256",
        kex="ECDHE", forward_secrecy=True,
        command_transcript=["EHLO", "STARTTLS", "EHLO", "AUTH PLAIN"],
        cert_visibility=CertVisibility.ENCRYPTED_TLS13,
        capture_time=datetime(2024, 2, 1, tzinfo=timezone.utc),
        expected_findings=[],
    ),
)


# B. TLS 1.0 still present  (STILL_PRESENT)
_pair(
    "deprecated_tls_still_present",
    expected_finding="SMS-PROTO-001",
    expected_status=RemediationStatus.STILL_PRESENT,
    expected_confidence=Confidence.HIGH,
    notes=["TLS 1.0 still negotiated in the AFTER capture — not remediated"],
    before=dict(
        description="Before: TLS 1.0",
        protocol=Protocol.SMTP, role=Role.SUBMISSION_ACCESS,
        banner="220 mail.example.com", capability_line="250-STARTTLS",
        starttls_offered=True, starttls_requested=True, starttls_accepted=True,
        tls_mode=TlsMode.STARTTLS, tls_version="1.0", cipher_suite="AES128-SHA",
        kex="RSA", forward_secrecy=False,
        command_transcript=["EHLO", "STARTTLS", "EHLO", "AUTH PLAIN"],
        cert_visibility=CertVisibility.OBSERVED,
        chain=[_cert()], chain_valid=True, name_match=True,
        capture_time=datetime(2024, 1, 1, tzinfo=timezone.utc),
        expected_findings=["SMS-PROTO-001"],
    ),
    after=dict(
        description="After: still TLS 1.0 (no remediation)",
        protocol=Protocol.SMTP, role=Role.SUBMISSION_ACCESS,
        banner="220 mail.example.com", capability_line="250-STARTTLS",
        starttls_offered=True, starttls_requested=True, starttls_accepted=True,
        tls_mode=TlsMode.STARTTLS, tls_version="1.0", cipher_suite="AES128-SHA",
        kex="RSA", forward_secrecy=False,
        command_transcript=["EHLO", "STARTTLS", "EHLO", "AUTH PLAIN"],
        cert_visibility=CertVisibility.OBSERVED,
        chain=[_cert()], chain_valid=True, name_match=True,
        capture_time=datetime(2024, 2, 1, tzinfo=timezone.utc),
        expected_findings=["SMS-PROTO-001"],
    ),
)


# C. TLS 1.0 + weak cipher → only TLS fixed, cipher remains  (PARTIALLY_FIXED)
_pair(
    "deprecated_tls_partial_fix_only_tls",
    expected_finding="SMS-CIPH-002",
    expected_status=RemediationStatus.PARTIALLY_FIXED,
    expected_confidence=Confidence.HIGH,
    notes=["TLS upgraded but weak cipher (no Forward Secrecy) remains — partial remediation"],
    before=dict(
        description="Before: TLS 1.0 + RSA key exchange (no PFS)",
        protocol=Protocol.SMTP, role=Role.SUBMISSION_ACCESS,
        banner="220 mail.example.com", capability_line="250-STARTTLS",
        starttls_offered=True, starttls_requested=True, starttls_accepted=True,
        tls_mode=TlsMode.STARTTLS, tls_version="1.0", cipher_suite="AES128-SHA",
        kex="RSA", forward_secrecy=False,
        command_transcript=["EHLO", "STARTTLS", "EHLO", "AUTH PLAIN"],
        cert_visibility=CertVisibility.OBSERVED,
        chain=[_cert()], chain_valid=True, name_match=True,
        capture_time=datetime(2024, 1, 1, tzinfo=timezone.utc),
        expected_findings=["SMS-PROTO-001", "SMS-CIPH-002", "SMS-FS-001"],
    ),
    after=dict(
        description="After: TLS 1.2 but still RSA (no forward secrecy)",
        protocol=Protocol.SMTP, role=Role.SUBMISSION_ACCESS,
        banner="220 mail.example.com", capability_line="250-STARTTLS",
        starttls_offered=True, starttls_requested=True, starttls_accepted=True,
        tls_mode=TlsMode.STARTTLS, tls_version="1.2", cipher_suite="AES128-SHA",
        kex="RSA", forward_secrecy=False,
        command_transcript=["EHLO", "STARTTLS", "EHLO", "AUTH PLAIN"],
        cert_visibility=CertVisibility.OBSERVED,
        chain=[_cert()], chain_valid=True, name_match=True,
        capture_time=datetime(2024, 2, 1, tzinfo=timezone.utc),
        expected_findings=["SMS-CIPH-002", "SMS-FS-001"],
    ),
)


# D. Missing TLS handshake after remediation  (UNVERIFIABLE)
_pair(
    "deprecated_tls_missing_handshake",
    expected_finding="SMS-PROTO-001",
    expected_status=RemediationStatus.UNVERIFIABLE,
    expected_confidence=Confidence.MEDIUM,
    notes=["Finding absent from AFTER but no TLS handshake observable — UNVERIFIABLE"],
    before=dict(
        description="Before: TLS 1.0 observed",
        protocol=Protocol.SMTP, role=Role.SUBMISSION_ACCESS,
        banner="220 mail.example.com", capability_line="250-STARTTLS",
        starttls_offered=True, starttls_requested=True, starttls_accepted=True,
        tls_mode=TlsMode.STARTTLS, tls_version="1.0", cipher_suite="AES128-SHA",
        kex="RSA", forward_secrecy=False,
        command_transcript=["EHLO", "STARTTLS", "EHLO", "AUTH PLAIN"],
        cert_visibility=CertVisibility.OBSERVED,
        chain=[_cert()], chain_valid=True, name_match=True,
        capture_time=datetime(2024, 1, 1, tzinfo=timezone.utc),
        expected_findings=["SMS-PROTO-001"],
    ),
    after=dict(
        description="After: STARTTLS offered but handshake incomplete — TLS not observable",
        protocol=Protocol.SMTP, role=Role.SUBMISSION_ACCESS,
        banner="220 mail.example.com", capability_line="250-STARTTLS",
        starttls_offered=True, starttls_requested=True, starttls_accepted=False,
        tls_mode=TlsMode.CLEARTEXT,
        command_transcript=["EHLO", "STARTTLS"],
        cert_visibility=CertVisibility.ABSENT,
        first_frame=0, last_frame=8,
        capture_time=datetime(2024, 2, 1, tzinfo=timezone.utc),
        expected_findings=[],
    ),
)


# E. AUTH-before-TLS → AUTH-after-TLS  (FIXED)
_pair(
    "auth_before_tls_fixed",
    expected_finding="SMS-AUTH-001",
    expected_status=RemediationStatus.FIXED,
    expected_confidence=Confidence.HIGH,
    notes=["Cleartext AUTH replaced by AUTH-after-TLS; finding gone and AUTH observable"],
    before=dict(
        description="Before: AUTH PLAIN in cleartext",
        protocol=Protocol.SMTP, role=Role.SUBMISSION_ACCESS,
        banner="220 mail.example.com", capability_line="250-STARTTLS",
        starttls_offered=True, starttls_requested=False, starttls_accepted=False,
        tls_mode=TlsMode.CLEARTEXT,
        cleartext_auth=AuthExposure(mechanism="PLAIN", username="user",
                                    secret_sha256="abc", frame=10),
        command_transcript=["EHLO", "AUTH PLAIN"],
        capture_time=datetime(2024, 1, 1, tzinfo=timezone.utc),
        expected_findings=["SMS-AUTH-001", "SMS-STRIP-002"],
    ),
    after=dict(
        description="After: STARTTLS then AUTH after TLS",
        protocol=Protocol.SMTP, role=Role.SUBMISSION_ACCESS,
        banner="220 mail.example.com", capability_line="250-STARTTLS",
        starttls_offered=True, starttls_requested=True, starttls_accepted=True,
        tls_mode=TlsMode.STARTTLS, tls_version="1.2",
        cipher_suite="ECDHE-RSA-AES128-GCM-SHA256",
        kex="ECDHE", forward_secrecy=True,
        command_transcript=["EHLO", "STARTTLS", "EHLO", "AUTH PLAIN"],
        cert_visibility=CertVisibility.OBSERVED,
        chain=[_cert()], chain_valid=True, name_match=True,
        capture_time=datetime(2024, 2, 1, tzinfo=timezone.utc),
        expected_findings=[],
    ),
)


# F. AUTH-before-TLS remains  (STILL_PRESENT)
_pair(
    "auth_before_tls_still_present",
    expected_finding="SMS-AUTH-001",
    expected_status=RemediationStatus.STILL_PRESENT,
    expected_confidence=Confidence.HIGH,
    notes=["Cleartext AUTH still present in AFTER — not remediated"],
    before=dict(
        description="Before: AUTH before TLS",
        protocol=Protocol.SMTP, role=Role.SUBMISSION_ACCESS,
        banner="220 mail.example.com", capability_line="250-STARTTLS",
        starttls_offered=True, starttls_requested=False, starttls_accepted=False,
        tls_mode=TlsMode.CLEARTEXT,
        cleartext_auth=AuthExposure(mechanism="PLAIN", username="user",
                                    secret_sha256="abc", frame=10),
        command_transcript=["EHLO", "AUTH PLAIN"],
        capture_time=datetime(2024, 1, 1, tzinfo=timezone.utc),
        expected_findings=["SMS-AUTH-001"],
    ),
    after=dict(
        description="After: still AUTH before TLS",
        protocol=Protocol.SMTP, role=Role.SUBMISSION_ACCESS,
        banner="220 mail.example.com", capability_line="250-STARTTLS",
        starttls_offered=True, starttls_requested=False, starttls_accepted=False,
        tls_mode=TlsMode.CLEARTEXT,
        cleartext_auth=AuthExposure(mechanism="PLAIN", username="user",
                                    secret_sha256="abc", frame=10),
        command_transcript=["EHLO", "AUTH PLAIN"],
        capture_time=datetime(2024, 2, 1, tzinfo=timezone.utc),
        expected_findings=["SMS-AUTH-001"],
    ),
)


# G. Expired certificate → valid certificate  (FIXED)
_pair(
    "cert_expired_fixed",
    expected_finding="SMS-CERT-001",
    expected_status=RemediationStatus.FIXED,
    expected_confidence=Confidence.HIGH,
    notes=["Expired cert replaced with valid cert; cert observable in AFTER"],
    before=dict(
        description="Before: expired certificate",
        protocol=Protocol.SMTP, role=Role.SUBMISSION_ACCESS,
        banner="220 mail.example.com", capability_line="250-STARTTLS",
        starttls_offered=True, starttls_requested=True, starttls_accepted=True,
        tls_mode=TlsMode.STARTTLS, tls_version="1.2",
        cipher_suite="ECDHE-RSA-AES128-GCM-SHA256", kex="ECDHE", forward_secrecy=True,
        command_transcript=["EHLO", "STARTTLS", "EHLO", "AUTH PLAIN"],
        cert_visibility=CertVisibility.OBSERVED,
        chain=[_cert(not_before=datetime(2020, 1, 1, tzinfo=timezone.utc),
                      not_after=datetime(2023, 6, 1, tzinfo=timezone.utc),
                      expired_at_capture=True)],
        chain_valid=False, name_match=True,
        capture_time=datetime(2024, 1, 1, tzinfo=timezone.utc),
        expected_findings=["SMS-CERT-001"],
    ),
    after=dict(
        description="After: valid certificate",
        protocol=Protocol.SMTP, role=Role.SUBMISSION_ACCESS,
        banner="220 mail.example.com", capability_line="250-STARTTLS",
        starttls_offered=True, starttls_requested=True, starttls_accepted=True,
        tls_mode=TlsMode.STARTTLS, tls_version="1.2",
        cipher_suite="ECDHE-RSA-AES128-GCM-SHA256", kex="ECDHE", forward_secrecy=True,
        command_transcript=["EHLO", "STARTTLS", "EHLO", "AUTH PLAIN"],
        cert_visibility=CertVisibility.OBSERVED,
        chain=[_cert(not_before=datetime(2024, 1, 1, tzinfo=timezone.utc),
                      not_after=datetime(2026, 1, 1, tzinfo=timezone.utc))],
        chain_valid=True, name_match=True,
        capture_time=datetime(2024, 2, 1, tzinfo=timezone.utc),
        expected_findings=[],
    ),
)


# H. Certificate not observable after remediation  (UNVERIFIABLE)
_pair(
    "cert_not_observable_after",
    expected_finding="SMS-CERT-001",
    expected_status=RemediationStatus.UNVERIFIABLE,
    expected_confidence=Confidence.MEDIUM,
    notes=["Expired cert finding gone, but AFTER uses TLS 1.3 so cert not observable — UNVERIFIABLE"],
    before=dict(
        description="Before: expired cert with TLS 1.2 (cert visible)",
        protocol=Protocol.SMTP, role=Role.SUBMISSION_ACCESS,
        banner="220 mail.example.com", capability_line="250-STARTTLS",
        starttls_offered=True, starttls_requested=True, starttls_accepted=True,
        tls_mode=TlsMode.STARTTLS, tls_version="1.2",
        cipher_suite="ECDHE-RSA-AES128-GCM-SHA256", kex="ECDHE", forward_secrecy=True,
        command_transcript=["EHLO", "STARTTLS", "EHLO", "AUTH PLAIN"],
        cert_visibility=CertVisibility.OBSERVED,
        chain=[_cert(not_before=datetime(2020, 1, 1, tzinfo=timezone.utc),
                      not_after=datetime(2023, 6, 1, tzinfo=timezone.utc),
                      expired_at_capture=True)],
        chain_valid=False, name_match=True,
        capture_time=datetime(2024, 1, 1, tzinfo=timezone.utc),
        expected_findings=["SMS-CERT-001"],
    ),
    after=dict(
        description="After: TLS 1.3 — certificate encrypted, not observable",
        protocol=Protocol.SMTP, role=Role.SUBMISSION_ACCESS,
        banner="220 mail.example.com", capability_line="250-STARTTLS",
        starttls_offered=True, starttls_requested=True, starttls_accepted=True,
        tls_mode=TlsMode.STARTTLS, tls_version="1.3",
        cipher_suite="TLS_AES_128_GCM_SHA256", kex="ECDHE", forward_secrecy=True,
        command_transcript=["EHLO", "STARTTLS", "EHLO", "AUTH PLAIN"],
        cert_visibility=CertVisibility.ENCRYPTED_TLS13,
        capture_time=datetime(2024, 2, 1, tzinfo=timezone.utc),
        expected_findings=[],
    ),
)


# I. STARTTLS not used → STARTTLS negotiated  (FIXED)
_pair(
    "starttls_fixed",
    expected_finding="SMS-STRIP-002",
    expected_status=RemediationStatus.FIXED,
    expected_confidence=Confidence.HIGH,
    notes=["STARTTLS now negotiated; finding gone and STARTTLS handshake observable"],
    before=dict(
        description="Before: STARTTLS offered but not used, cleartext auth",
        protocol=Protocol.SMTP, role=Role.SUBMISSION_ACCESS,
        banner="220 mail.example.com", capability_line="250-STARTTLS",
        starttls_offered=True, starttls_requested=False, starttls_accepted=False,
        tls_mode=TlsMode.CLEARTEXT,
        cleartext_auth=AuthExposure(mechanism="PLAIN", username="user",
                                    secret_sha256="abc", frame=10),
        command_transcript=["EHLO", "AUTH PLAIN"],
        capture_time=datetime(2024, 1, 1, tzinfo=timezone.utc),
        expected_findings=["SMS-STRIP-002"],
    ),
    after=dict(
        description="After: STARTTLS negotiated successfully",
        protocol=Protocol.SMTP, role=Role.SUBMISSION_ACCESS,
        banner="220 mail.example.com", capability_line="250-STARTTLS",
        starttls_offered=True, starttls_requested=True, starttls_accepted=True,
        tls_mode=TlsMode.STARTTLS, tls_version="1.2",
        cipher_suite="ECDHE-RSA-AES128-GCM-SHA256", kex="ECDHE", forward_secrecy=True,
        command_transcript=["EHLO", "STARTTLS", "EHLO", "AUTH PLAIN"],
        cert_visibility=CertVisibility.OBSERVED,
        chain=[_cert()], chain_valid=True, name_match=True,
        capture_time=datetime(2024, 2, 1, tzinfo=timezone.utc),
        expected_findings=[],
    ),
)


# J. STARTTLS still not used  (STILL_PRESENT)
_pair(
    "starttls_still_present",
    expected_finding="SMS-STRIP-002",
    expected_status=RemediationStatus.STILL_PRESENT,
    expected_confidence=Confidence.HIGH,
    notes=["STARTTLS still not used in AFTER — not remediated"],
    before=dict(
        description="Before: STARTTLS offered but not used",
        protocol=Protocol.SMTP, role=Role.SUBMISSION_ACCESS,
        banner="220 mail.example.com", capability_line="250-STARTTLS",
        starttls_offered=True, starttls_requested=False, starttls_accepted=False,
        tls_mode=TlsMode.CLEARTEXT,
        command_transcript=["EHLO", "MAIL FROM"],
        capture_time=datetime(2024, 1, 1, tzinfo=timezone.utc),
        expected_findings=["SMS-STRIP-002"],
    ),
    after=dict(
        description="After: still STARTTLS offered but not used",
        protocol=Protocol.SMTP, role=Role.SUBMISSION_ACCESS,
        banner="220 mail.example.com", capability_line="250-STARTTLS",
        starttls_offered=True, starttls_requested=False, starttls_accepted=False,
        tls_mode=TlsMode.CLEARTEXT,
        command_transcript=["EHLO", "MAIL FROM"],
        capture_time=datetime(2024, 2, 1, tzinfo=timezone.utc),
        expected_findings=["SMS-STRIP-002"],
    ),
)


# K. Weak cipher fixed  (FIXED)
_pair(
    "weak_cipher_fixed",
    expected_finding="SMS-CIPH-001",
    expected_status=RemediationStatus.FIXED,
    expected_confidence=Confidence.HIGH,
    notes=["RC4-SHA (broken) replaced by TLS_AES_128_GCM_SHA256; cipher observable in AFTER"],
    before=dict(
        description="Before: broken RC4 cipher suite",
        protocol=Protocol.SMTP, role=Role.SUBMISSION_ACCESS,
        banner="220 mail.example.com", capability_line="250-STARTTLS",
        starttls_offered=True, starttls_requested=True, starttls_accepted=True,
        tls_mode=TlsMode.STARTTLS, tls_version="1.2",
        cipher_suite="RC4-SHA", kex="RSA", forward_secrecy=False,
        command_transcript=["EHLO", "STARTTLS", "EHLO", "AUTH PLAIN"],
        cert_visibility=CertVisibility.OBSERVED,
        chain=[_cert()], chain_valid=True, name_match=True,
        capture_time=datetime(2024, 1, 1, tzinfo=timezone.utc),
        expected_findings=["SMS-CIPH-001", "SMS-CIPH-002", "SMS-FS-001"],
    ),
    after=dict(
        description="After: modern AEAD cipher with forward secrecy",
        protocol=Protocol.SMTP, role=Role.SUBMISSION_ACCESS,
        banner="220 mail.example.com", capability_line="250-STARTTLS",
        starttls_offered=True, starttls_requested=True, starttls_accepted=True,
        tls_mode=TlsMode.STARTTLS, tls_version="1.2",
        cipher_suite="ECDHE-RSA-AES128-GCM-SHA256", kex="ECDHE", forward_secrecy=True,
        command_transcript=["EHLO", "STARTTLS", "EHLO", "AUTH PLAIN"],
        cert_visibility=CertVisibility.OBSERVED,
        chain=[_cert()], chain_valid=True, name_match=True,
        capture_time=datetime(2024, 2, 1, tzinfo=timezone.utc),
        expected_findings=[],
    ),
)


# L. Weak cipher still present  (STILL_PRESENT)
_pair(
    "weak_cipher_still_present",
    expected_finding="SMS-CIPH-001",
    expected_status=RemediationStatus.STILL_PRESENT,
    expected_confidence=Confidence.HIGH,
    notes=["Broken cipher (RC4) still negotiated in AFTER — not remediated"],
    before=dict(
        description="Before: broken RC4 cipher",
        protocol=Protocol.SMTP, role=Role.SUBMISSION_ACCESS,
        banner="220 mail.example.com", capability_line="250-STARTTLS",
        starttls_offered=True, starttls_requested=True, starttls_accepted=True,
        tls_mode=TlsMode.STARTTLS, tls_version="1.2",
        cipher_suite="RC4-SHA", kex="RSA", forward_secrecy=False,
        command_transcript=["EHLO", "STARTTLS", "EHLO", "AUTH PLAIN"],
        cert_visibility=CertVisibility.OBSERVED,
        chain=[_cert()], chain_valid=True, name_match=True,
        capture_time=datetime(2024, 1, 1, tzinfo=timezone.utc),
        expected_findings=["SMS-CIPH-001"],
    ),
    after=dict(
        description="After: still using RC4",
        protocol=Protocol.SMTP, role=Role.SUBMISSION_ACCESS,
        banner="220 mail.example.com", capability_line="250-STARTTLS",
        starttls_offered=True, starttls_requested=True, starttls_accepted=True,
        tls_mode=TlsMode.STARTTLS, tls_version="1.2",
        cipher_suite="RC4-SHA", kex="RSA", forward_secrecy=False,
        command_transcript=["EHLO", "STARTTLS", "EHLO", "AUTH PLAIN"],
        cert_visibility=CertVisibility.OBSERVED,
        chain=[_cert()], chain_valid=True, name_match=True,
        capture_time=datetime(2024, 2, 1, tzinfo=timezone.utc),
        expected_findings=["SMS-CIPH-001"],
    ),
)


# M. Multiple findings partially fixed  (PARTIALLY_FIXED)
_pair(
    "multiple_findings_partially_fixed",
    expected_finding=None,
    expected_status=RemediationStatus.PARTIALLY_FIXED,
    expected_confidence=Confidence.HIGH,
    notes=["Some findings fixed (TLS), others remain (no forward secrecy)"],
    before=dict(
        description="Before: TLS 1.0 + no forward secrecy + weak cipher",
        protocol=Protocol.SMTP, role=Role.SUBMISSION_ACCESS,
        banner="220 mail.example.com", capability_line="250-STARTTLS",
        starttls_offered=True, starttls_requested=True, starttls_accepted=True,
        tls_mode=TlsMode.STARTTLS, tls_version="1.0",
        cipher_suite="AES128-SHA", kex="RSA", forward_secrecy=False,
        command_transcript=["EHLO", "STARTTLS", "EHLO", "AUTH PLAIN"],
        cert_visibility=CertVisibility.OBSERVED,
        chain=[_cert()], chain_valid=True, name_match=True,
        capture_time=datetime(2024, 1, 1, tzinfo=timezone.utc),
        expected_findings=["SMS-PROTO-001", "SMS-CIPH-002", "SMS-FS-001"],
    ),
    after=dict(
        description="After: TLS 1.2 but still RSA (no forward secrecy)",
        protocol=Protocol.SMTP, role=Role.SUBMISSION_ACCESS,
        banner="220 mail.example.com", capability_line="250-STARTTLS",
        starttls_offered=True, starttls_requested=True, starttls_accepted=True,
        tls_mode=TlsMode.STARTTLS, tls_version="1.2",
        cipher_suite="ECDHE-RSA-AES128-GCM-SHA256", kex="RSA", forward_secrecy=False,
        command_transcript=["EHLO", "STARTTLS", "EHLO", "AUTH PLAIN"],
        cert_visibility=CertVisibility.OBSERVED,
        chain=[_cert()], chain_valid=True, name_match=True,
        capture_time=datetime(2024, 2, 1, tzinfo=timezone.utc),
        expected_findings=["SMS-FS-001"],
    ),
)


# N. Incomplete AFTER capture  (UNVERIFIABLE)
_pair(
    "incomplete_after_capture",
    expected_finding="SMS-PROTO-001",
    expected_status=RemediationStatus.UNVERIFIABLE,
    expected_confidence=Confidence.MEDIUM,
    notes=["AFTER capture ends mid-handshake; condition not observable → UNVERIFIABLE"],
    before=dict(
        description="Before: TLS 1.0 fully captured",
        protocol=Protocol.SMTP, role=Role.SUBMISSION_ACCESS,
        banner="220 mail.example.com", capability_line="250-STARTTLS",
        starttls_offered=True, starttls_requested=True, starttls_accepted=True,
        tls_mode=TlsMode.STARTTLS, tls_version="1.0", cipher_suite="AES128-SHA",
        kex="RSA", forward_secrecy=False,
        command_transcript=["EHLO", "STARTTLS", "EHLO", "AUTH PLAIN"],
        cert_visibility=CertVisibility.OBSERVED,
        chain=[_cert()], chain_valid=True, name_match=True,
        capture_time=datetime(2024, 1, 1, tzinfo=timezone.utc),
        expected_findings=["SMS-PROTO-001"],
    ),
    after=dict(
        description="After: STARTTLS requested but handshake incomplete (truncated capture)",
        protocol=Protocol.SMTP, role=Role.SUBMISSION_ACCESS,
        banner="220 mail.example.com", capability_line="250-STARTTLS",
        starttls_offered=True, starttls_requested=True, starttls_accepted=False,
        tls_mode=TlsMode.CLEARTEXT,
        command_transcript=["EHLO", "STARTTLS"],
        cert_visibility=CertVisibility.ABSENT,
        first_frame=0, last_frame=5,
        capture_time=datetime(2024, 2, 1, tzinfo=timezone.utc),
        expected_findings=[],
    ),
)


# O. Different asset  (UNVERIFIABLE)
_pair(
    "different_asset",
    expected_finding="SMS-PROTO-001",
    expected_status=RemediationStatus.UNVERIFIABLE,
    expected_confidence=Confidence.LOW,
    notes=["BEFORE and AFTER target different server identities — cannot pair"],
    before=dict(
        description="Before: TLS 1.0 on mail.example",
        protocol=Protocol.SMTP, role=Role.SUBMISSION_ACCESS,
        banner="220 mail.example.com", capability_line="250-STARTTLS",
        starttls_offered=True, starttls_requested=True, starttls_accepted=True,
        tls_mode=TlsMode.STARTTLS, tls_version="1.0", cipher_suite="AES128-SHA",
        kex="RSA", forward_secrecy=False,
        command_transcript=["EHLO", "STARTTLS", "EHLO", "AUTH PLAIN"],
        cert_visibility=CertVisibility.OBSERVED,
        chain=[_cert()], chain_valid=True, name_match=True,
        capture_time=datetime(2024, 1, 1, tzinfo=timezone.utc),
        expected_findings=["SMS-PROTO-001"],
    ),
    after=dict(
        description="After: TLS 1.3 on other.example (different asset)",
        protocol=Protocol.SMTP, role=Role.SUBMISSION_ACCESS,
        banner="220 other.example.com", capability_line="250-STARTTLS",
        starttls_offered=True, starttls_requested=True, starttls_accepted=True,
        tls_mode=TlsMode.STARTTLS, tls_version="1.3",
        cipher_suite="TLS_AES_128_GCM_SHA256", kex="ECDHE", forward_secrecy=True,
        command_transcript=["EHLO", "STARTTLS", "EHLO", "AUTH PLAIN"],
        cert_visibility=CertVisibility.OBSERVED,
        chain=[_cert()], chain_valid=True, name_match=True,
        capture_time=datetime(2024, 2, 1, tzinfo=timezone.utc),
        expected_findings=[],
    ),
    after_server_name="other.example",
    after_identity_key="other.example:587",
)


# P. Missing timestamps  (UNVERIFIABLE — pair supplied explicitly but chronological order unverifiable)
_pair(
    "missing_timestamps",
    expected_finding="SMS-PROTO-001",
    expected_status=RemediationStatus.UNVERIFIABLE,
    expected_confidence=Confidence.MEDIUM,
    notes=["BEFORE/AFTER pair supplied but timestamps missing; temporal ordering NOT_OBSERVABLE"],
    before=dict(
        description="Before: TLS 1.0 (no timestamp)",
        protocol=Protocol.SMTP, role=Role.SUBMISSION_ACCESS,
        banner="220 mail.example.com", capability_line="250-STARTTLS",
        starttls_offered=True, starttls_requested=True, starttls_accepted=True,
        tls_mode=TlsMode.STARTTLS, tls_version="1.0", cipher_suite="AES128-SHA",
        kex="RSA", forward_secrecy=False,
        command_transcript=["EHLO", "STARTTLS", "EHLO", "AUTH PLAIN"],
        cert_visibility=CertVisibility.OBSERVED,
        chain=[_cert()], chain_valid=True, name_match=True,
        capture_time=None,
        expected_findings=["SMS-PROTO-001"],
    ),
    after=dict(
        description="After: TLS 1.3 (no timestamp)",
        protocol=Protocol.SMTP, role=Role.SUBMISSION_ACCESS,
        banner="220 mail.example.com", capability_line="250-STARTTLS",
        starttls_offered=True, starttls_requested=True, starttls_accepted=True,
        tls_mode=TlsMode.STARTTLS, tls_version="1.3",
        cipher_suite="TLS_AES_128_GCM_SHA256", kex="ECDHE", forward_secrecy=True,
        command_transcript=["EHLO", "STARTTLS", "EHLO", "AUTH PLAIN"],
        cert_visibility=CertVisibility.ENCRYPTED_TLS13,
        capture_time=None,
        expected_findings=[],
    ),
)


# Q. Regression: TLS 1.0 reappears in a later capture  (STILL_PRESENT)
_pair(
    "regression_tls_returns",
    expected_finding="SMS-PROTO-001",
    expected_status=RemediationStatus.STILL_PRESENT,
    expected_confidence=Confidence.HIGH,
    notes=["Regression: TLS 1.0 was remediated but reappeared in AFTER"],
    before=dict(
        description="Before: TLS 1.3 (remediated from prior TLS 1.0)",
        protocol=Protocol.SMTP, role=Role.SUBMISSION_ACCESS,
        banner="220 mail.example.com", capability_line="250-STARTTLS",
        starttls_offered=True, starttls_requested=True, starttls_accepted=True,
        tls_mode=TlsMode.STARTTLS, tls_version="1.3",
        cipher_suite="TLS_AES_128_GCM_SHA256", kex="ECDHE", forward_secrecy=True,
        command_transcript=["EHLO", "STARTTLS", "EHLO", "AUTH PLAIN"],
        cert_visibility=CertVisibility.ENCRYPTED_TLS13,
        capture_time=datetime(2024, 2, 1, tzinfo=timezone.utc),
        expected_findings=[],
    ),
    after=dict(
        description="After: TLS 1.0 reappeared (regression)",
        protocol=Protocol.SMTP, role=Role.SUBMISSION_ACCESS,
        banner="220 mail.example.com", capability_line="250-STARTTLS",
        starttls_offered=True, starttls_requested=True, starttls_accepted=True,
        tls_mode=TlsMode.STARTTLS, tls_version="1.0", cipher_suite="AES128-SHA",
        kex="RSA", forward_secrecy=False,
        command_transcript=["EHLO", "STARTTLS", "EHLO", "AUTH PLAIN"],
        cert_visibility=CertVisibility.OBSERVED,
        chain=[_cert()], chain_valid=True, name_match=True,
        capture_time=datetime(2024, 3, 1, tzinfo=timezone.utc),
        expected_findings=["SMS-PROTO-001", "SMS-CIPH-002", "SMS-FS-001"],
    ),
)


# R. Control FAIL → PASS  (FIXED)
_pair(
    "control_fail_to_pass",
    expected_finding="SMS-PROTO-001",
    expected_control="TLS_VERSION_SECURITY",
    expected_status=RemediationStatus.FIXED,
    expected_confidence=Confidence.HIGH,
    notes=["Control TLS_VERSION_SECURITY: FAIL → PASS"],
    before=dict(
        description="Before: TLS 1.0 — control FAIL",
        protocol=Protocol.SMTP, role=Role.SUBMISSION_ACCESS,
        banner="220 mail.example.com", capability_line="250-STARTTLS",
        starttls_offered=True, starttls_requested=True, starttls_accepted=True,
        tls_mode=TlsMode.STARTTLS, tls_version="1.0", cipher_suite="AES128-SHA",
        kex="RSA", forward_secrecy=False,
        command_transcript=["EHLO", "STARTTLS", "EHLO", "AUTH PLAIN"],
        cert_visibility=CertVisibility.OBSERVED,
        chain=[_cert()], chain_valid=True, name_match=True,
        capture_time=datetime(2024, 1, 1, tzinfo=timezone.utc),
        expected_findings=["SMS-PROTO-001", "SMS-CIPH-002", "SMS-FS-001"],
    ),
    after=dict(
        description="After: TLS 1.3 — control PASS",
        protocol=Protocol.SMTP, role=Role.SUBMISSION_ACCESS,
        banner="220 mail.example.com", capability_line="250-STARTTLS",
        starttls_offered=True, starttls_requested=True, starttls_accepted=True,
        tls_mode=TlsMode.STARTTLS, tls_version="1.3",
        cipher_suite="TLS_AES_128_GCM_SHA256", kex="ECDHE", forward_secrecy=True,
        command_transcript=["EHLO", "STARTTLS", "EHLO", "AUTH PLAIN"],
        cert_visibility=CertVisibility.ENCRYPTED_TLS13,
        capture_time=datetime(2024, 2, 1, tzinfo=timezone.utc),
        expected_findings=[],
    ),
)


# S. Control FAIL → WARN  (PARTIALLY_FIXED)
_pair(
    "control_fail_to_warn",
    expected_finding="SMS-AUTH-001",
    expected_control="AUTHENTICATION_ORDERING",
    expected_status=RemediationStatus.PARTIALLY_FIXED,
    expected_confidence=Confidence.HIGH,
    notes=["Control AUTHENTICATION_ORDERING: FAIL → WARN (auth now after STARTTLS offered but still cleartext session)"],
    before=dict(
        description="Before: AUTH before TLS — control FAIL",
        protocol=Protocol.SMTP, role=Role.SUBMISSION_ACCESS,
        banner="220 mail.example.com", capability_line="250-STARTTLS",
        starttls_offered=True, starttls_requested=False, starttls_accepted=False,
        tls_mode=TlsMode.CLEARTEXT,
        cleartext_auth=AuthExposure(mechanism="PLAIN", username="user",
                                    secret_sha256="abc", frame=10),
        command_transcript=["EHLO", "AUTH PLAIN"],
        capture_time=datetime(2024, 1, 1, tzinfo=timezone.utc),
        expected_findings=["SMS-AUTH-001", "SMS-STRIP-002"],
    ),
    after=dict(
        description="After: STARTTLS negotiated but AUTH-before-TLS still present — control WARN",
        protocol=Protocol.SMTP, role=Role.SUBMISSION_ACCESS,
        banner="220 mail.example.com", capability_line="250-STARTTLS",
        starttls_offered=True, starttls_requested=True, starttls_accepted=True,
        tls_mode=TlsMode.STARTTLS, tls_version="1.2",
        cipher_suite="ECDHE-RSA-AES128-GCM-SHA256", kex="ECDHE", forward_secrecy=True,
        command_transcript=["EHLO", "STARTTLS", "EHLO", "AUTH PLAIN"],
        cert_visibility=CertVisibility.OBSERVED,
        chain=[_cert()], chain_valid=True, name_match=True,
        capture_time=datetime(2024, 2, 1, tzinfo=timezone.utc),
        # AUTH before TLS finding still present in this synthetic case
        expected_findings=["SMS-AUTH-001"],
    ),
)


# T. Control FAIL → FAIL  (STILL_PRESENT)
_pair(
    "control_fail_to_fail",
    expected_finding="SMS-CIPH-001",
    expected_control="CIPHER_SECURITY",
    expected_status=RemediationStatus.STILL_PRESENT,
    expected_confidence=Confidence.HIGH,
    notes=["Control CIPHER_SECURITY: FAIL → FAIL"],
    before=dict(
        description="Before: broken RC4 cipher — control FAIL",
        protocol=Protocol.SMTP, role=Role.SUBMISSION_ACCESS,
        banner="220 mail.example.com", capability_line="250-STARTTLS",
        starttls_offered=True, starttls_requested=True, starttls_accepted=True,
        tls_mode=TlsMode.STARTTLS, tls_version="1.2",
        cipher_suite="RC4-SHA", kex="RSA", forward_secrecy=False,
        command_transcript=["EHLO", "STARTTLS", "EHLO", "AUTH PLAIN"],
        cert_visibility=CertVisibility.OBSERVED,
        chain=[_cert()], chain_valid=True, name_match=True,
        capture_time=datetime(2024, 1, 1, tzinfo=timezone.utc),
        expected_findings=["SMS-CIPH-001"],
    ),
    after=dict(
        description="After: still RC4 — control FAIL",
        protocol=Protocol.SMTP, role=Role.SUBMISSION_ACCESS,
        banner="220 mail.example.com", capability_line="250-STARTTLS",
        starttls_offered=True, starttls_requested=True, starttls_accepted=True,
        tls_mode=TlsMode.STARTTLS, tls_version="1.2",
        cipher_suite="RC4-SHA", kex="RSA", forward_secrecy=False,
        command_transcript=["EHLO", "STARTTLS", "EHLO", "AUTH PLAIN"],
        cert_visibility=CertVisibility.OBSERVED,
        chain=[_cert()], chain_valid=True, name_match=True,
        capture_time=datetime(2024, 2, 1, tzinfo=timezone.utc),
        expected_findings=["SMS-CIPH-001"],
    ),
)


# U. Relevant protocol missing  (UNVERIFIABLE)
_pair(
    "relevant_protocol_missing",
    expected_finding="SMS-PROTO-001",
    expected_status=RemediationStatus.UNVERIFIABLE,
    expected_confidence=Confidence.MEDIUM,
    notes=["BEFORE has cleartext SMTP only; no TLS protocol was ever observed in either capture"],
    before=dict(
        description="Before: cleartext SMTP, no STARTTLS advertised",
        protocol=Protocol.SMTP, role=Role.MTA_RELAY,
        banner="220 mail.example.com", capability_line="250-AUTH PLAIN LOGIN",
        starttls_offered=False, starttls_requested=False, starttls_accepted=False,
        tls_mode=TlsMode.CLEARTEXT,
        command_transcript=["EHLO", "MAIL FROM"],
        capture_time=datetime(2024, 1, 1, tzinfo=timezone.utc),
        expected_findings=["SMS-STRIP-004"],
    ),
    after=dict(
        description="After: cleartext SMTP, still no STARTTLS",
        protocol=Protocol.SMTP, role=Role.MTA_RELAY,
        banner="220 mail.example.com", capability_line="250-AUTH PLAIN LOGIN",
        starttls_offered=False, starttls_requested=False, starttls_accepted=False,
        tls_mode=TlsMode.CLEARTEXT,
        command_transcript=["EHLO", "MAIL FROM"],
        capture_time=datetime(2024, 2, 1, tzinfo=timezone.utc),
        expected_findings=["SMS-STRIP-004"],
    ),
)


# V. Contradictory observations  (UNVERIFIABLE)
_pair(
    "contradictory_observations",
    expected_finding="SMS-PROTO-001",
    expected_status=RemediationStatus.UNVERIFIABLE,
    expected_confidence=Confidence.LOW,
    notes=["BEFORE says TLS 1.0 removed but TLS 1.0 still listed in tls_versions — contradictory evidence"],
    before=dict(
        description="Before: contradictory — finding absent but TLS 1.0 in versions",
        protocol=Protocol.SMTP, role=Role.SUBMISSION_ACCESS,
        banner="220 mail.example.com", capability_line="250-STARTTLS",
        starttls_offered=True, starttls_requested=True, starttls_accepted=True,
        tls_mode=TlsMode.STARTTLS, tls_version="1.0", cipher_suite="AES128-SHA",
        kex="RSA", forward_secrecy=False,
        command_transcript=["EHLO", "STARTTLS", "EHLO", "AUTH PLAIN"],
        cert_visibility=CertVisibility.OBSERVED,
        chain=[_cert()], chain_valid=True, name_match=True,
        capture_time=datetime(2024, 1, 1, tzinfo=timezone.utc),
        # expected_findings omits SMS-PROTO-001 to create contradiction
        expected_findings=[],
    ),
    after=dict(
        description="After: TLS 1.3",
        protocol=Protocol.SMTP, role=Role.SUBMISSION_ACCESS,
        banner="220 mail.example.com", capability_line="250-STARTTLS",
        starttls_offered=True, starttls_requested=True, starttls_accepted=True,
        tls_mode=TlsMode.STARTTLS, tls_version="1.3",
        cipher_suite="TLS_AES_128_GCM_SHA256", kex="ECDHE", forward_secrecy=True,
        command_transcript=["EHLO", "STARTTLS", "EHLO", "AUTH PLAIN"],
        cert_visibility=CertVisibility.ENCRYPTED_TLS13,
        capture_time=datetime(2024, 2, 1, tzinfo=timezone.utc),
        expected_findings=[],
    ),
)


# W. Uncertain asset identity  (UNVERIFIABLE)
_pair(
    "uncertain_asset_identity",
    expected_finding="SMS-PROTO-001",
    expected_status=RemediationStatus.UNVERIFIABLE,
    expected_confidence=Confidence.LOW,
    notes=["Asset identity confidence UNCERTAIN — cannot safely pair BEFORE/AFTER"],
    before=dict(
        description="Before: TLS 1.0 on an IP-only host (uncertain identity)",
        protocol=Protocol.SMTP, role=Role.SUBMISSION_ACCESS,
        banner="220 mail.example.com", capability_line="250-STARTTLS",
        starttls_offered=True, starttls_requested=True, starttls_accepted=True,
        tls_mode=TlsMode.STARTTLS, tls_version="1.0", cipher_suite="AES128-SHA",
        kex="RSA", forward_secrecy=False,
        command_transcript=["EHLO", "STARTTLS", "EHLO", "AUTH PLAIN"],
        cert_visibility=CertVisibility.OBSERVED,
        chain=[_cert()], chain_valid=True, name_match=True,
        capture_time=datetime(2024, 1, 1, tzinfo=timezone.utc),
        expected_findings=["SMS-PROTO-001"],
    ),
    after=dict(
        description="After: TLS 1.3 on an IP-only host (uncertain identity)",
        protocol=Protocol.SMTP, role=Role.SUBMISSION_ACCESS,
        banner="220 mail.example.com", capability_line="250-STARTTLS",
        starttls_offered=True, starttls_requested=True, starttls_accepted=True,
        tls_mode=TlsMode.STARTTLS, tls_version="1.3",
        cipher_suite="TLS_AES_128_GCM_SHA256", kex="ECDHE", forward_secrecy=True,
        command_transcript=["EHLO", "STARTTLS", "EHLO", "AUTH PLAIN"],
        cert_visibility=CertVisibility.ENCRYPTED_TLS13,
        capture_time=datetime(2024, 2, 1, tzinfo=timezone.utc),
        expected_findings=[],
    ),
    before_identity_confidence=AssetIdentityConfidence.UNCERTAIN,
    after_identity_confidence=AssetIdentityConfidence.UNCERTAIN,
)
