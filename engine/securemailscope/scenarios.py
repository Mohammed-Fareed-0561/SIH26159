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
                  capture_time: Optional[datetime] = None) -> Session:
    """Build a Session from a ground-truth scenario."""
    if capture_time is None:
        capture_time = scenario.capture_time or datetime(2024, 1, 1, tzinfo=timezone.utc)
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
        server_name="mail.example",
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
    SCENARIOS[name] = GroundTruthScenario(name=name, **kwargs)


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
