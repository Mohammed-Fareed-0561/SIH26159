"""
Forensic evidence model.

Every finding can be traced to evidence.  Evidence is never the full packet
payload — it is a structured observation: what was seen, where in the capture,
how confident we are, and whether the conclusion is observed directly or
inferred from multiple facts.

This module is the foundation for trustworthy forensic reporting.  It does not
produce findings; it produces the evidence objects that findings reference.
"""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional


class ObservationStatus(str, Enum):
    """How a conclusion relates to the evidence."""
    OBSERVED = "observed"
    INFERRED = "inferred"
    NOT_OBSERVABLE = "not_observable"
    CONTRADICTED = "contradicted"
    INSUFFICIENT_CAPTURE = "insufficient_capture"


class Confidence(str, Enum):
    """Qualitative confidence in a finding or observation."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class ProtocolObservationType(str, Enum):
    """Types of protocol-level observations."""
    SMTP_BANNER = "smtp_banner"
    SMTP_EHLO_RESPONSE = "smtp_ehlo_response"
    SMTP_COMMAND = "smtp_command"
    SMTP_REPLY = "smtp_reply"
    IMAP_BANNER = "imap_banner"
    IMAP_COMMAND = "imap_command"
    IMAP_RESPONSE = "imap_response"
    POP_BANNER = "pop_banner"
    POP_COMMAND = "pop_command"
    POP_RESPONSE = "pop_response"
    STARTTLS_CAPABILITY = "starttls_capability"
    STARTTLS_REQUEST = "starttls_request"
    STARTTLS_ACCEPTED = "starttls_accepted"
    STARTTLS_REFUSED = "starttls_refused"
    AUTH_EXCHANGE = "auth_exchange"
    CREDENTIALS_EXPOSED = "credentials_exposed"
    TCP_CONNECTION = "tcp_connection"
    TCP_DISCONNECTION = "tcp_disconnection"


class TLSObservationType(str, Enum):
    """Types of TLS-level observations."""
    RECORD = "tls_record"
    CLIENT_HELLO = "client_hello"
    SERVER_HELLO = "server_hello"
    CERTIFICATE = "certificate"
    SERVER_KEY_EXCHANGE = "server_key_exchange"
    SERVER_HELLO_DONE = "server_hello_done"
    FINISHED = "finished"
    ALERT = "tls_alert"
    CHANGE_CIPHER_SPEC = "change_cipher_spec"
    APPLICATION_DATA = "application_data"
    HANDSHAKE_COMPLETE = "handshake_complete"
    HANDSHAKE_INCOMPLETE = "handshake_incomplete"
    SESSION_RESUMED = "session_resumed"


class CertificateObservationType(str, Enum):
    """Types of certificate observations."""
    LEAF_PRESENTED = "leaf_presented"
    CHAIN_PRESENTED = "chain_presented"
    CHAIN_VALID = "chain_valid"
    CHAIN_INVALID = "chain_invalid"
    NAME_MATCH = "name_match"
    NAME_MISMATCH = "name_mismatch"
    EXPIRED_AT_CAPTURE = "expired_at_capture"
    NOT_YET_VALID_AT_CAPTURE = "not_yet_valid_at_capture"
    SELF_SIGNED = "self_signed"
    WEAK_SIGNATURE = "weak_signature"
    OCSP_STAPLE = "ocsp_staple"
    ENCRYPTED_TLS13 = "encrypted_tls13"
    MISSING = "missing"


class DNSObservationType(str, Enum):
    """Types of DNS observations."""
    MTA_STS_PUBLISHED = "mta_sts_published"
    TLSA_PRESENT = "tlsa_present"
    TLS_RPT_PUBLISHED = "tls_rpt_published"
    MX_RECORD = "mx_record"
    A_RECORD = "a_record"
    AAAA_RECORD = "aaaa_record"
    REVERSE_MAPPED = "reverse_mapped"


# -----------------------------------------------------------------------------
# core evidence structures
# -----------------------------------------------------------------------------

@dataclass
class EvidenceRef:
    """A lightweight reference to an evidence item from a finding."""
    evidence_id: str
    observation_type: str
    status: ObservationStatus
    excerpt: Optional[str] = None


@dataclass
class PacketRef:
    """Which packet(s) and flow an observation came from."""
    frame: Optional[int] = None
    timestamp: Optional[datetime] = None
    tcp_stream: Optional[int] = None
    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None


@dataclass
class ProtocolObservation:
    """One protocol-level observation."""
    observation_id: str
    session_id: str
    capture_id: str
    protocol: str
    observation_type: ProtocolObservationType
    value: Any
    status: ObservationStatus
    confidence: Confidence = Confidence.HIGH
    packet: Optional[PacketRef] = None
    extracted_field: Optional[str] = None
    details: Optional[dict[str, Any]] = None


@dataclass
class TLSObservation:
    """One TLS-level observation."""
    observation_id: str
    session_id: str
    capture_id: str
    observation_type: TLSObservationType
    value: Any
    status: ObservationStatus
    confidence: Confidence = Confidence.HIGH
    packet: Optional[PacketRef] = None
    extracted_field: Optional[str] = None
    details: Optional[dict[str, Any]] = None


@dataclass
class CertificateObservation:
    """One certificate-level observation."""
    observation_id: str
    session_id: str
    capture_id: str
    observation_type: CertificateObservationType
    value: Any
    status: ObservationStatus
    confidence: Confidence = Confidence.HIGH
    details: Optional[dict[str, Any]] = None


@dataclass
class DNSObservation:
    """One DNS-level observation."""
    observation_id: str
    capture_id: str
    observation_type: DNSObservationType
    value: Any
    status: ObservationStatus
    confidence: Confidence = Confidence.HIGH
    details: Optional[dict[str, Any]] = None


# -----------------------------------------------------------------------------
# evidence container (per session / per capture)
# -----------------------------------------------------------------------------

@dataclass
class EvidenceBundle:
    """All evidence gathered for a single session."""
    session_id: str
    capture_id: str
    protocol_observations: list[ProtocolObservation] = field(default_factory=list)
    tls_observations: list[TLSObservation] = field(default_factory=list)
    certificate_observations: list[CertificateObservation] = field(default_factory=list)
    dns_observations: list[DNSObservation] = field(default_factory=list)
    status_summary: dict[ObservationStatus, int] = field(default_factory=dict)

    def add(self, obs) -> None:
        if isinstance(obs, ProtocolObservation):
            self.protocol_observations.append(obs)
        elif isinstance(obs, TLSObservation):
            self.tls_observations.append(obs)
        elif isinstance(obs, CertificateObservation):
            self.certificate_observations.append(obs)
        elif isinstance(obs, DNSObservation):
            self.dns_observations.append(obs)
        self.status_summary[obs.status] = self.status_summary.get(obs.status, 0) + 1

    def observations(self) -> list:
        return (
            self.protocol_observations
            + self.tls_observations
            + self.certificate_observations
            + self.dns_observations
        )

    def has_status(self, status: ObservationStatus) -> bool:
        return status in self.status_summary


@dataclass
class CaptureEvidence:
    """All evidence gathered for an entire capture."""
    capture_id: str
    sessions: dict[str, EvidenceBundle] = field(default_factory=dict)
    flow_count: int = 0

    def bundle_for(self, session_id: str) -> EvidenceBundle:
        if session_id not in self.sessions:
            self.sessions[session_id] = EvidenceBundle(
                session_id=session_id,
                capture_id=self.capture_id,
            )
        return self.sessions[session_id]

    def all_observations(self) -> list:
        out = []
        for b in self.sessions.values():
            out.extend(b.observations())
        return out
