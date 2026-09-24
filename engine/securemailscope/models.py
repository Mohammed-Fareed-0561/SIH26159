"""
SecureMailScope — the frozen data contract.

Every stage of the pipeline reads and writes these objects and nothing else.
The rules of the contract:

  * The *parser* fills observation fields only.
  * The *rule engine* fills ``findings`` and ``grade``.
  * The *ML stage* fills ``ml``.
  * Nobody writes to another stage's fields.

That separation is what makes every stage a pure function testable against a
JSON fixture with no PCAP involved.

Every observation field is Optional for a reason: passive observation is lossy,
and a schema that cannot express "we could not see this" forces a lie somewhere.
"""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

# These modules have no dependency on models.py — safe to import directly.
from .capture_completeness import CaptureCompleteness
from .evidence import CaptureEvidence

SCHEMA_VERSION = "1.0.0"


# --------------------------------------------------------------------------
# enumerations
# --------------------------------------------------------------------------

class Protocol(str, Enum):
    SMTP = "smtp"
    IMAP = "imap"
    POP3 = "pop3"
    UNKNOWN = "unknown"


class TlsMode(str, Enum):
    """How (or whether) the session became encrypted."""
    IMPLICIT = "implicit"
    STARTTLS = "starttls"
    CLEARTEXT = "cleartext"
    UNKNOWN = "unknown"


class Role(str, Enum):
    """
    Which rulebook applies.

    RFC 8314 mandates implicit TLS for *submission and access* (587/465/143/993/
    110/995).  It does not govern MTA-to-MTA relay on port 25, where TLS is
    opportunistic by design (RFC 7435) and cleartext fallback is the deployed
    reality of the internet.  Grading them identically is technically wrong.
    """
    SUBMISSION_ACCESS = "submission_access"
    MTA_RELAY = "mta_relay"


class CertVisibility(str, Enum):
    OBSERVED = "observed"
    ENCRYPTED_TLS13 = "encrypted_tls13"
    ABSENT = "absent"


class Revocation(str, Enum):
    GOOD = "good"
    REVOKED = "revoked"
    UNKNOWN_OFFLINE = "unknown_offline"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}[self.value]


class Confidence(str, Enum):
    FULL = "full"
    PARTIAL = "partial"


# --------------------------------------------------------------------------
# leaf structures
# --------------------------------------------------------------------------

@dataclass
class Endpoint:
    ip: str
    port: int

    def __str__(self) -> str:
        return f"{self.ip}:{self.port}"


@dataclass
class AuthExposure:
    """
    Credentials observed on an unencrypted channel.

    The password is NEVER retained.  We keep the username (redacted by default)
    and a SHA-256 of the secret so an investigator can correlate reuse without
    the report itself becoming a credential leak.
    """
    mechanism: str                      # PLAIN | LOGIN | USER/PASS
    username: Optional[str] = None
    username_redacted: bool = True
    secret_sha256: Optional[str] = None
    frame: Optional[int] = None


@dataclass
class CertInfo:
    subject: str
    issuer: str
    serial: str
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    key_algorithm: Optional[str] = None      # RSA | EC | DSA | Ed25519
    key_bits: Optional[int] = None
    signature_algorithm: Optional[str] = None
    signature_hash: Optional[str] = None     # SHA256 | SHA1 | MD5 ...
    self_signed: bool = False
    is_ca: bool = False
    san: list[str] = field(default_factory=list)
    sha256_fingerprint: Optional[str] = None
    # Set relative to the *capture* clock, not wall-clock.  See the README.
    expired_at_capture: Optional[bool] = None
    not_yet_valid_at_capture: Optional[bool] = None
    days_to_expiry_at_capture: Optional[int] = None


@dataclass
class Evidence:
    """Every finding must point back at the packets that produced it."""
    frames: list[int] = field(default_factory=list)
    tcp_stream: Optional[int] = None
    excerpt: Optional[str] = None


@dataclass
class Finding:
    rule_id: str                  # e.g. SMS-CIPH-002
    title: str
    severity: Severity
    standard: str                 # the clause this cites
    remediation: str
    detail: Optional[str] = None
    cap_grade: Optional[str] = None
    evidence: Evidence = field(default_factory=Evidence)


@dataclass
class ScoreComponents:
    """SSL-Labs-style component scores, before caps."""
    protocol: float = 0.0
    key_exchange: float = 0.0
    cipher: float = 0.0

    def weighted(self) -> float:
        return 0.30 * self.protocol + 0.30 * self.key_exchange + 0.40 * self.cipher


@dataclass
class Grade:
    letter: str                              # A+ A B C D E F  (or T for untrusted)
    raw_score: float                         # weighted average BEFORE caps
    components: ScoreComponents = field(default_factory=ScoreComponents)
    capped_by: Optional[str] = None          # rule id that decided the letter
    cap_reason: Optional[str] = None
    trusted: bool = True                     # False => certificate chain untrusted
    zero_category: Optional[str] = None      # a 0 in any category forces score 0


@dataclass
class ShapContribution:
    feature: str
    value: Any
    contribution: float


@dataclass
class MLVerdict:
    risk_class: Optional[str] = None         # secure | weak | vulnerable | critical
    risk_score: Optional[float] = None       # P(worst class) in [0,1]
    class_probabilities: dict[str, float] = field(default_factory=dict)
    anomaly: bool = False
    anomaly_score: Optional[float] = None    # lower = more anomalous
    shap: list[ShapContribution] = field(default_factory=list)
    model_version: Optional[str] = None
    explanation: Optional[str] = None


# --------------------------------------------------------------------------
# the session — the unit everything else is built from
# --------------------------------------------------------------------------

@dataclass
class Session:
    # ---- identity & provenance -------------------------------------------
    session_id: str
    tcp_stream: int
    client: Endpoint
    server: Endpoint
    first_frame: int = 0
    last_frame: int = 0
    capture_time: Optional[datetime] = None
    capture_time_suspect: bool = False
    duration_seconds: float = 0.0
    packets: int = 0
    bytes_client_to_server: int = 0
    bytes_server_to_client: int = 0

    # ---- classification ---------------------------------------------------
    protocol: Protocol = Protocol.UNKNOWN
    role: Role = Role.SUBMISSION_ACCESS
    tls_mode: TlsMode = TlsMode.UNKNOWN
    server_name: Optional[str] = None        # SNI, or reverse-mapped MX name

    # ---- pre-TLS cleartext phase (what active scanners can never see) -----
    banner: Optional[str] = None
    capability_line: Optional[str] = None
    starttls_offered: bool = False
    starttls_requested: bool = False
    starttls_accepted: bool = False
    capability_mangled: bool = False         # XXXXXXXX-style substitution
    mangled_token: Optional[str] = None
    cleartext_auth: Optional[AuthExposure] = None
    command_transcript: list[str] = field(default_factory=list)

    # ---- TLS handshake ----------------------------------------------------
    tls_version: Optional[str] = None        # "1.0" ... "1.3"
    tls_version_raw: Optional[int] = None
    cipher_suite: Optional[str] = None       # IANA name
    cipher_suite_id: Optional[int] = None
    kex: Optional[str] = None                # ECDHE | DHE | RSA | PSK
    kex_bits: Optional[int] = None
    cipher_bits: Optional[int] = None
    cipher_mode: Optional[str] = None        # AEAD | CBC | STREAM
    forward_secrecy: Optional[bool] = None
    alpn: Optional[str] = None
    resumed: bool = False
    ja3: Optional[str] = None
    ja3_string: Optional[str] = None
    ja4: Optional[str] = None
    offered_ciphers: list[int] = field(default_factory=list)
    extensions: list[int] = field(default_factory=list)
    handshake_complete: bool = False

    # ---- certificates -----------------------------------------------------
    cert_visibility: CertVisibility = CertVisibility.ABSENT
    chain: list[CertInfo] = field(default_factory=list)
    chain_valid: Optional[bool] = None
    chain_error: Optional[str] = None
    name_match: Optional[bool] = None
    revocation: Revocation = Revocation.UNKNOWN_OFFLINE

    # ---- DNS policy observed in the same capture --------------------------
    mta_sts_published: Optional[bool] = None
    tlsa_records: list[str] = field(default_factory=list)
    tls_rpt_published: Optional[bool] = None

    # ---- filled by later stages ------------------------------------------
    features: dict[str, float] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    grade: Optional[Grade] = None
    ml: Optional[MLVerdict] = None
    confidence: Confidence = Confidence.FULL
    notes: list[str] = field(default_factory=list)

    coverage: dict[str, Any] = field(default_factory=dict)

    # ---- convenience ------------------------------------------------------
    @property
    def encrypted(self) -> bool:
        return self.tls_version is not None

    @property
    def asset_key(self) -> str:
        """Identity of the server this session was talking to."""
        return f"{self.server_name or self.server.ip}:{self.server.port}"

    def worst_severity(self) -> Optional[Severity]:
        if not self.findings:
            return None
        return min((f.severity for f in self.findings), key=lambda s: s.rank)


# --------------------------------------------------------------------------
# asset (server) rollup — the unit an administrator actually acts on
# --------------------------------------------------------------------------

@dataclass
class Asset:
    key: str
    host: str
    port: int
    protocol: Protocol
    role: Role
    session_ids: list[str] = field(default_factory=list)
    session_count: int = 0
    distinct_clients: int = 0
    grade: Optional[Grade] = None
    best_tls: Optional[str] = None
    worst_tls: Optional[str] = None
    version_spread: bool = False      # negotiated different versions with different clients
    findings: list[Finding] = field(default_factory=list)
    credentials_exposed: bool = False
    exposure_score: float = 0.0       # risk x reach — drives remediation order
    ml_risk: Optional[float] = None


# --------------------------------------------------------------------------
# capture-level report
# --------------------------------------------------------------------------

@dataclass
class CaptureInfo:
    filename: str
    sha256: str
    bytes: int
    format: str                       # pcap | pcapng | pcap.gz
    packet_count: int = 0
    first_packet_time: Optional[datetime] = None
    last_packet_time: Optional[datetime] = None
    median_packet_time: Optional[datetime] = None
    suspect_timestamps: int = 0
    link_types: list[str] = field(default_factory=list)
    truncated_packets: int = 0


@dataclass
class Report:
    provenance: dict[str, Any] = field(default_factory=dict)
    coverage: dict[str, Any] = field(default_factory=dict)
    history: dict[str, Any] = field(default_factory=dict)
    schema_version: str = SCHEMA_VERSION
    tool_version: str = "1.1.0"
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    capture: Optional[CaptureInfo] = None
    sessions: list[Session] = field(default_factory=list)
    assets: list[Asset] = field(default_factory=list)
    overall_grade: Optional[str] = None
    overall_score: float = 0.0
    counts: dict[str, int] = field(default_factory=dict)
    remediation: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    # Phase 1 additions -----------------------------------------------------
    capture_completeness: Optional[CaptureCompleteness] = None
    evidence: Optional[CaptureEvidence] = None

    # Phase 2 additions -----------------------------------------------------
    email_security_state_machines: Optional[list] = None


# --------------------------------------------------------------------------
# serialisation
# --------------------------------------------------------------------------

def _encode(obj: Any) -> Any:
    if isinstance(obj, datetime):
        return obj.astimezone(timezone.utc).isoformat()
    if isinstance(obj, Enum):
        return obj.value
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {k: _encode(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, dict):
        return {k: _encode(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_encode(v) for v in obj]
    return obj


def to_dict(obj: Any) -> Any:
    """Recursively convert dataclasses/enums/datetimes into JSON-safe types."""
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        out: dict[str, Any] = {}
        for f in dataclasses.fields(obj):
            out[f.name] = _encode(getattr(obj, f.name))
        return out
    return _encode(obj)
