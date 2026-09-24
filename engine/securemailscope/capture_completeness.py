"""
Capture completeness assessment.

Before any conclusions are drawn, assess the quality of the capture itself.
Incomplete captures cannot support strong conclusions.

DO NOT allow the system to make a stronger conclusion than the evidence supports.
"""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class CaptureQuality(str, Enum):
    GOOD = "good"
    LIMITED = "limited"
    INSUFFICIENT = "insufficient"


@dataclass
class MissingEvidence:
    """A piece of evidence that was expected but not found."""
    check: str
    what_is_missing: str
    why_it_matters: str
    findings_affected: list[str] = field(default_factory=list)


@dataclass
class Limitation:
    """A limitation of this capture that affects interpretation."""
    check: str
    description: str
    affects: list[str] = field(default_factory=list)


@dataclass
class TCPFlowStats:
    """Stats about TCP flows in the capture."""
    total: int = 0
    complete_syn_ack: int = 0
    with_fin: int = 0
    with_rst: int = 0
    reassembled_without_gaps: int = 0
    with_reassembly_gaps: int = 0
    truncated_packets: int = 0


@dataclass
class EmailSessionStats:
    """Stats about email sessions in the capture."""
    total: int = 0
    with_complete_conversation: int = 0
    with_incomplete_conversation: int = 0
    starttls_negotiated: int = 0
    starttls_offered_not_used: int = 0
    starttls_not_offered: int = 0
    auth_before_tls: int = 0
    plaintext_only: int = 0


@dataclass
class TLSSessionStats:
    """Stats about TLS sessions in the capture."""
    total: int = 0
    handshake_complete: int = 0
    handshake_incomplete: int = 0
    certificate_observed: int = 0
    certificate_encrypted_tls13: int = 0
    certificate_missing: int = 0


@dataclass
class CaptureCompleteness:
    """First-class assessment of capture quality."""
    status: CaptureQuality
    score: int  # 0-100
    packet_count: int
    flow_count: int
    tcp: TCPFlowStats = field(default_factory=TCPFlowStats)
    email: EmailSessionStats = field(default_factory=EmailSessionStats)
    tls: TLSSessionStats = field(default_factory=TLSSessionStats)
    dns_queries_seen: int = 0
    truncated_packets: int = 0
    missing_evidence: list[MissingEvidence] = field(default_factory=list)
    limitations: list[Limitation] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "score": self.score,
            "packet_count": self.packet_count,
            "flow_count": self.flow_count,
            "tcp": dataclasses.asdict(self.tcp),
            "email": dataclasses.asdict(self.email),
            "tls": dataclasses.asdict(self.tls),
            "dns_queries_seen": self.dns_queries_seen,
            "truncated_packets": self.truncated_packets,
            "missing_evidence": [dataclasses.asdict(m) for m in self.missing_evidence],
            "limitations": [dataclasses.asdict(l) for l in self.limitations],
        }
