"""
Structured analysis result types.

These types capture the outcome of attempting to analyse a capture —
whether it succeeded completely, partially, or was rejected — so that
upstream callers (subprocess, API) receive a machine-readable reason
instead of an exception or an empty document.
"""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional


class AnalysisStatus(str, Enum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    REJECTED = "rejected"
    FAILED = "failed"


class RejectionReason(str, Enum):
    SIZE_LIMIT_EXCEEDED = "CAPTURE_SIZE_LIMIT_EXCEEDED"
    DECOMPRESSED_SIZE_LIMIT_EXCEEDED = "DECOMPRESSED_SIZE_LIMIT_EXCEEDED"
    PACKET_COUNT_EXCEEDED = "PACKET_COUNT_EXCEEDED"
    INVALID_CAPTURE = "INVALID_CAPTURE"
    UNSUPPORTED_FORMAT = "UNSUPPORTED_FORMAT"
    TRUNCATED_CAPTURE = "TRUNCATED_CAPTURE"
    INTERNAL_ERROR = "INTERNAL_ERROR"


@dataclass
class AnalysisLimits:
    max_input_bytes: int
    max_decompressed_bytes: int
    max_packet_count: int


@dataclass
class AnalysisError:
    status: AnalysisStatus
    reason: RejectionReason
    message: str
    limits: AnalysisLimits

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "reason": self.reason.value,
            "message": self.message,
            "limits": dataclasses.asdict(self.limits),
        }
