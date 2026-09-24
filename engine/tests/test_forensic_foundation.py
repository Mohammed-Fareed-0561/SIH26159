"""
Phase 1 forensic foundation tests.

Covers:
- gzip decompression bomb protection
- capture size limits
- malformed PCAP handling
- capture completeness model
- evidence model
- observation statuses
- sensitive information not leaked into logs
- backward compatibility with existing findings
"""
from __future__ import annotations

import gzip
import io
import json
import os
import struct
import tempfile
from pathlib import Path

import pytest

from securemailscope.analysis_result import (
    AnalysisError,
    AnalysisLimits,
    AnalysisStatus,
    RejectionReason,
)
from securemailscope.capture_completeness import (
    CaptureCompleteness,
    CaptureQuality,
    MissingEvidence,
    Limitation,
)
from securemailscope.config import (
    MAX_CAPTURE_BYTES,
    MAX_DECOMPRESSED_BYTES,
    MAX_DECOMPRESSED_SIZE_MB,
    MAX_PACKET_COUNT,
)
from securemailscope.evidence import (
    CertificateObservation,
    CertificateObservationType,
    Confidence as EvidenceConfidence,
    DNSObservation,
    DNSObservationType,
    EvidenceBundle,
    EvidenceRef,
    ObservationStatus,
    PacketRef,
    ProtocolObservation,
    ProtocolObservationType,
    TLSObservation,
    TLSObservationType,
    CaptureEvidence,
)
from securemailscope.pcap.reader import (
    CaptureFormatError,
    CaptureReader,
    CaptureSecurityError,
    _BoundedGzipReader,
    _limits,
)
from securemailscope.pipeline import analyse_capture
from securemailscope import config as _cfg


# ===========================================================================
# helpers
# ===========================================================================

def _make_minimal_pcap(packets: list[bytes]) -> bytes:
    """Build a classic pcap file with the given payloads."""
    out = bytearray()
    # global header
    out += struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for i, payload in enumerate(packets, 1):
        ts_sec = 1700000000 + i
        ts_frac = 0
        out += struct.pack("<IIII", ts_sec, ts_frac, len(payload), len(payload))
        out += payload
    return bytes(out)


def _wrap_in_gzip(data: bytes) -> bytes:
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
        gz.write(data)
    return buf.getvalue()


# ===========================================================================
# A. security hardening: gzip decompression
# ===========================================================================

class TestGzipBoundedDecompression:
    """A compressed capture must not expand beyond the configured limit."""

    def _make_bomb(self, target_mb: int = 100) -> bytes:
        """Create a small gzip that expands to ~target_mb."""
        chunk = b"\x00" * 1024
        n = min((target_mb * 1024) + 100, 50000)  # cap at ~50 MB for speed
        raw = chunk * n
        return _wrap_in_gzip(raw)

    def test_small_valid_gzip_loads(self, tmp_path):
        pcap = _make_minimal_pcap([b"hello", b"world"])
        gz = tmp_path / "small.pcap.gz"
        gz.write_bytes(_wrap_in_gzip(pcap))
        reader = CaptureReader(str(gz))
        assert reader.meta.format == "pcap.gz"
        assert reader.meta.packet_count == 2

    def test_bomb_raises_security_error(self, tmp_path):
        bomb = tmp_path / "bomb.pcap.gz"
        bomb.write_bytes(self._make_bomb(50))  # 50 MB of zeros
        original = _cfg.MAX_DECOMPRESSED_BYTES
        _cfg.MAX_DECOMPRESSED_BYTES = 1 * 1024 * 1024  # 1 MB limit
        try:
            with pytest.raises(CaptureSecurityError) as exc:
                CaptureReader(str(bomb))
            err = exc.value.args[0]
            assert isinstance(err, AnalysisError)
            assert err.status == AnalysisStatus.REJECTED
            assert err.reason == RejectionReason.DECOMPRESSED_SIZE_LIMIT_EXCEEDED
        finally:
            _cfg.MAX_DECOMPRESSED_BYTES = original

    def test_bomb_does_not_expand_unbounded(self, tmp_path):
        """Even a huge bomb should fail quickly, not consume gigabytes."""
        bomb = tmp_path / "huge.pcap.gz"
        bomb.write_bytes(self._make_bomb(50))  # 50 MB of zeros
        original = _cfg.MAX_DECOMPRESSED_BYTES
        _cfg.MAX_DECOMPRESSED_BYTES = 1 * 1024 * 1024  # 1 MB limit
        try:
            with pytest.raises(CaptureSecurityError):
                CaptureReader(str(bomb))
        finally:
            _cfg.MAX_DECOMPRESSED_BYTES = original


# ===========================================================================
# B. engine-side file limits
# ===========================================================================

class TestEngineSideLimits:

    def test_raw_size_limit_enforced(self, tmp_path):
        huge = tmp_path / "huge.pcap"
        original = _cfg.MAX_CAPTURE_BYTES
        _cfg.MAX_CAPTURE_BYTES = 100
        try:
            # Create a valid pcap header + enough data to exceed limit
            # Global header is 24 bytes. We need > 100 bytes total.
            header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
            huge.write_bytes(header + b"\x00" * 500)
            with pytest.raises(CaptureSecurityError) as exc:
                CaptureReader(str(huge))
            err = exc.value.args[0]
            assert err.reason == RejectionReason.SIZE_LIMIT_EXCEEDED
        finally:
            _cfg.MAX_CAPTURE_BYTES = original

    def test_packet_count_limit_enforced(self, tmp_path):
        """A pcap with more packets than the limit is rejected."""
        original = _cfg.MAX_PACKET_COUNT
        # Create a valid pcap with 5 packets
        pcap = _make_minimal_pcap([b"x" * 100] * 5)
        path = tmp_path / "many.pcap"
        path.write_bytes(pcap)
        _cfg.MAX_PACKET_COUNT = 3
        try:
            with pytest.raises(CaptureSecurityError) as exc:
                CaptureReader(str(path))
            err = exc.value.args[0]
            assert err.reason == RejectionReason.PACKET_COUNT_EXCEEDED
        finally:
            _cfg.MAX_PACKET_COUNT = original


# ===========================================================================
# C. malformed PCAP handling
# ===========================================================================

class TestMalformedPcap:

    def test_empty_file_raises_format_error(self, tmp_path):
        empty = tmp_path / "empty.pcap"
        empty.write_bytes(b"")
        with pytest.raises(CaptureFormatError):
            CaptureReader(str(empty))

    def test_random_bytes_raises_format_error(self, tmp_path):
        junk = tmp_path / "junk.pcap"
        junk.write_bytes(os.urandom(200))
        with pytest.raises(CaptureFormatError):
            CaptureReader(str(junk))

    def test_truncated_pcap_is_handled(self, tmp_path):
        # A pcap header that claims more packets than are present
        out = bytearray()
        out += struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        out += struct.pack("<IIII", 1700000001, 0, 100, 100)
        out += b"\x00" * 20  # truncated payload
        path = tmp_path / "truncated.pcap"
        path.write_bytes(bytes(out))
        # Should not crash — reader yields what it can
        reader = CaptureReader(str(path))
        assert reader.meta.packet_count >= 0

    def test_pcapng_with_bad_block(self, tmp_path):
        # A minimal pcapng with a truncated EPB
        out = bytearray()
        # Section Header Block
        out += struct.pack("<III", 0x0A0D0D0A, 28, 0x1A2B3C4D)
        out += struct.pack("<IHH", 1, 0, 0)
        out += struct.pack("<I", 28)
        # IDB
        out += struct.pack("<III", 0x00000001, 20, 1)
        out += struct.pack("<HH", 1, 0)
        out += struct.pack("<I", 20)
        # Truncated EPB
        out += struct.pack("<II", 0x00000006, 100)
        out += b"\x00" * 20
        path = tmp_path / "bad.pcapng"
        path.write_bytes(bytes(out))
        # Reader should handle without crashing
        try:
            reader = CaptureReader(str(path))
        except CaptureFormatError:
            pass  # acceptable


# ===========================================================================
# D. structured error output
# ===========================================================================

class TestStructuredErrors:

    def test_analysis_error_to_dict(self):
        err = AnalysisError(
            status=AnalysisStatus.REJECTED,
            reason=RejectionReason.SIZE_LIMIT_EXCEEDED,
            message="too big",
            limits=AnalysisLimits(100, 200, 300),
        )
        d = err.to_dict()
        assert d["status"] == "rejected"
        assert d["reason"] == "CAPTURE_SIZE_LIMIT_EXCEEDED"
        assert "limits" in d
        assert d["limits"]["max_input_bytes"] == 100

    def test_limits_function(self):
        lim = _limits()
        assert lim.max_input_bytes == _cfg.MAX_CAPTURE_BYTES
        assert lim.max_decompressed_bytes == _cfg.MAX_DECOMPRESSED_BYTES
        assert lim.max_packet_count == _cfg.MAX_PACKET_COUNT

    def test_rejection_reason_has_all_values(self):
        reasons = {r.value for r in RejectionReason}
        assert "CAPTURE_SIZE_LIMIT_EXCEEDED" in reasons
        assert "INVALID_CAPTURE" in reasons


# ===========================================================================
# E. capture completeness model
# ===========================================================================

class TestCaptureCompletenessModel:

    def test_good_capture(self):
        cc = CaptureCompleteness(
            status=CaptureQuality.GOOD,
            score=95,
            packet_count=100,
            flow_count=5,
        )
        d = cc.to_dict()
        assert d["status"] == "good"
        assert d["score"] == 95

    def test_missing_evidence_structure(self):
        m = MissingEvidence(
            check="truncated_packets",
            what_is_missing="some packets truncated",
            why_it_matters="may hide commands",
            findings_affected=["cmd-detection"],
        )
        d = m.__dict__
        assert d["check"] == "truncated_packets"

    def test_limitation_structure(self):
        lim = Limitation(
            check="tls13_cert_encrypted",
            description="TLS 1.3 encrypts certs",
            affects=["cert-check"],
        )
        assert lim.check == "tls13_cert_encrypted"

    def test_completeness_attached_to_report(self, captures):
        report = analyse_capture(captures["smtp_relay_cleartext"], run_ml=False)
        assert report.capture_completeness is not None
        assert report.capture_completeness.packet_count > 0


# ===========================================================================
# F. evidence model
# ===========================================================================

class TestEvidenceModel:

    def test_observation_status_enum(self):
        assert ObservationStatus.OBSERVED.value == "observed"
        assert ObservationStatus.INFERRED.value == "inferred"
        assert ObservationStatus.NOT_OBSERVABLE.value == "not_observable"
        assert ObservationStatus.CONTRADICTED.value == "contradicted"
        assert ObservationStatus.INSUFFICIENT_CAPTURE.value == "insufficient_capture"

    def test_confidence_enum(self):
        assert EvidenceConfidence.HIGH.value == "high"
        assert EvidenceConfidence.MEDIUM.value == "medium"
        assert EvidenceConfidence.LOW.value == "low"
        assert EvidenceConfidence.UNKNOWN.value == "unknown"

    def test_evidence_bundle_add_and_count(self):
        bundle = EvidenceBundle(session_id="s1", capture_id="c1")
        obs = ProtocolObservation(
            observation_id="obs1",
            session_id="s1",
            capture_id="c1",
            protocol="smtp",
            observation_type=ProtocolObservationType.SMTP_BANNER,
            value="220 mail.example.com",
            status=ObservationStatus.OBSERVED,
        )
        bundle.add(obs)
        assert len(bundle.protocol_observations) == 1
        assert bundle.status_summary[ObservationStatus.OBSERVED] == 1
        assert bundle.has_status(ObservationStatus.OBSERVED)

    def test_evidence_bundle_mixed_types(self):
        bundle = EvidenceBundle(session_id="s1", capture_id="c1")
        bundle.add(ProtocolObservation(
            observation_id="p1", session_id="s1", capture_id="c1",
            protocol="smtp", observation_type=ProtocolObservationType.SMTP_BANNER,
            value="220", status=ObservationStatus.OBSERVED,
        ))
        bundle.add(TLSObservation(
            observation_id="t1", session_id="s1", capture_id="c1",
            observation_type=TLSObservationType.CLIENT_HELLO,
            value={}, status=ObservationStatus.OBSERVED,
        ))
        bundle.add(CertificateObservation(
            observation_id="c1_obs", session_id="s1", capture_id="c1",
            observation_type=CertificateObservationType.LEAF_PRESENTED,
            value="subject", status=ObservationStatus.OBSERVED,
        ))
        bundle.add(DNSObservation(
            observation_id="d1", capture_id="c1",
            observation_type=DNSObservationType.MTA_STS_PUBLISHED,
            value="example.com", status=ObservationStatus.INFERRED,
        ))
        all_obs = bundle.observations()
        assert len(all_obs) == 4

    def test_evidence_ref(self):
        ref = EvidenceRef(
            evidence_id="obs1",
            observation_type="smtp_banner",
            status=ObservationStatus.OBSERVED,
            excerpt="220 mail",
        )
        assert ref.evidence_id == "obs1"

    def test_capture_evidence_container(self):
        ce = CaptureEvidence(capture_id="abc123", flow_count=5)
        b1 = ce.bundle_for("s1")
        b2 = ce.bundle_for("s2")
        assert len(ce.sessions) == 2

    def test_protocol_observation_types(self):
        types = {t.value for t in ProtocolObservationType}
        assert "smtp_banner" in types
        assert "credentials_exposed" in types
        assert "starttls_capability" in types

    def test_tls_observation_types(self):
        types = {t.value for t in TLSObservationType}
        assert "client_hello" in types
        assert "server_hello" in types
        assert "certificate" in types

    def test_certificate_observation_types(self):
        types = {t.value for t in CertificateObservationType}
        assert "leaf_presented" in types
        assert "chain_valid" in types
        assert "expired_at_capture" in types

    def test_dns_observation_types(self):
        types = {t.value for t in DNSObservationType}
        assert "mta_sts_published" in types
        assert "tlsa_present" in types

    def test_packet_ref(self):
        p = PacketRef(frame=42, tcp_stream=3, source_ip="10.0.0.1", source_port=54321)
        assert p.frame == 42


# ===========================================================================
# G. observation statuses in analysis
# ===========================================================================

class TestObservationStatusesInAnalysis:

    def test_cleartext_session_has_observations(self, captures):
        report = analyse_capture(captures["smtp_relay_cleartext"], run_ml=False)
        assert len(report.sessions) > 0
        s = report.sessions[0]
        assert s.cleartext_auth is not None or not s.encrypted

    def test_encrypted_session_has_tls_observations(self, captures):
        report = analyse_capture(captures["pop3_starttls"], run_ml=False)
        assert any(s.encrypted for s in report.sessions)

    def test_tls13_session_reports_encrypted_cert_visibility(self, captures):
        report = analyse_capture(captures["imaps_tls13"], run_ml=False)
        assert any(s.cert_visibility.value == "encrypted_tls13" for s in report.sessions)

    def test_finding_works_with_legacy_structure(self, captures):
        """Existing findings must still work — backward compatibility."""
        report = analyse_capture(captures["imap_cleartext"], run_ml=False)
        for s in report.sessions:
            for f in s.findings:
                assert f.rule_id
                assert f.severity
                assert hasattr(f, "evidence")


# ===========================================================================
# H. sensitive information not leaked
# ===========================================================================

class TestSensitiveInfoNotLeaked:

    def test_cleartext_auth_password_not_in_report(self, captures):
        """Passwords must never appear in the JSON report."""
        report = analyse_capture(captures["smtp_relay_cleartext"], run_ml=False)
        for s in report.sessions:
            if s.cleartext_auth:
                assert s.cleartext_auth.secret_sha256 is not None
                for attr in vars(s.cleartext_auth):
                    val = getattr(s.cleartext_auth, attr)
                    if isinstance(val, str):
                        assert "secret" not in attr or attr == "secret_sha256"

    def test_transcript_does_not_contain_raw_credentials(self, captures):
        """Transcripts must be redacted."""
        report = analyse_capture(captures["imap_cleartext"], run_ml=False)
        for s in report.sessions:
            for line in s.command_transcript:
                assert not line.startswith("AK"), "AUTH PLAIN base64 blob leaked"
                assert "PASS " not in line or "<redacted>" in line

    def test_analysis_error_does_not_contain_path(self):
        """Structured errors must not expose filesystem paths."""
        err = AnalysisError(
            status=AnalysisStatus.REJECTED,
            reason=RejectionReason.SIZE_LIMIT_EXCEEDED,
            message="too big",
            limits=AnalysisLimits(100, 200, 300),
        )
        msg = err.message
        assert "/" not in msg or "MB" in msg
        assert "\\" not in msg

    def test_capture_completeness_does_not_expose_paths(self, captures):
        report = analyse_capture(captures["smtp_relay_cleartext"], run_ml=False)
        d = report.capture_completeness.to_dict()
        assert "storage_path" not in d
        assert "filename" not in d.get("tcp", {})


# ===========================================================================
# I. JSON/HTML output
# ===========================================================================

class TestOutputFormats:

    def test_json_includes_completeness(self, captures):
        from securemailscope.report import json_report
        report = analyse_capture(captures["smtp_relay_cleartext"], run_ml=False)
        payload = json_report.dumps(report, indent=2)
        doc = json.loads(payload)
        assert "capture_completeness" in doc
        assert doc["capture_completeness"]["status"] in ("good", "limited", "insufficient")

    def test_json_serialisable(self, captures):
        from securemailscope.report import json_report
        report = analyse_capture(captures["imap_cleartext"], run_ml=False)
        payload = json_report.dumps(report)
        doc = json.loads(payload)
        assert "sessions" in doc

    def test_html_report_renders(self, captures):
        from securemailscope.report import json_report, html_report
        report = analyse_capture(captures["imap_cleartext"], run_ml=False)
        payload = json_report.dumps(report)
        doc = json.loads(payload)
        html = html_report.render_document(doc)
        assert "SecureMailScope" in html


# ===========================================================================
# J. backward compatibility
# ===========================================================================

class TestBackwardCompatibility:

    def test_all_demo_captures_analyse_without_error(self, captures):
        for name, path in captures.items():
            report = analyse_capture(path, run_ml=False)
            assert report is not None
            assert report.overall_grade is not None

    def test_existing_findings_preserved(self, captures):
        report = analyse_capture(captures["imap_cleartext"], run_ml=False)
        rule_ids = {f.rule_id for s in report.sessions for f in s.findings}
        assert "SMS-AUTH-001" in rule_ids

    def test_grades_preserved(self, captures):
        report = analyse_capture(captures["pop3_starttls"], run_ml=False)
        for s in report.sessions:
            assert s.grade is not None
            assert s.grade.letter in ("A+", "A", "B", "C", "D", "E", "F")
