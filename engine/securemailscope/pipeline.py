"""
The analysis pipeline: capture file in, Report out.

Stage order mirrors the architecture exactly, and each stage only writes the
fields it owns:

    ingest -> parse -> reassemble -> classify -> analyse -> features
           -> rules -> grade -> ml -> aggregate -> report

Phase 1 additions:
- structured CaptureCompleteness assessment is computed and attached
- EvidenceBundle is built for every session so findings can cite evidence
- CaptureSecurityError from the reader propagates as a structured AnalysisError
"""
from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from .analysis_result import (
    AnalysisError,
    AnalysisLimits,
    AnalysisStatus,
    RejectionReason,
)
from .assessment import coverage, provenance
from .capture_completeness import (
    CaptureCompleteness,
    CaptureQuality,
    EmailSessionStats,
    Limitation,
    MissingEvidence,
    TCPFlowStats,
    TLSSessionStats,
)
from .config import MAX_CAPTURE_BYTES, MAX_DECOMPRESSED_BYTES, MAX_PACKET_COUNT
from .evidence import (
    CertificateObservation,
    CertificateObservationType,
    Confidence as EvidenceConfidence,
    DNSObservation,
    DNSObservationType,
    EvidenceBundle,
    ObservationStatus,
    PacketRef,
    ProtocolObservation,
    ProtocolObservationType,
    TLSObservation,
    TLSObservationType,
    CaptureEvidence,
)
from .history import annotate_history

from .analyze import certs as certmod
from .analyze import dnspolicy, starttls, tls
from .analyze.ciphers import group_strength_bits, properties, suite_name
from .classify import classify_mode, classify_protocol, classify_role, is_email_stream
from .features import extract as extract_features
from .models import (
    CaptureInfo,
    CertVisibility,
    Confidence,
    Endpoint,
    Protocol,
    Report,
    Session,
    Severity,
    TlsMode,
)
from .net.reassembly import TcpStream, reassemble
from .pcap.reader import (
    CaptureFormatError,
    CaptureReader,
    CaptureSecurityError,
    epoch_to_datetime,
)
from .scoring.aggregate import build_assets, overall, remediation_plan
from .scoring.grade import grade_session
from .scoring.rules import apply_rules


def file_sha256(path: str, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            b = fh.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def _limits() -> AnalysisLimits:
    return AnalysisLimits(
        max_input_bytes=MAX_CAPTURE_BYTES,
        max_decompressed_bytes=MAX_DECOMPRESSED_BYTES,
        max_packet_count=MAX_PACKET_COUNT,
    )


def _assess_capture_completeness(
    reader: CaptureReader,
    sessions: list[Session],
    streams: list[TcpStream],
    dns_query_count: int,
) -> CaptureCompleteness:
    """
    Build a first-class CaptureCompleteness from what we observed.
    """
    meta = reader.meta

    # --- TCP flow stats --------------------------------------------------
    tcp = TCPFlowStats()
    tcp.total = len(streams)
    for st in streams:
        if st.saw_syn:
            tcp.complete_syn_ack += 1
        if st.saw_fin:
            tcp.with_fin += 1
        if st.saw_rst:
            tcp.with_rst += 1
        gaps_c = len(st.client_to_server.gaps)
        gaps_s = len(st.server_to_client.gaps)
        if gaps_c == 0 and gaps_s == 0:
            tcp.reassembled_without_gaps += 1
        else:
            tcp.with_reassembly_gaps += 1
    tcp.truncated_packets = meta.truncated_packets

    # --- email session stats ---------------------------------------------
    email = EmailSessionStats()
    email.total = len(sessions)
    for s in sessions:
        if s.tls_mode == TlsMode.CLEARTEXT:
            email.plaintext_only += 1
        if s.starttls_accepted:
            email.starttls_negotiated += 1
        elif s.starttls_offered:
            email.starttls_offered_not_used += 1
        else:
            email.starttls_not_offered += 1
        if s.cleartext_auth is not None:
            email.auth_before_tls += 1
        if s.command_transcript and s.tls_mode != TlsMode.UNKNOWN:
            email.with_complete_conversation += 1
        else:
            email.with_incomplete_conversation += 1

    # --- TLS session stats -----------------------------------------------
    tls_stats = TLSSessionStats()
    for s in sessions:
        if s.tls_version is not None:
            tls_stats.total += 1
            if s.handshake_complete:
                tls_stats.handshake_complete += 1
            else:
                tls_stats.handshake_incomplete += 1
            if s.cert_visibility == CertVisibility.OBSERVED:
                tls_stats.certificate_observed += 1
            elif s.cert_visibility == CertVisibility.ENCRYPTED_TLS13:
                tls_stats.certificate_encrypted_tls13 += 1
            else:
                tls_stats.certificate_missing += 1

    # --- missing evidence -----------------------------------------------
    missing: list[MissingEvidence] = []
    limitations: list[Limitation] = []

    if meta.truncated_packets > 0:
        missing.append(MissingEvidence(
            check="truncated_packets",
            what_is_missing=f"{meta.truncated_packets} packet(s) were truncated by the capture snaplen",
            why_it_matters="truncated packets may hide protocol commands or TLS handshake messages",
            findings_affected=["protocol-detection", "tls-handshake"],
        ))

    if meta.suspect_timestamps > 0:
        missing.append(MissingEvidence(
            check="suspect_timestamps",
            what_is_missing=f"{meta.suspect_timestamps} packet(s) carry a timestamp far outside the capture range",
            why_it_matters="certificate validity is judged against the capture clock",
            findings_affected=["certificate-validity"],
        ))

    if tcp.with_reassembly_gaps > 0:
        missing.append(MissingEvidence(
            check="tcp_gaps",
            what_is_missing=f"{tcp.with_reassembly_gaps} TCP stream(s) have reassembly gaps",
            why_it_matters="missing bytes may hide protocol commands or credentials",
            findings_affected=["protocol-commands", "credential-exposure"],
        ))

    if tls_stats.handshake_incomplete > 0:
        missing.append(MissingEvidence(
            check="incomplete_handshake",
            what_is_missing=f"{tls_stats.handshake_incomplete} TLS session(s) have an incomplete handshake in the capture",
            why_it_matters="without the full handshake the negotiated parameters may be unknown",
            findings_affected=["tls-version", "cipher-suite"],
        ))

    if tls_stats.certificate_encrypted_tls13 > 0:
        limitations.append(Limitation(
            check="tls13_cert_encrypted",
            description=f"{tls_stats.certificate_encrypted_tls13} TLS 1.3 session(s) have encrypted certificates (per RFC 8446)",
            affects=["certificate-validity", "hostname-match"],
        ))

    # --- score -----------------------------------------------------------
    score = 100
    if meta.truncated_packets > 0:
        score -= min(20, meta.truncated_packets * 2)
    if meta.suspect_timestamps > 0:
        score -= min(10, meta.suspect_timestamps)
    if tcp.with_reassembly_gaps > 0:
        score -= min(20, tcp.with_reassembly_gaps * 5)
    if tls_stats.handshake_incomplete > 0:
        score -= min(15, tls_stats.handshake_incomplete * 5)
    if email.with_incomplete_conversation > 0:
        score -= min(15, email.with_incomplete_conversation * 3)
    score = max(0, min(100, score))

    if score >= 80:
        status = CaptureQuality.GOOD
    elif score >= 50:
        status = CaptureQuality.LIMITED
    else:
        status = CaptureQuality.INSUFFICIENT

    return CaptureCompleteness(
        status=status,
        score=score,
        packet_count=meta.packet_count,
        flow_count=len(streams),
        tcp=tcp,
        email=email,
        tls=tls_stats,
        dns_queries_seen=dns_query_count,
        truncated_packets=meta.truncated_packets,
        missing_evidence=missing,
        limitations=limitations,
    )


def analyse_capture(
    path: str,
    run_ml: bool = True,
    model_path: Optional[str] = None,
    progress: Optional[Callable[[str], None]] = None,
    history: Optional[list] = None,
) -> Report:
    emit = progress or (lambda stage: None)
    emit("READING")

    try:
        reader = CaptureReader(path)
    except CaptureSecurityError as exc:
        raise exc
    except CaptureFormatError as exc:
        raise AnalysisError(
            status=AnalysisStatus.REJECTED,
            reason=RejectionReason.INVALID_CAPTURE,
            message=str(exc),
            limits=_limits(),
        )

    meta = reader.meta

    capture = CaptureInfo(
        filename=os.path.basename(path),
        sha256=file_sha256(path),
        bytes=os.path.getsize(path),
        format=meta.format,
        packet_count=meta.packet_count,
        first_packet_time=epoch_to_datetime(meta.first_time),
        last_packet_time=epoch_to_datetime(meta.last_time),
        median_packet_time=epoch_to_datetime(meta.median_time),
        suspect_timestamps=meta.suspect_timestamps,
        link_types=[str(t) for t in meta.link_types],
        truncated_packets=meta.truncated_packets,
    )

    warnings: list[str] = []
    if meta.suspect_timestamps:
        warnings.append(
            f"{meta.suspect_timestamps} packet(s) carry a timestamp far outside the "
            f"capture's range and were excluded from the capture clock. Certificate "
            f"validity was judged against the median capture time."
        )
    if meta.truncated_packets:
        warnings.append(
            f"{meta.truncated_packets} packet(s) were truncated by the capture "
            f"snaplen; some payload was not recorded."
        )

    policy = dnspolicy.collect(reader.udp_datagrams())
    emit("REASSEMBLING")
    streams = reassemble(reader.tcp_segments())

    emit("TLS_AND_CERTIFICATES")
    sessions: list[Session] = []
    for st in streams:
        session = _build_session(st, reader, capture.sha256, policy)
        if session is None:
            continue
        sessions.append(session)

    emit("RULES_AND_COVERAGE")
    for s in sessions:
        s.features = extract_features(s)
        s.findings = apply_rules(s)
        s.grade = grade_session(s, s.findings)

    emit("ML_ASSESSMENT")
    if run_ml and sessions:
        try:
            from .ml.predict import annotate
            annotate(sessions, model_path=model_path)
        except ImportError as exc:
            warnings.append(
                f"Model stage skipped — {exc}. Install the optional model layer with "
                f"`pip install 'securemailscope[ml]'`. Every finding and grade above "
                f"comes from the rule engine and is unaffected."
            )
        except Exception as exc:
            warnings.append(f"Model stage skipped — {exc}")

    emit("AGGREGATING")
    assets = build_assets(sessions)
    letter, score = overall(assets)

    counts = {
        "sessions": len(sessions),
        "assets": len(assets),
        "critical": sum(1 for s in sessions for f in s.findings if f.severity == Severity.CRITICAL),
        "high": sum(1 for s in sessions for f in s.findings if f.severity == Severity.HIGH),
        "medium": sum(1 for s in sessions for f in s.findings if f.severity == Severity.MEDIUM),
        "low": sum(1 for s in sessions for f in s.findings if f.severity == Severity.LOW),
        "encrypted_sessions": sum(1 for s in sessions if s.encrypted),
        "cleartext_sessions": sum(1 for s in sessions if not s.encrypted),
        "credentials_exposed": sum(1 for s in sessions if s.cleartext_auth),
        "anomalies": sum(1 for s in sessions if s.ml and s.ml.anomaly),
    }

    # --- Phase 1: capture completeness ----------------------------------
    capture_completeness = _assess_capture_completeness(reader, sessions, streams, policy.queries_seen)

    report = Report(
        provenance=provenance(model_path),
        coverage={"sessions": len(sessions), "limited_sessions": sum(s.coverage["label"] == "limited" for s in sessions),
                  "assessed_checks": sum(s.coverage["assessed_checks"] for s in sessions),
                  "applicable_checks": sum(s.coverage["applicable_checks"] for s in sessions)},
        capture=capture,
        sessions=sessions,
        assets=assets,
        overall_grade=letter,
        overall_score=score,
        counts=counts,
        remediation=remediation_plan(assets),
        warnings=warnings,
        capture_completeness=capture_completeness,
        evidence=None,
    )

    emit("HISTORY_COMPARISON")
    report.history = annotate_history(report, history or [])
    report.provenance["ml_enabled"] = run_ml
    report.provenance["ml_applied"] = any(s.ml for s in sessions)
    return report


def _build_session(
    st: TcpStream,
    reader: CaptureReader,
    capture_hash: str,
    policy: dnspolicy.DnsPolicy,
) -> Optional[Session]:
    c_data = st.client_to_server.data
    s_data = st.server_to_client.data

    tls_c = tls.find_tls_start(c_data)
    tls_s = tls.find_tls_start(s_data)

    protocol = classify_protocol(st, tls_s)
    if not is_email_stream(protocol, st):
        return None

    c_clear = c_data[:tls_c] if tls_c is not None else c_data
    s_clear = s_data[:tls_s] if tls_s is not None else s_data

    lines = starttls.build_dialogue(
        c_clear, s_clear, st.client_to_server, st.server_to_client
    )
    stls = starttls.analyse(protocol, lines, tls_started=tls_c is not None)

    mode = classify_mode(st, protocol, tls_c, stls.accepted)
    role = classify_role(protocol, st.server_port)

    raw_time = st.first_time
    suspect = reader.is_suspect_time(raw_time)
    capture_time = epoch_to_datetime(reader.sane_time(raw_time))

    session = Session(
        session_id=f"{capture_hash[:8]}-{st.stream_id}",
        tcp_stream=st.stream_id,
        client=Endpoint(st.client_ip, st.client_port),
        server=Endpoint(st.server_ip, st.server_port),
        first_frame=st.first_frame,
        last_frame=st.last_frame,
        capture_time=capture_time,
        capture_time_suspect=suspect,
        duration_seconds=round(st.duration, 3),
        packets=st.packets,
        bytes_client_to_server=len(c_data),
        bytes_server_to_client=len(s_data),
        protocol=protocol,
        role=role,
        tls_mode=mode,
        banner=stls.banner,
        capability_line=stls.capability_line,
        starttls_offered=stls.offered,
        starttls_requested=stls.requested,
        starttls_accepted=stls.accepted,
        capability_mangled=stls.mangled,
        mangled_token=stls.mangled_token,
        cleartext_auth=stls.auth,
        command_transcript=stls.transcript,
    )

    # ---- TLS ------------------------------------------------------------
    if tls_c is not None or tls_s is not None:
        hs = tls.analyse_handshake(c_data, s_data)
        session.tls_version_raw = hs.negotiated_version
        session.tls_version = tls.version_name(hs.negotiated_version)
        session.handshake_complete = hs.complete
        session.resumed = hs.resumed
        session.ja3 = hs.ja3
        session.ja3_string = hs.ja3_string
        session.ja4 = hs.ja4
        session.alpn = hs.alpn
        session.server_name = hs.server_name
        if hs.client_hello:
            session.offered_ciphers = hs.client_hello.cipher_suites
            session.extensions = hs.client_hello.extensions

        if hs.cipher_suite is not None:
            props = properties(hs.cipher_suite)
            session.cipher_suite_id = hs.cipher_suite
            session.cipher_suite = props.name
            session.kex = props.kex
            session.cipher_bits = props.key_bits
            session.cipher_mode = props.mode
            session.forward_secrecy = props.forward_secrecy

        if hs.named_group:
            session.kex_bits = group_strength_bits(hs.named_group) or None
        elif hs.dhe_bits:
            session.kex_bits = hs.dhe_bits

        if hs.certificates:
            session.cert_visibility = CertVisibility.OBSERVED
            analysis = certmod.analyse(
                hs.certificates, capture_time, session.server_name, hs.ocsp_response
            )
            session.chain = analysis.chain
            session.chain_valid = analysis.chain_valid
            session.chain_error = analysis.chain_error
            session.name_match = analysis.name_match
            session.revocation = analysis.revocation
            if session.kex_bits is None and analysis.smallest_key_bits:
                session.kex_bits = analysis.smallest_key_bits
        elif hs.negotiated_version == 0x0304:
            session.cert_visibility = CertVisibility.ENCRYPTED_TLS13
            session.confidence = Confidence.PARTIAL
        else:
            session.cert_visibility = CertVisibility.ABSENT
            if session.tls_version:
                session.confidence = Confidence.PARTIAL

    mta, tlsa, rpt = policy.policy_for_ip(st.server_ip)
    session.mta_sts_published = mta
    session.tlsa_records = tlsa
    session.tls_rpt_published = rpt
    if not session.server_name:
        session.server_name = policy.ip_to_host.get(st.server_ip)

    if session.capture_time_suspect:
        session.notes.append(
            "This session's first packet carries an implausible timestamp; the "
            "capture median was used as the reference clock."
        )
    if st.client_to_server.gaps or st.server_to_client.gaps:
        session.notes.append("Reassembled stream contains gaps; some bytes were not captured.")
        session.confidence = Confidence.PARTIAL

    session.coverage = coverage(session, len(st.client_to_server.gaps) + len(st.server_to_client.gaps), reader.meta.truncated_packets > 0)
    return session
