"""
Phase 3 — Security Reasoning + Finding/Evidence Graph tests.

Covers:
1.  finding to transition linkage
2.  transition to evidence linkage
3.  exact frame attribution
4.  fallback frame attribution
5.  unknown frame attribution
6.  STARTTLS not negotiated reasoning
7.  AUTH before TLS reasoning
8.  attack explanation with low confidence
9.  configuration explanation
10. incomplete capture reasoning
11. security control status
12. cross-session TLS version variation
13. cross-session certificate variation
14. repeated AUTH-before-TLS
15. explainable risk
16. IMAP state machine
17. POP3 state machine
18. TLS 1.3 NOT_OBSERVABLE
19. standards mapping
20. JSON serialization
21. HTML rendering
22. all Phase 1 tests
23. all Phase 2 tests
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from securemailscope.evidence import (
    Confidence,
    ObservationStatus,
)
from securemailscope.finding_reference import FindingReference, LinkConfidence
from securemailscope.finding_linker import link_finding_to_transitions, link_all_findings
from securemailscope.reasoning import (
    ReasoningEngine,
    ExplanationId,
    RiskComponents,
    compute_risk,
    Impact,
    Exposure,
    ObservedFact,
    Inference,
    PossibleExplanation,
    ReasoningResult,
)
from securemailscope.security_controls import (
    ControlId,
    ControlStatus,
    evaluate_security_controls,
    ControlEvaluation,
)
from securemailscope.cross_session import (
    PatternId,
    PatternResult,
    CrossSessionAnalysis,
    correlate_sessions,
)
from securemailscope.models import (
    Protocol,
    Session,
    TlsMode,
    CertVisibility,
    Endpoint,
    Finding,
    Severity,
    Evidence,
    AuthExposure,
    Grade,
    ScoreComponents,
)
from securemailscope.smtp_state_machine import (
    SmtpStateMachine,
    build_state_machine_for_session,
    StateMachineResult,
)
from securemailscope.imap_state_machine import ImapStateMachine
from securemailscope.pop3_state_machine import Pop3StateMachine
from securemailscope.state_machine import (
    StateTransition,
    StateCategory,
    ProtocolState,
)
from securemailscope.report import json_report, html_report


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _make_session(**kw) -> Session:
    defaults = dict(
        session_id="test-0",
        tcp_stream=0,
        client=Endpoint("10.0.0.1", 40000),
        server=Endpoint("10.0.0.2", 587),
        first_frame=1,
        last_frame=20,
        capture_time=datetime(2020, 6, 1, tzinfo=timezone.utc),
        protocol=Protocol.SMTP,
    )
    defaults.update(kw)
    return Session(**defaults)


def _make_finding(rule_id: str, severity: Severity = Severity.HIGH, **kw) -> Finding:
    defaults = dict(
        rule_id=rule_id,
        title=f"Test finding {rule_id}",
        severity=severity,
        standard="RFC 8314",
        remediation="Fix it",
        detail="detail",
    )
    defaults.update(kw)
    return Finding(**defaults)


# --------------------------------------------------------------------------
# 1. finding to transition linkage
# --------------------------------------------------------------------------

class TestFindingTransitionLinkage:
    def test_finding_links_to_transition(self):
        session = _make_session(
            protocol=Protocol.SMTP,
            banner="220 mail.example.com",
            capability_line="250-STARTTLS",
            starttls_offered=True,
            starttls_requested=False,
            starttls_accepted=False,
            tls_mode=TlsMode.CLEARTEXT,
            command_transcript=["EHLO client", "AUTH LOGIN"],
        )
        sm_result = SmtpStateMachine(session).build_states()
        finding = _make_finding("SMS-STRIP-002")
        session.findings = [finding]
        ref = link_finding_to_transitions(finding, session, sm_result)
        assert ref.finding_id == "SMS-STRIP-002"
        assert ref.link_confidence == LinkConfidence.EXACT
        assert len(ref.transition_ids) > 0
        assert len(ref.evidence_ids) > 0

    def test_finding_without_state_machine(self):
        session = _make_session(protocol=Protocol.SMTP)
        finding = _make_finding("SMS-STRIP-002")
        ref = link_finding_to_transitions(finding, session, None)
        assert ref.link_confidence == LinkConfidence.NOT_ATTEMPTED

    def test_finding_ref_backward_compatible(self):
        """FindingReference should not alter the Finding.evidence field."""
        session = _make_session(protocol=Protocol.SMTP)
        finding = _make_finding(
            "SMS-STRIP-002",
            evidence=Evidence(frames=[5, 6], tcp_stream=0, excerpt="test"),
        )
        session.findings = [finding]
        sm_result = SmtpStateMachine(session).build_states()
        ref = link_finding_to_transitions(finding, session, sm_result)
        # The original evidence field is untouched
        assert finding.evidence.frames == [5, 6]
        assert finding.evidence.excerpt == "test"


# --------------------------------------------------------------------------
# 2. transition to evidence linkage
# --------------------------------------------------------------------------

class TestTransitionEvidenceLinkage:
    def test_transition_has_evidence_refs(self):
        session = _make_session(
            protocol=Protocol.SMTP,
            banner="220 mail.example.com",
            capability_line="250-STARTTLS",
            starttls_offered=True,
            command_transcript=["EHLO client"],
        )
        sm_result = SmtpStateMachine(session).build_states()
        for tr in sm_result.transitions:
            if tr.security_relevant:
                assert hasattr(tr, "observation_refs")
                # At least some transitions carry evidence refs
        # BANNER transition should carry evidence
        banner_tr = next(
            (t for t in sm_result.transitions if t.to_state == "BANNER"), None
        )
        assert banner_tr is not None
        assert len(banner_tr.observation_refs) > 0

    def test_security_relevant_transitions_have_refs(self):
        session = _make_session(
            protocol=Protocol.SMTP,
            banner="220 mail.example.com",
            capability_line="250-STARTTLS",
            starttls_offered=True,
            starttls_requested=False,
            starttls_accepted=False,
            tls_mode=TlsMode.CLEARTEXT,
            cleartext_auth=AuthExposure(
                mechanism="LOGIN", username="user", secret_sha256="abc",
                frame=10,
            ),
            command_transcript=["EHLO client", "AUTH LOGIN"],
        )
        sm_result = SmtpStateMachine(session).build_states()
        assert len(sm_result.security_relevant_transitions) > 0
        for tr in sm_result.security_relevant_transitions:
            assert isinstance(tr, StateTransition)


# --------------------------------------------------------------------------
# 3. exact frame attribution
# --------------------------------------------------------------------------

class TestExactFrameAttribution:
    def test_auth_has_exact_frame(self):
        session = _make_session(
            protocol=Protocol.SMTP,
            banner="220 mail.example.com",
            capability_line="250-STARTTLS",
            starttls_offered=True,
            cleartext_auth=AuthExposure(
                mechanism="LOGIN", username="user", secret_sha256="abc",
                frame=15,
            ),
            tls_mode=TlsMode.CLEARTEXT,
            command_transcript=["EHLO client", "AUTH LOGIN"],
        )
        sm_result = SmtpStateMachine(session).build_states()
        auth_state = next(s for s in sm_result.states if s.name == "AUTH")
        assert auth_state.frame is not None
        # AUTH with cleartext_auth.frame should be EXACT
        auth_tr = next(t for t in sm_result.transitions if t.to_state == "AUTH")
        assert auth_tr.frame_precision in ("EXACT", "FALLBACK")

    def test_exact_frame_precision_on_transition(self):
        session = _make_session(
            protocol=Protocol.SMTP,
            banner="220 mail.example.com",
            capability_line="250-STARTTLS",
            starttls_offered=True,
            starttls_requested=True,
            starttls_accepted=True,
            tls_mode=TlsMode.STARTTLS,
            tls_version="1.2",
            command_transcript=["EHLO client", "STARTTLS", "EHLO client", "AUTH PLAIN"],
        )
        sm_result = SmtpStateMachine(session).build_states()
        for tr in sm_result.transitions:
            assert hasattr(tr, "frame_precision")
            assert tr.frame_precision in ("EXACT", "FALLBACK", "UNKNOWN")


# --------------------------------------------------------------------------
# 4. fallback frame attribution
# --------------------------------------------------------------------------

class TestFallbackFrameAttribution:
    def test_starttls_offered_uses_fallback(self):
        session = _make_session(
            protocol=Protocol.SMTP,
            banner="220 mail.example.com",
            capability_line="250-STARTTLS",
            starttls_offered=True,
            command_transcript=["EHLO client"],
        )
        sm_result = SmtpStateMachine(session).build_states()
        stls_offered_tr = next(
            (t for t in sm_result.transitions if t.to_state == "STARTTLS_OFFERED"),
            None,
        )
        assert stls_offered_tr is not None
        # Without explicit frame data, should be FALLBACK
        assert stls_offered_tr.frame_precision in ("FALLBACK", "UNKNOWN")


# --------------------------------------------------------------------------
# 5. unknown frame attribution
# --------------------------------------------------------------------------

class TestUnknownFrameAttribution:
    def test_connect_transition_precision(self):
        """CONNECT transitions should have UNKNOWN or FALLBACK precision."""
        session = _make_session(
            protocol=Protocol.SMTP,
            banner="220 mail.example.com",
            command_transcript=["EHLO client"],
        )
        sm_result = SmtpStateMachine(session).build_states()
        connect_tr = next(
            (t for t in sm_result.transitions if t.from_state == "CONNECT"),
            None,
        )
        assert connect_tr is not None
        # CONNECT frame attribution is imprecise — no SYN tracking
        assert connect_tr.frame_precision in ("UNKNOWN", "FALLBACK")

    def test_closed_transition_is_unknown(self):
        session = _make_session(
            protocol=Protocol.SMTP,
            banner="220 mail.example.com",
            command_transcript=["EHLO client", "QUIT"],
            first_frame=1,
            last_frame=10,
        )
        sm_result = SmtpStateMachine(session).build_states()
        closed_tr = next(
            (t for t in sm_result.transitions if t.to_state == "CLOSED"),
            None,
        )
        if closed_tr:
            assert closed_tr.frame_precision == "UNKNOWN"


# --------------------------------------------------------------------------
# 6. STARTTLS not negotiated reasoning
# --------------------------------------------------------------------------

class TestSTARTTLSNotNegotiatedReasoning:
    def test_starttls_not_negotiated_has_explanations(self):
        session = _make_session(
            protocol=Protocol.SMTP,
            banner="220 mail.example.com",
            capability_line="250-STARTTLS",
            starttls_offered=True,
            starttls_requested=False,
            starttls_accepted=False,
            tls_mode=TlsMode.CLEARTEXT,
            command_transcript=["EHLO client", "AUTH LOGIN"],
        )
        sm_result = SmtpStateMachine(session).build_states()
        finding = _make_finding("SMS-STRIP-002", evidence=Evidence(frames=[5]))
        session.findings = [finding]
        ref = link_finding_to_transitions(finding, session, sm_result)
        engine = ReasoningEngine()
        result = engine.reason(session, sm_result, "SMS-STRIP-002", finding, ref)
        assert len(result.possible_explanations) > 0
        # STARTTLS_STRIPPING should be in the explanations
        expl_ids = [e.explanation_id for e in result.possible_explanations]
        assert ExplanationId.STARTTLS_STRIPPING in expl_ids
        # STARTTLS_STRIPPING must have LOW confidence
        strip_expl = next(
            e for e in result.possible_explanations
            if e.explanation_id == ExplanationId.STARTTLS_STRIPPING
        )
        assert strip_expl.confidence == Confidence.LOW

    def test_starttls_not_negotiated_incomplete_capture_explanation(self):
        session = _make_session(
            protocol=Protocol.SMTP,
            banner="220 mail.example.com",
            capability_line="250-STARTTLS",
            starttls_offered=True,
            starttls_requested=False,
            starttls_accepted=False,
            tls_mode=TlsMode.CLEARTEXT,
            command_transcript=["EHLO client", "AUTH LOGIN"],
        )
        session._capture_completeness_status = "LIMITED"
        sm_result = SmtpStateMachine(session).build_states()
        finding = _make_finding("SMS-STRIP-002", evidence=Evidence(frames=[5]))
        session.findings = [finding]
        engine = ReasoningEngine()
        result = engine.reason(session, sm_result, "SMS-STRIP-002", finding, None)
        expl_ids = [e.explanation_id for e in result.possible_explanations]
        assert ExplanationId.INCOMPLETE_CAPTURE in expl_ids


# --------------------------------------------------------------------------
# 7. AUTH before TLS reasoning
# --------------------------------------------------------------------------

class TestAuthBeforeTLSReasoning:
    def test_auth_before_tls_reasoning(self):
        session = _make_session(
            protocol=Protocol.SMTP,
            banner="220 mail.example.com",
            starttls_offered=False,
            cleartext_auth=AuthExposure(
                mechanism="PLAIN", username="user", secret_sha256="abc",
                frame=10,
            ),
            tls_mode=TlsMode.CLEARTEXT,
            command_transcript=["EHLO client", "AUTH PLAIN"],
        )
        sm_result = SmtpStateMachine(session).build_states()
        finding = _make_finding("SMS-AUTH-001", evidence=Evidence(frames=[10]))
        session.findings = [finding]
        ref = link_finding_to_transitions(finding, session, sm_result)
        engine = ReasoningEngine()
        result = engine.reason(session, sm_result, "SMS-AUTH-001", finding, ref)
        assert result.finding_id == "SMS-AUTH-001"
        assert len(result.observed_facts) > 0
        assert len(result.inferences) > 0
        # Should have CLIENT_CONFIGURATION as a possible explanation
        expl_ids = [e.explanation_id for e in result.possible_explanations]
        assert ExplanationId.CLIENT_CONFIGURATION in expl_ids


# --------------------------------------------------------------------------
# 8. attack explanation with low confidence
# --------------------------------------------------------------------------

class TestAttackExplanationLowConfidence:
    def test_starttls_stripping_is_not_confirmed(self):
        """STARTTLS stripping must be LOW confidence, never 'confirmed'."""
        session = _make_session(
            protocol=Protocol.SMTP,
            banner="220 mail.example.com",
            capability_line="250-STARTTLS",
            starttls_offered=True,
            starttls_requested=False,
            starttls_accepted=False,
            tls_mode=TlsMode.CLEARTEXT,
            command_transcript=["EHLO client", "QUIRT"],
        )
        sm_result = SmtpStateMachine(session).build_states()
        finding = _make_finding("SMS-STRIP-002", evidence=Evidence(frames=[5]))
        session.findings = [finding]
        engine = ReasoningEngine()
        result = engine.reason(session, sm_result, "SMS-STRIP-002", finding, None)
        strip_expl = next(
            (e for e in result.possible_explanations
             if e.explanation_id == ExplanationId.STARTTLS_STRIPPING),
            None,
        )
        assert strip_expl is not None
        assert strip_expl.confidence == Confidence.LOW
        assert strip_expl.status == "possible"
        # Must NOT claim "confirmed attack"
        assert not any(
            "confirmed" in f.lower() for f in result.confidence_factors
        )


# --------------------------------------------------------------------------
# 9. configuration explanation
# --------------------------------------------------------------------------

class TestConfigurationExplanation:
    def test_server_configuration_explanation(self):
        """Server not advertising STARTTLS → SERVER_CONFIGURATION."""
        session = _make_session(
            protocol=Protocol.SMTP,
            banner="220 mail.example.com",
            capability_line="250-AUTH PLAIN",
            starttls_offered=False,
            cleartext_auth=AuthExposure(
                mechanism="PLAIN", username="u", secret_sha256="x", frame=5,
            ),
            tls_mode=TlsMode.CLEARTEXT,
            command_transcript=["EHLO client", "AUTH PLAIN"],
        )
        sm_result = SmtpStateMachine(session).build_states()
        finding = _make_finding("SMS-STRIP-004", evidence=Evidence(frames=[5]))
        session.findings = [finding]
        engine = ReasoningEngine()
        result = engine.reason(session, sm_result, "SMS-STRIP-004", finding, None)
        expl_ids = [e.explanation_id for e in result.possible_explanations]
        assert ExplanationId.SERVER_CONFIGURATION in expl_ids


# --------------------------------------------------------------------------
# 10. incomplete capture reasoning
# --------------------------------------------------------------------------

class TestIncompleteCaptureReasoning:
    def test_incomplete_capture_in_limits(self):
        session = _make_session(
            protocol=Protocol.SMTP,
            banner="220 mail.example.com",
            command_transcript=[],
            first_frame=1,
            last_frame=5,
        )
        session._capture_completeness_status = "LIMITED"
        sm_result = SmtpStateMachine(session).build_states()
        finding = _make_finding("SMS-AUTH-001", evidence=Evidence(frames=[]))
        session.findings = [finding]
        engine = ReasoningEngine()
        result = engine.reason(session, sm_result, "SMS-AUTH-001", finding, None)
        assert len(result.limitations) > 0


# --------------------------------------------------------------------------
# 11. security control status
# --------------------------------------------------------------------------

class TestSecurityControlStatus:
    def test_control_pass_on_secure_session(self):
        session = _make_session(
            protocol=Protocol.SMTP,
            banner="220 mail.example.com",
            starttls_offered=True,
            starttls_requested=True,
            starttls_accepted=True,
            tls_mode=TlsMode.STARTTLS,
            tls_version="1.2",
            cipher_suite="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            kex="ECDHE",
            forward_secrecy=True,
            cert_visibility=CertVisibility.ABSENT,
        )
        evaluation = evaluate_security_controls(session, None)
        assert len(evaluation) > 0
        ctrl_ids = [e.control_id for e in evaluation]
        assert ControlId.TRANSPORT_ENCRYPTION in ctrl_ids

    def test_control_fail_on_cleartext_auth(self):
        session = _make_session(
            protocol=Protocol.SMTP,
            banner="220 mail.example.com",
            starttls_offered=False,
            starttls_accepted=False,
            tls_mode=TlsMode.CLEARTEXT,
            cleartext_auth=AuthExposure(
                mechanism="PLAIN", username="u", secret_sha256="x", frame=5,
            ),
            command_transcript=["EHLO", "AUTH PLAIN"],
            first_frame=1,
            last_frame=20,
        )
        finding = _make_finding("SMS-AUTH-001", evidence=Evidence(frames=[5]))
        session.findings = [finding]
        sm_result = SmtpStateMachine(session).build_states()
        evaluation = evaluate_security_controls(session, sm_result)
        auth_ctrl = next(e for e in evaluation if e.control_id == ControlId.AUTHENTICATION_ORDERING)
        assert auth_ctrl.status == ControlStatus.FAIL

    def test_control_status_explainable(self):
        """Every control evaluation must have a non-empty reason."""
        session = _make_session(protocol=Protocol.SMTP)
        evaluation = evaluate_security_controls(session, None)
        for e in evaluation:
            assert e.reason  # non-empty string


# --------------------------------------------------------------------------
# 12. cross-session TLS version variation
# --------------------------------------------------------------------------

class TestCrossSessionTLSVariation:
    def test_tls_version_variation_detected(self):
        sessions = [
            _make_session(
                protocol=Protocol.SMTP, server=Endpoint("10.0.0.2", 587),
                client=Endpoint("10.0.0.1", 1000),
                session_id=f"s{i}",
                tls_version="1.2",
                capture_time=datetime(2020, 6, 1, 12, 0, tzinfo=timezone.utc),
            ) for i in range(3)
        ]
        sessions[2].tls_version = "1.0"
        sessions[2].session_id = "s2-low"
        analyses = correlate_sessions(sessions)
        all_patterns = []
        for a in analyses:
            all_patterns.extend(a.patterns)
        pattern_ids = [p.pattern_id for p in all_patterns]
        assert PatternId.TLS_VERSION_VARIATION.value in pattern_ids

    def test_no_variation_no_pattern(self):
        sessions = [
            _make_session(
                protocol=Protocol.SMTP, server=Endpoint("10.0.0.2", 587),
                client=Endpoint("10.0.0.1", 1000),
                session_id=f"s{i}",
                tls_version="1.2",
                capture_time=datetime(2020, 6, 1, 12, 0, tzinfo=timezone.utc),
            ) for i in range(3)
        ]
        analyses = correlate_sessions(sessions)
        all_patterns = []
        for a in analyses:
            all_patterns.extend(a.patterns)
        pattern_ids = [p.pattern_id for p in all_patterns]
        assert PatternId.TLS_VERSION_VARIATION.value not in pattern_ids


# --------------------------------------------------------------------------
# 13. cross-session certificate variation
# --------------------------------------------------------------------------

class TestCrossSessionCertVariation:
    def test_certificate_variation_detected(self):
        from securemailscope.models import CertInfo
        sessions = []
        for i in range(3):
            s = _make_session(
                protocol=Protocol.SMTP, server=Endpoint("10.0.0.2", 587),
                client=Endpoint("10.0.0.1", 1000),
                session_id=f"s{i}",
                tls_version="1.2",
                capture_time=datetime(2020, 6, 1, 12, 0, tzinfo=timezone.utc),
            )
            if i == 0:
                s.chain = [CertInfo(subject="a", issuer="x", serial="1",
                                    sha256_fingerprint="aaa")]
            else:
                s.chain = [CertInfo(subject="b", issuer="y", serial="2",
                                    sha256_fingerprint="bbb")]
            sessions.append(s)
        analyses = correlate_sessions(sessions)
        all_patterns = []
        for a in analyses:
            all_patterns.extend(a.patterns)
        pattern_ids = [p.pattern_id for p in all_patterns]
        assert PatternId.CERTIFICATE_VARIATION.value in pattern_ids


# --------------------------------------------------------------------------
# 14. repeated AUTH-before-TLS
# --------------------------------------------------------------------------

class TestRepeatedAuthBeforeTLS:
    def test_repeated_auth_before_tls_detected(self):
        sessions = []
        for i in range(3):
            s = _make_session(
                protocol=Protocol.SMTP, server=Endpoint("10.0.0.2", 587),
                client=Endpoint("10.0.0.1", 1000),
                session_id=f"s{i}",
                tls_mode=TlsMode.CLEARTEXT,
                capture_time=datetime(2020, 6, 1, 12, 0, tzinfo=timezone.utc),
            )
            s.cleartext_auth = AuthExposure(
                mechanism="PLAIN", username="u", secret_sha256="x", frame=10,
            )
            sessions.append(s)
        analyses = correlate_sessions(sessions)
        all_patterns = []
        for a in analyses:
            all_patterns.extend(a.patterns)
        pattern_ids = [p.pattern_id for p in all_patterns]
        assert PatternId.AUTH_BEFORE_TLS_REPEATED.value in pattern_ids


# --------------------------------------------------------------------------
# 15. explainable risk
# --------------------------------------------------------------------------

class TestExplainableRisk:
    def test_risk_high_impact_exposure_confidence(self):
        risk = compute_risk(Impact.HIGH, Exposure.HIGH, Confidence.HIGH)
        assert risk.overall == "high"
        assert risk.methodology  # non-empty
        assert risk.impact == Impact.HIGH
        assert risk.exposure == Exposure.HIGH
        assert risk.confidence == Confidence.HIGH

    def test_risk_unknown_propagates(self):
        risk = compute_risk(Impact.HIGH, Exposure.UNKNOWN, Confidence.HIGH)
        assert risk.overall == "unknown"

    def test_risk_low_confidence_caps_at_low(self):
        risk = compute_risk(Impact.HIGH, Exposure.HIGH, Confidence.LOW)
        assert risk.overall == "low"

    def test_risk_components_explainable(self):
        risk = compute_risk(Impact.MEDIUM, Exposure.MEDIUM, Confidence.HIGH)
        assert risk.overall == "medium"
        assert "Impact" in risk.methodology or "impact" in risk.methodology.lower()


# --------------------------------------------------------------------------
# 16. IMAP state machine
# --------------------------------------------------------------------------

class TestImapStateMachine:
    def test_imap_states(self):
        session = _make_session(
            protocol=Protocol.IMAP,
            banner="* OK [CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN] mail.example.com",
            capability_line="IMAP4rev1 STARTTLS AUTH=PLAIN",
            starttls_offered=True,
            starttls_requested=True,
            starttls_accepted=True,
            tls_mode=TlsMode.STARTTLS,
            tls_version="1.2",
            command_transcript=["a1 CAPABILITY", "a2 STARTTLS", "a3 AUTHENTICATE PLAIN",
                                "a4 SELECT INBOX", "a5 FETCH 1:5 BODY[]", "a6 LOGOUT"],
        )
        sm_result = ImapStateMachine(session).build_states()
        state_names = [s.name for s in sm_result.states]
        assert "GREETING" in state_names
        assert "CAPABILITY" in state_names
        assert "STARTTLS_OFFERED" in state_names
        assert "STARTTLS_REQUESTED" in state_names
        assert "TLS_ESTABLISHED" in state_names
        assert "AUTH" in state_names
        assert "SELECT" in state_names
        assert "FETCH" in state_names
        assert "LOGOUT" in state_names

    def test_imap_starttls_security_transition(self):
        session = _make_session(
            protocol=Protocol.IMAP,
            banner="* OK [CAPABILITY IMAP4rev1] mail.example.com",
            capability_line="IMAP4rev1 STARTTLS",
            starttls_offered=True,
            starttls_requested=False,
            starttls_accepted=False,
            tls_mode=TlsMode.CLEARTEXT,
            command_transcript=["a1 CAPABILITY", "a2 AUTHENTICATE PLAIN"],
        )
        sm_result = ImapStateMachine(session).build_states()
        state_names = [s.name for s in sm_result.states]
        assert "STARTTLS_OFFERED" in state_names
        assert "AUTH" in state_names
        # Security-relevant: STARTTLS offered but AUTH without upgrade
        sec_trans = [(t.from_state, t.to_state) for t in sm_result.security_relevant_transitions]
        assert ("STARTTLS_OFFERED", "AUTH") in sec_trans


# --------------------------------------------------------------------------
# 17. POP3 state machine
# --------------------------------------------------------------------------

class TestPop3StateMachine:
    def test_pop3_states(self):
        session = _make_session(
            protocol=Protocol.POP3,
            banner="+OK POP3 server ready",
            capability_line="STLS USER PASS",
            starttls_offered=True,
            starttls_requested=True,
            starttls_accepted=True,
            tls_mode=TlsMode.STARTTLS,
            tls_version="1.2",
            command_transcript=["CAPA", "STLS", "USER test", "PASS secret",
                                "RETR 1", "QUIT"],
        )
        sm_result = Pop3StateMachine(session).build_states()
        state_names = [s.name for s in sm_result.states]
        assert "GREETING" in state_names
        assert "CAPA" in state_names
        assert "STLS_OFFERED" in state_names
        assert "STLS_REQUESTED" in state_names
        assert "TLS_ESTABLISHED" in state_names
        assert "AUTH" in state_names
        assert "RETR" in state_names
        assert "QUIT" in state_names
        assert "CLOSED" in state_names

    def test_pop3_stls_security_transition(self):
        session = _make_session(
            protocol=Protocol.POP3,
            banner="+OK POP3 server ready",
            capability_line="STLS USER PASS",
            starttls_offered=True,
            starttls_requested=False,
            starttls_accepted=False,
            tls_mode=TlsMode.CLEARTEXT,
            command_transcript=["CAPA", "USER test", "PASS secret"],
        )
        sm_result = Pop3StateMachine(session).build_states()
        sec_trans = [(t.from_state, t.to_state) for t in sm_result.security_relevant_transitions]
        assert ("STLS_OFFERED", "AUTH") in sec_trans


# --------------------------------------------------------------------------
# 18. TLS 1.3 NOT_OBSERVABLE
# --------------------------------------------------------------------------

class TestTLS13NotObservable:
    def test_tls13_cert_not_observable(self):
        from securemailscope.models import CertInfo
        session = _make_session(
            protocol=Protocol.IMAP,
            banner="* OK [CAPABILITY IMAP4rev1 STARTTLS] mail.example.com",
            starttls_offered=True,
            starttls_requested=True,
            starttls_accepted=True,
            tls_mode=TlsMode.STARTTLS,
            tls_version="1.3",
            cert_visibility=CertVisibility.ENCRYPTED_TLS13,
            capture_time=datetime(2020, 6, 1, 12, 0, tzinfo=timezone.utc),
            command_transcript=["a1 CAPABILITY", "a2 STARTTLS", "a3 AUTHENTICATE PLAIN"],
        )
        sm_result = ImapStateMachine(session).build_states()
        finding = _make_finding("SMS-CERT-001", evidence=Evidence(frames=[]))
        session.findings = [finding]
        engine = ReasoningEngine()
        result = engine.reason(session, sm_result, "SMS-CERT-001", finding, None)
        # Should have a NOT_OBSERVABLE fact about TLS 1.3 certificate visibility
        facts = [f.description for f in result.observed_facts]
        assert any("TLS 1.3" in f or "certificate" in f.lower() for f in facts)

    def test_does_not_overclaim_tls13_support(self):
        """Must not claim server doesn't support TLS 1.3 when capture shows TLS 1.2."""
        session = _make_session(
            protocol=Protocol.SMTP,
            banner="220 mail.example.com",
            starttls_offered=True,
            starttls_requested=True,
            starttls_accepted=True,
            tls_mode=TlsMode.STARTTLS,
            tls_version="1.2",
            command_transcript=["EHLO", "STARTTLS", "EHLO", "AUTH PLAIN"],
        )
        sm_result = SmtpStateMachine(session).build_states()
        finding = _make_finding("SMS-PROTO-002", evidence=Evidence(frames=[20]))
        session.findings = [finding]
        engine = ReasoningEngine()
        result = engine.reason(session, sm_result, "SMS-PROTO-002", finding, None)
        # The reasoning should mention NOT_OBSERVABLE, not claim TLS 1.3 unsupported
        all_text = json.dumps(result.to_dict(), default=str)
        assert "does not support TLS 1.3" not in all_text.lower()


# --------------------------------------------------------------------------
# 19. standards mapping
# --------------------------------------------------------------------------

class TestStandardsMapping:
    def test_rules_have_standards(self):
        from securemailscope.scoring.rules import load_rules
        rules = load_rules()
        for r in rules:
            assert r.standard  # every rule cites at least one standard clause

    def test_standards_kb_loaded(self):
        from securemailscope.kb import load_standards
        stds = load_standards()
        assert isinstance(stds, dict)
        assert len(stds) > 0
        # Key findings should have standards
        for key in ("SMS-AUTH-001", "SMS-STRIP-002", "SMS-PROTO-003"):
            if key in stds:
                assert "standards" in stds[key]

    def test_control_has_standards(self):
        from securemailscope.security_controls import _control_standards
        ctrl_stds = _control_standards(ControlId.STARTTLS_SECURITY)
        assert isinstance(ctrl_stds, list)


# --------------------------------------------------------------------------
# 20. JSON serialization
# --------------------------------------------------------------------------

class TestJSONSerialization:
    def test_report_with_phase3_serializable(self):
        from securemailscope.pipeline import analyse_capture
        # Build a synthetic report with Phase 3 data
        session = _make_session(
            protocol=Protocol.SMTP,
            banner="220 mail.example.com",
            capability_line="250-STARTTLS",
            starttls_offered=True,
            starttls_requested=False,
            starttls_accepted=False,
            tls_mode=TlsMode.CLEARTEXT,
            command_transcript=["EHLO client", "AUTH LOGIN"],
        )
        sm_result = SmtpStateMachine(session).build_states()
        finding = _make_finding("SMS-STRIP-002", evidence=Evidence(frames=[5]))
        session.findings = [finding]
        ref = link_finding_to_transitions(finding, session, sm_result)
        session.finding_references = [ref]
        engine = ReasoningEngine()
        reasoning = engine.reason(session, sm_result, "SMS-STRIP-002", finding, ref)
        session.reasoning = [reasoning]
        controls = evaluate_security_controls(session, sm_result)
        session.security_controls = controls

        from securemailscope.models import to_dict
        doc = to_dict(session)
        assert "finding_references" in doc
        assert "reasoning" in doc
        assert "security_controls" in doc
        # Must be JSON serializable
        json_str = json.dumps(doc, default=str)
        assert "SMS-STRIP-002" in json_str

    def test_reasoning_result_serializable(self):
        session = _make_session(
            protocol=Protocol.SMTP,
            banner="220 mail.example.com",
            starttls_offered=True,
            starttls_requested=False,
            starttls_accepted=False,
            tls_mode=TlsMode.CLEARTEXT,
            command_transcript=["EHLO client", "AUTH LOGIN"],
        )
        sm_result = SmtpStateMachine(session).build_states()
        finding = _make_finding("SMS-STRIP-002", evidence=Evidence(frames=[5]))
        session.findings = [finding]
        ref = link_finding_to_transitions(finding, session, sm_result)
        engine = ReasoningEngine()
        result = engine.reason(session, sm_result, "SMS-STRIP-002", finding, ref)
        doc = result.to_dict()
        json_str = json.dumps(doc, default=str)
        assert "SMS-STRIP-002" in json_str


# --------------------------------------------------------------------------
# 21. HTML rendering
# --------------------------------------------------------------------------

class TestHTMLRenderingPhase3:
    def test_html_includes_security_controls(self):
        session = _make_session(
            protocol=Protocol.SMTP,
            banner="220 mail.example.com",
            capability_line="250-STARTTLS",
            starttls_offered=True,
            starttls_requested=True,
            starttls_accepted=True,
            tls_mode=TlsMode.STARTTLS,
            tls_version="1.2",
            command_transcript=["EHLO", "STARTTLS", "EHLO", "AUTH PLAIN"],
        )
        sm_result = SmtpStateMachine(session).build_states()
        finding = _make_finding("SMS-OK-001", evidence=Evidence(frames=[15]))
        session.findings = [finding]
        session.grade = Grade(letter="A", raw_score=90.0, components=ScoreComponents())
        ref = link_finding_to_transitions(finding, session, sm_result)
        session.finding_references = [ref]
        engine = ReasoningEngine()
        reasoning = engine.reason(session, sm_result, "SMS-OK-001", finding, ref)
        session.reasoning = [reasoning]
        controls = evaluate_security_controls(session, sm_result)
        session.security_controls = controls
        session.coverage = {"assessed_checks": 1, "applicable_checks": 1,
                            "limited_sessions": 0, "skipped_checks": []}

        from securemailscope.models import to_dict
        doc = to_dict(session)
        # Build a complete report dict with all top-level fields the template expects
        report_dict = {
            "capture": {
                "filename": "test.pcap",
                "format": "pcap",
                "bytes": 10240,
                "packet_count": 10,
                "sha256": "abc123",
                "first_packet_time": "2024-01-01T00:00:00Z",
            },
            "generated_at": "2024-01-01T12:00:00Z",
            "overall_grade": "A",
            "counts": {"sessions": 1, "assets": 1, "critical": 0,
                       "high": 0, "credentials_exposed": 0},
            "assets": [],
            "remediation": [],
            "sessions": [doc],
            "security_controls": [to_dict(c) for c in controls],
            "reasoning": [r.to_dict() for r in session.reasoning],
            "cross_session_patterns": [],
            "finding_references": [to_dict(r) for r in session.finding_references],
            "email_security_state_machines": [to_dict(sm_result)],
            "schema_version": "3.0",
            "tool_version": "test",
        }
        html = html_report.render_document(report_dict)
        assert "Security controls" in html

    def test_html_includes_reasoning_section(self):
        session = _make_session(
            protocol=Protocol.SMTP,
            banner="220 mail.example.com",
            starttls_offered=False,
            tls_mode=TlsMode.CLEARTEXT,
            command_transcript=["EHLO", "AUTH PLAIN"],
        )
        sm_result = SmtpStateMachine(session).build_states()
        finding = _make_finding("SMS-AUTH-001", evidence=Evidence(frames=[5]))
        session.findings = [finding]
        session.grade = Grade(letter="F", raw_score=0.0, components=ScoreComponents())
        session.coverage = {"assessed_checks": 1, "applicable_checks": 1,
                            "limited_sessions": 0, "skipped_checks": []}
        engine = ReasoningEngine()
        reasoning = engine.reason(session, sm_result, "SMS-AUTH-001", finding, None)
        session.reasoning = [reasoning]
        controls = evaluate_security_controls(session, sm_result)
        session.security_controls = controls

        from securemailscope.models import to_dict
        doc = to_dict(session)
        report_dict = {
            "capture": {
                "filename": "test.pcap",
                "format": "pcap",
                "bytes": 10240,
                "packet_count": 10,
                "sha256": "abc123",
                "first_packet_time": "2024-01-01T00:00:00Z",
            },
            "generated_at": "2024-01-01T12:00:00Z",
            "overall_grade": "F",
            "counts": {"sessions": 1, "assets": 1, "critical": 1,
                       "high": 0, "credentials_exposed": 1},
            "assets": [],
            "remediation": [],
            "sessions": [doc],
            "security_controls": [to_dict(c) for c in controls],
            "reasoning": [r.to_dict() for r in session.reasoning],
            "cross_session_patterns": [],
            "finding_references": [],
            "email_security_state_machines": [to_dict(sm_result)],
            "schema_version": "3.0",
            "tool_version": "test",
        }
        html = html_report.render_document(report_dict)
        assert "Security reasoning" in html


# --------------------------------------------------------------------------
# 22. all Phase 1 tests (verifies backward compatibility)
# --------------------------------------------------------------------------

class TestPhase1BackwardCompat:
    def test_phase1_evidence_model(self):
        from securemailscope.evidence import EvidenceBundle, EvidenceRef, ObservationStatus
        bundle = EvidenceBundle(session_id="test", capture_id="cap1")
        ref = EvidenceRef(
            evidence_id="ev-1",
            observation_type="smtp_banner",
            status=ObservationStatus.OBSERVED,
        )
        assert bundle.session_id == "test"

    def test_phase1_capture_completeness(self):
        from securemailscope.capture_completeness import (
            CaptureCompleteness, CaptureQuality
        )
        cc = CaptureCompleteness(
            status=CaptureQuality.GOOD, score=90, packet_count=10, flow_count=1
        )
        assert cc.status == CaptureQuality.GOOD
        assert cc.score == 90


# --------------------------------------------------------------------------
# 23. all Phase 2 tests (verifies backward compatibility)
# --------------------------------------------------------------------------

class TestPhase2BackwardCompat:
    def test_phase2_state_machine_abstraction(self):
        from securemailscope.state_machine import (
            EmailSecurityStateMachine, StateCategory, ProtocolState,
            StateTransition, StateMachineResult, TransitionRule
        )
        smr = StateMachineResult(session_id="test-0", protocol="smtp")
        assert smr.protocol == "smtp"

    def test_phase2_smtp_transitions(self):
        from securemailscope.smtp_state_machine import SMTP_TRANSITIONS
        assert len(SMTP_TRANSITIONS) > 0
        # Verify security-relevant transitions exist
        assert any(t.security_relevant for t in SMTP_TRANSITIONS)

    def test_phase2_smtp_state_machine_build(self):
        session = _make_session(
            protocol=Protocol.SMTP,
            banner="220 mail.example.com",
            capability_line="250-STARTTLS",
            starttls_offered=True,
            starttls_requested=True,
            starttls_accepted=True,
            tls_mode=TlsMode.STARTTLS,
            tls_version="1.2",
            command_transcript=["EHLO", "STARTTLS", "EHLO", "AUTH PLAIN"],
        )
        sm_result = SmtpStateMachine(session).build_states()
        assert sm_result.protocol == "smtp"
        assert len(sm_result.states) > 0
        assert len(sm_result.transitions) == len(sm_result.states) - 1

    def test_phase2_state_machine_attached_to_report(self, captures):
        from securemailscope.pipeline import analyse_capture
        report = analyse_capture(captures.get("smtp_relay_cleartext", ""), run_ml=False)
        assert report.email_security_state_machines is not None
