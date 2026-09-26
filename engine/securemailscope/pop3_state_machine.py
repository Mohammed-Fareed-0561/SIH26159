"""
POP3 Security State Machine.

Models the observed sequence of states in a POP3 session.

States:
  CONNECT
  GREETING          (+ response from server)
  CAPA              (CAPABILITIES command/response)
  STLS_OFFERED      (CAPA lists STLS)
  STLS_REQUESTED    (client sent STLS command)
  TLS_NEGOTIATING
  TLS_ESTABLISHED
  AUTH               (USER/PASS, AUTH command)
  RETR               (message retrieval)
  QUIT
  CLOSED
  ERROR
  INCOMPLETE

Only security-relevant states and transitions are modelled precisely.
"""
from __future__ import annotations

import re
from typing import Optional

from .evidence import (
    Confidence,
    EvidenceRef,
    ObservationStatus,
    ProtocolObservationType,
)
from .models import Protocol, Session, TlsMode
from .state_machine import (
    EmailSecurityStateMachine,
    ProtocolState,
    StateCategory,
    StateMachineResult,
    StateTransition,
    TransitionRule,
)

POP3_TRANSITIONS = [
    # connection / banner
    TransitionRule("CONNECT", "GREETING"),
    TransitionRule("CONNECT", "INCOMPLETE"),
    # greeting → capa
    TransitionRule("GREETING", "CAPA"),
    # STLS path — security relevant transitions
    TransitionRule("CAPA", "STLS_OFFERED",
                   security_relevant=True,
                   security_note="Server advertised STLS capability"),
    TransitionRule("CAPA", "STLS_REQUESTED",
                   security_relevant=True,
                   security_note="Client requested STLS upgrade"),
    # STLS offered but client went to AUTH without upgrading
    TransitionRule("STLS_OFFERED", "STLS_REQUESTED"),
    TransitionRule("STLS_OFFERED", "AUTH",
                   security_relevant=True,
                   security_note="STLS was offered but the client proceeded to AUTH without it"),
    # TLS negotiation
    TransitionRule("STLS_REQUESTED", "TLS_NEGOTIATING"),
    TransitionRule("TLS_NEGOTIATING", "TLS_ESTABLISHED"),
    TransitionRule("TLS_NEGOTIATING", "ERROR",
                   security_relevant=True,
                   security_note="TLS handshake failed or was interrupted"),
    TransitionRule("TLS_NEGOTIATING", "INCOMPLETE",
                   security_relevant=True,
                   security_note="TLS handshake incomplete in capture"),
    TransitionRule("TLS_ESTABLISHED", "AUTH"),
    # cleartext auth path (security relevant)
    TransitionRule("CAPA", "AUTH",
                   security_relevant=True,
                   security_note="Authentication occurred without transport encryption"),
    # transfer / termination
    TransitionRule("AUTH", "RETR"),
    TransitionRule("RETR", "QUIT"),
    TransitionRule("AUTH", "QUIT"),
    TransitionRule("QUIT", "CLOSED"),
    # error / incomplete
    TransitionRule("*", "ERROR"),
    TransitionRule("*", "INCOMPLETE"),
]


def _pop3_state_category(name: str) -> StateCategory:
    mapping = {
        "CONNECT": StateCategory.CONNECTION,
        "GREETING": StateCategory.NEGOTIATION,
        "CAPA": StateCategory.NEGOTIATION,
        "STLS_OFFERED": StateCategory.NEGOTIATION,
        "STLS_REQUESTED": StateCategory.ENCRYPTION,
        "TLS_NEGOTIATING": StateCategory.ENCRYPTION,
        "TLS_ESTABLISHED": StateCategory.ENCRYPTION,
        "AUTH": StateCategory.AUTHENTICATION,
        "RETR": StateCategory.TRANSFER,
        "QUIT": StateCategory.TERMINATION,
        "CLOSED": StateCategory.TERMINATION,
        "ERROR": StateCategory.ERROR,
        "INCOMPLETE": StateCategory.INCOMPLETE,
    }
    return mapping.get(name, StateCategory.NEGOTIATION)


class Pop3StateMachine(EmailSecurityStateMachine):
    """POP3 state machine — consumes parsed Session data."""

    def __init__(self, session: Session):
        super().__init__(session)
        self._current_precision = "FALLBACK"

    @property
    def protocol_name(self) -> str:
        return "pop3"

    def _define_transitions(self) -> list[TransitionRule]:
        return POP3_TRANSITIONS

    def build_states(self) -> StateMachineResult:
        session = self.session
        result = StateMachineResult(
            session_id=session.session_id, protocol="pop3"
        )

        states: list[tuple[str, Optional[int], list[EvidenceRef], str]] = []

        # CONNECT
        states.append(("CONNECT", session.first_frame, [], "UNKNOWN"))

        # GREETING
        if session.banner:
            ref = EvidenceRef(
                evidence_id=f"{session.session_id}:pop3_greeting",
                observation_type=ProtocolObservationType.POP_BANNER.value,
                status=ObservationStatus.OBSERVED,
                excerpt=session.banner[:200],
            )
            states.append(("GREETING", session.first_frame, [ref], "FALLBACK"))

        # CAPA — CAPABILITIES response
        if session.capability_line:
            ref = EvidenceRef(
                evidence_id=f"{session.session_id}:pop3_capa",
                observation_type=ProtocolObservationType.POP_RESPONSE.value,
                status=ObservationStatus.OBSERVED,
                excerpt=session.capability_line[:400],
            )
            states.append(("CAPA", session.first_frame, [ref], "FALLBACK"))

        # STLS_OFFERED
        if session.starttls_offered:
            ref = EvidenceRef(
                evidence_id=f"{session.session_id}:pop3_stls_offered",
                observation_type=ProtocolObservationType.STARTTLS_CAPABILITY.value,
                status=ObservationStatus.OBSERVED,
                excerpt="STLS",
            )
            states.append(("STLS_OFFERED", session.first_frame, [ref], "FALLBACK"))

        # STLS_REQUESTED
        if session.starttls_requested:
            frame = session.first_frame
            precision = "FALLBACK"
            ref = EvidenceRef(
                evidence_id=f"{session.session_id}:pop3_stls_requested",
                observation_type=ProtocolObservationType.STARTTLS_REQUEST.value,
                status=ObservationStatus.OBSERVED,
                excerpt="STLS",
            )
            states.append(("STLS_REQUESTED", frame, [ref], precision))

        # TLS states
        if session.tls_mode == TlsMode.STARTTLS or session.tls_mode == TlsMode.IMPLICIT:
            if session.tls_version:
                frame = session.first_frame
                ref = EvidenceRef(
                    evidence_id=f"{session.session_id}:pop3_tls_established",
                    observation_type="tls_established",
                    status=ObservationStatus.OBSERVED,
                    excerpt=f"TLS {session.tls_version}",
                )
                states.append(("TLS_NEGOTIATING", session.first_frame, [], "FALLBACK"))
                states.append(("TLS_ESTABLISHED", frame, [ref], "FALLBACK"))
            else:
                states.append(("TLS_NEGOTIATING", session.first_frame, [], "FALLBACK"))
                states.append(("INCOMPLETE", session.last_frame, [], "UNKNOWN"))

        # AUTH
        if session.cleartext_auth is not None:
            frame = session.cleartext_auth.frame or session.first_frame
            precision = "EXACT" if session.cleartext_auth.frame else "FALLBACK"
            ref = EvidenceRef(
                evidence_id=f"{session.session_id}:pop3_auth",
                observation_type=ProtocolObservationType.AUTH_EXCHANGE.value,
                status=ObservationStatus.OBSERVED,
                excerpt=session.cleartext_auth.mechanism,
            )
            states.append(("AUTH", frame, [ref], precision))
        elif any(re.match(r"^\s*(USER|PASS|AUTH)\b", l, re.IGNORECASE)
                 for l in session.command_transcript):
            frame = session.first_frame
            ref = EvidenceRef(
                evidence_id=f"{session.session_id}:pop3_auth",
                observation_type=ProtocolObservationType.AUTH_EXCHANGE.value,
                status=ObservationStatus.OBSERVED,
                excerpt="AUTH",
            )
            states.append(("AUTH", frame, [ref], "FALLBACK"))

        # RETR
        if any(re.match(r"^\s*RETR\b", l, re.IGNORECASE) for l in session.command_transcript):
            frame = session.first_frame
            ref = EvidenceRef(
                evidence_id=f"{session.session_id}:pop3_retr",
                observation_type=ProtocolObservationType.POP_COMMAND.value,
                status=ObservationStatus.OBSERVED,
                excerpt="RETR",
            )
            states.append(("RETR", frame, [ref], "FALLBACK"))

        # QUIT
        if any(re.match(r"^\s*QUIT\b", l, re.IGNORECASE) for l in session.command_transcript):
            frame = session.first_frame
            ref = EvidenceRef(
                evidence_id=f"{session.session_id}:pop3_quit",
                observation_type=ProtocolObservationType.POP_COMMAND.value,
                status=ObservationStatus.OBSERVED,
                excerpt="QUIT",
            )
            states.append(("QUIT", frame, [ref], "FALLBACK"))
            states.append(("CLOSED", frame, [], "UNKNOWN"))

        # If we have no transcript data and no TLS, mark as INCOMPLETE
        if len(states) <= 2 and not session.command_transcript:
            states.append(("INCOMPLETE", session.last_frame, [], "UNKNOWN"))

        # Build ProtocolState objects
        for name, frame, refs, _precision in states:
            category = _pop3_state_category(name)
            result.states.append(ProtocolState(
                state_id=self._make_id(f"pop3-{name}"),
                name=name,
                category=category,
                frame=frame,
                observation_refs=refs,
            ))

        # Build transitions
        for i in range(1, len(result.states)):
            from_state = result.states[i - 1].name
            to_state = result.states[i].name
            is_sec, sec_note = self._is_security_relevant(from_state, to_state)
            dest_precision = states[i][3] if i < len(states) else "UNKNOWN"
            ref = StateTransition(
                transition_id=self._make_id("tr"),
                session_id=session.session_id,
                from_state=from_state,
                to_state=to_state,
                frame=result.states[i].frame,
                observation_refs=result.states[i].observation_refs,
                confidence=Confidence.HIGH,
                status=ObservationStatus.OBSERVED,
                security_relevant=is_sec,
                details=sec_note,
                frame_precision=dest_precision,
            )
            result.transitions.append(ref)
            if is_sec:
                result.security_relevant_transitions.append(ref)

        if result.states:
            result.current_state = result.states[-1].name
            result.terminal_state = result.states[-1].name

        # Completeness
        if "INCOMPLETE" in [s.name for s in result.states]:
            result.completeness = "incomplete"
            result.limitations.append(
                "The capture does not contain the full POP3 conversation."
            )
        elif "ERROR" in [s.name for s in result.states]:
            result.completeness = "error"

        return result


def build_pop3_state_machine(session: Session) -> Optional[StateMachineResult]:
    """Build the POP3 state machine result for a session."""
    if session.protocol == Protocol.POP3:
        return Pop3StateMachine(session).build_states()
    return None
