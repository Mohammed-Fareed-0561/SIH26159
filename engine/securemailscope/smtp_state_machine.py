"""
SMTP Security State Machine.

Models the observed sequence of states in an SMTP session.

States (derived from the existing starttls parser):
  CONNECT
  BANNER
  EHLO
  CAPABILITIES
  STARTTLS_OFFERED
  STARTTLS_REQUESTED
  TLS_NEGOTIATING
  TLS_ESTABLISHED
  AUTH
  MAIL_FROM
  RCPT_TO
  DATA
  QUIT
  ERROR
  INCOMPLETE
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional

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


SMTP_TRANSITIONS = [
    # connection
    TransitionRule("CONNECT", "BANNER"),
    TransitionRule("CONNECT", "INCOMPLETE"),
    # banner → EHLO
    TransitionRule("BANNER", "EHLO"),
    TransitionRule("EHLO", "CAPABILITIES"),
    # STARTTLS path
    TransitionRule("CAPABILITIES", "STARTTLS_OFFERED"),
    TransitionRule("STARTTLS_OFFERED", "STARTTLS_REQUESTED"),
    TransitionRule("STARTTLS_OFFERED", "AUTH",
                   security_relevant=True,
                   security_note="STARTTLS was advertised but the client proceeded to AUTH without it"),
    TransitionRule("STARTTLS_OFFERED", "MAIL_FROM",
                   security_relevant=True,
                   security_note="STARTTLS was advertised but the client proceeded to MAIL without it"),
    TransitionRule("STARTTLS_OFFERED", "QUIT"),
    TransitionRule("STARTTLS_REQUESTED", "TLS_NEGOTIATING"),
    TransitionRule("TLS_NEGOTIATING", "TLS_ESTABLISHED"),
    TransitionRule("TLS_NEGOTIATING", "ERROR",
                   security_relevant=True,
                   security_note="TLS handshake failed or was interrupted"),
    TransitionRule("TLS_NEGOTIATING", "INCOMPLETE",
                   security_relevant=True,
                   security_note="TLS handshake incomplete in capture"),
    TransitionRule("TLS_ESTABLISHED", "EHLO"),  # second EHLO after TLS
    TransitionRule("TLS_ESTABLISHED", "AUTH"),
    # cleartext path
    TransitionRule("CAPABILITIES", "AUTH"),
    TransitionRule("CAPABILITIES", "MAIL_FROM"),
    # AUTH before TLS (security-relevant)
    TransitionRule("CAPABILITIES", "AUTH",
                   security_relevant=True,
                   security_note="Authentication occurred without transport encryption"),
    # transfer
    TransitionRule("AUTH", "MAIL_FROM"),
    TransitionRule("MAIL_FROM", "RCPT_TO"),
    TransitionRule("RCPT_TO", "DATA"),
    TransitionRule("DATA", "QUIT"),
    # quit
    TransitionRule("MAIL_FROM", "QUIT"),
    TransitionRule("RCPT_TO", "QUIT"),
    TransitionRule("QUIT", "CLOSED"),
    # error / incomplete
    TransitionRule("*", "ERROR"),
    TransitionRule("*", "INCOMPLETE"),
]


class SmtpStateMachine(EmailSecurityStateMachine):
    """SMTP state machine — consumes parsed Session data."""

    @property
    def protocol_name(self) -> str:
        return "smtp"

    def _define_transitions(self) -> list[TransitionRule]:
        return SMTP_TRANSITIONS

    def build_states(self) -> StateMachineResult:
        session = self.session
        result = StateMachineResult(session_id=session.session_id, protocol="smtp")

        # Build the observed state sequence from the parsed session.
        states: list[tuple[str, Optional[int], list[EvidenceRef]]] = []

        # CONNECT
        states.append(("CONNECT", session.first_frame, []))

        # BANNER
        if session.banner:
            ref = EvidenceRef(
                evidence_id=f"{session.session_id}:banner",
                observation_type=ProtocolObservationType.SMTP_BANNER.value,
                status=ObservationStatus.OBSERVED,
                excerpt=session.banner[:200],
            )
            states.append(("BANNER", session.first_frame, [ref]))

        # EHLO
        if any(re.match(r"^\s*EHLO\b", l, re.IGNORECASE) for l in session.command_transcript):
            frame = self._frame_for_command(session, "EHLO")
            ref = EvidenceRef(
                evidence_id=f"{session.session_id}:ehlo",
                observation_type=ProtocolObservationType.SMTP_COMMAND.value,
                status=ObservationStatus.OBSERVED,
                excerpt="EHLO",
            )
            states.append(("EHLO", frame, [ref]))

        # CAPABILITIES
        if session.capability_line:
            frame = self._frame_for_capability(session)
            ref = EvidenceRef(
                evidence_id=f"{session.session_id}:capabilities",
                observation_type=ProtocolObservationType.SMTP_EHLO_RESPONSE.value,
                status=ObservationStatus.OBSERVED,
                excerpt=session.capability_line[:400],
            )
            states.append(("CAPABILITIES", frame, [ref]))

        # STARTTLS_OFFERED
        if session.starttls_offered:
            frame = self._frame_for_capability(session)
            ref = EvidenceRef(
                evidence_id=f"{session.session_id}:starttls_offered",
                observation_type=ProtocolObservationType.STARTTLS_CAPABILITY.value,
                status=ObservationStatus.OBSERVED,
                excerpt="STARTTLS",
            )
            states.append(("STARTTLS_OFFERED", frame, [ref]))

        # STARTTLS_REQUESTED
        if session.starttls_requested:
            frame = self._frame_for_command(session, "STARTTLS")
            ref = EvidenceRef(
                evidence_id=f"{session.session_id}:starttls_requested",
                observation_type=ProtocolObservationType.STARTTLS_REQUEST.value,
                status=ObservationStatus.OBSERVED,
                excerpt="STARTTLS",
            )
            states.append(("STARTTLS_REQUESTED", frame, [ref]))

        # TLS states
        if session.tls_mode == TlsMode.STARTTLS or session.tls_mode == TlsMode.IMPLICIT:
            if session.tls_version:
                frame = self._frame_for_command(session, "STARTTLS") if session.tls_mode == TlsMode.STARTTLS else session.first_frame
                # We observed TLS was established
                ref = EvidenceRef(
                    evidence_id=f"{session.session_id}:tls_established",
                    observation_type="tls_established",
                    status=ObservationStatus.OBSERVED,
                    excerpt=f"TLS {session.tls_version}",
                )
                states.append(("TLS_NEGOTIATING", session.first_frame, []))
                states.append(("TLS_ESTABLISHED", frame, [ref]))
            else:
                # TLS requested but we didn't see completion
                states.append(("TLS_NEGOTIATING", session.first_frame, []))
                states.append(("INCOMPLETE", session.last_frame, []))

        # AUTH
        if session.cleartext_auth is not None:
            frame = session.cleartext_auth.frame or self._frame_for_command(session, "AUTH")
            ref = EvidenceRef(
                evidence_id=f"{session.session_id}:auth",
                observation_type=ProtocolObservationType.AUTH_EXCHANGE.value,
                status=ObservationStatus.OBSERVED,
                excerpt=session.cleartext_auth.mechanism,
            )
            states.append(("AUTH", frame, [ref]))
        elif any(re.match(r"^\s*AUTH\b", l, re.IGNORECASE) for l in session.command_transcript):
            frame = self._frame_for_command(session, "AUTH")
            ref = EvidenceRef(
                evidence_id=f"{session.session_id}:auth",
                observation_type=ProtocolObservationType.AUTH_EXCHANGE.value,
                status=ObservationStatus.OBSERVED,
                excerpt="AUTH",
            )
            states.append(("AUTH", frame, [ref]))

        # MAIL / RCPT / DATA
        if any(re.match(r"^\s*MAIL\s+FROM\b", l, re.IGNORECASE) for l in session.command_transcript):
            frame = self._frame_for_command(session, "MAIL FROM")
            ref = EvidenceRef(
                evidence_id=f"{session.session_id}:mail_from",
                observation_type=ProtocolObservationType.SMTP_COMMAND.value,
                status=ObservationStatus.OBSERVED,
                excerpt="MAIL FROM",
            )
            states.append(("MAIL_FROM", frame, [ref]))

        if any(re.match(r"^\s*RCPT\s+TO\b", l, re.IGNORECASE) for l in session.command_transcript):
            frame = self._frame_for_command(session, "RCPT TO")
            ref = EvidenceRef(
                evidence_id=f"{session.session_id}:rcpt_to",
                observation_type=ProtocolObservationType.SMTP_COMMAND.value,
                status=ObservationStatus.OBSERVED,
                excerpt="RCPT TO",
            )
            states.append(("RCPT_TO", frame, [ref]))

        if any(re.match(r"^\s*DATA\b", l, re.IGNORECASE) for l in session.command_transcript):
            frame = self._frame_for_command(session, "DATA")
            ref = EvidenceRef(
                evidence_id=f"{session.session_id}:data",
                observation_type=ProtocolObservationType.SMTP_COMMAND.value,
                status=ObservationStatus.OBSERVED,
                excerpt="DATA",
            )
            states.append(("DATA", frame, [ref]))

        # QUIT
        if any(re.match(r"^\s*QUIT\b", l, re.IGNORECASE) for l in session.command_transcript):
            frame = self._frame_for_command(session, "QUIT")
            ref = EvidenceRef(
                evidence_id=f"{session.session_id}:quit",
                observation_type=ProtocolObservationType.SMTP_COMMAND.value,
                status=ObservationStatus.OBSERVED,
                excerpt="QUIT",
            )
            states.append(("QUIT", frame, [ref]))
            states.append(("CLOSED", frame, []))

        # If we have no transcript data and no TLS, mark as INCOMPLETE
        if len(states) <= 2 and not session.command_transcript:
            states.append(("INCOMPLETE", session.last_frame, []))

        # Build ProtocolState objects
        for name, frame, refs in states:
            category = _state_category(name)
            result.states.append(ProtocolState(
                state_id=self._make_id(f"smtp-{name}"),
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
            result.limitations.append("The capture does not contain the full SMTP conversation.")
        elif "ERROR" in [s.name for s in result.states]:
            result.completeness = "error"

        return result

    def _frame_for_command(self, session: Session, command: str) -> Optional[int]:
        """Find the frame where a command was sent."""
        for line in session.command_transcript:
            if command in line.upper():
                # frame tracking is approximate — use first_frame if unknown
                return session.first_frame
        return session.first_frame

    def _frame_for_capability(self, session: Session) -> Optional[int]:
        """Find the frame where capabilities were advertised."""
        return session.first_frame


def _state_category(name: str) -> StateCategory:
    mapping = {
        "CONNECT": StateCategory.CONNECTION,
        "BANNER": StateCategory.NEGOTIATION,
        "EHLO": StateCategory.NEGOTIATION,
        "CAPABILITIES": StateCategory.NEGOTIATION,
        "STARTTLS_OFFERED": StateCategory.NEGOTIATION,
        "STARTTLS_REQUESTED": StateCategory.ENCRYPTION,
        "TLS_NEGOTIATING": StateCategory.ENCRYPTION,
        "TLS_ESTABLISHED": StateCategory.ENCRYPTION,
        "AUTH": StateCategory.AUTHENTICATION,
        "MAIL_FROM": StateCategory.TRANSFER,
        "RCPT_TO": StateCategory.TRANSFER,
        "DATA": StateCategory.TRANSFER,
        "QUIT": StateCategory.TERMINATION,
        "CLOSED": StateCategory.TERMINATION,
        "ERROR": StateCategory.ERROR,
        "INCOMPLETE": StateCategory.INCOMPLETE,
    }
    return mapping.get(name, StateCategory.NEGOTIATION)


def build_state_machine_for_session(session: Session) -> Optional[StateMachineResult]:
    """Build the appropriate state machine result for a session."""
    if session.protocol == Protocol.SMTP:
        return SmtpStateMachine(session).build_states()
    # IMAP / POP3: future extension
    return None
