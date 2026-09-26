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


SMTP_TRANSITIONS = [
    # connection
    TransitionRule("CONNECT", "BANNER"),
    TransitionRule("CONNECT", "INCOMPLETE"),
    # banner -> EHLO
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


_state_category_map = {
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


def _state_category(name: str) -> StateCategory:
    return _state_category_map.get(name, StateCategory.NEGOTIATION)


class SmtpStateMachine(EmailSecurityStateMachine):
    """SMTP state machine — consumes parsed Session data."""

    def __init__(self, session: Session):
        super().__init__(session)
        self._current_precision = "FALLBACK"

    @property
    def protocol_name(self) -> str:
        return "smtp"

    def _define_transitions(self) -> list[TransitionRule]:
        return SMTP_TRANSITIONS

    def build_states(self) -> StateMachineResult:
        session = self.session
        result = StateMachineResult(session_id=session.session_id, protocol="smtp")
        # Build the observed state sequence from the parsed session.
        # Each entry: (name, frame, refs, precision)
        states: list[tuple[str, Optional[int], list[EvidenceRef], str]] = []

        # CONNECT
        states.append(("CONNECT", session.first_frame, [], "UNKNOWN"))

        # BANNER
        if session.banner:
            ref = EvidenceRef(
                evidence_id=f"{session.session_id}:banner",
                observation_type=ProtocolObservationType.SMTP_BANNER.value,
                status=ObservationStatus.OBSERVED,
                excerpt=session.banner[:200],
            )
            states.append(("BANNER", session.first_frame, [ref], "FALLBACK"))

        # EHLO
        if any(re.match(r"^\s*EHLO\b", l, re.IGNORECASE) for l in session.command_transcript):
            frame = self._frame_for_command(session, "EHLO")
            precision = self._current_precision  # set by _frame_for_command (FALLBACK)
            ref = EvidenceRef(
                evidence_id=f"{session.session_id}:ehlo",
                observation_type=ProtocolObservationType.SMTP_COMMAND.value,
                status=ObservationStatus.OBSERVED,
                excerpt="EHLO",
            )
            states.append(("EHLO", frame, [ref], precision))

        # CAPABILITIES
        if session.capability_line:
            frame = self._frame_for_capability(session)
            precision = self._current_precision
            ref = EvidenceRef(
                evidence_id=f"{session.session_id}:capabilities",
                observation_type=ProtocolObservationType.SMTP_EHLO_RESPONSE.value,
                status=ObservationStatus.OBSERVED,
                excerpt=session.capability_line[:400],
            )
            states.append(("CAPABILITIES", frame, [ref], precision))

        # STARTTLS_OFFERED
        if session.starttls_offered:
            frame = self._frame_for_capability(session)
            precision = self._current_precision
            ref = EvidenceRef(
                evidence_id=f"{session.session_id}:starttls_offered",
                observation_type=ProtocolObservationType.STARTTLS_CAPABILITY.value,
                status=ObservationStatus.OBSERVED,
                excerpt="STARTTLS",
            )
            states.append(("STARTTLS_OFFERED", frame, [ref], precision))

        # STARTTLS_REQUESTED
        if session.starttls_requested:
            frame = self._frame_for_command(session, "STARTTLS")
            precision = self._current_precision
            ref = EvidenceRef(
                evidence_id=f"{session.session_id}:starttls_requested",
                observation_type=ProtocolObservationType.STARTTLS_REQUEST.value,
                status=ObservationStatus.OBSERVED,
                excerpt="STARTTLS",
            )
            states.append(("STARTTLS_REQUESTED", frame, [ref], precision))

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
                states.append(("TLS_NEGOTIATING", session.first_frame, [], "FALLBACK"))
                states.append(("TLS_ESTABLISHED", frame, [ref], "FALLBACK"))
            else:
                # TLS requested but we didn't see completion
                states.append(("TLS_NEGOTIATING", session.first_frame, [], "FALLBACK"))
                states.append(("INCOMPLETE", session.last_frame, [], "UNKNOWN"))

        # AUTH
        if session.cleartext_auth is not None:
            frame = session.cleartext_auth.frame or self._frame_for_command(session, "AUTH")
            precision = "EXACT" if session.cleartext_auth.frame else self._current_precision
            ref = EvidenceRef(
                evidence_id=f"{session.session_id}:auth",
                observation_type=ProtocolObservationType.AUTH_EXCHANGE.value,
                status=ObservationStatus.OBSERVED,
                excerpt=session.cleartext_auth.mechanism,
            )
            states.append(("AUTH", frame, [ref], precision))
        elif any(re.match(r"^\s*AUTH\b", l, re.IGNORECASE) for l in session.command_transcript):
            frame = self._frame_for_command(session, "AUTH")
            precision = self._current_precision  # FALLBACK since no exact frame
            ref = EvidenceRef(
                evidence_id=f"{session.session_id}:auth",
                observation_type=ProtocolObservationType.AUTH_EXCHANGE.value,
                status=ObservationStatus.OBSERVED,
                excerpt="AUTH",
            )
            states.append(("AUTH", frame, [ref], precision))

        # MAIL / RCPT / DATA
        if any(re.match(r"^\s*MAIL\s+FROM\b", l, re.IGNORECASE) for l in session.command_transcript):
            frame = self._frame_for_command(session, "MAIL FROM")
            precision = self._current_precision
            ref = EvidenceRef(
                evidence_id=f"{session.session_id}:mail_from",
                observation_type=ProtocolObservationType.SMTP_COMMAND.value,
                status=ObservationStatus.OBSERVED,
                excerpt="MAIL FROM",
            )
            states.append(("MAIL_FROM", frame, [ref], precision))

        if any(re.match(r"^\s*RCPT\s+TO\b", l, re.IGNORECASE) for l in session.command_transcript):
            frame = self._frame_for_command(session, "RCPT TO")
            precision = self._current_precision
            ref = EvidenceRef(
                evidence_id=f"{session.session_id}:rcpt_to",
                observation_type=ProtocolObservationType.SMTP_COMMAND.value,
                status=ObservationStatus.OBSERVED,
                excerpt="RCPT TO",
            )
            states.append(("RCPT_TO", frame, [ref], precision))

        if any(re.match(r"^\s*DATA\b", l, re.IGNORECASE) for l in session.command_transcript):
            frame = self._frame_for_command(session, "DATA")
            precision = self._current_precision
            ref = EvidenceRef(
                evidence_id=f"{session.session_id}:data",
                observation_type=ProtocolObservationType.SMTP_COMMAND.value,
                status=ObservationStatus.OBSERVED,
                excerpt="DATA",
            )
            states.append(("DATA", frame, [ref], precision))

        # QUIT
        if any(re.match(r"^\s*QUIT\b", l, re.IGNORECASE) for l in session.command_transcript):
            frame = self._frame_for_command(session, "QUIT")
            precision = self._current_precision
            ref = EvidenceRef(
                evidence_id=f"{session.session_id}:quit",
                observation_type=ProtocolObservationType.SMTP_COMMAND.value,
                status=ObservationStatus.OBSERVED,
                excerpt="QUIT",
            )
            states.append(("QUIT", frame, [ref], precision))
            states.append(("CLOSED", frame, [], "UNKNOWN"))

        # If we have no transcript data and no TLS, mark as INCOMPLETE
        if len(states) <= 2 and not session.command_transcript:
            states.append(("INCOMPLETE", session.last_frame, [], "UNKNOWN"))

        # Build ProtocolState objects
        for name, frame, refs, _precision in states:
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
            # Use the precision of the destination state
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
            result.limitations.append("The capture does not contain the full SMTP conversation.")
        elif "ERROR" in [s.name for s in result.states]:
            result.completeness = "error"

        return result

    def _frame_for_command(self, session: Session, command: str) -> Optional[int]:
        """
        Find the frame where a command was sent.

        Returns session.first_frame as fallback (precision set to FALLBACK).
        Only AUTH has exact frame attribution when cleartext_auth.frame is set.
        """
        frame = session.first_frame
        precision = "FALLBACK"

        # AUTH has exact frame when cleartext_auth.frame is available
        if command.upper() == "AUTH" and session.cleartext_auth is not None:
            if session.cleartext_auth.frame is not None:
                frame = session.cleartext_auth.frame
                precision = "EXACT"

        # For STARTTLS, no dedicated frame field exists on Session
        if command.upper() == "STARTTLS":
            starttls_frame = getattr(session, '_starttls_frame', None)
            if starttls_frame is not None:
                frame = starttls_frame
                precision = "EXACT"

        self._current_precision = precision
        return frame

    def _frame_for_capability(self, session: Session) -> Optional[int]:
        """
        Find the frame where capabilities were advertised (server -> client
        EHLO response).  In the current data model the capability_line is
        stored as a string without frame attribution, so we use first_frame
        as a fallback.
        """
        # Try to get the exact frame from session metadata
        cap_frame = getattr(session, '_capability_frame', None)
        if cap_frame is not None:
            self._current_precision = "EXACT"
            return cap_frame
        self._current_precision = "FALLBACK"
        return session.first_frame

    def _build_transition_frame(self, state_name: str, session: Session, exact_frame: Optional[int], precision: str = None) -> tuple[Optional[int], str]:
        """
        Helper to compute (frame, precision) for a state.

        If precision is None, it is derived from _frame_precision_for.
        """
        frame = exact_frame
        if frame is None:
            frame = session.first_frame
        if precision is None:
            precision = self._frame_precision_for(state_name)
        return frame, precision


def build_state_machine_for_session(session: Session) -> Optional[StateMachineResult]:
    """Build the appropriate state machine result for a session."""
    if session.protocol == Protocol.SMTP:
        return SmtpStateMachine(session).build_states()
    # IMAP / POP3: handled by dedicated modules
    from .imap_state_machine import ImapStateMachine
    from .pop3_state_machine import Pop3StateMachine
    if session.protocol == Protocol.IMAP:
        return ImapStateMachine(session).build_states()
    if session.protocol == Protocol.POP3:
        return Pop3StateMachine(session).build_states()
    return None
