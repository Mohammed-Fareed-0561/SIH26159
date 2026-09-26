"""
IMAP Security State Machine.

Models the observed sequence of states in an IMAP session.

States:
  CONNECT
  GREETING          (* response from server)
  CAPABILITY
  STARTTLS_OFFERED    (CAPABILITY includes STARTTLS)
  STARTTLS_REQUESTED  (client sent STARTTLS command)
  TLS_NEGOTIATING
  TLS_ESTABLISHED
  AUTH               (LOGIN or AUTHENTICATE command)
  SELECT             (mailbox selected)
  FETCH              (message content retrieved)
  LOGOUT
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

IMAP_TRANSITIONS = [
    # connection / banner
    TransitionRule("CONNECT", "GREETING"),
    TransitionRule("CONNECT", "INCOMPLETE"),
    # greeting → capability
    TransitionRule("GREETING", "CAPABILITY"),
    # STARTTLS path — security relevant transitions
    TransitionRule("CAPABILITY", "STARTTLS_OFFERED",
                   security_relevant=True,
                   security_note="Server advertised STARTTLS capability"),
    TransitionRule("CAPABILITY", "STARTTLS_REQUESTED",
                   security_relevant=True,
                   security_note="Client requested STARTTLS upgrade"),
    # STARTTLS offered but client went to AUTH without upgrading
    TransitionRule("STARTTLS_OFFERED", "STARTTLS_REQUESTED"),
    TransitionRule("STARTTLS_OFFERED", "AUTH",
                   security_relevant=True,
                   security_note="STARTTLS was offered but the client proceeded to AUTH without it"),
    # TLS negotiation
    TransitionRule("STARTTLS_REQUESTED", "TLS_NEGOTIATING"),
    TransitionRule("TLS_NEGOTIATING", "TLS_ESTABLISHED"),
    TransitionRule("TLS_NEGOTIATING", "ERROR",
                   security_relevant=True,
                   security_note="TLS handshake failed or was interrupted"),
    TransitionRule("TLS_NEGOTIATING", "INCOMPLETE",
                   security_relevant=True,
                   security_note="TLS handshake incomplete in capture"),
    TransitionRule("TLS_ESTABLISHED", "AUTH"),
    # cleartext auth path (security relevant)
    TransitionRule("CAPABILITY", "AUTH",
                   security_relevant=True,
                   security_note="Authentication occurred without transport encryption"),
    # authenticated operations
    TransitionRule("AUTH", "SELECT"),
    TransitionRule("SELECT", "FETCH"),
    TransitionRule("FETCH", "LOGOUT"),
    TransitionRule("SELECT", "LOGOUT"),
    TransitionRule("LOGOUT", "CLOSED"),
    # error / incomplete
    TransitionRule("*", "ERROR"),
    TransitionRule("*", "INCOMPLETE"),
]


def _imap_state_category(name: str) -> StateCategory:
    mapping = {
        "CONNECT": StateCategory.CONNECTION,
        "GREETING": StateCategory.NEGOTIATION,
        "CAPABILITY": StateCategory.NEGOTIATION,
        "STARTTLS_OFFERED": StateCategory.NEGOTIATION,
        "STARTTLS_REQUESTED": StateCategory.ENCRYPTION,
        "TLS_NEGOTIATING": StateCategory.ENCRYPTION,
        "TLS_ESTABLISHED": StateCategory.ENCRYPTION,
        "AUTH": StateCategory.AUTHENTICATION,
        "SELECT": StateCategory.TRANSFER,
        "FETCH": StateCategory.TRANSFER,
        "LOGOUT": StateCategory.TERMINATION,
        "CLOSED": StateCategory.TERMINATION,
        "ERROR": StateCategory.ERROR,
        "INCOMPLETE": StateCategory.INCOMPLETE,
    }
    return mapping.get(name, StateCategory.NEGOTIATION)


class ImapStateMachine(EmailSecurityStateMachine):
    """IMAP state machine — consumes parsed Session data."""

    def __init__(self, session: Session):
        super().__init__(session)
        self._current_precision = "FALLBACK"

    @property
    def protocol_name(self) -> str:
        return "imap"

    def _define_transitions(self) -> list[TransitionRule]:
        return IMAP_TRANSITIONS

    def build_states(self) -> StateMachineResult:
        session = self.session
        result = StateMachineResult(
            session_id=session.session_id, protocol="imap"
        )

        states: list[tuple[str, Optional[int], list[EvidenceRef], str]] = []

        # CONNECT
        states.append(("CONNECT", session.first_frame, [], "UNKNOWN"))

        # GREETING — the server's * greeting (e.g. "* OK [CAPABILITY ...]")
        if session.banner:
            ref = EvidenceRef(
                evidence_id=f"{session.session_id}:imap_greeting",
                observation_type=ProtocolObservationType.IMAP_BANNER.value,
                status=ObservationStatus.OBSERVED,
                excerpt=session.banner[:200],
            )
            states.append(("GREETING", session.first_frame, [ref], "FALLBACK"))

        # CAPABILITY — explicit CAPABILITY command or embedded in greeting
        if session.capability_line:
            ref = EvidenceRef(
                evidence_id=f"{session.session_id}:imap_capability",
                observation_type=ProtocolObservationType.IMAP_RESPONSE.value,
                status=ObservationStatus.OBSERVED,
                excerpt=session.capability_line[:400],
            )
            states.append(("CAPABILITY", session.first_frame, [ref], "FALLBACK"))

        # STARTTLS_OFFERED — capability line mentions STARTTLS
        if session.starttls_offered:
            ref = EvidenceRef(
                evidence_id=f"{session.session_id}:imap_starttls_offered",
                observation_type=ProtocolObservationType.STARTTLS_CAPABILITY.value,
                status=ObservationStatus.OBSERVED,
                excerpt="STARTTLS",
            )
            states.append(("STARTTLS_OFFERED", session.first_frame, [ref], "FALLBACK"))

        # STARTTLS_REQUESTED
        if session.starttls_requested:
            frame = session.first_frame
            precision = "FALLBACK"
            if session.cleartext_auth is not None and session.cleartext_auth.frame is not None:
                # cleartext_auth frame isn't the STARTTLS frame, but we lack
                # a dedicated field — use first_frame as fallback
                pass
            ref = EvidenceRef(
                evidence_id=f"{session.session_id}:imap_starttls_requested",
                observation_type=ProtocolObservationType.STARTTLS_REQUEST.value,
                status=ObservationStatus.OBSERVED,
                excerpt="STARTTLS",
            )
            states.append(("STARTTLS_REQUESTED", frame, [ref], precision))

        # TLS states
        if session.tls_mode == TlsMode.STARTTLS or session.tls_mode == TlsMode.IMPLICIT:
            if session.tls_version:
                frame = session.first_frame
                ref = EvidenceRef(
                    evidence_id=f"{session.session_id}:imap_tls_established",
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
                evidence_id=f"{session.session_id}:imap_auth",
                observation_type=ProtocolObservationType.AUTH_EXCHANGE.value,
                status=ObservationStatus.OBSERVED,
                excerpt=session.cleartext_auth.mechanism,
            )
            states.append(("AUTH", frame, [ref], precision))
        elif any(re.search(r"\b(AUTHENTICATE|LOGIN)\b", l, re.IGNORECASE)
                 for l in session.command_transcript):
            frame = session.first_frame
            ref = EvidenceRef(
                evidence_id=f"{session.session_id}:imap_auth",
                observation_type=ProtocolObservationType.AUTH_EXCHANGE.value,
                status=ObservationStatus.OBSERVED,
                excerpt="AUTH",
            )
            states.append(("AUTH", frame, [ref], "FALLBACK"))

        # SELECT
        if any(re.search(r"\bSELECT\b", l, re.IGNORECASE) for l in session.command_transcript):
            frame = session.first_frame
            ref = EvidenceRef(
                evidence_id=f"{session.session_id}:imap_select",
                observation_type=ProtocolObservationType.IMAP_COMMAND.value,
                status=ObservationStatus.OBSERVED,
                excerpt="SELECT",
            )
            states.append(("SELECT", frame, [ref], "FALLBACK"))

        # FETCH
        if any(re.search(r"\bFETCH\b", l, re.IGNORECASE) for l in session.command_transcript):
            frame = session.first_frame
            ref = EvidenceRef(
                evidence_id=f"{session.session_id}:imap_fetch",
                observation_type=ProtocolObservationType.IMAP_COMMAND.value,
                status=ObservationStatus.OBSERVED,
                excerpt="FETCH",
            )
            states.append(("FETCH", frame, [ref], "FALLBACK"))

        # LOGOUT
        if any(re.search(r"\bLOGOUT\b", l, re.IGNORECASE) for l in session.command_transcript):
            frame = session.first_frame
            ref = EvidenceRef(
                evidence_id=f"{session.session_id}:imap_logout",
                observation_type=ProtocolObservationType.IMAP_COMMAND.value,
                status=ObservationStatus.OBSERVED,
                excerpt="LOGOUT",
            )
            states.append(("LOGOUT", frame, [ref], "FALLBACK"))
            states.append(("CLOSED", frame, [], "UNKNOWN"))

        # If we have no transcript data and no TLS, mark as INCOMPLETE
        if len(states) <= 2 and not session.command_transcript:
            states.append(("INCOMPLETE", session.last_frame, [], "UNKNOWN"))

        # Build ProtocolState objects
        for name, frame, refs, precision in states:
            category = _imap_state_category(name)
            result.states.append(ProtocolState(
                state_id=self._make_id(f"imap-{name}"),
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
            precision = states[i - 1][3] if i - 1 < len(states) else "UNKNOWN"
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
            result.limitations.append(
                "The capture does not contain the full IMAP conversation."
            )
        elif "ERROR" in [s.name for s in result.states]:
            result.completeness = "error"

        return result


def build_imap_state_machine(session: Session) -> Optional[StateMachineResult]:
    """Build the IMAP state machine result for a session."""
    if session.protocol == Protocol.IMAP:
        return ImapStateMachine(session).build_states()
    return None
