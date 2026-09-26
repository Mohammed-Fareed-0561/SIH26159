"""
Email Security State Machine.

Models observed email protocol behavior as a state machine. The machine consumes
already-parsed observations from the existing pipeline — it never re-parses
packets or reconstructs TCP streams.

Architecture:
  - EmailSecurityStateMachine: protocol-independent abstraction
  - SmtpStateMachine: SMTP-specific states and transitions
  - (ImapStateMachine / PopStateMachine: future extension points)

Each analyzed session produces:
  - ordered list of states entered
  - ordered list of transitions between them
  - security-relevant transitions flagged for analysis
  - evidence references for every transition

The state machine answers "WHAT HAPPENED", not "WHY".
"""
from __future__ import annotations

import dataclasses
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional

from .evidence import (
    Confidence,
    EvidenceRef,
    ObservationStatus,
)


# --------------------------------------------------------------------------
# core state / transition model
# --------------------------------------------------------------------------

class StateCategory(str, Enum):
    """Broad category of a protocol state."""
    CONNECTION = "connection"
    NEGOTIATION = "negotiation"
    ENCRYPTION = "encryption"
    AUTHENTICATION = "authentication"
    TRANSFER = "transfer"
    TERMINATION = "termination"
    ERROR = "error"
    INCOMPLETE = "incomplete"


@dataclass
class ProtocolState:
    """One state the session was observed in."""
    state_id: str
    name: str
    category: StateCategory
    timestamp: Optional[datetime] = None
    frame: Optional[int] = None
    observation_refs: list[EvidenceRef] = field(default_factory=list)
    details: Optional[dict[str, Any]] = None


@dataclass
class StateTransition:
    """A transition from one state to another."""
    transition_id: str
    session_id: str
    from_state: str
    to_state: str
    timestamp: Optional[datetime] = None
    frame: Optional[int] = None
    observation_refs: list[EvidenceRef] = field(default_factory=list)
    confidence: Confidence = Confidence.HIGH
    status: ObservationStatus = ObservationStatus.OBSERVED
    security_relevant: bool = False
    details: Optional[str] = None
    # Phase 3: precision of frame attribution (Part 3)
    frame_precision: str = "UNKNOWN"  # EXACT | FALLBACK | UNKNOWN


@dataclass
class StateMachineResult:
    """Full result of running the state machine on one session."""
    session_id: str
    protocol: str
    states: list[ProtocolState] = field(default_factory=list)
    transitions: list[StateTransition] = field(default_factory=list)
    current_state: Optional[str] = None
    terminal_state: Optional[str] = None
    security_relevant_transitions: list[StateTransition] = field(default_factory=list)
    completeness: str = "complete"
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "protocol": self.protocol,
            "states": [dataclasses.asdict(s) for s in self.states],
            "transitions": [dataclasses.asdict(t) for t in self.transitions],
            "current_state": self.current_state,
            "terminal_state": self.terminal_state,
            "security_relevant_transitions": [dataclasses.asdict(t) for t in self.security_relevant_transitions],
            "completeness": self.completeness,
            "limitations": self.limitations,
        }


# --------------------------------------------------------------------------
# protocol transition definition
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class TransitionRule:
    """A valid protocol transition."""
    from_state: str
    to_state: str
    security_relevant: bool = False
    security_note: Optional[str] = None


# --------------------------------------------------------------------------
# abstract base
# --------------------------------------------------------------------------

class EmailSecurityStateMachine(ABC):
    """
    Protocol-independent email security state machine.

    Subclasses provide:
      - protocol name
      - ordered list of TransitionRule objects
      - logic to map parsed session data to states
    """

    def __init__(self, session):
        self.session = session
        self._transition_rules: list[TransitionRule] = self._define_transitions()
        self._valid_transitions: dict[tuple[str, str], TransitionRule] = {
            (r.from_state, r.to_state): r for r in self._transition_rules
        }

    @property
    @abstractmethod
    def protocol_name(self) -> str:
        ...

    @abstractmethod
    def _define_transitions(self) -> list[TransitionRule]:
        """Return the allowed transitions for this protocol."""
        ...

    @abstractmethod
    def build_states(self) -> StateMachineResult:
        """Build the full state machine result from the session."""
        ...

    def _make_id(self, prefix: str) -> str:
        return f"{prefix}-{uuid.uuid4().hex[:8]}"

    def _is_security_relevant(self, from_state: str, to_state: str) -> tuple[bool, Optional[str]]:
        rule = self._valid_transitions.get((from_state, to_state))
        if rule and rule.security_relevant:
            return True, rule.security_note
        return False, None
