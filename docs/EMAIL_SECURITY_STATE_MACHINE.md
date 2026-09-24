# EMAIL SECURITY STATE MACHINE — SecureMailScope

**Date:** 2026-09-25
**Branch:** phase-2-state-machine-evidence
**Phase:** 2

---

## 1. Purpose

The Email Security State Machine models the observed sequence of protocol states
in an email session. It answers one question:

**WHAT HAPPENED?**

Not "WHY did it happen?" — that is Phase 3 (attack vs misconfiguration).

The state machine:
- Consumes observations from the existing parser (does NOT reparse packets)
- Produces an ordered list of states and transitions
- Flags security-relevant transitions
- Links every transition to structured evidence (Phase 1 model)
- Explains WHAT occurred and references the evidence that supports it

---

## 2. Architecture

```
EmailSecurityStateMachine (abstract base)
├── SmtpStateMachine (implemented)
├── ImapStateMachine (future — interface defined)
└── PopStateMachine (future — interface defined)
```

### Design principles
- **Protocol-independent abstraction**: common state/transition model
- **Protocol-specific implementations**: SMTP, IMAP, POP3 states
- **No massive if/else blocks**: clean TransitionRule definitions
- **Evidence-driven**: every transition references EvidenceRef objects
- **Parser-fed**: builds from existing Session observations, never reparses

### Class hierarchy

```
EmailSecurityStateMachine (ABC)
├── protocol_name: str                         [abstract]
├── _define_transitions() → list[TransitionRule] [abstract]
├── build_states() → StateMachineResult        [abstract]
├── _is_security_relevant(from, to) → (bool, note)
├── _make_id(prefix) → str
└── session: Session

StateMachineResult
├── session_id, protocol: str
├── states: list[ProtocolState]
├── transitions: list[StateTransition]
├── current_state, terminal_state: Optional[str]
├── security_relevant_transitions: list[StateTransition]
├── completeness: str
└── limitations: list[str]

ProtocolState
├── state_id, name: str
├── category: StateCategory
├── timestamp, frame: Optional
├── observation_refs: list[EvidenceRef]
└── details: Optional[dict]

StateTransition
├── transition_id, session_id: str
├── from_state, to_state: str
├── timestamp, frame: Optional
├── observation_refs: list[EvidenceRef]
├── confidence: Confidence
├── status: ObservationStatus
├── security_relevant: bool
└── details: Optional[str]

TransitionRule (frozen dataclass)
├── from_state, to_state: str
├── security_relevant: bool
└── security_note: Optional[str]
```

---

## 3. SMTP States

| State | Category | Description |
|-------|----------|-------------|
| CONNECT | connection | TCP connection established |
| BANNER | negotiation | Server sent greeting (220) |
| EHLO | negotiation | Client sent EHLO |
| CAPABILITIES | negotiation | Server advertised capabilities |
| STARTTLS_OFFERED | negotiation | STARTTLS advertised |
| STARTTLS_REQUESTED | encryption | Client requested STARTTLS |
| TLS_NEGOTIATING | encryption | TLS handshake in progress |
| TLS_ESTABLISHED | encryption | TLS session established |
| AUTH | authentication | Client attempted authentication |
| MAIL_FROM | transfer | MAIL FROM command |
| RCPT_TO | transfer | RCPT TO command |
| DATA | transfer | Message data transfer |
| QUIT | termination | Session ended normally |
| CLOSED | termination | Connection closed |
| ERROR | error | Error condition |
| INCOMPLETE | incomplete | Capture ended before completion |

---

## 4. Transitions

### Normal STARTTLS flow
```
CONNECT → BANNER → EHLO → CAPABILITIES → STARTTLS_OFFERED → STARTTLS_REQUESTED
→ TLS_NEGOTIATING → TLS_ESTABLISHED → EHLO → AUTH → MAIL_FROM → RCPT_TO
→ DATA → QUIT → CLOSED
```

### AUTH before TLS (security-relevant)
```
CONNECT → BANNER → EHLO → CAPABILITIES → STARTTLS_OFFERED → AUTH
```
Transition `STARTTLS_OFFERED → AUTH` is flagged as security-relevant.

### STARTTLS not offered (cleartext)
```
CONNECT → BANNER → EHLO → CAPABILITIES → AUTH → MAIL_FROM → RCPT_TO
→ DATA → QUIT → CLOSED
```

### Transition rules
Defined as a list of `TransitionRule(from_state, to_state, security_relevant, security_note)`:

```python
TransitionRule("STARTTLS_OFFERED", "AUTH",
               security_relevant=True,
               security_note="STARTTLS was advertised but the client proceeded to AUTH without it"),
TransitionRule("CAPABILITIES", "AUTH",
               security_relevant=True,
               security_note="Authentication occurred without transport encryption"),
```

The `*` wildcard allows any state to transition to ERROR or INCOMPLETE.

---

## 5. Security-Relevant Transitions

These transitions are flagged for security analysis:

| Transition | Note |
|------------|------|
| STARTTLS_OFFERED → AUTH | STARTTLS was advertised but client proceeded to AUTH without it |
| STARTTLS_OFFERED → MAIL_FROM | STARTTLS was advertised but client proceeded to MAIL without it |
| CAPABILITIES → AUTH | Authentication occurred without transport encryption |
| TLS_NEGOTIATING → ERROR | TLS handshake failed or was interrupted |
| TLS_NEGOTIATING → INCOMPLETE | TLS handshake incomplete in capture |

**Important**: At this stage we do NOT attribute cause. We only report WHAT happened.

---

## 6. Evidence Integration

### Every transition carries evidence references:

```json
{
  "transition_id": "tr-abc123",
  "session_id": "smtp-session-12",
  "from_state": "STARTTLS_OFFERED",
  "to_state": "AUTH",
  "frame": 184,
  "observation_refs": [
    {
      "evidence_id": "smtp-session-12:starttls_offered",
      "observation_type": "starttls_capability",
      "status": "observed",
      "excerpt": "STARTTLS"
    },
    {
      "evidence_id": "smtp-session-12:auth",
      "observation_type": "auth_exchange",
      "status": "observed",
      "excerpt": "LOGIN"
    }
  ],
  "confidence": "high",
  "status": "observed",
  "security_relevant": true,
  "details": "STARTTLS was advertised but the client proceeded to AUTH without it"
}
```

### Finding-to-evidence chain:
```
Finding
→ EvidenceRef
→ Observation (ProtocolObservation / TLSObservation)
→ PacketRef (frame, timestamp, IPs, ports)
→ Rule (YAML rule ID)
```

---

## 7. Confidence/Status Handling

### OBSERVED
Every state that is directly observed in the capture is OBSERVED.
Example: Server advertised STARTTLS.

### INFERRED
Conclusions derived from multiple observed facts.
Example: "Authentication occurred before transport encryption" is INFERRED
from {STARTTLS offered, AUTH observed, TLS not established}.

### NOT_OBSERVABLE
Capture lacks the evidence.
Example: Whether the server would support TLS 1.3.

### CONTRADICTED
Evidence conflicts.
Example: Certificate expired at capture time but server presented it.

### INSUFFICIENT_CAPTURE
Evidence may exist but capture is incomplete.
Example: TLS handshake started but Certificate message not captured.

---

## 8. SMTP Implementation

`SmtpStateMachine` extends `EmailSecurityStateMachine`:

```python
class SmtpStateMachine(EmailSecurityStateMachine):
    @property
    def protocol_name(self) -> str:
        return "smtp"

    def _define_transitions(self) -> list[TransitionRule]:
        return SMTP_TRANSITIONS

    def build_states(self) -> StateMachineResult:
        # Builds states from session data:
        # - CONNECT, BANNER, EHLO, CAPABILITIES
        # - STARTTLS_OFFERED if session.starttls_offered
        # - STARTTLS_REQUESTED if session.starttls_requested
        # - TLS_NEGOTIATING / TLS_ESTABLISHED if tls_mode
        # - AUTH if cleartext_auth or AUTH command
        # - MAIL_FROM, RCPT_TO, DATA if commands present
        # - QUIT, CLOSED if QUIT command
        # - INCOMPLETE if capture truncated
        ...
```

### Evidence references are created for each state:
- BANNER → EvidenceRef with SMTP_BANNER observation type
- CAPABILITIES → EvidenceRef with SMTP_EHLO_RESPONSE type
- STARTTLS_OFFERED → EvidenceRef with STARTTLS_CAPABILITY type
- AUTH → EvidenceRef with AUTH_EXCHANGE type
- etc.

---

## 9. Future IMAP/POP3 Extension

The `EmailSecurityStateMachine` abstraction supports IMAP/POP3. The factory
function `build_state_machine_for_session()` returns `None` for non-SMTP
sessions. Future phases will add:

```python
class ImapStateMachine(EmailSecurityStateMachine):
    @property
    def protocol_name(self) -> str:
        return "imap"
    # IMAP states: CONNECT → CAPABILITY → STARTTLS → TLS → AUTH → SELECT → FETCH → LOGOUT

class PopStateMachine(EmailSecurityStateMachine):
    @property
    def protocol_name(self) -> str:
        return "pop3"
    # POP3 states: CONNECT → GREETING → CAPA → STLS → TLS → AUTH → RETR → QUIT
```

---

## 10. Examples

### Example 1: Normal TLS session
```
CONNECT → BANNER → EHLO → CAPABILITIES → STARTTLS_OFFERED → STARTTLS_REQUESTED
→ TLS_NEGOTIATING → TLS_ESTABLISHED → EHLO → AUTH → MAIL_FROM → RCPT_TO
→ DATA → QUIT → CLOSED

Security-relevant transitions: none
```

### Example 2: STARTTLS offered but ignored
```
CONNECT → BANNER → CAPABILITIES → STARTTLS_OFFERED → AUTH

Security-relevant transitions:
  STARTTLS_OFFERED → AUTH
    Note: STARTTLS was advertised but the client proceeded to AUTH without it
    Frame: 184
    Evidence: SMTP CAPABILITIES, SMTP AUTH
    Status: OBSERVED
    Confidence: HIGH
```

### Example 3: Cleartext session (no STARTTLS)
```
CONNECT → BANNER → CAPABILITIES → AUTH → MAIL_FROM → QUIT → CLOSED

Security-relevant transitions:
  CAPABILITIES → AUTH
    Note: Authentication occurred without transport encryption
    Frame: 50
    Evidence: SMTP AUTH
    Status: OBSERVED
    Confidence: HIGH
```

---

## 11. Integration Points

| Component | Integration |
|-----------|-------------|
| Pipeline | `analyse_capture()` builds state machines for all sessions |
| Report model | `Report.email_security_state_machines` field |
| JSON report | Includes `email_security_state_machines` array |
| HTML report | Per-session state machine section with flow visualization |
| Tests | `test_state_machine.py` — 30 tests |

---

*End of EMAIL SECURITY STATE MACHINE*
