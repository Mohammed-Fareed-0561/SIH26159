# Phase 3 — Security Reasoning + Finding/Evidence Graph

## Overview

Phase 3 builds the reasoning layer that answers "WHY might it have happened?" on top of the Phase 2 state machine that answers "WHAT happened?".

The reasoning engine does **not** declare attacks. It enumerates possible explanations for each security-relevant finding, gathers the evidence that supports or contradicts each one, and assigns an explainable confidence level.

## Architecture

### Finding → Transition → Evidence → Observation → Packet

Every security-relevant finding is now linked to the state-machine transitions and evidence that produced it via `FindingReference`:

```
Finding
  ↓  (FindingReference)
State Transition
  ↓  (EvidenceRef on transition)
Observation
  ↓  (packet_refs)
Packet/Frame
```

Backward compatibility: legacy findings retain their existing `evidence` field. `FindingReference` is a parallel pointer — it does not replace or mutate the original finding.

### Modules

| Module | Purpose |
|--------|---------|
| `finding_reference.py` | `FindingReference` model: links findings → transitions → evidence → observations → packet refs. `LinkConfidence` enum (EXACT / TRANSITION_INFERRED / NO_TRANSITION / NOT_ATTEMPTED). |
| `finding_linker.py` | `link_finding_to_transitions()` and `link_all_findings()` — heuristic mapping of rule IDs to state-machine transitions. |
| `reasoning.py` | `ReasoningEngine` — produces `ReasoningResult` with observed facts → inferences → possible explanations → confidence → risk. Never claims attacks. |
| `security_controls.py` | `ControlEvaluation` model and `evaluate_security_controls()` — deterministic control status (PASS / WARN / FAIL / LOW / UNKNOWN / NOT_ASSESSABLE). |
| `cross_session.py` | `correlate_sessions()` — groups sessions by asset, detects patterns (TLS version variation, certificate variation, STARTTLS offered-but-not-used, AUTH-before-TLS repeated, etc.). |
| `imap_state_machine.py` | IMAP security state machine (CONNECT → GREETING → CAPABILITY → STARTTLS_OFFERED → STARTTLS_REQUESTED → TLS_NEGOTIATING → TLS_ESTABLISHED → AUTH → SELECT → FETCH → LOGOUT → CLOSED). |
| `pop3_state_machine.py` | POP3 security state machine (CONNECT → GREETING → CAPA → STLS_OFFERED → STLS_REQUESTED → STLS_ACCEPTED → TLS_NEGOTIATING → TLS_ESTABLISHED → AUTH → LOGGED_IN → QUIT). |
| `kb/standards.yaml` | Standards knowledge base mapping findings and controls to RFCs. |

### Exact Frame Attribution

Transitions carry a `frame_precision` field:

| Value | Meaning |
|-------|---------|
| `EXACT` | The frame where the command/capability was sent is known (e.g., AUTH command frame from `cleartext_auth.frame`). |
| `FALLBACK` | First frame in the session is used as a proxy (e.g., BANNER, CAPABILITIES, STARTTLS_OFFERED without explicit frame tracking). |
| `UNKNOWN` | No frame attribution is possible (e.g., CONNECT — TCP SYN not tracked, CLOSED — no packet reference). |

Frame numbers are never invented. When exact attribution is impossible, the `frame` is set to `session.first_frame` or `session.last_frame` and the precision is marked as `FALLBACK` or `UNKNOWN` with a documented reason.

### Reasoning Engine

The `ReasoningEngine` produces a `ReasoningResult` with:

1. **Observed facts** — derived from session model, state machine, and findings.
2. **Inferences** — logical conclusions drawn from facts.
3. **Possible explanations** — each with:
   - `explanation_id` (e.g., `STARTTLS_STRIPPING`, `CLIENT_CONFIGURATION`, `SERVER_CONFIGURATION`, `NEGOTIATION_FAILURE`, `INTERMEDIARY_MODIFICATION`, `INCOMPLETE_CAPTURE`, `LEGITIMATE_NEGOTIATION`, `CLIENT_LIMITATION`, `PROTOCOL_CONSTRAINT`)
   - `description`
   - `supporting_evidence` list
   - `contradicting_evidence` list
   - `missing_evidence` list
   - `confidence` (HIGH / MEDIUM / LOW / UNKNOWN)
   - `status` ("possible" / "likely" / "unlikely")
4. **Overall confidence** — qualitative, derived from explainable factors.
5. **Risk** — `RiskComponents` with impact × exposure × confidence, using a documented combination table.

### Security Controls

Each finding maps to one or more `ControlId`s. `evaluate_security_controls()` evaluates all 9 controls for a session:

| Control | Description |
|---------|-------------|
| `TRANSPORT_ENCRYPTION` | TLS must protect all email protocol traffic. |
| `STARTTLS_SECURITY` | When STARTTLS is offered, it must be negotiated. |
| `TLS_VERSION_SECURITY` | TLS 1.2+ required; 1.0/1.1/SSLv2/SSLv3 deprecated. |
| `CIPHER_SECURITY` | Modern AEAD cipher suites with forward secrecy. |
| `KEY_EXCHANGE_SECURITY` | Forward secrecy, ≥2048-bit finite-field or ≥P-256 elliptic. |
| `CERTIFICATE_SECURITY` | Valid, trusted, hostname-matching certificate. |
| `AUTHENTICATION_ORDERING` | AUTH must occur after TLS establishment. |
| `EMAIL_POLICY_SECURITY` | MTA-STS / DANE / SMTP-TLSRPT policies consistent. |
| `SESSION_SECURITY` | Session-level properties (renegotiation, resumption). |

### Cross-Session Correlation

`correlate_sessions()` groups sessions by `asset_key` (server IP:port) and detects:

- **PATTERN_1** — TLS version variation (same server, different TLS versions)
- **PATTERN_2** — Certificate variation (same server, different certificates)
- **PATTERN_3** — STARTTLS offered but frequently unused
- **PATTERN_4** — AUTH-before-TLS repeated across sessions
- **PATTERN_5** — TLS failures concentrated around one client
- **PATTERN_6** — Security posture changes over time

## Pipeline Integration

Phase 3 analysis runs after Phase 2 state machine building in `pipeline.py`:

1. Build state machines (Phase 2)
2. Link findings to transitions (`link_all_findings`)
3. Run reasoning engine per finding (`ReasoningEngine.reason`)
4. Evaluate security controls (`evaluate_security_controls`)
5. Correlate sessions (`correlate_sessions`)

## Testing

Phase 3 tests live in `engine/tests/test_security_reasoning_phase3.py` (46 tests):

- Finding→transition linkage
- Transition→evidence linkage
- Exact, fallback, and unknown frame attribution
- STARTTLS-not-negotiated reasoning (multiple explanations, stripping = LOW confidence)
- AUTH-before-TLS reasoning
- Attack explanation is never "confirmed"
- Server configuration explanation
- Incomplete capture reasoning
- Security control status (PASS on secure, FAIL on vulnerable)
- Cross-session TLS version variation
- Cross-session certificate variation
- Repeated AUTH-before-TLS pattern
- Explainable risk computation
- IMAP state machine states and transitions
- POP3 state machine states and transitions
- TLS 1.3 certificate invisibility (NOT_ASSESSABLE, NOT a failure)
- Standards mapping via `kb/standards.yaml`
- JSON serialization of all Phase 3 objects
- HTML rendering of Phase 3 sections
- Phase 1 and Phase 2 backward compatibility
