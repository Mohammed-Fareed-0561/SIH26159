# Phase 5 Baseline Audit

## Purpose

Before implementing Phase 5 (remediation verification), this audit inspects
the Phase 4 codebase to identify what infrastructure already exists that can
support remediation verification, and what must be added.

## 1. Existing posture representation (Phase 4)

`PostureSnapshot` in `engine/securemailscope/posture.py` captures observable
security properties of an asset at a point in time:

- `tls_versions`: dict[str, int] — versions observed and their counts
- `cipher_suites`: dict[str, int] — cipher suites observed
- `certificates`: dict[str, int] — certificate fingerprints
- `cert_chain_valid`: Optional[bool] — chain validity
- `cert_expired_count`: int
- `starttls_offered_count`, `starttls_requested_count`, `starttls_accepted_count`
- `auth_before_tls_count`: int
- `finding_rule_ids`: list[str] — unique finding rules present
- `finding_severities`: dict[str, str] — rule_id → severity
- `security_controls`: dict[str, str] — control_id → worst status
- `completeness`: str — capture completeness status
- `confidence`: Confidence — overall confidence
- `limitations`: list[str]
- `session_ids`: list[str] — sessions contributing to this snapshot
- `frame_ranges`: list[tuple[int, int]] — frame ranges per session
- `observation_ids`: list[str]

### What is good for remediation

- Finding rule IDs and severities are stored → can check if a finding disappeared
- Security controls are stored as a dict → can check control status changes
- Session IDs are stored → evidence linkage is possible
- Completeness is tracked → can determine if the relevant protocol was observable
- Confidence is stored → can degrade verification confidence accordingly

### What is missing

- No explicit "finding present/absent" tracking with confidence per finding
- No per-finding completeness information (only snapshot-level completeness)
- No explicit mapping from finding rule_id to the specific observation it describes
- No before/after capture pairing logic
- No RemediationStatus enum or verification model

## 2. Existing finding representation (Phase 4)

`Finding` in `models.py` has:
- `rule_id`: str (e.g., "SMS-PROTO-001")
- `severity`: Severity enum
- `evidence`: Evidence (with frames, tcp_stream, observation_ids)
- `cap_grade`: Optional[str]
- `detail`: Optional[str]

`Evidence` has:
- `frames`: list[int] — frame numbers
- `tcp_stream`: int
- `observation_ids`: list[str]
- `status`: ObservationStatus (OBSERVED, INFERRED, NOT_OBSERVABLE, etc.)
- `confidence`: Confidence

### What is good

- Findings carry their evidence (frames, observation IDs)
- Finding severity is explicit
- Evidence has observation status and confidence

### What is missing for remediation

- No explicit "absent" representation — a finding not present in a session
  is simply not in the list. There's no `FindingAbsent` object with
  completeness/observability context.
- The `evidence` field on Finding doesn't carry which specific observation
  (state transition) it refers to in a machine-readable way
- Finding references (Phase 3) link findings to transitions, but don't
  carry completeness information about whether the finding COULD have been
  observed in the AFTER capture

## 3. Existing control representation (Phase 4)

`ControlEvaluation` in `security_controls.py` has:
- `control_id`: ControlId enum (TRANSPORT_ENCRYPTION, STARTTLS_SECURITY, etc.)
- `status`: ControlStatus enum (PASS, WARN, FAIL, LOW, UNKNOWN, NOT_ASSESSABLE)
- `reason`: str
- `contributing_finding_ids`: list[str]
- `evidence_ids`: list[str]
- `frames`: list[int]
- `limitations`: list[str]

`PostureSnapshot.security_controls`: dict[str, str] — control_id → status

### What is good

- Controls are evaluated deterministically from findings
- Control IDs are stable and named
- Controls carry evidence references and limitations
- The `_FINDING_TO_CONTROL` mapping explicitly links findings to controls

### What is missing

- No control history tracking (before/after comparison of control status)
- The posture snapshot stores only the control status string, not the
  full ControlEvaluation with evidence references

## 4. Existing evidence references (Phase 3/4)

`FindingReference` in `finding_reference.py`:
- `finding_id`: str
- `link_confidence`: LinkConfidence (EXACT, TRANSITION_INFERRED, NO_TRANSITION, NOT_ATTEMPTED)
- `transition_ids`: list[str]
- `evidence_ids`: list[str]
- `observation_ids`: list[str]
- `packet_ids`: list (when available)
- `finding_rule_id`: str (added in Phase 3)

### What is good

- Explicit linkage from findings to state machine transitions
- Link confidence is explicit
- Evidence and observation IDs are preserved

### What is missing for remediation

- No before/after pairing of finding references
- No completeness context on the finding reference itself

## 5. Existing completeness information (Phase 1-4)

`CaptureCompleteness` in `capture_completeness.py`:
- `status`: CaptureQuality (GOOD, LIMITED, INSUFFICIENT)
- `score`: int (0-100)
- `tls`: TLSSessionStats (handshake_complete, handshake_incomplete, certificate_observed, etc.)
- `email`: EmailSessionStats (starttls_negotiated, starttls_offered_not_used, auth_before_tls, etc.)
- `missing_evidence`: list[MissingEvidence]
- `limitations`: list[Limitation]

### What is good

- Can check if TLS handshake was complete in the AFTER capture
- Can check if STARTTLS negotiation was observed
- Can check if AUTH-before-TLS was observed
- Can check if certificate was observed

### What is missing

- Per-session completeness granularity (the completeness model is capture-level)
- Per-finding observability assessment (could this specific finding have
  been observed in this capture?)

## 6. Existing confidence information

- `Confidence` enum: FULL, PARTIAL, HIGH, MEDIUM, LOW, UNKNOWN
- `PostureSnapshot.confidence`: aggregate confidence
- `FindingReference.link_confidence`: EXPLICIT / TRANSITION_INFERRED / etc
- `StateTransition.confidence`: Confidence enum
- `StateTransition.frame_precision`: EXACT / FALLBACK / UNKNOWN

### What is good

- Confidence is propagated through the evidence chain
- Frame precision is tracked per transition

### What is missing

- No explicit confidence propagation from evidence to remediation verification
- Need to aggregate confidence from multiple evidence sources

## 7. Existing temporal information

`TemporalAnalysis` in `temporal.py`:
- `points`: list[TemporalPoint] (capture_id, capture_time, snapshot)
- `drifts`: list[DriftResult] between consecutive points
- `temporal_confidence`: Confidence (degraded when timestamps missing)
- `limitations`: includes NOT_OBSERVABLE when timestamps missing

`CaptureRef.capture_time`: Optional[datetime]

### What is good

- Temporal ordering is tracked
- Missing/unreliable timestamps are handled explicitly
- Drift results are associated with temporal points

### What is missing

- No explicit regression detection (needs to be built on top of drift)
- No before/after capture pairing with explicit capture IDs

## 8. What can already support remediation verification

1. **Finding disappearance** — can compare `finding_rule_ids` in before/after snapshots
2. **Control status changes** — can compare `security_controls` dicts
3. **TLS version changes** — can compare `tls_versions` dicts
4. **Certificate changes** — can compare `certificates` and `cert_chain_valid`
5. **Capture completeness** — `completeness` field on snapshot
6. **Evidence references** — `session_ids`, `observation_ids` on snapshot
7. **Asset identity** — `AssetIdentity` with confidence from Phase 4
8. **Temporal ordering** — `TemporalAnalysis` with timestamp handling
9. **Drift detection** — `DriftResult` / `PostureChange` from Phase 4

## 9. What must be added

1. **RemediationVerification model** — dataclass with status (FIXED/STILL_PRESENT/PARTIALLY_FIXED/UNVERIFIABLE), confidence, evidence refs, limitations
2. **Before/after pairing** — pair snapshots by asset identity, with confidence
3. **Finding-level verification** — check if a specific finding's condition still holds
4. **Control-level verification** — check if a control's status improved
5. **Completeness-aware verification** — use capture completeness to determine observability
6. **Regression detection** — detect when a previously verified finding reappears
7. **Report integration** — add remediation verification sections to JSON/HTML
8. **Ground-truth scenarios** — BEFORE/AFTER scenario pairs for testing
9. **Comprehensive tests** — covering all verification cases
