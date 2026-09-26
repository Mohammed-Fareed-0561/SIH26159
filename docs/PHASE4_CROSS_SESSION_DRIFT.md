# Phase 4: Cross-Session Drift

## 1. Architecture

Phase 4 extends SecureMailScope from per-session analysis to cross-session
security posture tracking. The core idea is:

> Move from analyzing one email session at a time to understanding how an
> email system's security posture behaves across multiple sessions and over time.

### Module layout

```
engine/securemailscope/
├── scenarios.py          # Ground-truth test scenarios (15+ cases)
├── posture.py            # PostureSnapshot, PostureChange, DriftResult, AssetPostureHistory
├── temporal.py           # TemporalAnalysis — time-ordered posture evolution
├── smtp_state_machine.py # Fixed: frame precision now FALLBACK (was incorrectly EXACT)
├── imap_state_machine.py # Phase 3 — unchanged
├── pop3_state_machine.py # Phase 3 — unchanged
├── finding_reference.py  # Phase 3 — unchanged
├── finding_linker.py     # Phase 3 — unchanged
├── reasoning.py          # Phase 3 — unchanged
├── security_controls.py  # Phase 3 — unchanged
├── cross_session.py      # Phase 3 — extended by Phase 4 (not duplicated)
├── models.py             # Report — Phase 4 fields added (backward compatible)
├── report/               # HTML/JSON templates — Phase 4 sections added
│   ├── json_report.py
│   ├── html_report.py
│   └── templates/report.html.j2
└── tests/
    └── test_posture_drift_phase4.py   # 48 tests
```

### Data flow

```
Multiple captures/sessions
    │
    ▼
correlate_sessions()                     [Phase 3 cross_session.py]
    │  groups sessions by asset identity
    ▼
build_posture_snapshot(sessions, capture_id)  [Phase 4 posture.py]
    │  aggregates observable security properties
    ▼
PostureSnapshot
    │
    ├── compare_snapshots(before, after)       [Phase 4 posture.py]
    │   │
    │   └── DriftResult (list of PostureChange)
    │
    ├── build_temporal_analysis(snapshots)     [Phase 4 temporal.py]
    │   │
    │   └── TemporalAnalysis (timeline of points + changes)
    │
    └── AssetPostureHistory (snapshots + drift + temporal)
```

## 2. Asset identity

Sessions are grouped into assets using `correlate_sessions()` from
the existing `cross_session.py` module (extended, not replaced).

### Grouping key hierarchy

1. **CERTAIN** — same `server_name` (SNI/MX) + same port
   → `mail.example:587`
2. **HIGH** — same server IP + port + protocol
   → `10.0.0.2:587/smtp`
3. **MEDIUM** — same IP:port only
4. **LOW** — IP inferred from limited data
5. **UNCERTAIN** — insufficient evidence (sessions NOT grouped)

### Why this hierarchy

- Server names from SNI/MX are the most reliable identifier — they are
  the names the server presents to clients.
- IP+port is reliable when SNI is absent (e.g., implicit TLS or
  certificate visibility is `encrypted_tls13`).
- We do **not** merge sessions with different server_names, even if the
  IP:port matches — that could conflate different virtual hosts.
- We do **not** merge sessions with different protocols on the same
  IP:port — SMTP and IMAP are different services.

### AssetIdentityConfidence enum

```python
class AssetIdentityConfidence(str, Enum):
    CERTAIN = "certain"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNCERTAIN = "uncertain"
```

## 3. Posture snapshots

### PostureSnapshot

`PostureSnapshot` captures what was **directly observed** about an asset
at a point in time (a capture or a set of sessions). It contains no
inferences — only observable properties.

```python
@dataclass
class PostureSnapshot:
    asset_key: str
    asset_identity: AssetIdentity
    capture: CaptureRef
    tls_versions: dict[str, int]
    cipher_suites: dict[str, int]
    kex_methods: dict[str, int]
    forward_secrecy: Optional[bool]
    tls_modes: dict[str, int]  # cleartext/starttls/implicit
    certificates: dict[str, int]  # fingerprint -> count
    cert_chain_valid: Optional[bool]
    name_match: Optional[bool]
    cert_expired_count: int
    cert_self_signed_count: int
    cert_visibility: dict[str, int]
    starttls_offered_count: int
    starttls_requested_count: int
    starttls_accepted_count: int
    starttls_not_offered_count: int
    auth_before_tls_count: int
    credentials_exposed_count: int
    finding_rule_ids: list[str]
    finding_severities: dict[str, str]  # rule_id -> severity
    security_controls: dict[str, str]  # control_id -> worst status
    completeness: str
    confidence: Confidence
    limitations: list[str]
    session_ids: list[str]
    frame_ranges: list[tuple[int, int]]
```

### Why findings_severities

The `finding_severities` dict maps finding rule IDs to their severity
levels. This is needed by `compare_snapshots()` to classify drift
severity when findings appear or disappear. Without it, the comparison
would treat all finding changes as configuration changes (since the
rule IDs themselves don't encode severity).

## 4. Cross-session correlation

`correlate_sessions()` was extended (not duplicated) in Phase 4 to
add `tls_versions`, `tls_modes`, `auth_before_tls_count`, and other
posture fields to `CrossSessionAnalysis`. The grouping and pattern
detection logic is unchanged — Phase 4 adds a posture layer on top.

### Pattern detection (from Phase 3, extended)

Patterns detected across sessions:

| Pattern | Condition |
|---------|-----------|
| PATTERN_1 | TLS version variation across sessions |
| PATTERN_2 | Cipher suite variation |
| PATTERN_3 | Certificate fingerprint variation |
| PATTERN_4 | AUTH-before-TLS in multiple sessions |
| PATTERN_5 | STARTTLS offered but not used in multiple sessions |
| PATTERN_6 | Inconsistent TLS behavior across protocols |

Every pattern retains `evidence` references (observation IDs).

## 5. Drift detection

### PostureChange

Each detected change is a `PostureChange` with:

- `property_name` — what changed (e.g. `"tls_versions"`)
- `description` — human-readable description
- `before_value` / `after_value` — what was observed before/after
- `severity` — classification (see below)
- `confidence` — Confidence enum
- `affected_session_ids` — which sessions support the change
- `evidence_refs` — observation IDs
- `capture_before` / `capture_after` — capture references
- `frame_before` / `frame_after` — frame numbers when available
- `affected_control` — control ID if a control is affected
- `affected_finding` — finding rule ID if a finding changed
- `limitations` — what is uncertain

### DriftSeverity

```python
class DriftSeverity(str, Enum):
    IMPROVEMENT = "improvement"
    DEGRADATION = "degradation"
    CONFIGURATION_CHANGE = "configuration_change"
    NO_MEANINGFUL_CHANGE = "no_meaningful_change"
    INCONCLUSIVE = "inconclusive"
```

### Classification logic

| Change | Classification | Rationale |
|--------|---------------|-----------|
| TLS version added | DEGRADATION if deprecated (1.0/1.1/SSL), IMPROVEMENT if modern (1.2/1.3), else CONFIGURATION_CHANGE | |
| TLS version removed | IMPROVEMENT if deprecated, DEGRADATION if modern, else CONFIGURATION_CHANGE | |
| Cipher suite added | DEGRADATION if weak (RC4/EXPORT/DES/etc.), else CONFIGURATION_CHANGE | Not all cipher changes are degradations |
| Cipher suite removed | IMPROVEMENT if weak, CONFIGURATION_CHANGE otherwise | |
| Certificate changed | CONFIGURATION_CHANGE | Cert rotation is not inherently bad |
| cert_chain_valid: True → False | DEGRADATION | Server now has broken cert chain |
| cert_chain_valid: False → True | IMPROVEMENT | Server fixed cert chain |
| cert_expired_count increased | DEGRADATION | More expired certs observed |
| STARTTLS not offered appeared | DEGRADATION | Server stopped advertising STARTTLS |
| STARTTLS offered appeared | IMPROVEMENT | Server added STARTTLS support |
| AUTH-before-TLS appeared | DEGRADATION | Credentials now exposed in cleartext |
| AUTH-before-TLS disappeared | IMPROVEMENT | Credentials no longer exposed |
| Forward secrecy lost | DEGRADATION | |
| Forward secrecy gained | IMPROVEMENT | |
| Control: PASS → FAIL | DEGRADATION | |
| Control: FAIL → PASS | IMPROVEMENT | |
| Control: PASS → WARN | DEGRADATION | |
| Control: WARN → PASS | IMPROVEMENT | |
| Finding added (worse severity) | DEGRADATION | |
| Finding removed (was worse) | IMPROVEMENT | |
| Finding added (same/better severity) | CONFIGURATION_CHANGE | |
| Capability mangling appeared | DEGRADATION | |

### What is NOT a degradation

- Certificate rotation (same validity, same properties) → CONFIGURATION_CHANGE
- A finding appearing that is the same severity as existing findings → CONFIGURATION_CHANGE
- TLS version change from 1.2 to 1.3 → IMPROVEMENT (not "change for change's sake")

## 6. Temporal analysis

### TemporalAnalysis / TemporalPoint

Uses capture timestamps to build a timeline:

```python
@dataclass
class TemporalPoint:
    capture_id: str
    timestamp: Optional[datetime]  # None if missing
    timestamp_suspect: bool
    snapshot: PostureSnapshot

@dataclass
class TemporalAnalysis:
    asset_key: str
    points: list[TemporalPoint]
    changes: list[TemporalPoint]  # points where posture changed
    status: str  # "complete" | "incomplete"
    limitations: list[str]
```

### Handling missing timestamps

When timestamps are missing or unreliable, temporal comparison is marked
as `"NOT_OBSERVABLE"` in the limitations. The system never invents
timestamps.

### Temporal comparison

Between consecutive captures (ordered by timestamp), the system compares
posture snapshots and reports which observations changed. If timestamps
are missing, the comparison is marked as inconclusive.

## 7. Evidence propagation

Every `PostureChange` retains:

1. **`evidence_refs`** — observation IDs from the Phase 3 evidence model
2. **`capture_before` / `capture_after`** — which captures the before/after
   observations came from
3. **`frame_before` / `frame_after`** — exact frame numbers when available,
   `None` when the frame is not attributed
4. **`affected_session_ids`** — which sessions contributed observations
5. **`affected_control` / `affected_finding`** — which control or finding
   is affected by the change

Frame precision (`EXACT` / `FALLBACK` / `UNKNOWN`) is preserved from
the state machine transition that produced the observation.

## 8. Uncertainty handling

### Confidence propagation

- When all evidence has `Confidence.HIGH`, the change has `Confidence.HIGH`
- When some evidence is missing or incomplete, confidence degrades to
  `Confidence.MEDIUM` or `Confidence.LOW`
- When timestamp evidence is missing, temporal analysis is
  `Confidence.LOW` with `NOT_OBSERVABLE` in limitations

### Frame precision

- `EXACT` — frame number directly attributed (e.g., AUTH with
  `cleartext_auth.frame`)
- `FALLBACK` — frame number from `first_frame` or best available
  (most SMTP state transitions)
- `UNKNOWN` — no frame information available (CONNECT, CLOSED, INCOMPLETE)

The system never claims `EXACT` precision when the evidence only
supports `FALLBACK`.

### Attack claims

STARTTLS stripping-like patterns are classified as `possible` with
`Confidence.LOW`, never as `confirmed`. The system distinguishes:
- AUTH-before-TLS: deterministic credential exposure (not an attack,
  an insecure configuration)
- STARTTLS offered-but-not-used: suspicious but cannot prove active
  attack without network-position evidence

## 9. Examples

### Example 1: TLS version degradation

```
BEFORE: TLS 1.2, TLS 1.3
AFTER:  TLS 1.0, TLS 1.2

Change:   tls_versions changed
Classification: DEGRADATION
Control: TLS_VERSION_SECURITY
Confidence: HIGH
Evidence: Capture B → Session → TLS observation
```

### Example 2: Certificate rotation

```
BEFORE: Certificate fp=a1b2c3...
AFTER:  Certificate fp=d4e5f6...

Change:   certificates changed (1 added, 1 removed)
Classification: CONFIGURATION_CHANGE
Control: CERTIFICATE_SECURITY
Confidence: HIGH
Limitation: Certificate change does not necessarily indicate degradation
```

### Example 3: STARTTLS stripping (across sessions)

```
BEFORE: STARTTLS offered=2, requested=2, accepted=2
AFTER:  STARTTLS offered=2, requested=0, accepted=0

Change:   STARTTLS offered-but-not-used changed: 0 → 2
Classification: DEGRADATION
Confidence: MEDIUM
Limitation: Could be client misconfiguration, not attack
```

## 10. Limitations

1. **No network-position evidence for attacks.** The system cannot
   prove STARTTLS stripping occurred — only that the client did not
   use STARTTLS when it was offered. This remains "possible/suspicious."

2. **Temporal ordering without timestamps.** When captures lack
   timestamps, the system cannot order them chronologically. It falls
   back to capture_id ordering, but marks this as suspect.

3. **Certificate identity.** Certificate fingerprint comparison uses
   SHA-256 fingerprints. Two different certificates with the same keys
   are still treated as different certificates.

4. **No active probing.** The system is passive — it sees only what
   was negotiated in the capture. Undvertised capabilities are not
   reported as findings.

5. **IMAP/POP3 STARTTLS frame attribution.** Like SMTP, exact frame
   attribution for STARTTLS in IMAP/POP3 relies on the `Frame`
   attribute attached to observations, not on session-level frame
   tracking.

6. **Small sample sizes.** With only 1-2 sessions per capture, posture
   snapshots may not represent the full range of server configurations.

## 11. Test methodology

### Ground-truth scenarios

15+ controlled scenarios in `scenarios.py` define expected:
- state transitions
- findings
- security controls
- evidence status
- confidence levels
- attack confirmability (True/False)

### Test structure

- **Part A** (BaselineAudit): Verifies Phase 3 frame precision is not
  over-claimed (e.g., EHLO is FALLBACK, not EXACT)
- **Part B** (GroundTruth): Verifies scenarios produce expected findings
- **Part C** (EvidenceChain): Validates evidence chain from frame to
  finding, verifying no fabricated frame numbers
- **Part D** (AssetGrouping): Tests asset identity grouping with
  confidence levels, including negative tests (unrelated assets not
  merged)
- **Part E** (PostureDrift): Tests before/after comparison with
  IMPROVEMENT/DEGRADATION/CONFIGURATION_CHANGE/NO_MEANINGFUL_CHANGE
- **Part F** (TemporalAnalysis): Tests temporal ordering with and
  without timestamps
- **Part G** (PostureSnapshot): Tests snapshot construction and
  field accuracy
- **Part H** (ExplainableDrift): Tests that every change has evidence
- **Part I** (Reporting): Tests JSON and HTML report output
- **Part J** (SecurityReview): Tests for path traversal, XSS safety,
  and report safety
- **Part K** (DeterministicOutput): Tests for reproducible output

### Running tests

```bash
.venv/Scripts/python.exe -m pytest engine/tests/ -q
```

Expected: all Phase 1–3 tests pass (1 pre-existing failure unrelated to
Phase 4), all Phase 4 tests pass.

### No fabricated evidence

Tests assert that:
- Transition frame IDs in `FindingReference` come from actual
  `StateTransition` objects (no fabricated IDs)
- Frame precision is `UNKNOWN` or `FALLBACK` where exact attribution
  is impossible
- `EXACT` precision is only used when a real frame number is available
