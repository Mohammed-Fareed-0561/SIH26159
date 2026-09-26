# Phase 4 Baseline Audit: Phase 3 Security Reasoning

## Purpose

Before implementing Phase 4 (cross-session drift), this audit inspects the
current Phase 3 implementation to identify what is deterministic, what is
heuristic, what is exact, what is fallback, and what remains unverified.

The audit covers:

- SMTP state-machine transitions
- IMAP state-machine transitions
- POP3 state-machine transitions
- FindingReference linkage
- finding_linker heuristics
- exact / fallback / unknown frame attribution
- ReasoningEngine
- Security controls
- Existing cross_session.py
- Evidence model
- Capture completeness
- Report integration (JSON + HTML)

---

## 1. State-Machine Transitions

### Deterministic

- Transition rules are defined as `TransitionRule` dataclasses with fixed
  `from_state → to_state` pairs and an optional `security_relevant` flag.
- The sequence of states is derived from parsed `Session` fields: `banner`,
  `capability_line`, `starttls_offered/requested/accepted`, `tls_mode`,
  `cleartext_auth`, `command_transcript`, `tls_version`.
- Security relevance is determined by a lookup in `_valid_transitions` — no
  ambiguity.

### Heuristic

- State ordering: states are added sequentially based on `if` checks on session
  fields. If multiple fields are set (e.g., both `starttls_offered` and
  `cleartext_auth`), the order of `if` blocks determines state sequence. This is
  a heuristic, not derived from packet order.
- IMAP/POP3 command detection uses `re.search(r"\bCOMMAND\b", ...)` which matches
  commands anywhere in the line (including tagged commands like `a1 AUTHENTICATE`).
  This is a heuristic simplification — it does not parse the exact protocol grammar.

### What is exact / fallback / unknown

#### SMTP (`smtp_state_machine.py`)

| State | Frame source | Precision | Notes |
|-------|-------------|-----------|-------|
| CONNECT | `session.first_frame` | UNKNOWN | TCP SYN frame not tracked |
| BANNER | `session.first_frame` | FALLBACK | No per-banner frame attribution in Session model |
| EHLO | `_frame_for_command("EHLO")` | FALLBACK | No observation frame stored for EHLO; defaults to first_frame |
| CAPABILITIES | `_frame_for_capability()` | FALLBACK | Capability line stored as string, no frame |
| STARTTLS_OFFERED | `_frame_for_capability()` | FALLBACK | Same as capabilities — no dedicated frame field |
| STARTTLS_REQUESTED | `_frame_for_command("STARTTLS")` | FALLBACK | No `_starttls_frame` attribute on Session |
| TLS_NEGOTIATING | `session.first_frame` | FALLBACK | No TLS handshake frame tracking |
| TLS_ESTABLISHED | `session.first_frame` | FALLBACK | No TLS handshake frame tracking |
| AUTH | `session.cleartext_auth.frame` | EXACT (if set), FALLBACK (if None) | Only AUTH has exact frame attribution when `cleartext_auth.frame` is populated |
| MAIL_FROM / RCPT_TO / DATA / QUIT | `_frame_for_command()` | FALLBACK | No per-command frame stored |
| CLOSED | final frame | UNKNOWN | No explicit packet for closed state |

**Key limitation:** The SMTP state machine uses `_frame_precision_for(to_state)` to
determine transition precision. This maps state names to precision categories.
However, the precision is derived from the *destination state*, not from actual
frame evidence. When `_frame_for_command` returns `session.first_frame`, it sets
`self._current_precision = "FALLBACK"` — but this is only consulted for
STARTTLS states, not for EHLO/MAIL_FROM/RCPT_TO/DATA/QUIT which always return
EXACT despite using `first_frame` as a fallback.

**This is a precision overclaim:** EHLO, MAIL_FROM, RCPT_TO, DATA, and QUIT
transitions are marked `frame_precision = "EXACT"` even though their frame is
`session.first_frame` (a fallback). The `_frame_for_command` method returns
`first_frame` in all cases except AUTH, but `_frame_precision_for` returns
`"EXACT"` for these states unconditionally.

#### IMAP (`imap_state_machine.py`)

| State | Frame source | Precision | Notes |
|-------|-------------|-----------|-------|
| CONNECT | `session.first_frame` | UNKNOWN | |
| GREETING | `session.first_frame` | FALLBACK | |
| CAPABILITY | `session.first_frame` | FALLBACK | |
| STARTTLS_OFFERED | `session.first_frame` | FALLBACK | |
| STARTTLS_REQUESTED | `session.first_frame` | FALLBACK | `cleartext_auth.frame` is not the STARTTLS frame |
| TLS_NEGOTIATING | `session.first_frame` | FALLBACK | |
| TLS_ESTABLISHED | `session.first_frame` | FALLBACK | |
| AUTH | `cleartext_auth.frame or first_frame` | EXACT (if frame set), FALLBACK (otherwise) | |
| SELECT / FETCH / LOGOUT | `session.first_frame` | FALLBACK | |
| CLOSED | final frame | UNKNOWN | |

IMAP uses 4-tuples `(name, frame, refs, precision)` and sets `frame_precision`
correctly per-state. No precision overclaim issue.

#### POP3 (`pop3_state_machine.py`)

Same pattern as IMAP — 4-tuples with per-state precision. AUTH uses
`cleartext_auth.frame` when available (EXACT), otherwise first_frame (FALLBACK).

**POP3 command detection:** Uses `re.match(r"^\s*(USER|PASS|AUTH)\b", ...)` —
requires the command at the start of the line. POP3 commands are not tagged, so
this is correct.

### Unverified

- IMAP `CAPA` command response parsing: the state machine checks `capability_line`
  but does not distinguish between CAPABILITY command/response and the greeting's
  CAPABILITY string. The transition `GREETING → CAPABILITY` is always added when
  `capability_line` is set, but the actual protocol flow may differ.
- POP3 `STLS_REQUESTED → TLS_NEGOTIATING` transition: the state machine does not
  verify that the STLS command was actually sent before TLS negotiation begins.

---

## 2. FindingReference

### Deterministic

- `FindingReference` is a dataclass with explicit fields: `finding_id`,
  `rule_id`, `transition_ids`, `evidence_ids`, `observation_ids`,
  `packet_refs`, `link_confidence`, `link_notes`.
- `LinkConfidence` enum: EXACT / TRANSITION_INFERRED / NO_TRANSITION /
  NOT_ATTEMPTED.
- `finding_reference_to_dict()` uses `_encode()` for proper enum serialization.

### Heuristic

- The `_RULE_TRANSITION_MAP` in `finding_linker.py` maps rule IDs to expected
  `(from_state, to_state)` pairs. This mapping is a heuristic — it assumes that
  a finding like `SMS-STRIP-002` (STARTTLS offered but not used) always maps to
  transitions like `STARTTLS_OFFERED → AUTH`. The actual mapping may vary
  depending on the session flow.
- When no exact transition match is found, the linker falls back to
  `TRANSITION_INFERRED` — linking to any transition whose from/to states overlap
  with expected pairs. This is a fuzzy match.
- `packet_refs` are populated with `tr.frame` and `obs_ref.excerpt` — the frame
  may be `None` (when `frame_precision` is UNKNOWN), and the excerpt is truncated
  to 80 characters.

### Exact

- When a rule maps to a transition that actually appears in the state machine
  result, the link is EXACT.
- `transition_ids`, `evidence_ids`, and `observation_ids` are populated from
  the actual transition objects — no fabrication.

### Fallback

- `TRANSITION_INFERRED` when no exact match but overlapping states exist.
- `NOT_ATTEMPTED` when no state machine result is provided.

### Unverified

- The linkage does not verify that the finding's `Evidence.frames` actually
  intersect with the transition's frame. It trusts the rule-to-transition map.
- `packet_refs` for inferred links include `"frame": None` — the system correctly
  reports no frame rather than fabricating one.

---

## 3. Finding Linker

### Heuristic (documented)

The `_RULE_TRANSITION_MAP` maps each finding rule_id to expected transition pairs.
This is inherently heuristic because:

1. A finding may fire on a transition that is not in the map (new rules added later).
2. The same rule may fire in different contexts with different transition flows.
3. The map assumes a canonical state sequence that may not always apply.

When the map doesn't match, the linker falls back to:
- Linking to security-relevant transitions by inference (overlap in state names)
- Marking `link_confidence = TRANSITION_INFERRED` or `NO_TRANSITION`

### Never fabricates

- `transition_ids` come from actual `StateTransition` objects.
- `evidence_ids` come from actual `EvidenceRef` objects on transitions.
- `packet_refs` frame values come from `tr.frame` — which may be `None`.

---

## 4. Frame Attribution (exact / fallback / unknown)

### Verified exact

- `AUTH` state in SMTP, IMAP, and POP3: when `session.cleartext_auth.frame` is
  not `None`, `frame_precision = "EXACT"` and `frame = cleartext_auth.frame`.
- This is the only frame attribution sourced from actual packet-level observation.

### Verified fallback

- All states that use `session.first_frame` as their frame.
- `frame_precision = "FALLBACK"` is set for BANNER, CAPABILITIES,
  STARTTLS_OFFERED/REQUESTED, TLS states, SELECT, FETCH, LOGOUT, etc.

### Verified unknown

- CONNECT state: `frame_precision = "UNKNOWN"` (TCP SYN not tracked).
- CLOSED state: `frame_precision = "UNKNOWN"`.
- INCOMPLETE state: `frame_precision = "UNKNOWN"`.

### Overclaims (issues found)

1. **SMTP `_frame_precision_for`**: Returns `"EXACT"` for `EHLO`, `MAIL_FROM`,
   `RCPT_TO`, `DATA`, `QUIT` states unconditionally, even though `_frame_for_command`
   returns `session.first_frame` (a fallback) for all of these. The precision should
   be `"FALLBACK"` for these states when no exact frame is available.

2. **SMTP STARTTLS transitions**: `frame_precision` is derived from
   `self._current_precision` which is set by `_frame_for_command("STARTTLS")`.
   Since `_starttls_frame` is never set on `Session`, this always returns
   `"FALLBACK"`, but the precision is only consulted in the `STARTTLS_OFFERED`
   and `STARTTLS_REQUESTED` branches — not for TLS_NEGOTIATING/TLS_ESTABLISHED.

3. **IMAP/POP3 STARTTLS_REQUESTED**: Sets `precision = "FALLBACK"` but does not
   attempt to find an exact frame for the STLS/STARTTLS command — just uses
   `first_frame`.

---

## 5. ReasoningEngine

### Deterministic

- `_EXPLANATION_RULES` maps rule IDs to explanation IDs via prefix matching
  (`rule_id.startswith(prefix)`). This is a deterministic mapping.
- `_IMPACT_BY_RULE` and `_EXPOSURE_BY_RULE` are deterministic lookups.
- `compute_risk()` uses a documented combination table:
  `(impact, exposure, confidence) → overall`.
- Any `UNKNOWN` component propagates to `UNKNOWN` risk.

### Heuristic

- `_candidates_for_rule()` returns which explanations are "relevant" to a rule.
  The rule-to-explanation mapping is a heuristic — it covers known rules but
  may not cover all possible rules.
- `_overall_confidence()` is heuristic — it uses rules like "if STARTTLS was
  offered but not negotiated, confidence is MEDIUM" based on the number of
  candidate explanations and supporting evidence.
- `_inferences()` generates inference text from facts — the inference logic is
  rule-based but the text descriptions are templates.

### Never claims attacks

- `STARTTLS_STRIPPING` always has `confidence = LOW` and `status = "possible"`.
- The engine does not have a "confirmed attack" status — explanations are
  "possible" or "likely" at best.
- The description for `STARTTLS_STRIPPING` explicitly states:
  "THIS IS A POSSIBLE EXPLANATION ONLY — it is not confirmed by a single capture."

### Exact

- Observed facts are derived directly from session fields (e.g.,
  `session.starttls_offered`, `session.cleartext_auth`, `session.tls_mode`).

### Fallback

- When `state_result` is `None`, the engine still reasons from session-level
  facts but marks evidence as inferred.
- `INCOMPLETE_CAPTURE` explanation is only added when
  `session._capture_completeness_status == "LIMITED"`.

### Unverified

- The `_overall_confidence()` method's logic is complex and not fully tested
  for all rule/explanation combinations. The confidence factors are documented
  but the exact combination rules are not exhaustively validated.
- TLS 1.3 certificate invisibility is handled (cert_visibility =
  ENCRYPTED_TLS13 → NOT_ASSESSABLE), but the reasoning engine's treatment of
  this case may not cover all certificate-related rules.

---

## 6. Security Controls

### Deterministic

- `_FINDING_TO_CONTROL` maps each rule_id to `(ControlId, ControlStatus, reason)`.
  This is a static, exhaustive mapping for all defined rules.
- `_control_standards()` loads standards from `kb/standards.yaml`.
- `evaluate_security_controls()` iterates all findings, applies the mapping,
  and picks the worst status per control.
- Session-level defaults: controls with no findings are PASS (if encrypted) or
  UNKNOWN/NOT_ASSESSABLE based on session state.

### Heuristic

- The "worst status wins" policy (`fail=0, warn=1, low=2, pass=3, ...`) is a
  design choice, not a protocol requirement.
- The mapping of `SMS-OK-001` to PASS for all controls is a heuristic — a single
  "OK" finding doesn't necessarily prove all controls pass, but it's a reasonable
  approximation.

### Exact

- `contributing_finding_ids`, `transition_ids`, `evidence_ids`, and `frames`
  are populated from actual finding/control objects.
- `transition_ids` come from `state_result.security_relevant_transitions`.

### Unverified

- The `_add_session_level_controls()` function is a no-op (`pass`) — it does not
  add any implicit controls based on session state beyond what the main loop
  handles.
- Control `SESSION_SECURITY` has an empty rule list `[]` — always
  NOT_ASSECTABLE. Not yet implemented.

---

## 7. Existing cross_session.py (Phase 3 version)

### Deterministic

- Sessions are grouped by `asset_key` (= `server_name:port` or `server.ip:port`).
- TLS version, cipher suite, and certificate aggregation are simple counts.
- Pattern detection is rule-based: `len(tls_versions) > 1` triggers
  TLS_VERSION_VARIATION, etc.

### Heuristic

- **Asset identity**: `asset_key` uses `server_name` if present, otherwise
  `server.ip`. When `server_name` is missing, the IP:port is used — but the same
  server may have different IPs behind a load balancer, leading to split groups.
  Conversely, different servers behind the same IP (NAT) would be merged.
- **Pattern thresholds**: PATTERN_3 (STARTTLS offered but not used) requires
  `offered_count >= 2` and `ratio < 0.5`. PATTERN_4 (AUTH before TLS) requires
  `>= 2` sessions. These thresholds are somewhat arbitrary.
- **Temporal analysis**: PATTERN_6 compares TLS versions between the first and
  last timestamps, but only if multiple sessions share exact timestamps. This is
  fragile — if timestamps have different precision, the comparison may fail.

### Exact

- `tls_versions`, `cipher_suites`, `certificates` dictionaries contain actual
  counts from session data.
- `by_client` breakdown uses actual client IP:port values.

### Unverified

- No `capture_id` tracking — sessions from different captures are mixed together
  without distinguishing which capture each came from.
- No `capture_time` aggregation per asset — the temporal pattern only compares
  first vs. last, not the full timeline.
- No uncertainty quantification in `asset_key` grouping — if two sessions have
  the same IP:port but different server_names, they are silently merged.

---

## 8. Evidence Model

### Deterministic

- `ObservationStatus` enum: OBSERVED / INFERRED / NOT_OBSERVABLE /
  CONTRADICTED / INSUFFICIENT_CAPTURE.
- `Confidence` enum: HIGH / MEDIUM / LOW / UNKNOWN (Phase 3 additions;
  Phase 1 values FULL/PARTIAL retained in models.py for backward compat).
- `EvidenceRef` carries `evidence_id`, `observation_type`, `status`, `excerpt`.
- `EvidenceBundle` tracks `status_summary` counts.

### Unverified

- `EvidenceBundle` is constructed in the pipeline but the
  `add()` method uses `obs.status` (an enum) as a dict key — this works but
  the bundle is never actually passed to the state machine or reasoning engine.
  The `Report.evidence` field is set to `None` in the pipeline.

---

## 9. Capture Completeness

### Deterministic

- `CaptureCompleteness` assesses TCP reassembly gaps, truncated packets,
  suspect timestamps, incomplete TLS handshakes.
- Scores are computed from these metrics.
- `MissingEvidence` and `Limitation` objects document specific gaps.

### Unverified

- `CaptureCompleteness` is computed in the pipeline but not used by the
  cross-session correlation or reasoning engine to adjust confidence.
- The `_capture_completeness_status` field (accessed as
  `session._capture_completeness_status` in the reasoning engine) is not a
  formal Session field — it is set ad-hoc in tests.

---

## 10. Report Integration

### JSON

- `to_dict()` recursively encodes dataclasses, enums, datetimes.
- Phase 3 fields are additive on `Report`: `security_controls`, `reasoning`,
  `cross_session_patterns`, `finding_references`, `email_security_state_machines`.
- `finding_reference_to_dict()`, `ControlEvaluation.to_dict()`,
  `ReasoningResult.to_dict()`, `PatternResult.to_dict()`,
  `CrossSessionAnalysis.to_dict()` all use `_encode()`.

### HTML

- Template includes Phase 3 sections: security controls table per session,
  reasoning section per session, cross-session patterns section.
- `frame_precision` is displayed on transitions.
- Standards references are shown on findings.
- The template uses `_Wrap` for attribute-style access over dicts.

### Unverified

- The HTML template references `r.capture.bytes` with `'{:,}'.format()` — this
  will fail if `bytes` is missing from the report dict. The `_Wrap` class returns
  `None` for missing keys, and `'{:,}'.format(None)` raises `TypeError`.
- `r.history.servers` section references `server.status`, `server.prior_sessions`,
  etc. — these fields are not part of the Phase 3 model and may be `None`.

---

## Summary of Issues Found

| # | Issue | Severity | Location |
|---|-------|----------|----------|
| 1 | SMTP marks EHLO/MAIL_FROM/RCPT_TO/DATA/QUIT as EXACT frame precision despite using first_frame fallback | Medium | smtp_state_machine.py `_frame_precision_for()` |
| 2 | `capture.bytes` format string in HTML template crashes on None | Low | report.html.j2 line 111 |
| 3 | `_capture_completeness_status` is not a formal Session field | Low | reasoning.py, test_security_reasoning_phase3.py |
| 4 | `EvidenceBundle` is never populated in the pipeline (evidence=None) | Medium | pipeline.py line 413 |
| 5 | Cross-session grouping has no capture_id tracking | Medium | cross_session.py |
| 6 | Temporal pattern detection is fragile (exact timestamp matching) | Medium | cross_session.py PATTERN_6 |
| 7 | No uncertainty quantification in asset_key grouping | Medium | cross_session.py `_asset_key_from_sessions()` |
| 8 | POP3 command detection uses `re.match` (start-of-line) which is correct for POP3 but inconsistent with IMAP's `re.search` | Low | pop3_state_machine.py vs imap_state_machine.py |

## What Phase 3 Guarantees

1. Every finding gets a `FindingReference` (if state machine ran) linking it to
   transitions and evidence — never fabricates IDs.
2. Frame precision is ALWAYS one of EXACT / FALLBACK / UNKNOWN — never invented.
3. The reasoning engine NEVER claims attacks — stripping is always LOW/possible.
4. Security controls are deterministic — each finding maps to controls via a
   static table.
5. Risk is explainable — the combination table is documented, and UNKNOWN
   inputs produce UNKNOWN risk.
6. Cross-session patterns carry confidence, interpretations, and limitations.
7. All Phase 3 objects serialize correctly via `_encode()`.

## What Phase 3 Does NOT Guarantee

1. Cross-capture analysis (no capture_id in sessions).
2. Temporal drift detection between captures.
3. Asset identity certainty across sessions (no uncertainty quantification).
4. Full evidence traceability from packet to finding (EvidenceBundle unused).
5. Capture completeness influencing reasoning confidence.
