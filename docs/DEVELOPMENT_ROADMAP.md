# DEVELOPMENT ROADMAP — SecureMailScope

**Date:** 2026-09-26  
**Branch:** phase-4-cross-session-drift  

---

## Phase 1: Forensic Foundation — COMPLETE ✅

**Objective:** Establish the foundation for trustworthy forensic analysis.

- Security hardening (bounded gzip, file limits, malformed PCAP handling)
- Capture completeness model
- Evidence model (ObservationStatus, Confidence, typed observations)
- Observation status model (OBSERVED / INFERRED / NOT_OBSERVABLE / CONTRADICTED / INSUFFICIENT_CAPTURE)
- Tests (test_forensic_foundation.py — all passing)
- Documentation (docs/FORENSIC_EVIDENCE_MODEL.md)

---

## Phase 2: Evidence Integration — COMPLETE ✅

**Objective:** Make findings reference structured evidence.

- Protocol-independent email security state machine
- SMTP/IMAP/POP3 state machines
- Security-relevant transitions
- Evidence references on findings
- HTML/JSON reports updated

229 of 232 tests passing (1 pre-existing sklearn failure).

---

## Phase 3: Security Reasoning — COMPLETE ✅

**Objective:** Present multiple explanations for suspicious behavior.

- `FindingReference` model (finding → transition → evidence linkage)
- Exact/fallback/unknown frame attribution
- `ReasoningEngine` with possible explanations and confidence levels
- `SecurityControl` model (PASS/WARN/FAIL/LOW/UNKNOWN/NOT_ASSESSABLE)
- IMAP and POP3 state machines (resolving Phase 2 limitation #3)
- Standards knowledge base (kb/standards.yaml)
- 46 Phase 3 tests, all passing

276 of 277 tests passing (1 pre-existing failure).

---

## Phase 4: Cross-Session Drift — COMPLETE ✅

**Objective:** Move from analyzing one email session at a time to understanding
how an email system's security posture behaves across multiple sessions and
over time.

### Completed ✅

- **Baseline audit** (docs/PHASE4_BASELINE_AUDIT.md) — documented what Phase 3
  guarantees, what is heuristic, what is deterministic, what is exact, what is
  fallback, what remains unverified
- **SMTP state machine fix** — corrected frame precision from EXACT to FALLBACK
  for EHLO and other commands where exact frame attribution is not available
- **Ground-truth scenarios** (engine/securemailscope/scenarios.py) — 17
  controlled scenarios covering all 15 required cases plus before/after config
  change variants
- **Posture snapshot model** (engine/securemailscope/posture.py) — PostureSnapshot,
  PostureChange, DriftResult, AssetPostureHistory, AssetIdentity with confidence
- **Drift detection** — IMPROVEMENT / DEGRADATION / CONFIGURATION_CHANGE /
  NO_MEANINGFUL_CHANGE / INCONCLUSIVE classification with explainable evidence
- **Temporal analysis** (engine/securemailscope/temporal.py) — time-ordered
  posture evolution with explicit NOT_OBSERVABLE handling for missing timestamps
- **Report integration** — HTML template extended with Section 6: Asset posture
  history; JSON report automatically includes Phase 4 fields
- **Documentation** (docs/PHASE4_CROSS_SESSION_DRIFT.md) — full architecture and
  design documentation

### Key design decisions

- Drift detection extends `cross_session.py` (no duplication)
- Only security-relevant changes are reported — not every difference is a regression
- STARTTLS stripping remains "possible/suspicious" (Confidence.LOW), never confirmed
- Frame precision is never over-claimed (EXACT only when real frame number available)
- Evidence references survive every aggregation layer
- Confidence is preserved through snapshots and drift comparison
- No O(N²) comparison — sessions are grouped by asset identity first

### Test results

- **317 passing, 1 pre-existing failure, 1 skipped** (total 319)
- 48 Phase 4 tests, all passing
- Pre-existing failure (`test_history_uses_prior_distinct_captures_and_keeps_verdicts`)
  confirmed unrelated (fails on clean Phase 3 branch)

---

## Phase 5: Configuration Drift + Remediation Verification — PLANNED

**Objective:** Compare captures over time and verify fixes.
- Formal before/after comparison (building on Phase 4 drift)
- Drift detection (Phase 4 complete)
- Remediation verification (FIXED/PARTIALLY_FIXED/STILL_PRESENT)

---

## Phase 6: Investigation Workspace UI — PLANNED

**Objective:** Full analyst workflow.
- Overview → Assets → Sessions → Findings → Evidence → Remediation → Verification → Report
- Timeline page
- Evidence Explorer page
- Settings/Privacy page

---

## Phase 7: AI/ML Refinements — PLANNED

**Objective:** Improve ML with real capture data.
- Real capture training data pipeline
- Online learning / incremental updates
- Model versioning and rollback

---

## Phase 8: Performance + Scale — PLANNED

**Objective:** Benchmark and optimize.
- PCAP benchmarks
- Memory profiling
- Streaming analysis for large files

---

## Phase 9: Demo Captures — PLANNED

**Objective:** Controlled synthetic captures for all scenarios.
- 20 documented synthetic scenarios
- Ground truth for each
- Evaluation against Wireshark/TShark/Zeek

---

*End of DEVELOPMENT ROADMAP*
