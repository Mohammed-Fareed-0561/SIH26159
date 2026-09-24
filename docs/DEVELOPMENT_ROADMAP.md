# DEVELOPMENT ROADMAP — SecureMailScope

**Date:** 2026-09-24
**Branch:** phase-1-forensic-foundation

---

## Phase 1: Forensic Foundation — **IN PROGRESS** ✅

**Objective:** Establish the foundation for trustworthy forensic analysis.

### Completed ✅

1. **Security hardening**
   - Bounded gzip decompression (`_BoundedGzipReader`)
   - Engine-side file limits (`config.py`)
   - Malformed PCAP handling (graceful degradation)
   - Structured error output (`AnalysisError`, `CaptureSecurityError`)
   - Log audit considerations

2. **Capture completeness model**
   - `CaptureCompleteness` dataclass with scoring
   - `MissingEvidence` and `Limitation` structures
   - Automatic assessment integrated into `analyse_capture()`
   - Status: GOOD / LIMITED / INSUFFICIENT

3. **Evidence model**
   - `ObservationStatus` enum (OBSERVED, INFERRED, NOT_OBSERVABLE, CONTRADICTED, INSUFFICIENT_CAPTURE)
   - `Confidence` enum (HIGH, MEDIUM, LOW, UNKNOWN)
   - Typed observation classes (Protocol, TLS, Certificate, DNS)
   - `EvidenceBundle` per session
   - `CaptureEvidence` container

4. **Observation status model**
   - Formal definitions for all five statuses
   - Documentation of when each applies

5. **Tests** (`test_forensic_foundation.py`)
   - gzip bomb protection
   - file size limits
   - packet count limits
   - malformed PCAP handling
   - capture completeness model
   - evidence model
   - observation statuses
   - sensitive information not leaked
   - JSON/HTML output
   - backward compatibility

6. **Documentation**
   - `docs/FORENSIC_EVIDENCE_MODEL.md`

### Pending Phase 1 items

- None currently blocking Phase 1

---

## Phase 2: Evidence Integration — PLANNED

**Objective:** Make findings reference structured evidence.

- Extend `Finding` to reference `EvidenceRef[]`
- Update rule engine to populate evidence refs per finding
- Update findings to carry observation status and confidence
- Add explicit limitations to findings
- Update HTML report to display evidence per finding
- Update JSON report to include full evidence

---

## Phase 3: Email Security State Machine — PLANNED

**Objective:** Model email sessions as state machines.

- Define SMTP state machine (CONNECT → EHLO → STARTTLS → ENCRYPTED → AUTH → ...)
- Define IMAP state machine
- Define POP3 state machine
- Detect abnormal transitions
- Explain observed transitions with evidence

---

## Phase 4: Attack vs Misconfiguration Reasoning — PLANNED

**Objective:** Present multiple explanations for suspicious behavior.

- Implement differential diagnosis for STARTTLS anomalies
- Confidence scoring per explanation
- Evidence requirements for each explanation
- UI for exploring explanations

---

## Phase 5: Security Control Model — PLANNED

**Objective:** Group findings into named security controls.

- Define security controls (Transport Encryption, STARTTLS Security, etc.)
- Map findings to controls
- Dashboard showing control health
- Cross-session correlation within controls

---

## Phase 6: Investigation Workspace UI — PLANNED

**Objective:** Full analyst workflow.

- Overview → Assets → Sessions → Findings → Evidence → Remediation → Verification → Report
- Timeline page
- Evidence Explorer page
- Settings/Privacy page

---

## Phase 7: Configuration Drift + Remediation Verification — PLANNED

**Objective:** Compare captures over time and verify fixes.

- Formal before/after comparison
- Drift detection
- Remediation verification (FIXED/PARTIALLY_FIXED/STILL_PRESENT)

---

## Phase 8: AI/ML Refinements — PLANNED

**Objective:** Improve ML with real capture data.

- Real capture training data pipeline
- Online learning / incremental updates
- Model versioning and rollback

---

## Phase 9: Performance + Scale — PLANNED

**Objective:** Benchmark and optimize.

- 10/100/500 MB / 1 GB PCAP benchmarks
- Memory profiling
- Streaming analysis for large files

---

## Phase 10: Demo Captures — PLANNED

**Objective:** Controlled synthetic captures for all scenarios.

- 20 documented synthetic scenarios
- Ground truth for each
- Evaluation against Wireshark/TShark/Zeek

---

*End of DEVELOPMENT ROADMAP*
