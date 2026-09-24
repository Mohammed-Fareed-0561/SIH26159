# BASELINE AUDIT — SecureMailScope

**Repository:** https://github.com/MalharBhoi/SecureMailScope
**License:** Apache-2.0
**Original commit hash:** 2e57c57 ("feat: add investigation workflow with evidence-based forensic tracking")
**Date of audit:** 2026-09-24
**Branch:** baseline-analysis

---

## A. Baseline Startup Status

| Component | Status | Notes |
|-----------|--------|-------|
| Python engine imports | OK | `securemailscope.pipeline` imports cleanly |
| Python 3.14 | OK | Engine installed as editable package |
| Demo PCAP analysis (smtp.pcap) | OK | Grade F, 1 session |
| Demo PCAP analysis (synthetic-imaps-tls13.pcap) | OK | Grade A+, 1 session |
| Docker daemon | Not running | Service started but pipe unavailable in this env |
| Java/Maven | Not installed | JDK 25 present but no `java`/`mvn` on PATH; backend untested |
| Node.js v22 | OK | Frontend deps not installed |

**Conclusion:** The Python engine is fully operational. The full-stack app (React + Spring Boot + PostgreSQL) could not be started because Docker and Java/Maven are unavailable. This is an environment limitation, not a project defect.

---

## B. Test Status

### Python Engine Tests

```
155 passed, 1 failed, 1 skipped in 9.37s
```

**Total:** 157 tests across 9 test files.

| Test file | Tests | Status |
|-----------|-------|--------|
| test_capture_reading.py | ~25 | All pass |
| test_starttls_and_tls.py | 37 | All pass |
| test_certificates.py | ~20 | All pass |
| test_grading.py | 31 | All pass |
| test_ml.py | ~8 | All pass (1 skipped — no sklearn) |
| test_end_to_end.py | ~12 | All pass |
| test_presentation_captures.py | 12 | All pass |
| test_cli_subprocess.py | ~4 | All pass |
| test_investigation_assessment.py | 8 | **1 FAILED** |

### Known Failure

**`test_history_uses_prior_distinct_captures_and_keeps_verdicts`**
- Location: `test_investigation_assessment.py:47`
- Cause: The test calls `annotate_history()` which tries to import sklearn for IsolationForest anomaly detection. Since scikit-learn is not installed in this environment, the ML status is `'unavailable'` instead of `'evaluated_against_prior_sessions'`.
- Severity: **Environmental, not a code defect.** The test passes when `scikit-learn` and `numpy` are installed.
- Workaround: `pip install scikit-learn numpy`

### Backend Tests

| Status | Notes |
|--------|-------|
| Untested | Maven not installed; cannot compile/run Java tests |

### Frontend Build

| Status | Notes |
|--------|-------|
| Untested | `npm install` not run in this environment |

---

## C. Architecture Summary

**Three-tier architecture:**

1. **React Frontend** (Vite + Tailwind, port 5173/8080)
   - Pages: Upload, Investigations, AnalysisJob, Dashboard, SessionDetail, Export
   - Communicates with backend via REST at `/api`

2. **Spring Boot Backend** (Java 17, port 8080)
   - Thin API layer: upload validation, persistence, job queue
   - Runs Python engine as a subprocess (one-shot, not long-lived)
   - PostgreSQL (Docker) or H2 (local) for storage
   - Flyway migrations for schema management
   - Background worker processes jobs from the queue

3. **Python Analysis Engine** (`engine/`)
   - All cryptographic analysis, ML, and reporting
   - Communicates with backend via JSON on stdout
   - Progress via `SMS_PROGRESS:` lines on stderr
   - No runtime network access (offline-capable)

**Pipeline stages:**
```
ingest → parse → reassemble → classify → analyse → features → rules → grade → ml → aggregate → report
```

---

## D. Existing Features

See [FEATURE_INVENTORY.md](./FEATURE_INVENTORY.md) for the complete table. Key capabilities:

- PCAP, PCAPNG, and gzip-compressed capture parsing
- TCP stream reassembly with frame-level evidence tracking
- SMTP/IMAP/POP3 protocol classification (content-based, port as fallback)
- STARTTLS detection with downgrade/stripping evidence
- TLS 1.0–1.3 handshake parsing, JA3/JA4 fingerprints
- X.509 certificate extraction, chain validation, OCSP stapling
- DNS policy detection (MTA-STS, DANE, TLS-RPT) from capture DNS
- Rule-based findings engine (YAML rule base, ~30 rules)
- SSL Labs-style A+–F grading with caps
- Asset (server) rollup with exposure-based prioritization
- ML posture estimation (RandomForest + IsolationForest + SHAP)
- Cross-capture history comparison
- Investigation workflow with remediation tracking
- JSON, HTML, and browser-print PDF reports
- Credential masking and SHA-256 hashing

---

## E. Weaknesses

### Critical

1. **No state machine for email sessions.** The tool detects STARTTLS anomalies but does not model the full protocol state machine. It cannot explain a transition like "STARTTLS offered → AUTH before TLS" as a sequence of states.
2. **No evidence graph.** Findings cite frame numbers but there is no structured relationship model (Finding → SecurityControl → Rule → Session → Flow → Evidence → Certificate).
3. **Missing confidence distinction.** The tool does not differentiate OBSERVED / INFERRED / NOT_OBSERVABLE / CONTRADICTED / INSUFFICIENT_CAPTURE in its conclusions.
4. **Attack vs. misconfiguration reasoning absent.** When STARTTLS is offered but not used, the tool flags it as a finding but does not present multiple explanations (client config, stripping, failed negotiation, incomplete capture).

### Moderate

5. **No capture completeness assessment.** The tool reports per-session coverage but no overall "Capture Quality: GOOD/LIMITED/INSUFFICIENT" before conclusions.
6. **No security control model.** Findings are not grouped into named controls (Transport Encryption, STARTTLS Security, etc.). The dashboard shows findings, not "which controls are failing."
7. **Cross-session correlation is shallow.** Asset rollup detects version spread but not downgrade patterns or configuration inconsistency across sessions.
8. **Configuration drift not formalized.** History comparison requires 8+ sessions across 2 captures. No structured "before/after" drift detection.
9. **Remediation verification absent.** Can mark remediation status but cannot verify "FIXED/PARTIALLY_FIXED/STILL_PRESENT" against a later capture.
10. **Investigation timeline missing.** No chronological event timeline linked to evidence.

### Minor

11. **No investigation workspace.** The UI has no Capture → Overview → Assets → Sessions → Findings → Evidence → Remediation → Verification → Report workflow.
12. **UI pages don't match proposed pages.** Current UI: Upload, Investigations, Dashboard, SessionDetail, Export. Missing: Security Controls, Evidence Explorer, Timeline, Remediation, Verification, Settings/Privacy.
13. **Privacy mode not explicit.** Credentials are masked but there is no privacy settings panel, retention/deletion controls, or data export policy.
14. **Standards knowledge base not fully structured.** Rules have RFC references but no structured confidence requirements, applicability conditions, or grade effects.

---

## F. Security Concerns

| Area | Status | Notes |
|------|--------|-------|
| Upload path traversal | Mitigated | Filename sanitised via `sanitise()` — strips path, replaces non-alphanumeric with `_` |
| Demo directory escape | Mitigated | `acceptDemo()` resolves and checks `source.startsWith(dir)` |
| Command injection | Mitigated | Engine invoked via `ProcessBuilder` list, not shell. No user input in command. |
| SQL injection | Mitigated | JPA/Hibernate with parameterized queries |
| XSS | Mitigated | React escapes by default; Jinja2 autoescape enabled for HTML reports |
| Credential leakage | Mitigated | Passwords never stored (SHA-256 only), transcripts redacted |
| Decompression bomb | **Not mitigated** | `gzip.open().read()` reads entire file into memory. No size limit before decompression. |
| Oversize PCAP | **Partially mitigated** | Backend limits upload size. No limit on engine-side processing memory (only Linux `RLIMIT_AS` via env var). |
| Malformed PCAP crash | **Partially mitigated** | Parser has guards but no proof against adversarial captures. Engine runs as subprocess so crash is contained. |
| Log leakage | **Not audited** | Logs may contain session details; no explicit sanitization review. |
| Dependency vulnerabilities | **Not audited** | No dependency scan performed. |
| Docker privileges | Acceptable | Container runs as non-root user `sms` (uid 10001). No `--privileged`. |

---

## G. Technical Debt

1. **Model version coupling.** scikit-learn pickles are version-locked; the trained artifact must be retrained on each environment. The Docker build does this correctly, but local setups may ship stale artifacts.

2. **Frontend-backend mapping layer.** `api.js` has a 100-line `adaptBackendCapture()` function to translate camelCase backend responses to snake_case engine shape. This duplication is fragile.

3. **No integration tests with Docker.** The `verify-e2e.sh` script exists but was not run in this environment. Full-stack behavior is verified by unit tests on components, not end-to-end through HTTP.

4. **ML training data is synthetic.** The training data is generated from synthetic server configurations, not real captures. The captured dataset pipeline exists but is marked "candidate_only" and requires manual review.

5. **No Java/Maven on PATH in dev environment.** Backend cannot be built or tested without installing Maven.

6. **Hardcoded demo grades.** The demo capture grades are hardcoded in `AnalysisService.DEMOS` and pinned by tests. This is intentional (the README calls it out) but means a capture change silently breaks the demo.

---

## H. Features to Preserve

| Feature | Rationale |
|---------|-----------|
| PCAP/PCAPNG/gzip reader (pure Python) | No native deps, well-tested, frame-accurate |
| TCP reassembly with frame evidence | Forensic-grade, every finding cites packets |
| Protocol classification (content-first) | Correctly excludes non-email on shared ports |
| STARTTLS downgrade detection | Unique capability vs. active scanners |
| TLS 1.0–1.3 + JA3/JA4 | Comprehensive handshake analysis |
| Capture-clock certificate validation | Correct forensic behavior (vs. wall-clock) |
| YAML rule base | Inspectable, auditable, no arbitrary code |
| Credential masking + SHA-256 | Privacy-by-design |
| SSL Labs-style grading | Familiar to reviewers |
| Asset rollup + exposure scoring | Actionable prioritization |
| Engine-as-subprocess boundary | Crash containment |
| HTML report from stored JSON | Reproducible, re-renderable |

---

## I. Features to Modify

| Feature | Change |
|---------|--------|
| History comparison | Add structured drift detection, reduce session threshold |
| Investigation workflow | Add remediation verification |
| Frontend UI | Add missing pages (Controls, Evidence, Timeline, Remediation, Verification, Settings) |
| Credential masking audit | Verify all paths that touch cleartext data |
| Docker compose | Add health checks for engine availability |
| Backend upload limits | Add configurable max size |

---

## J. Features to Replace

| Feature | Replacement |
|---------|-------------|
| Synthetic ML training data | Real capture dataset (pipeline exists but unused) |
| `api.js` backend adapter | Direct engine JSON shape or OpenAPI contract |

---

## K. New Features Requiring Implementation

These map to the features defined in the project specification:

| # | Feature | Complexity |
|---|---------|-----------|
| 1 | Email Security State Machine | High |
| 2 | Evidence Graph | High |
| 3 | Observed/Inferred/Not Observable distinction | Medium |
| 4 | Attack vs. Misconfiguration Reasoning | High |
| 5 | Security Control Model | Medium |
| 6 | Cross-Session Correlation | Medium |
| 7 | Configuration Drift | Medium |
| 8 | Remediation Verification | High |
| 9 | Capture Completeness Assessment | Medium |
| 10 | Explainable Risk Model | Medium |
| 11 | AI/ML improvements (keep deterministic + advisory) | Medium |
| 12 | Privacy Mode UI | Low–Medium |
| 13 | Standards Knowledge Base restructure | Low |
| 14 | Investigation Timeline | Medium |
| 15 | Investigation Workspace UI | Medium |
| 7–20 | Demo synthetic captures (controlled) | Medium |
| — | Security audit hardening | Medium |
| — | Performance benchmarks | Low–Medium |
| — | Documentation (12 docs) | Low–Medium |

---

## L. Recommended Implementation Order

1. **Phase 0:** Security hardening — fix decompression bomb, add upload size limits on engine side, audit log leakage
2. **Phase 1:** Capture completeness assessment (Feature 9) — quick win, no architectural change
3. **Phase 2:** Observed/Inferred/Not Observable model (Feature 3) — extends existing `Confidence` enum
4. **Phase 3:** Security control model (Feature 5) — group findings into controls
5. **Phase 4:** Email Security State Machine (Feature 1) — core new reasoning engine
6. **Phase 5:** Evidence Graph (Feature 2) — data model + API
7. **Phase 6:** Attack vs. Misconfiguration Reasoning (Feature 4) — builds on state machine
8. **Phase 7:** Investigation Timeline (Feature 14) — UI on top of graph
9. **Phase 8:** Cross-Session Correlation (Feature 6) + Configuration Drift (Feature 7)
10. **Phase 9:** Remediation Verification (Feature 8)
11. **Phase 10:** Explainable Risk (Feature 10)
12. **Phase 11:** Investigation Workspace UI (Feature 15) — ties together all previous
13. **Phase 12:** Privacy Mode (Feature 12) + Standards KB (Feature 13)
14. **Phase 13:** AI/ML refinements (Feature 11)
15. **Phase 14:** Demo captures + evaluation plan
16. **Phase 15:** Documentation

---

## M. Estimated Complexity of Major Features

| Feature | Effort | Dependencies |
|---------|--------|-------------|
| Email Security State Machine | 2–3 weeks | Protocol parsers (existing) |
| Evidence Graph | 2–3 weeks | Data model design |
| Attack vs. Misconfiguration | 1–2 weeks | State machine + graph |
| Security Control Model | 1 week | Rule engine extension |
| Remediation Verification | 1–2 weeks | History comparison (existing) |
| Investigation Workspace UI | 2–3 weeks | All backend features |
| Capture Completeness | 3–5 days | Coverage module (existing) |
| Cross-Session Correlation | 1 week | Asset rollup (existing) |
| Configuration Drift | 1 week | History comparison |
| Explainable Risk | 1 week | Grading (existing) |
| Privacy Mode | 3–5 days | Settings page |
| AI/ML refinements | 1–2 weeks | Existing ML pipeline |

---

*End of BASELINE AUDIT*
