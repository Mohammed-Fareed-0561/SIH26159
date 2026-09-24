# ARCHITECTURE AUDIT — SecureMailScope

**Date:** 2026-09-24
**Branch:** baseline-analysis

---

## System Overview

SecureMailScope is a three-tier application for passive cryptographic security assessment of email traffic:

```
┌─────────────────────────────────────────────────────────────┐
│                    React Frontend (Vite)                      │
│  Upload | Investigations | AnalysisJob | Dashboard | Session  │
│  Detail | Export                                               │
└──────────────────────────┬──────────────────────────────────┘
                           │ REST / JSON
┌──────────────────────────▼──────────────────────────────────┐
│               Spring Boot Backend (Java 17)                   │
│  CaptureController | InvestigationController | AnalysisService│
│  EngineClient (subprocess) | JobState | AnalysisQueue         │
│  Flyway migrations | JPA/Hibernate | PostgreSQL/H2            │
└──────────────────────────┬──────────────────────────────────┘
                           │ JSON on stdout / stderr
┌──────────────────────────▼──────────────────────────────────┐
│                Python Analysis Engine                         │
│  pcap/ → net/ → classify → analyze/ → scoring/ → ml/ → report/│
│  Pipeline: ingest→parse→reassemble→classify→analyse→features  │
│  →rules→grade→ml→aggregate→report                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Module-by-Module Analysis

### 1. PCAP Ingestion

**File:** `engine/securemailscope/pcap/reader.py`

**What it does:**
- Opens PCAP, PCAPNG, and gzip-compressed captures
- Parses global headers, per-packet headers, and link-layer types
- Supports classic pcap (microsecond/nanosecond timestamps) and pcapng (IFB, EPB, SPB, PB blocks)
- Handles multiple pcapng interfaces with independent timestamp resolution
- Computes capture-level metadata: packet count, timestamps, truncated packets, suspect timestamps

**Inputs:** File path (string)
**Outputs:** `CaptureMeta` + yields `RawPacket` objects (number, timestamp, data, dlt, captured_len, original_len)

**Dependencies:** `struct`, `gzip`, `io`, `statistics`, `datetime`

**Weaknesses:**
- Reads entire gzip into memory (decompression bomb risk)
- No file size limit before opening
- Suspect timestamp threshold is fixed at 1 year

**Verdict:** KEEP — dependency-free, well-tested, frame-accurate

---

### 2. Packet Parsing (Link/Network/Transport)

**File:** `engine/securemailscope/pcap/layers.py`

**What it does:**
- Strips link-layer headers (Ethernet, NULL/loopback, RAW, Linux SLL/SLL2, IPv4/IPv6 raw)
- Handles 802.1Q/QinQ VLAN tags (unlimited nesting)
- Parses IPv4/IPv6 + TCP headers
- Extracts TCP: src/dst IP:port, seq, ack, flags, payload
- Parses IPv4/IPv6 + UDP headers (for DNS policy module)
- IPv6 address formatting with RFC 5952 compression

**Inputs:** Raw packet data + DLT
**Outputs:** `TcpSegment` or `UdpDatagram` dataclasses

**Dependencies:** `struct`, internal `_ipv4_str`, `_ipv6_str`

**Weaknesses:**
- IPv6 extension header walking limited to 8 hops
- No IPv6 fragmentation handling
- No TCP options parsing

**Verdict:** KEEP — covers all needed link types

---

### 3. TCP Reconstruction

**File:** `engine/securemailscope/net/reassembly.py`

**What it does:**
- Groups TCP segments into bidirectional streams
- Reassembles client→server and server→client byte streams
- Handles out-of-order delivery, retransmission, overlap, sequence wraparound
- Tracks which frame carried each byte (for evidence citation)
- Records gaps in the reassembled stream (for coverage assessment)
- Detects SYN/FIN/RST, tracks stream lifecycle

**Inputs:** Iterator of `(RawPacket, TcpSegment)`
**Outputs:** `list[TcpStream]` with reassembled `Direction` objects

**Dependencies:** `bisect`, `math`

**Weaknesses:**
- Not IDS-grade (no OS-specific overlap resolution, no evasion defense)
- Maximum stream size capped at 64 MB
- No TCP window tracking or congestion analysis
- Overlap resolution is "first writer wins" (not RFC 793 specified)

**Verdict:** KEEP — appropriate for forensic reassembly of completed conversations

---

### 4. Protocol Classification

**File:** `engine/securemailscope/classify.py`

**What it does:**
- Identifies SMTP/IMAP/POP3 from cleartext dialogue patterns (banner, command keywords)
- Falls back to port numbers only when no payload evidence exists
- Classifies TLS mode: IMPLICIT / STARTTLS / CLEARTEXT / UNKNOWN
- Classifies role: SUBMISSION_ACCESS (587/465/143/993/110/995) or MTA_RELAY (25)
- Filters out non-email conversations sharing the capture

**Inputs:** `TcpStream`, TLS start offsets
**Outputs:** `Protocol`, `TlsMode`, `Role` enums

**Dependencies:** `re` patterns for banners and commands

**Weaknesses:**
- Port-based fallback could misclassify non-standard setups
- Some IMAP/POP3 servers use non-standard banners
- No support for LMTP, POP3S variants with custom banners

**Verdict:** KEEP — content-first approach is correct; fallback is conservative

---

### 5. SMTP Analysis

**File:** `engine/securemailscope/analyze/starttls.py`

**What it does:**
- Parses EHLO capability response (250-KEYWORD / 250 KEYWORD format)
- Extracts advertised STARTTLS capability
- Detects mangled capability tokens (equal-length substitution attack)
- Detects known strip variants (XXXXXXXX, STAR, TTLS, XXXX)
- Extracts cleartext AUTH credentials (PLAIN, LOGIN)
- Builds redacted command transcript

**Inputs:** Cleartext bytes (client/server), protocol type
**Outputs:** `StarttlsResult` (banner, capabilities, STARTTLS state, auth exposure)

**Dependencies:** `re`, `base64`, `hashlib`

**Weaknesses:**
- AUTH PLAIN with multi-line response parsing is simple
- No support for ETRN, VRFY, EXPN tracking
- No tracking of mail flow (MAIL FROM/RCPT TO/DATA counts)

**Verdict:** KEEP — covers the security-relevant aspects

---

### 6. IMAP Analysis

**File:** `engine/securemailscope/analyze/starttls.py`

**What it does:**
- Parses `* CAPABILITY` untagged responses
- Parses `[CAPABILITY]` response codes
- Detects STARTTLS in capability list
- Extracts LOGIN and AUTHENTICATE PLAIN credentials

**Inputs:** Cleartext bytes, protocol type
**Outputs:** `StarttlsResult`

**Dependencies:** `re`, `base64`, `hashlib`

**Weaknesses:**
- No IMAP command sequence tracking
- No SELECT/EXAMINE/FETCH tracking
- No IDLE command detection

**Verdict:** KEEP — sufficient for security analysis

---

### 7. POP3 Analysis

**File:** `engine/securemailscope/analyze/starttls.py`

**What it does:**
- Parses CAPA response (until lone `.`)
- Detects STLS capability
- Extracts USER/PASS/APOP credentials

**Inputs:** Cleartext bytes, protocol type
**Outputs:** `StarttlsResult`

**Dependencies:** `re`, `base64`, `hashlib`

**Weaknesses:**
- No TOP/UIDL/RETR tracking
- APOP detection is basic

**Verdict:** KEEP — sufficient for security analysis

---

### 8. STARTTLS Analysis

**File:** `engine/securemailscope/analyze/starttls.py`

**What it does:**
- Builds ordered dialogue (client/server lines with frame references)
- Detects STARTTLS offered / requested / accepted / refused
- Detects capability mangling (downgrade evidence)
- Detects cleartext authentication
- Redacts credential material in transcripts

**Inputs:** Protocol + dialogue lines + TLS started flag
**Outputs:** `StarttlsResult`

**Dependencies:** `re`, `base64`, `hashlib`

**Weaknesses:**
- Line budget per direction (600) may truncate long interactions
- No state machine modeling of the protocol flow

**Verdict:** KEEP — excellent forensic value; consider MODIFY for state machine

---

### 9. TLS Analysis

**File:** `engine/securemailscope/analyze/tls.py`

**What it does:**
- Finds TLS record start in reassembled stream (plausibility check for two chained records)
- Parses TLS record layer (content type, version, length)
- Parses handshake messages (defragmented across records)
- Parses ClientHello: cipher suites, extensions, supported groups, SNI, ALPN, signature algorithms
- Parses ServerHello: negotiated version, cipher suite, key_share group, ALPN
- Parses Certificate message (TLS 1.2 and 1.3 formats)
- Parses ServerKeyExchange (named curve / DHE prime bits)
- Parses CertificateStatus (OCSP staple)
- Computes JA3 fingerprint (MD5 of version,ciphers,extensions,groups,ec_point_formats)
- Computes JA4 fingerprint (FoxIO layout)
- Detects session resumption

**Inputs:** Reassembled client/server byte streams
**Outputs:** `HandshakeResult` (version, cipher, certs, ja3, ja4, sni, alpn, named_group, etc.)

**Dependencies:** `struct`, `hashlib`

**Weaknesses:**
- No TLS 1.3 middlebox compatibility mode detection
- No keylog file support
- No GREASE detection in JA4 extension count
- Limited to ClientHello/ServerHello/Cert/ServerKeyExchange parsing

**Verdict:** KEEP — comprehensive for passive analysis; some EXTEND possible

---

### 10. X.509 Analysis

**File:** `engine/securemailscope/analyze/certs.py`

**What it does:**
- Parses DER certificates using `cryptography` library
- Extracts subject, issuer, serial, validity, key info, signature, SAN
- Builds chain from presented certificates to trust store
- Validates signatures between chain links
- Checks hostname match (wildcard per RFC 6125)
- Checks certificate validity against capture clock (not wall clock)
- Parses stapled OCSP responses
- Detects self-signed certificates

**Inputs:** DER certificate bytes, capture time, server name, OCSP response
**Outputs:** `CertAnalysis` (chain, chain_valid, name_match, revocation, etc.)

**Dependencies:** `cryptography.x509`, `certifi` (or platform bundle)

**Weaknesses:**
- No RFC 5280 policy processing (name constraints, policy mappings)
- No CRL checking (only OCSP stapling)
- Trust store is loaded once (cached); no dynamic updates
- No Certificate Transparency (SCT) verification

**Verdict:** KEEP — covers the essential checks

---

### 11. Certificate Validation

**File:** `engine/securemailscope/analyze/certs.py`

**What it does:**
- Builds certification path from leaf to trusted root
- Verifies each signature in the chain
- Checks validity window against capture time
- Checks hostname against SAN/CN (wildcard support)

**Inputs:** Parsed certificates, hostname, capture time
**Outputs:** Chain validity boolean, error string

**Dependencies:** `cryptography`

**Weaknesses:**
- Maximum chain length of 10 (may miss deep chains)
- No handling of cross-signed certificates
- No Authority Key Identifier matching

**Verdict:** KEEP — correct for the vast majority of real-world chains

---

### 12. Cipher Analysis

**File:** `engine/securemailscope/analyze/ciphers.py`

**What it does:**
- Derives cipher properties from IANA suite name (kex, auth, bulk, bits, mode, MAC)
- Identifies forward secrecy, AEAD, export-grade, anonymous, broken, NULL ciphers
- Maps named groups to NIST-equivalent strength bits

**Inputs:** Cipher suite ID (int)
**Outputs:** `CipherProperties` dataclass

**Dependencies:** JSON cipher registry file

**Weaknesses:**
- Name-based parsing may fail for future suite formats
- No TLS 1.3 separate key exchange derivation (assumes TLS13 kex)

**Verdict:** KEEP — elegant approach; needs UPDATE for future TLS versions

---

### 13. Key Exchange Analysis

**Files:** `engine/securemailscope/analyze/tls.py` + `analyze/ciphers.py`

**What it does:**
- Extracts named group from ServerHello key_share (TLS 1.3) or ServerKeyExchange (TLS 1.2)
- Falls back to DHE prime bit length for plain DHE
- Maps group to NIST strength bits

**Inputs:** ServerHello body, ServerKeyExchange body
**Outputs:** Named group ID, DHE bits, kex strength bits

**Dependencies:** `struct`

**Weaknesses:**
- No FFDHE group validation against RFC 7919
- Post-quantum hybrid groups approximated

**Verdict:** KEEP — adequate for scoring

---

### 14. Forward Secrecy Analysis

**File:** `engine/securemailscope/analyze/ciphers.py`

**What it does:**
- Determines if cipher suite uses ephemeral key exchange (ECDHE/DHE/PSK variants)

**Inputs:** CipherProperties
**Outputs:** Boolean `forward_secrecy`

**Dependencies:** None

**Weaknesses:**
- None

**Verdict:** KEEP

---

### 15. DNS/MTA-STS/DANE/TLS-RPT Handling

**File:** `engine/securemailscope/analyze/dnspolicy.py`

**What it does:**
- Parses DNS messages from UDP datagrams in the capture
- Extracts MTA-STS policy publication (_mta-sts TXT records)
- Extracts TLS-RPT publication (_smtp._tls TXT records)
- Extracts DANE TLSA records
- Extracts MX, A, AAAA, CNAME records
- Resolves IPs to hostnames (reverse mapping) following CNAME chains

**Inputs:** UDP datagrams from capture
**Outputs:** `DnsPolicy` object with domain→record mappings

**Dependencies:** `struct`

**Weaknesses:**
- No DNSSEC validation (acknowledged in comments)
- MTA-STS policy body not fetched (cannot, passive)
- Limited DNS compression pointer depth (8)
- No handling of EDNS(0) or DNS COOKIE

**Verdict:** KEEP — excellent passive capability; DNSSEC limitation is inherent

---

### 16. Rule Engine

**File:** `engine/securemailscope/scoring/rules.py`

**What it does:**
- Loads rules from YAML (`kb/rules.yaml`)
- Evaluates structured conditions against session facts
- Supports all/any/not + field predicates (eq, ne, in, not_in, is_null, lt, lte, gt, gte)
- Generates findings with evidence references
- Applies role-based filtering (submission_access vs mta_relay)

**Inputs:** `Session` object
**Outputs:** `list[Finding]`

**Dependencies:** `yaml`

**Weaknesses:**
- Condition language is deliberately tiny — no arithmetic, no cross-field comparisons
- No rule composition or chaining
- Facts are pre-computed flat namespace — no nested evaluation

**Verdict:** KEEP — clean separation of rules from code; EXTEND condition language if needed

---

### 17. Grading Engine

**File:** `engine/securemailscope/scoring/grade.py`

**What it does:**
- Computes SSL Labs-style component scores (protocol 30%, key exchange 30%, cipher 40%)
- Applies caps from fired findings (lowest ceiling wins)
- Handles zero-in-any-category rule
- Adds A+ for clean modern sessions
- Reports both raw and capped grades

**Inputs:** `Session` + `list[Finding]`
**Outputs:** `Grade` dataclass

**Dependencies:** cipher properties

**Weaknesses:**
- Grade boundaries match SSL Labs, which some consider too generous
- No separate scoring for certificate trust (reported as `trusted` flag)

**Verdict:** KEEP — well-documented methodology

---

### 18. Server Aggregation

**File:** `engine/securemailscope/scoring/aggregate.py`

**What it does:**
- Groups sessions by server (host:port)
- Computes asset-level grade (best/worst protocol, worst kex/cipher)
- Detects version spread across sessions
- Computes exposure score (risk × reach)
- Orders remediation by severity × exposure

**Inputs:** `list[Session]`
**Outputs:** `list[Asset]`

**Dependencies:** grade module

**Weaknesses:**
- Session count affects exposure linearly — may over-count burst traffic
- No temporal weighting (recent sessions not prioritized)

**Verdict:** KEEP — provides actionable server-level view

---

### 19. ML Pipeline

**Files:** `engine/securemailscope/ml/train.py`, `predict.py`, `dataset.py`, `captured_dataset.py`

**What it does:**
- Trains RandomForest posture classifier on synthetic server configurations
- Uses GroupKFold CV by server profile (no data leakage)
- Trains IsolationForest for anomaly detection
- Generates SHAP explanations for predictions
- Classifies into: secure, weak, vulnerable, critical
- Per-capture anomaly detection (IsolationForest refit on capture's own sessions)
- Supports captured-dataset training (real traffic with lab ground truth)

**Inputs:** Synthetic config profiles or captured-dataset manifest
**Outputs:** `MLVerdict` (risk_class, risk_score, class_probabilities, anomaly, shap, explanation)

**Dependencies:** `scikit-learn`, `numpy`, `joblib`, `shap`

**Weaknesses:**
- Synthetic training data doesn't capture real-world correlations
- Feature vector is 26 features (18 core + 8 auxiliary)
- Missingness encoded as -1.0 — model must learn to handle this
- No online learning or incremental updates
- TLS 1.3 cert-masked sessions are the hardest case (7 features missing)

**Verdict:** KEEP — well-designed, but training data needs improvement. Candidate for MODIFY.

---

### 20. SHAP/Explainability

**File:** `engine/securemailscope/ml/predict.py`

**What it does:**
- Computes TreeSHAP values for RandomForest predictions
- Submits top-10 contributing features to verdict
- Generates plain-language explanation of the verdict

**Inputs:** Model bundle + feature row + predicted class index
**Outputs:** `list[ShapContribution]`

**Dependencies:** `shap`

**Weaknesses:**
- SHAP computation can be slow for large captures
- Fallback to empty list on SHAP errors

**Verdict:** KEEP — adds transparency

---

### 21. Report Generation

**Files:** `engine/securemailscope/report/json_report.py`, `html_report.py`

**What it does:**
- JSON report: dataclass → dict → JSON (the engine→backend contract)
- HTML report: Jinja2 template with inlined CSS, dark mode support
- PDF: browser print (no server-side renderer)
- Re-renderable from stored JSON (reproducibility)

**Inputs:** `Report` object or stored JSON dict
**Outputs:** JSON string or HTML string

**Dependencies:** `jinja2`, `json`

**Weaknesses:**
- HTML report is a single large file (no pagination for large captures)
- No interactive elements in HTML report

**Verdict:** KEEP — clean separation, reproducible

---

### 22. Backend API

**Files:** `backend/src/main/java/in/gov/ntro/sih/sms/`

**What it does:**
- REST API for uploads, investigations, jobs, reports
- Multipart file upload with streaming SHA-256 digest
- Job queue with state machine (PENDING→RUNNING→COMPLETED/FAILED/CANCELLED)
- Database persistence with Flyway migrations
- Engine subprocess invocation with timeout, cancellation, progress streaming
- Demo capture listing and analysis

**Dependencies:** Spring Boot 3.3.5, Spring Web, Spring Data JPA, Flyway, Thymeleaf, PostgreSQL, H2

**Weaknesses:**
- No authentication or authorization
- No rate limiting
- Single-threaded job processing (one analysis at a time)
- Engine timeout is configurable but not adaptive

**Verdict:** KEEP — functional and clean; EXTEND for production (auth, rate limiting)

---

### 23. Database

**Files:** `backend/src/main/resources/db/migration/V1__initial_schema.sql`, `V2__investigations_and_jobs.sql`

**What it does:**
- Stores captures, sessions, findings, assets, investigations, remediation statuses
- Uses identity columns and portable types (runs on PostgreSQL and H2)
- Indexed by sha256, status, grade, capture_id

**Dependencies:** Flyway, Hibernate

**Weaknesses:**
- Large TEXT columns (report_json, ml_explanation) can bloat the database
- No archival strategy for old captures
- No full-text search on findings

**Verdict:** KEEP — straightforward relational model

---

### 24. Frontend

**Files:** `frontend/src/`

**What it does:**
- Upload page (file drop + demo selection)
- Investigations list + capture history
- Analysis job progress tracking
- Dashboard with grade summary, findings list, asset rollup
- Session detail (TLS info, certificates, findings, transcript)
- Export page (JSON, HTML, print-to-PDF)
- Light/dark/system theme support

**Dependencies:** React 18, React Router 6, Vite 5, Tailwind CSS 3

**Weaknesses:**
- No dedicated pages for Security Controls, Evidence Explorer, Timeline, Remediation, Verification
- No investigation workspace flow
- Limited error handling for engine failures
- No pagination for large session lists

**Verdict:** MODIFY — good foundation but missing key pages and workflow

---

### 25. Docker Architecture

**Files:** `Dockerfile`, `docker-compose.yml`

**What it does:**
- Multi-stage build: frontend (Node) → backend (Maven) → runtime (JRE + Python)
- Single runtime image with everything baked in
- PostgreSQL service with healthcheck
- App container runs as non-root user
- No network access at runtime (provable with `--network none`)
- Named volumes for DB and uploads

**Dependencies:** Docker, Docker Compose

**Weaknesses:**
- Build requires internet access (npm, pip, maven)
- No orchestration for multiple replicas
- No secrets management (DB password in compose file)

**Verdict:** KEEP — well-designed for single-instance deployment

---

### 26. Test Architecture

**Files:** `engine/tests/`, `backend/src/test/`

**What it does:**
- Python tests: pytest with fixtures for demo captures and cached analysis
- Backend tests: Spring Boot integration tests with H2
- Golden tests for demo captures
- Grading arithmetic tests
- ML training and prediction tests
- CLI subprocess tests
- Capture reading tests (packet counts verified against tshark)

**Dependencies:** pytest, pytest-cov, Spring Boot Test

**Weaknesses:**
- Backend tests not runnable without Maven
- No performance tests
- No security-specific tests (malformed input handling)

**Verdict:** KEEP — good coverage for what exists; EXTEND for new features

---

## Key Architectural Decisions

| Decision | Rationale |
|----------|-----------|
| Engine as subprocess | Crash containment; language-appropriate tools for each layer |
| YAML rule base | Inspectable, auditable, no arbitrary code |
| Capture-clock certificate validation | Correct forensic behavior (old captures) |
| ML never decides a verdict | Deterministic rules are ground truth; ML is advisory |
| SHA-256 for credential correlation | Investigator can detect reuse without storing secrets |
| Engine communicates via JSON on stdout | Machine-clean output; stderr for diagnostics |
| No server-side PDF renderer | Native library dependencies cause deployment issues |
| PostgreSQL (Docker) or H2 (local) | Flexible deployment |
| Flyway for migrations | Version-controlled schema |

---

*End of ARCHITECTURE AUDIT*
