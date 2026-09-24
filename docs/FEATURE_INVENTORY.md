# FEATURE INVENTORY — SecureMailScope

**Date:** 2026-09-24
**Branch:** baseline-analysis

Format: `| Feature | Existing implementation | Quality | Keep/Modify/Replace | Notes |`

---

## PCAP/Network Layer

| Feature | Existing implementation | Quality | Keep/Modify/Replace | Notes |
|---|---|---|---|---|
| PCAP/PCAPNG parsing | `pcap/reader.py` — pure Python, both classic and pcapng | HIGH | KEEP | Dependency-free; verified against tshark packet counts |
| gzip support | Transparent decompression | MEDIUM | MODIFY | Reads entire file into memory; needs bomb protection |
| TCP reassembly | `net/reassembly.py` — handles out-of-order, retransmission, wraparound | HIGH | KEEP | Frame-accurate evidence tracking; 64 MB cap |
| Packet/frame references | Every finding cites frame numbers | HIGH | KEEP | Core forensic value |

---

## Protocol Detection

| Feature | Existing implementation | Quality | Keep/Modify/Replace | Notes |
|---|---|---|---|---|
| SMTP detection | Banner + command regex, port fallback | HIGH | KEEP | Content-first; excludes non-email on shared ports |
| IMAP detection | Banner + command regex, port fallback | HIGH | KEEP | Distinguishes IMAP from POP3 correctly |
| POP3 detection | Banner + command regex, port fallback | HIGH | KEEP | Handles +OK/-ERR banners |
| Email role classification | Port-based: submission/access vs relay | HIGH | KEEP | RFC 7435 aware (relay is opportunistic) |

---

## STARTTLS Analysis

| Feature | Existing implementation | Quality | Keep/Modify/Replace | Notes |
|---|---|---|---|---|
| STARTTLS detection | Capability parsing in `starttls.py` | HIGH | KEEP | Protocol-aware capability extraction |
| STARTTLS offered/requested/accepted | Full state tracking | HIGH | KEEP | Detects ignored STARTTLS |
| STARTTLS stripping detection | Equal-length substitution detection | HIGH | KEEP | Based on Durumeric et al. IMC 2015 |
| Plaintext authentication detection | AUTH LOGIN/PLAIN, IMAP LOGIN, POP3 USER/PASS | HIGH | KEEP | Redacts credentials; stores SHA-256 only |

---

## TLS Analysis

| Feature | Existing implementation | Quality | Keep/Modify/Replace | Notes |
|---|---|---|---|---|
| TLS handshake extraction | `analyze/tls.py` — record layer + handshake messages | HIGH | KEEP | Handles defragmentation, GREASE, TLS 1.3 |
| TLS version detection | ServerHello supported_version/legacy_version | HIGH | KEEP | SSL3.0 through TLS 1.3 |
| Cipher detection | IANA registry lookup + name parsing | HIGH | KEEP | Derives kex, bulk, mode, bits from name |
| Key exchange | Named group (TLS 1.3) / ServerKeyExchange (TLS 1.2) | HIGH | KEEP | Falls back to DHE prime bits |
| Forward secrecy | Cipher suite property | HIGH | KEEP | Ephemeral kex detection |
| JA3 fingerprint | MD5(version,ciphers,extensions,groups,ec_point_formats) | HIGH | KEEP | GREASE-excluded |
| JA4 fingerprint | FoxIO layout | HIGH | KEEP | Extension-order-resistant |
| SNI extraction | ClientHello server_name extension | HIGH | KEEP | IDNA decoding |
| ALPN extraction | ClientHello/ServerHello ALPN extension | MEDIUM | KEEP | Only first protocol |

---

## Certificate Analysis

| Feature | Existing implementation | Quality | Keep/Modify/Replace | Notes |
|---|---|---|---|---|
| Certificate parsing | `cryptography.x509` | HIGH | KEEP | DER parsing, all fields |
| Certificate chain validation | Path building + signature verification | HIGH | KEEP | To trust store (certifi/platform) |
| Hostname validation | RFC 6125 wildcard matching | HIGH | KEEP | SAN + CN fallback |
| Certificate expiry | Capture-clock validation | HIGH | KEEP | Key forensic feature |
| OCSP | Stapled response parsing only | MEDIUM | KEEP | Offline limitation acknowledged |
| Self-signed detection | Subject/issuer match + self-signature verify | HIGH | KEEP | |
| Weak signature detection | SHA-1/MD5/SHA-256 identification | HIGH | KEEP | |
| Key strength | RSA/EC/DSA key bits | HIGH | KEEP | |

---

## DNS/Policy Analysis

| Feature | Existing implementation | Quality | Keep/Modify/Replace | Notes |
|---|---|---|---|---|
| MTA-STS handling | TXT record detection in capture DNS | HIGH | KEEP | Passive limitation acknowledged |
| DANE/TLSA handling | TLSA record extraction | HIGH | KEEP | No DNSSEC validation |
| TLS-RPT handling | TXT record detection | HIGH | KEEP | |
| MX resolution | From capture DNS | MEDIUM | KEEP | Reverse-maps server IPs to hostnames |
| CNAME chain resolution | Multi-hop CNAME following | MEDIUM | KEEP | |

---

## Rule Engine

| Feature | Existing implementation | Quality | Keep/Modify/Replace | Notes |
|---|---|---|---|---|
| Weak/deprecated crypto rules | ~30 YAML rules | HIGH | KEEP | Rule IDs, RFC references, caps |
| Plaintext authentication | SMS-AUTH-001 | HIGH | KEEP | |
| STARTTLS stripping | SMS-STRIP-001/002/003/004 | HIGH | KEEP | |
| Policy violations | SMS-POL-001/002 (MTA-STS/DANE) | HIGH | KEEP | |
| Visibility/coverage | SMS-VIS-001/002 | HIGH | KEEP | |
| Positive findings | SMS-OK-001 | HIGH | KEEP | |

---

## Grading & Scoring

| Feature | Existing implementation | Quality | Keep/Modify/Replace | Notes |
|---|---|---|---|---|
| Risk scoring | SSL Labs-style weighted average | HIGH | KEEP | Protocol 30%, KEX 30%, Cipher 40% |
| A-F grading | Band-based with caps | HIGH | KEEP | Caps override average |
| A+ grade | Clean modern TLS 1.2/1.3 | HIGH | KEEP | Forward secrecy + AEAD + recommended |
| Grade capping | Per-rule cap ceiling | HIGH | KEEP | Lowest ceiling wins |
| Server aggregation | Asset rollup by server:port | HIGH | KEEP | Exposure-based prioritization |

---

## ML/AI

| Feature | Existing implementation | Quality | Keep/Modify/Replace | Notes |
|---|---|---|---|---|
| Anomaly detection | IsolationForest (per-capture) | MEDIUM | KEEP | Requires 8+ sessions |
| SHAP explainability | TreeSHAP on RandomForest | MEDIUM | KEEP | Top-10 feature contributions |
| Posture classification | RandomForest (secure/weak/vulnerable/critical) | MEDIUM | KEEP | Synthetic training data |
| Feature extraction | 26-dimension feature vector | MEDIUM | KEEP | Missingness encoded as -1 |
| Plain-language explanations | Template-based narrative | LOW | MODIFY | Could be richer |

---

## History/Comparison

| Feature | Existing implementation | Quality | Keep/Modify/Replace | Notes |
|---|---|---|---|---|
| Cross-capture comparison | `history.py` — change detection | MEDIUM | MODIFY | Needs more structured drift analysis |
| Server matching | Protocol+hostname+IP+port | HIGH | KEEP | Conservative matching |
| Remediation tracking | DB status updates | MEDIUM | MODIFY | No verification of fixes |

---

## Privacy/Security

| Feature | Existing implementation | Quality | Keep/Modify/Replace | Notes |
|---|---|---|---|---|
| Credential masking | SHA-256 hashing, redacted transcripts | HIGH | KEEP | Passwords never stored |
| Local/offline processing | No runtime network access | HIGH | KEEP | Docker `--network none` demonstrable |
| Decompression bomb | Not handled | NONE | ADD | gzip reads entire file |
| Oversize file handling | Backend limit, engine RLIMIT_AS (Linux only) | MEDIUM | MODIFY | Needs engine-side limit |
| Upload validation | Filename sanitization, demo dir confinement | HIGH | KEEP | |

---

## Dashboard/UI

| Feature | Existing implementation | Quality | Keep/Modify/Replace | Notes |
|---|---|---|---|---|
| Dashboard | Overview, findings, assets | MEDIUM | MODIFY | Good start, missing controls/timeline |
| Upload | File drop, demo selection | HIGH | KEEP | |
| Investigation workflow | Create, list, compare | MEDIUM | MODIFY | Missing workspace flow |
| JSON report | Full engine JSON | HIGH | KEEP | |
| HTML report | Jinja2 template, dark mode | HIGH | KEEP | |
| PDF workflow | Browser print | HIGH | KEEP | No server-side dependency |

---

## Explicitly Missing Features (Phase 5+)

These are NOT in the baseline and must be built:

| Feature | Status |
|---|---|
| Email Security State Machine | NOT BUILT |
| Evidence Graph (structured relationships) | NOT BUILT |
| OBSERVED/INFERRED/NOT_OBSERVABLE distinction | PARTIAL (Confidence enum exists but limited) |
| Attack vs Misconfiguration Reasoning | NOT BUILT |
| Security Control Model | NOT BUILT |
| Cross-Session Correlation (downgrade patterns) | NOT BUILT |
| Configuration Drift (formal before/after) | NOT BUILT |
| Remediation Verification | NOT BUILT |
| Capture Completeness Assessment | PARTIAL (per-session coverage only) |
| Explainable Risk Model | PARTIAL (SHAP exists, no formal model) |
| Investigation Timeline | NOT BUILT |
| Investigation Workspace | NOT BUILT |
| Privacy Mode UI | NOT BUILT |
| Standards Knowledge Base (structured) | PARTIAL (YAML rules but not full KB) |

---

## Novelty Assessment

Per Phase 4 requirements, the following are NOT novel and should not be claimed as such:

| Capability | Already provided by |
|---|---|
| Reading PCAP | Wireshark, tcpdump, tshark, Zeek, Xplico |
| TCP reconstruction | Wireshark, Zeek, Xplico |
| SMTP/IMAP/POP3 detection | Wireshark, Zeek |
| TLS parsing | Wireshark, Zeek, ssldump |
| Certificate parsing | OpenSSL, Wireshark, Zeek |
| Cipher detection | Wireshark, testssl.sh, SSL Labs |
| STARTTLS detection | Wireshark (with filters) |
| Dashboard | Grafana, Kibana |
| JSON/PDF reports | Many tools |
| AI anomaly detection | Akyuz, Ullah et al. (2021+) |
| Security scoring | SSL Labs, Mozilla Observatory |

**Our novelty** (to be built): Email-specific security state machine, evidence graph, attack-vs-misconfiguration reasoning, security control model, remediation verification, configuration drift, capture completeness assessment — layered on top of the baseline protocol analysis.

---

*End of FEATURE INVENTORY*
