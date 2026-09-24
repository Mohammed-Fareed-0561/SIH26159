# FORENSIC EVIDENCE MODEL — SecureMailScope

**Date:** 2026-09-24
**Branch:** phase-1-forensic-foundation
**Phase:** 1

---

## 1. Evidence Entities

### 1.1 Observation

The fundamental unit of forensic evidence is an **Observation** — a single
structured statement about what was seen in the capture:

```
Observation
├── observation_id: unique identifier
├── session_id: which email session
├── capture_id: which capture file
├── protocol / observation_type: what kind of observation
├── value: the observed value (never the full packet payload)
├── status: OBSERVED | INFERRED | NOT_OBSERVABLE | CONTRADICTED | INSUFFICIENT_CAPTURE
├── confidence: HIGH | MEDIUM | LOW | UNKNOWN
├── packet: reference to frame/timestamp/IPs/ports (optional)
├── extracted_field: which field this represents
└── details: additional structured data
```

### 1.2 Observation Types

**Protocol observations:**
- SMTP_BANNER, SMTP_EHLO_RESPONSE, SMTP_COMMAND, SMTP_REPLY
- IMAP_BANNER, IMAP_COMMAND, IMAP_RESPONSE
- POP_BANNER, POP_COMMAND, POP_RESPONSE
- STARTTLS_CAPABILITY, STARTTLS_REQUEST, STARTTLS_ACCEPTED, STARTTLS_REFUSED
- AUTH_EXCHANGE, CREDENTIALS_EXPOSED
- TCP_CONNECTION, TCP_DISCONNECTION

**TLS observations:**
- CLIENT_HELLO, SERVER_HELLO, CERTIFICATE, SERVER_KEY_EXCHANGE
- SERVER_HELLO_DONE, FINISHED, ALERT, CHANGE_CIPHER_SPEC
- APPLICATION_DATA, HANDSHAKE_COMPLETE, HANDSHAKE_INCOMPLETE
- SESSION_RESUMED

**Certificate observations:**
- LEAF_PRESENTED, CHAIN_PRESENTED, CHAIN_VALID, CHAIN_INVALID
- NAME_MATCH, NAME_MISMATCH, EXPIRED_AT_CAPTURE, NOT_YET_VALID_AT_CAPTURE
- SELF_SIGNED, WEAK_SIGNATURE, OCSP_STAPLE, ENCRYPTED_TLS13, MISSING

**DNS observations:**
- MTA_STS_PUBLISHED, TLSA_PRESENT, TLS_RPT_PUBLISHED
- MX_RECORD, A_RECORD, AAAA_RECORD, REVERSE_MAPPED

---

## 2. Evidence Relationships

```
Capture
└── EvidenceBundle (per session)
    ├── ProtocolObservation[]
    ├── TLSObservation[]
    ├── CertificateObservation[]
    └── DNSObservation[]
```

Each session has exactly one `EvidenceBundle`. All observations for that
session are collected there.

---

## 3. Observation Statuses

### OBSERVED
Directly supported by captured evidence.

Example: Server advertised STARTTLS.

### INFERRED
Derived from multiple observed facts.

Example: Authentication occurred before transport encryption was established
(inferred from STARTTLS offered + AUTH command + no TLS handshake).

### NOT_OBSERVABLE
The capture does not contain enough information to determine the fact.

Example: Whether the server would have supported TLS 1.3 cannot be
established from a capture that shows TLS 1.2.

### CONTRADICTED
Available evidence conflicts with the expected condition.

Example: Certificate not valid at the capture time but the server continued
to present it.

### INSUFFICIENT_CAPTURE
The relevant evidence may exist in principle but the capture is incomplete.

Example: TLS handshake started but the Certificate message was not captured.

---

## 4. Capture Completeness

Before making strong conclusions, assess the capture quality:

```
CaptureCompleteness
├── status: GOOD | LIMITED | INSUFFICIENT
├── score: 0-100
├── packet_count
├── flow_count
├── tcp: TCPFlowStats
├── email: EmailSessionStats
├── tls: TLSSessionStats
├── dns_queries_seen
├── truncated_packets
├── missing_evidence: MissingEvidence[]
└── limitations: Limitation[]
```

Each `MissingEvidence` explains:
- WHAT IS MISSING
- WHY IT MATTERS
- WHICH FINDINGS ARE AFFECTED

Each `Limitation` describes a capture property that constrains interpretation.

### Scoring

| Condition | Penalty |
|-----------|---------|
| Truncated packets | -2 each (max -20) |
| Suspect timestamps | -1 each (max -10) |
| TCP reassembly gaps | -5 each (max -20) |
| Incomplete handshakes | -5 each (max -15) |
| Incomplete conversations | -3 each (max -15) |

Status thresholds:
- GOOD: score >= 80
- LIMITED: 50 <= score < 80
- INSUFFICIENT: score < 50

---

## 5. Confidence

Qualitative confidence in a finding or observation:

| Level | Meaning |
|-------|---------|
| HIGH | Multiple independent observations support the conclusion |
| MEDIUM | Some evidence supports the conclusion but gaps remain |
| LOW | The conclusion is based on weak or indirect evidence |
| UNKNOWN | Insufficient evidence to assess confidence |

---

## 6. Limitations

Limitations are NOT the same as missing evidence. They are properties of the
analysis context that affect interpretation:

- TLS 1.3 encrypts the Certificate message (RFC 8446) — certificate checks
  are not applicable for TLS 1.3 sessions observed passively.
- Offline analysis cannot query OCSP responders — only stapled responses
  can be evaluated.
- DNS policy records observed in cleartext DNS are evidence of intent, not
  proof of authenticity (no DNSSEC validation).
- A finding absent from a later capture does not automatically mean the
  issue was resolved.

---

## 7. Finding-to-Evidence Relationship

Every finding should eventually reference structured evidence. The
`Finding` dataclass already has an `evidence` field (with frame numbers
and excerpts). In Phase 1, this is preserved for backward compatibility.
Future phases will extend findings to include:

```json
{
  "finding_id": "SMS-AUTH-001",
  "rule_id": "SMS-AUTH-001",
  "severity": "critical",
  "title": "Authentication credentials transmitted in cleartext",
  "status": "INFERRED",
  "confidence": "HIGH",
  "evidence_refs": [
    {
      "evidence_id": "obs1",
      "observation_type": "starttls_capability",
      "status": "OBSERVED",
      "excerpt": "250-STARTTLS"
    },
    {
      "evidence_id": "obs2",
      "observation_type": "auth_exchange",
      "status": "OBSERVED",
      "excerpt": "AUTH LOGIN"
    }
  ],
  "limitations": [
    "Capture cannot establish whether an intermediary modified the connection."
  ]
}
```

---

## 8. Privacy Considerations

### 8.1 What we DO store
- Observation metadata (type, field, status)
- Frame numbers and timestamps
- IP addresses and ports (needed for forensics)
- Redacted transcripts (credentials masked)
- SHA-256 hashes of secrets (for correlation)

### 8.2 What we DO NOT store
- Raw packet payloads
- Email message bodies
- Passwords or authentication secrets
- Attachment contents

### 8.3 Structured errors
Analysis errors never expose:
- Filesystem paths
- Internal configuration details
- Raw exception messages

---

## 9. Security Hardening

### 9.1 gzip decompression
- Bounded decompression: `MAX_DECOMPRESSED_SIZE_MB` (default: 4096 MB)
- Streaming: decompresses in 64 KB chunks
- Aborts immediately when limit is exceeded
- Returns structured `AnalysisError` instead of crashing

### 9.2 Engine-side file limits
- `MAX_CAPTURE_SIZE_MB` (default: 2048 MB) — raw file size
- `MAX_DECOMPRESSED_SIZE_MB` (default: 4096 MB) — decompressed size
- `MAX_PACKET_COUNT` (default: 5,000,000) — per capture
- All limits are configurable via environment variables

### 9.3 Malformed PCAP handling
- Truncated packets: handled gracefully, reader yields what it can
- Invalid magic: raises `CaptureFormatError`
- Truncated headers: raises `CaptureFormatError`
- Never crashes the analysis process — errors propagate as structured types

### 9.4 Log audit
- Sensitive values (passwords, secrets) are never logged
- Transcripts are redacted before storage
- Analysis errors contain only safe, structured information

---

*End of FORENSIC EVIDENCE MODEL*
