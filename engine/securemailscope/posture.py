"""
Posture snapshot and drift detection for Phase 4.

A **PostureSnapshot** captures the security-relevant properties of an asset
(server identity) at a point in time (a capture or a set of sessions).

A **PostureChange** compares two snapshots and classifies the difference:

- IMPROVEMENT: security posture got better
- DEGRADATION: security posture got worse
- CONFIGURATION_CHANGE: security-relevant change that is neither
  clearly improvement nor degradation (e.g. cert rotated with same properties)
- NO_MEANINGFUL_CHANGE: differences are below the significance threshold
- INCONCLUSIVE: changes detected but evidence is insufficient to classify

Every change retains evidence references (session IDs, frame numbers, capture IDs).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional

from .evidence import Confidence
from .models import Session, TlsMode, CertVisibility


class DriftSeverity(str, Enum):
    """Severity of a posture change."""
    IMPROVEMENT = "improvement"
    DEGRADATION = "degradation"
    CONFIGURATION_CHANGE = "configuration_change"
    NO_MEANINGFUL_CHANGE = "no_meaningful_change"
    INCONCLUSIVE = "inconclusive"


class AssetIdentityConfidence(str, Enum):
    """How confident we are that a set of sessions belong to the same asset."""
    CERTAIN = "certain"        # same server_name (SNI/MX) + same port
    HIGH = "high"              # same IP:port + same protocol
    MEDIUM = "medium"          # same IP:port, protocol inferred
    LOW = "low"                # IP:port inferred from limited data
    UNCERTAIN = "uncertain"    # insufficient evidence for identity


@dataclass
class AssetIdentity:
    """Identity of an email asset, with confidence."""
    key: str                    # e.g. "mail.example:587" or "10.0.0.2:587"
    host: Optional[str] = None  # server_name (SNI/MX) if known
    ip: Optional[str] = None    # server IP if known
    port: Optional[int] = None
    protocol: Optional[str] = None  # "smtp" | "imap" | "pop3"
    confidence: AssetIdentityConfidence = AssetIdentityConfidence.UNCERTAIN
    evidence: list[str] = field(default_factory=list)  # session_ids that informed this identity


@dataclass
class CaptureRef:
    """Reference to a capture that contained a snapshot."""
    capture_id: str
    capture_time: Optional[datetime] = None
    capture_time_suspect: bool = False
    filename: Optional[str] = None


@dataclass
class PostureSnapshot:
    """
    Security posture of an asset at a point in time.

    Contains observable security properties aggregated from one or more
    sessions belonging to the same asset.  Does NOT contain inferred
    conclusions — only what was directly observed.
    """
    asset_key: str
    asset_identity: AssetIdentity
    capture: CaptureRef

    # TLS properties
    tls_versions: dict[str, int] = field(default_factory=dict)  # version -> count
    cipher_suites: dict[str, int] = field(default_factory=dict)
    kex_methods: dict[str, int] = field(default_factory=dict)
    forward_secrecy: Optional[bool] = None  # set if consistent across sessions
    tls_modes: dict[str, int] = field(default_factory=dict)  # cleartext/starttls/implicit -> count

    # Certificate properties
    certificates: dict[str, int] = field(default_factory=dict)  # fingerprint -> count
    cert_chain_valid: Optional[bool] = None
    name_match: Optional[bool] = None
    cert_expired_count: int = 0
    cert_not_yet_valid_count: int = 0
    cert_self_signed_count: int = 0
    cert_visibility: dict[str, int] = field(default_factory=dict)  # visibility -> count

    # STARTTLS / security protocol behavior
    starttls_offered_count: int = 0
    starttls_requested_count: int = 0
    starttls_accepted_count: int = 0
    starttls_not_offered_count: int = 0
    stls_offered_count: int = 0  # POP3 STLS
    capability_mangled_count: int = 0
    auth_before_tls_count: int = 0
    credentials_exposed_count: int = 0

    # Findings and controls
    finding_rule_ids: list[str] = field(default_factory=list)  # unique sorted
    finding_severities: dict[str, str] = field(default_factory=dict)  # rule_id -> severity
    security_controls: dict[str, str] = field(default_factory=dict)  # control_id -> worst status

    # Completeness and confidence
    completeness: str = "complete"  # complete | incomplete | error
    completeness_score: int = 100
    confidence: Confidence = Confidence.HIGH
    limitations: list[str] = field(default_factory=list)

    # Evidence references
    session_ids: list[str] = field(default_factory=list)
    frame_ranges: list[tuple[int, int]] = field(default_factory=list)  # (first, last) per session

    # Raw observations for comparison
    observation_ids: list[str] = field(default_factory=list)


@dataclass
class PostureChange:
    """A single detected change between two posture snapshots."""
    property_name: str              # e.g. "tls_versions", "certificates"
    description: str                # human-readable description
    before_value: Any               # what was observed before
    after_value: Any                # what is observed after
    severity: DriftSeverity
    confidence: Confidence
    affected_session_ids: list[str] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)  # observation_ids
    capture_before: Optional[str] = None
    capture_after: Optional[str] = None
    frame_before: Optional[int] = None
    frame_after: Optional[int] = None
    affected_control: Optional[str] = None  # control_id if a control is affected
    affected_finding: Optional[str] = None  # rule_id if a finding changed
    limitations: list[str] = field(default_factory=list)


@dataclass
class DriftResult:
    """Complete drift analysis between two posture snapshots."""
    asset_key: str
    snapshot_before: PostureSnapshot
    snapshot_after: PostureSnapshot
    changes: list[PostureChange] = field(default_factory=list)
    overall_severity: DriftSeverity = DriftSeverity.NO_MEANINGFUL_CHANGE
    confidence: Confidence = Confidence.HIGH
    summary: str = ""
    evidence_refs: list[str] = field(default_factory=list)


@dataclass
class AssetPostureHistory:
    """History of posture snapshots for a single asset."""
    asset_key: str
    asset_identity: AssetIdentity
    snapshots: list[PostureSnapshot] = field(default_factory=list)
    drift_results: list[DriftResult] = field(default_factory=list)
    temporal_analysis: Optional[Any] = None  # TemporalAnalysis
    confidence: Confidence = Confidence.HIGH
    limitations: list[str] = field(default_factory=list)


def build_posture_snapshot(
    sessions: list[Session],
    capture_id: str = "unknown",
    capture_time: Optional[datetime] = None,
) -> PostureSnapshot:
    """
    Build a PostureSnapshot from a list of sessions for one asset.

    Sessions are assumed to already be grouped by asset (by the caller).
    """
    if not sessions:
        raise ValueError("Cannot build posture snapshot from empty session list")

    # Determine asset identity
    first = sessions[0]
    host = first.server_name
    ip = first.server.ip if hasattr(first, 'server') else None
    port = first.server.port if hasattr(first, 'server') else None
    protocol = first.protocol.value if hasattr(first, 'protocol') else None

    # Asset identity confidence
    if host and port:
        identity_confidence = AssetIdentityConfidence.CERTAIN
    elif ip and port and protocol:
        identity_confidence = AssetIdentityConfidence.HIGH
    elif ip and port:
        identity_confidence = AssetIdentityConfidence.MEDIUM
    else:
        identity_confidence = AssetIdentityConfidence.LOW

    asset_key = first.asset_key

    identity = AssetIdentity(
        key=asset_key,
        host=host,
        ip=ip,
        port=port,
        protocol=protocol,
        confidence=identity_confidence,
        evidence=[s.session_id for s in sessions],
    )

    snapshot = PostureSnapshot(
        asset_key=asset_key,
        asset_identity=identity,
        capture=CaptureRef(
            capture_id=capture_id,
            capture_time=capture_time or first.capture_time,
            capture_time_suspect=getattr(first, 'capture_time_suspect', False),
        ),
    )

    # Aggregate from sessions
    for s in sessions:
        snapshot.session_ids.append(s.session_id)
        snapshot.frame_ranges.append((s.first_frame, s.last_frame))

        # TLS versions
        if s.tls_version:
            snapshot.tls_versions[s.tls_version] = snapshot.tls_versions.get(s.tls_version, 0) + 1

        # TLS modes
        mode = s.tls_mode.value if s.tls_mode else "unknown"
        snapshot.tls_modes[mode] = snapshot.tls_modes.get(mode, 0) + 1

        # Cipher suites
        if s.cipher_suite:
            snapshot.cipher_suites[s.cipher_suite] = snapshot.cipher_suites.get(s.cipher_suite, 0) + 1

        # KEX
        if s.kex:
            snapshot.kex_methods[s.kex] = snapshot.kex_methods.get(s.kex, 0) + 1

        # Forward secrecy (track consistency)
        if s.forward_secrecy is not None:
            if snapshot.forward_secrecy is None:
                snapshot.forward_secrecy = s.forward_secrecy
            elif snapshot.forward_secrecy != s.forward_secrecy:
                snapshot.forward_secrecy = None  # inconsistent

        # Certificates
        if s.chain:
            for cert in s.chain:
                if cert.sha256_fingerprint:
                    snapshot.certificates[cert.sha256_fingerprint] = \
                        snapshot.certificates.get(cert.sha256_fingerprint, 0) + 1
            if s.chain_valid is False:
                snapshot.cert_chain_valid = False
            elif s.chain_valid is True and snapshot.cert_chain_valid is None:
                snapshot.cert_chain_valid = True
            if s.name_match is False:
                snapshot.name_match = False
            elif s.name_match is True and snapshot.name_match is None:
                snapshot.name_match = True
            for cert in s.chain:
                if cert.expired_at_capture:
                    snapshot.cert_expired_count += 1
                if cert.not_yet_valid_at_capture:
                    snapshot.cert_not_yet_valid_count += 1
                if cert.self_signed:
                    snapshot.cert_self_signed_count += 1

        # Cert visibility
        vis = s.cert_visibility.value if s.cert_visibility else "absent"
        snapshot.cert_visibility[vis] = snapshot.cert_visibility.get(vis, 0) + 1

        # STARTTLS / STLS
        if s.starttls_offered:
            snapshot.starttls_offered_count += 1
        else:
            snapshot.starttls_not_offered_count += 1
        if s.starttls_requested:
            snapshot.starttls_requested_count += 1
        if s.starttls_accepted:
            snapshot.starttls_accepted_count += 1
        if s.cleartext_auth is not None:
            snapshot.auth_before_tls_count += 1
            snapshot.credentials_exposed_count += 1

        # Capability mangling
        if getattr(s, 'capability_mangled', False) or getattr(s, 'mangled_token', None):
            snapshot.capability_mangled_count += 1

        # Findings
        for f in s.findings:
            if f.rule_id not in snapshot.finding_rule_ids:
                snapshot.finding_rule_ids.append(f.rule_id)
            # Store severity from the Finding object
            sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
            snapshot.finding_severities[f.rule_id] = sev

        # Security controls (from Phase 3)
        for c in getattr(s, 'security_controls', []):
            ctrl_key = c.control_id.value if hasattr(c.control_id, 'value') else str(c.control_id)
            status_val = c.status.value if hasattr(c.status, 'value') else str(c.status)
            snapshot.security_controls[ctrl_key] = status_val

        # Capture completeness
        if s.tls_mode == TlsMode.CLEARTEXT and not s.starttls_accepted:
            pass  # tracked in tls_modes

    snapshot.finding_rule_ids.sort()

    return snapshot


def compare_snapshots(
    before: PostureSnapshot,
    after: PostureSnapshot,
) -> DriftResult:
    """
    Compare two posture snapshots and produce a DriftResult.

    Only security-relevant differences are reported.  Each change is classified
    with a DriftSeverity and carries evidence references.
    """
    changes: list[PostureChange] = []

    # --- TLS versions ---
    before_versions = set(before.tls_versions.keys())
    after_versions = set(after.tls_versions.keys())
    if before_versions != after_versions:
        added = after_versions - before_versions
        removed = before_versions - after_versions
        severity = _classify_tls_change(added, removed)
        changes.append(PostureChange(
            property_name="tls_versions",
            description=f"TLS versions changed: added {sorted(added)}, removed {sorted(removed)}",
            before_value=sorted(before_versions),
            after_value=sorted(after_versions),
            severity=severity,
            confidence=Confidence.HIGH if added or removed else Confidence.MEDIUM,
            affected_session_ids=after.session_ids,
            capture_before=before.capture.capture_id,
            capture_after=after.capture.capture_id,
            affected_control="TLS_VERSION_SECURITY",
            limitations=[],
        ))

    # --- Cipher suites ---
    before_ciphers = set(before.cipher_suites.keys())
    after_ciphers = set(after.cipher_suites.keys())
    if before_ciphers != after_ciphers:
        added = after_ciphers - before_ciphers
        removed = before_ciphers - after_ciphers
        severity = _classify_cipher_change(added, removed)
        changes.append(PostureChange(
            property_name="cipher_suites",
            description=f"Cipher suites changed: added {sorted(added)}, removed {sorted(removed)}",
            before_value=sorted(before_ciphers),
            after_value=sorted(after_ciphers),
            severity=severity,
            confidence=Confidence.HIGH,
            affected_session_ids=after.session_ids,
            capture_before=before.capture.capture_id,
            capture_after=after.capture.capture_id,
            affected_control="CIPHER_SECURITY",
            limitations=[],
        ))

    # --- Certificates ---
    before_certs = set(before.certificates.keys())
    after_certs = set(after.certificates.keys())
    if before_certs != after_certs:
        added = after_certs - before_certs
        removed = before_certs - after_certs
        changes.append(PostureChange(
            property_name="certificates",
            description=f"Certificates changed: added {len(added)}, removed {len(removed)}",
            before_value=sorted(before_certs),
            after_value=sorted(after_certs),
            severity=DriftSeverity.CONFIGURATION_CHANGE,
            confidence=Confidence.HIGH,
            affected_session_ids=after.session_ids,
            capture_before=before.capture.capture_id,
            capture_after=after.capture.capture_id,
            affected_control="CERTIFICATE_SECURITY",
            limitations=["Certificate change does not necessarily indicate degradation"],
        ))

    # --- Certificate validity ---
    if before.cert_chain_valid != after.cert_chain_valid:
        severity = DriftSeverity.DEGRADATION if after.cert_chain_valid is False else DriftSeverity.IMPROVEMENT
        changes.append(PostureChange(
            property_name="cert_chain_valid",
            description=f"Certificate chain validity changed: {before.cert_chain_valid} → {after.cert_chain_valid}",
            before_value=before.cert_chain_valid,
            after_value=after.cert_chain_valid,
            severity=severity,
            confidence=Confidence.HIGH,
            affected_session_ids=after.session_ids,
            affected_control="CERTIFICATE_SECURITY",
            limitations=[],
        ))

    # --- Cert expiration ---
    if before.cert_expired_count != after.cert_expired_count:
        severity = (DriftSeverity.DEGRADATION if after.cert_expired_count > before.cert_expired_count
                    else DriftSeverity.IMPROVEMENT)
        changes.append(PostureChange(
            property_name="cert_expired_count",
            description=f"Expired certificate count changed: {before.cert_expired_count} → {after.cert_expired_count}",
            before_value=before.cert_expired_count,
            after_value=after.cert_expired_count,
            severity=severity,
            confidence=Confidence.HIGH,
            affected_session_ids=after.session_ids,
            affected_control="CERTIFICATE_SECURITY",
        ))

    # --- STARTTLS behavior ---
    if before.starttls_offered_count != after.starttls_offered_count:
        severity = (DriftSeverity.DEGRADATION if after.starttls_offered_count < before.starttls_offered_count
                    else DriftSeverity.IMPROVEMENT)
        changes.append(PostureChange(
            property_name="starttls_offered_count",
            description=f"STARTTLS offered count changed: {before.starttls_offered_count} → {after.starttls_offered_count}",
            before_value=before.starttls_offered_count,
            after_value=after.starttls_offered_count,
            severity=severity,
            confidence=Confidence.HIGH,
            affected_session_ids=after.session_ids,
            affected_control="STARTTLS_SECURITY",
        ))

    # STARTTLS not offered appeared
    if before.starttls_not_offered_count == 0 and after.starttls_not_offered_count > 0:
        changes.append(PostureChange(
            property_name="starttls_not_offered_count",
            description=f"Server stopped advertising STARTTLS: {before.starttls_not_offered_count} → {after.starttls_not_offered_count}",
            before_value=before.starttls_not_offered_count,
            after_value=after.starttls_not_offered_count,
            severity=DriftSeverity.DEGRADATION,
            confidence=Confidence.HIGH,
            affected_session_ids=after.session_ids,
            affected_control="STARTTLS_SECURITY",
        ))

    # STARTTLS offered but not requested (stripping-like)
    before_stripping_like = (before.starttls_offered_count - before.starttls_requested_count
                             if before.starttls_offered_count else 0)
    after_stripping_like = (after.starttls_offered_count - after.starttls_requested_count
                            if after.starttls_offered_count else 0)
    if before_stripping_like != after_stripping_like:
        changes.append(PostureChange(
            property_name="starttls_offered_not_used",
            description=f"STARTTLS offered-but-not-used count changed: {before_stripping_like} → {after_stripping_like}",
            before_value=before_stripping_like,
            after_value=after_stripping_like,
            severity=(DriftSeverity.DEGRADATION if after_stripping_like > before_stripping_like
                      else DriftSeverity.IMPROVEMENT),
            confidence=Confidence.MEDIUM,
            affected_session_ids=after.session_ids,
            affected_control="STARTTLS_SECURITY",
            limitations=["Could be client misconfiguration, not attack"],
        ))

    # --- AUTH before TLS ---
    if before.auth_before_tls_count != after.auth_before_tls_count:
        severity = (DriftSeverity.DEGRADATION if after.auth_before_tls_count > before.auth_before_tls_count
                    else DriftSeverity.IMPROVEMENT)
        changes.append(PostureChange(
            property_name="auth_before_tls_count",
            description=f"AUTH-before-TLS count changed: {before.auth_before_tls_count} → {after.auth_before_tls_count}",
            before_value=before.auth_before_tls_count,
            after_value=after.auth_before_tls_count,
            severity=severity,
            confidence=Confidence.HIGH,
            affected_session_ids=after.session_ids,
            affected_control="AUTHENTICATION_ORDERING",
        ))

    # --- TLS mode ---
    before_cleartext = before.tls_modes.get("cleartext", 0)
    after_cleartext = after.tls_modes.get("cleartext", 0)
    if before_cleartext != after_cleartext:
        severity = (DriftSeverity.DEGRADATION if after_cleartext > before_cleartext
                    else DriftSeverity.IMPROVEMENT)
        changes.append(PostureChange(
            property_name="tls_mode_cleartext",
            description=f"Cleartext sessions: {before_cleartext} → {after_cleartext}",
            before_value=before_cleartext,
            after_value=after_cleartext,
            severity=severity,
            confidence=Confidence.HIGH,
            affected_session_ids=after.session_ids,
            affected_control="TRANSPORT_ENCRYPTION",
        ))

    # --- Forward secrecy ---
    if before.forward_secrecy is not None and after.forward_secrecy is not None:
        if before.forward_secrecy != after.forward_secrecy:
            severity = (DriftSeverity.DEGRADATION if after.forward_secrecy is False
                        else DriftSeverity.IMPROVEMENT)
            changes.append(PostureChange(
                property_name="forward_secrecy",
                description=f"Forward secrecy changed: {before.forward_secrecy} → {after.forward_secrecy}",
                before_value=before.forward_secrecy,
                after_value=after.forward_secrecy,
                severity=severity,
                confidence=Confidence.HIGH,
                affected_session_ids=after.session_ids,
                affected_control="KEY_EXCHANGE_SECURITY",
            ))

    # --- Findings ---
    before_findings = set(before.finding_rule_ids)
    after_findings = set(after.finding_rule_ids)
    if before_findings != after_findings:
        added = after_findings - before_findings
        removed = before_findings - after_findings
        # Look up severity from stored severity mappings
        sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        # Determine severity based on finding criticality
        def _worst_severity(ids: set[str], sev_map: dict[str, str]) -> int:
            """Return the rank of the most severe finding in ids."""
            return min((sev_rank.get(sev_map.get(f, "info"), 5) for f in ids), default=5)
        worst_after = _worst_severity(after_findings, after.finding_severities)
        worst_before = _worst_severity(before_findings, before.finding_severities)
        if worst_after < worst_before:
            severity = DriftSeverity.DEGRADATION
        elif worst_after > worst_before:
            severity = DriftSeverity.IMPROVEMENT
        else:
            severity = DriftSeverity.CONFIGURATION_CHANGE
        changes.append(PostureChange(
            property_name="findings",
            description=f"Findings changed: added {sorted(added)}, removed {sorted(removed)}",
            before_value=sorted(before_findings),
            after_value=sorted(after_findings),
            severity=severity,
            confidence=Confidence.HIGH,
            affected_session_ids=after.session_ids,
            capture_before=before.capture.capture_id,
            capture_after=after.capture.capture_id,
            affected_finding=sorted(added)[0] if added else None,
        ))

    # --- Security controls ---
    before_controls = before.security_controls
    after_controls = after.security_controls
    for ctrl_id in set(list(before_controls.keys()) + list(after_controls.keys())):
        b_status = before_controls.get(ctrl_id)
        a_status = after_controls.get(ctrl_id)
        if b_status != a_status:
            severity = _classify_control_change(b_status, a_status)
            if severity != DriftSeverity.NO_MEANINGFUL_CHANGE:
                changes.append(PostureChange(
                    property_name=f"control_{ctrl_id}",
                    description=f"Control {ctrl_id} status changed: {b_status} → {a_status}",
                    before_value=b_status,
                    after_value=a_status,
                    severity=severity,
                    confidence=Confidence.HIGH,
                    affected_session_ids=after.session_ids,
                    affected_control=ctrl_id,
                    capture_before=before.capture.capture_id,
                    capture_after=after.capture.capture_id,
                ))

    # --- Capability mangling ---
    if before.capability_mangled_count != after.capability_mangled_count:
        severity = (DriftSeverity.DEGRADATION if after.capability_mangled_count > before.capability_mangled_count
                    else DriftSeverity.IMPROVEMENT)
        changes.append(PostureChange(
            property_name="capability_mangled_count",
            description=f"Capability mangling detected: {before.capability_mangled_count} → {after.capability_mangled_count}",
            before_value=before.capability_mangled_count,
            after_value=after.capability_mangled_count,
            severity=severity,
            confidence=Confidence.HIGH,
            affected_session_ids=after.session_ids,
            capture_before=before.capture.capture_id,
            capture_after=after.capture.capture_id,
            limitations=["Capability mangling may indicate intermediary modification"],
        ))

    # --- Overall severity ---
    overall = DriftSeverity.NO_MEANINGFUL_CHANGE
    if changes:
        # Pick the most severe change
        severity_order = {
            DriftSeverity.DEGRADATION: 0,
            DriftSeverity.CONFIGURATION_CHANGE: 1,
            DriftSeverity.IMPROVEMENT: 2,
            DriftSeverity.INCONCLUSIVE: 3,
            DriftSeverity.NO_MEANINGFUL_CHANGE: 4,
        }
        overall = min(
            (c.severity for c in changes),
            key=lambda s: severity_order.get(s, 5),
        )

    # Build summary
    if not changes:
        summary = "No meaningful security posture changes detected."
    else:
        summary_parts = []
        for c in changes:
            summary_parts.append(f"{c.property_name}: {c.description} ({c.severity.value})")
        summary = "; ".join(summary_parts)

    return DriftResult(
        asset_key=before.asset_key,
        snapshot_before=before,
        snapshot_after=after,
        changes=changes,
        overall_severity=overall,
        confidence=Confidence.HIGH if changes else Confidence.MEDIUM,
        summary=summary,
        evidence_refs=[s for s in after.observation_ids],
    )


def _classify_tls_change(added: set[str], removed: set[str]) -> DriftSeverity:
    """Classify TLS version changes as degradation or improvement."""
    deprecated = {"1.0", "1.1", "SSLv3", "SSLv2"}
    modern = {"1.2", "1.3"}
    if any(v in deprecated for v in added):
        return DriftSeverity.DEGRADATION
    if any(v in deprecated for v in removed):
        return DriftSeverity.IMPROVEMENT
    if any(v in modern for v in added) and not any(v in deprecated for v in added):
        return DriftSeverity.IMPROVEMENT
    if any(v in modern for v in removed):
        return DriftSeverity.DEGRADATION
    return DriftSeverity.CONFIGURATION_CHANGE


def _classify_cipher_change(added: set[str], removed: set[str]) -> DriftSeverity:
    """Classify cipher suite changes."""
    weak_indicators = ("RC4", "EXPORT", "DES", "3DES", "MD5", "SHA1")
    if any(any(ind in c for ind in weak_indicators) for c in added):
        return DriftSeverity.DEGRADATION
    if any(any(ind in c for ind in weak_indicators) for c in removed):
        return DriftSeverity.IMPROVEMENT
    return DriftSeverity.CONFIGURATION_CHANGE


def _classify_control_change(b_status: Optional[str], a_status: Optional[str]) -> DriftSeverity:
    """Classify security control status changes."""
    if b_status is None or a_status is None:
        return DriftSeverity.INCONCLUSIVE
    rank = {"fail": 0, "warn": 1, "low": 2, "pass": 3, "unknown": 4, "not_assessable": 5}
    b_rank = rank.get(b_status, 5)
    a_rank = rank.get(a_status, 5)
    if a_rank < b_rank:
        return DriftSeverity.DEGRADATION
    elif a_rank > b_rank:
        return DriftSeverity.IMPROVEMENT
    else:
        return DriftSeverity.NO_MEANINGFUL_CHANGE
