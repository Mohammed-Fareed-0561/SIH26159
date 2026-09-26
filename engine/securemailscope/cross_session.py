"""
Cross-session correlation and pattern detection.

Groups sessions by server identity and detects patterns across multiple
sessions *without* reparsing PCAPs — it operates on already-parsed Session
objects.

Complexity: sessions are grouped by asset first (O(n)), then comparisons
happen within each group.  Within a group of *k* sessions, the pairwise
comparison is O(k²) but k is typically small (tens, not thousands) for a
single server identity.  For the dominant cost (TLS version / cipher
aggregation) we use set accumulation which is O(k).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from .evidence import Confidence
from .models import Session, TlsMode


class PatternId(str, Enum):
    """Detectable cross-session patterns."""

    TLS_VERSION_VARIATION = "PATTERN_1"       # same server, different TLS versions
    CERTIFICATE_VARIATION = "PATTERN_2"       # same server, different certificates
    STARTTLS_OFFERED_NOT_USED = "PATTERN_3"   # STARTTLS offered but frequently unused
    AUTH_BEFORE_TLS_REPEATED = "PATTERN_4"    # AUTH-before-TLS repeated across sessions
    TLS_FAILURE_CLIENT_CONCENTRATION = "PATTERN_5"  # TLS failures concentrated around one client
    POSTURE_CHANGES_OVER_TIME = "PATTERN_6"   # security posture changes over time


@dataclass
class PatternResult:
    """One detected cross-session pattern."""
    pattern_id: str                          # e.g. "PATTERN_1"
    name: str
    description: str
    observations: list[str] = field(default_factory=list)
    affected_session_ids: list[str] = field(default_factory=list)
    affected_asset_key: Optional[str] = None
    confidence: Confidence = Confidence.LOW
    possible_interpretations: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    confidence_factors: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    standards: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        from .models import _encode
        return _encode(self)


@dataclass
class CrossSessionAnalysis:
    """Output of cross-session correlation for one asset."""
    asset_key: str
    sessions: list[str] = field(default_factory=list)
    tls_versions: dict[str, int] = field(default_factory=dict)  # version -> count
    cipher_suites: dict[str, int] = field(default_factory=dict)
    certificates: dict[str, int] = field(default_factory=dict)  # fingerprint -> count
    starttls_offered_count: int = 0
    starttls_used_count: int = 0
    auth_before_tls_count: int = 0
    tls_failure_count: int = 0
    patterns: list[PatternResult] = field(default_factory=list)
    # Per-client breakdown
    by_client: dict[str, dict[str, Any]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from .models import _encode
        return _encode(self)


def _asset_key_from_sessions(sessions: list[Session]) -> dict[str, list[Session]]:
    """Group sessions by their asset_key (server_name:port or server IP:port)."""
    groups: dict[str, list[Session]] = {}
    for s in sessions:
        key = s.asset_key
        groups.setdefault(key, []).append(s)
    return groups


def correlate_sessions(sessions: list[Session]) -> list[CrossSessionAnalysis]:
    """
    Perform cross-session correlation across a list of sessions.

    Groups by asset_key, then for each group:
    - Aggregates TLS versions, ciphers, certificates
    - Detects patterns
    - Builds a CrossSessionAnalysis

    Complexity: O(n) for grouping + O(k) per group for aggregation +
    O(k²) per group for pairwise pattern detection (k = sessions per group,
    typically small).
    """
    groups = _asset_key_from_sessions(sessions)
    analyses: list[CrossSessionAnalysis] = []

    for asset_key, group_sessions in groups.items():
        analysis = CrossSessionAnalysis(asset_key=asset_key)
        analysis.sessions = [s.session_id for s in group_sessions]

        # Aggregate TLS versions
        for s in group_sessions:
            if s.tls_version:
                analysis.tls_versions[s.tls_version] = (
                    analysis.tls_versions.get(s.tls_version, 0) + 1
                )
            if s.cipher_suite:
                analysis.cipher_suites[s.cipher_suite] = (
                    analysis.cipher_suites.get(s.cipher_suite, 0) + 1
                )
            # Certificate fingerprints
            if s.chain:
                fp = s.chain[0].sha256_fingerprint
                if fp:
                    analysis.certificates[fp] = (
                        analysis.certificates.get(fp, 0) + 1
                    )
            # STARTTLS stats
            if s.starttls_offered:
                analysis.starttls_offered_count += 1
            if s.starttls_requested:
                analysis.starttls_used_count += 1
            # Auth before TLS
            if s.cleartext_auth is not None:
                analysis.auth_before_tls_count += 1
            # TLS failures
            if s.tls_mode == TlsMode.CLEARTEXT and s.cleartext_auth is not None:
                analysis.tls_failure_count += 1

            # Per-client breakdown
            client_key = f"{s.client.ip}:{s.client.port}"
            if client_key not in analysis.by_client:
                analysis.by_client[client_key] = {
                    "tls_versions": {},
                    "auth_before_tls": 0,
                    "tls_failures": 0,
                    "session_ids": [],
                }
            client_data = analysis.by_client[client_key]
            client_data["session_ids"].append(s.session_id)
            if s.tls_version:
                client_data["tls_versions"][s.tls_version] = (
                    client_data["tls_versions"].get(s.tls_version, 0) + 1
                )
            if s.cleartext_auth is not None:
                client_data["auth_before_tls"] += 1

        # Detect patterns
        analysis.patterns = _detect_patterns(group_sessions, analysis)

        analyses.append(analysis)

    return analyses


def _detect_patterns(
    sessions: list[Session], analysis: CrossSessionAnalysis
) -> list[PatternResult]:
    """Detect all applicable patterns for a group of sessions."""
    patterns: list[PatternResult] = []

    # PATTERN_1: same server + different TLS versions
    if len(analysis.tls_versions) > 1:
        versions = sorted(analysis.tls_versions.keys())
        patterns.append(PatternResult(
            pattern_id=PatternId.TLS_VERSION_VARIATION.value,
            name="TLS version variation",
            description=(
                f"Server '{analysis.asset_key}' negotiated different TLS "
                f"versions with different clients: {versions}"
            ),
            observations=[
                f"TLS versions observed: {versions}",
                f"Version distribution: {analysis.tls_versions}",
            ],
            affected_session_ids=analysis.sessions,
            affected_asset_key=analysis.asset_key,
            confidence=Confidence.HIGH,
            possible_interpretations=[
                "Clients have different TLS version capabilities",
                "Server configuration is inconsistent across client contexts",
                "An intermediary is downgrading TLS for some clients",
            ],
            limitations=[
                "Cannot determine whether variation is client-driven or "
                "server-driven without client capability information",
                "Does not confirm a downgrade attack — could be normal "
                "client heterogeneity",
            ],
            confidence_factors=[
                f"{len(analysis.tls_versions)} distinct TLS versions observed",
                "Multiple sessions to the same server identity",
            ],
            standards=["RFC 8421", "RFC 7435"],
        ))

    # PATTERN_2: same server + different certificates
    if len(analysis.certificates) > 1:
        patterns.append(PatternResult(
            pattern_id=PatternId.CERTIFICATE_VARIATION.value,
            name="Certificate variation",
            description=(
                f"Server '{analysis.asset_key}' presented {len(analysis.certificates)} "
                f"different certificates across sessions"
            ),
            observations=[
                f"Distinct certificate fingerprints: {len(analysis.certificates)}",
            ],
            affected_session_ids=analysis.sessions,
            affected_asset_key=analysis.asset_key,
            confidence=Confidence.MEDIUM,
            possible_interpretations=[
                "Server uses SNI to present different certificates",
                "Multiple server instances behind the same identity use different certificates",
                "Certificate was rotated during the capture period",
                "An intermediary is serving a different certificate",
            ],
            limitations=[
                "SNI-based cert differences are normal; only anomalous if the "
                "same client/SNI gets different certs across sessions",
                "Cannot distinguish legitimate rotation from tampering without "
                "timing or independent observation",
            ],
            confidence_factors=[
                f"{len(analysis.certificates)} distinct certificates",
            ],
            standards=["RFC 6125", "RFC 5280"],
        ))

    # PATTERN_3: STARTTLS offered but frequently unused
    if analysis.starttls_offered_count > 0:
        ratio = analysis.starttls_used_count / analysis.starttls_offered_count
        if ratio < 0.5 and analysis.starttls_offered_count >= 2:
            patterns.append(PatternResult(
                pattern_id=PatternId.STARTTLS_OFFERED_NOT_USED.value,
                name="STARTTLS offered but frequently unused",
                description=(
                    f"STARTTLS was offered in {analysis.starttls_offered_count} "
                    f"sessions but only used in {analysis.starttls_used_count} "
                    f"({ratio:.0%})"
                ),
                observations=[
                    f"STARTTLS offered: {analysis.starttls_offered_count}",
                    f"STARTTLS used: {analysis.starttls_used_count}",
                    f"Usage ratio: {ratio:.0%}",
                ],
                affected_session_ids=analysis.sessions,
                affected_asset_key=analysis.asset_key,
                confidence=Confidence.MEDIUM,
                possible_interpretations=[
                    "Client configurations do not enable STARTTLS",
                    "Intermediary is stripping STARTTLS in some sessions",
                    "Clients with outdated software do not support STARTTLS",
                ],
                limitations=[
                    "Per-session causality (client vs intermediary) cannot be "
                    "determined from capture alone",
                    "Requires comparison with known-good client behavior",
                ],
                confidence_factors=[
                    f"STARTTLS offered in {analysis.starttls_offered_count} sessions "
                    f"but used in only {analysis.starttls_used_count}",
                ],
                standards=["RFC 3207", "RFC 8314"],
            ))

    # PATTERN_4: AUTH-before-TLS repeated
    if analysis.auth_before_tls_count >= 2:
        patterns.append(PatternResult(
            pattern_id=PatternId.AUTH_BEFORE_TLS_REPEATED.value,
            name="AUTH-before-TLS repeated",
            description=(
                f"Authentication before TLS occurred in "
                f"{analysis.auth_before_tls_count} sessions to the same server"
            ),
            observations=[
                f"AUTH before TLS in {analysis.auth_before_tls_count}/{len(sessions)} sessions",
            ],
            affected_session_ids=analysis.sessions,
            affected_asset_key=analysis.asset_key,
            confidence=Confidence.HIGH,
            possible_interpretations=[
                "Server is configured to allow (or require) AUTH before STARTTLS",
                "Clients consistently do not enforce STARTTLS before AUTH",
                "Intermediary is stripping STARTTLS, forcing cleartext auth",
            ],
            limitations=[
                "Repeated occurrence strengthens the signal but does not prove "
                "malicious intent",
                "Could be a deliberate server configuration (misconfiguration, "
                "not attack)",
            ],
            confidence_factors=[
                f"Repeated in {analysis.auth_before_tls_count} sessions",
            ],
            standards=["RFC 8314", "RFC 3207"],
        ))

    # PATTERN_5: TLS failures concentrated around one client
    for client_key, client_data in analysis.by_client.items():
        if client_data.get("tls_failures", 0) >= 2:
            patterns.append(PatternResult(
                pattern_id=PatternId.TLS_FAILURE_CLIENT_CONCENTRATION.value,
                name="TLS failures concentrated around one client",
                description=(
                    f"Client '{client_key}' experienced "
                    f"{client_data['tls_failures']} TLS failures"
                ),
                observations=[
                    f"Client {client_key} had TLS issues in multiple sessions",
                ],
                affected_session_ids=client_data["session_ids"],
                affected_asset_key=analysis.asset_key,
                confidence=Confidence.MEDIUM,
                possible_interpretations=[
                    "Client has outdated TLS libraries",
                    "Client cannot satisfy server's cipher or version requirements",
                    "An intermediary is interfering with this client's connections",
                ],
                limitations=[
                    "Client-specific issue, not necessarily a server or attack problem",
                    "Requires active probing of the client to confirm capability",
                ],
                confidence_factors=[
                    f"Multiple TLS failures for client {client_key}",
                ],
            ))

    # PATTERN_6: posture changes over time
    if len(sessions) >= 2:
        timestamps = [(s.session_id, s.capture_time) for s in sessions if s.capture_time]
        if len(timestamps) >= 2:
            timestamps.sort(key=lambda x: x[1])
            # Check for TLS version changes over time
            first_versions = set()
            last_versions = set()
            for s in sessions:
                if s.capture_time and s.tls_version:
                    if s.capture_time == timestamps[0][1]:
                        first_versions.add(s.tls_version)
                    if s.capture_time == timestamps[-1][1]:
                        last_versions.add(s.tls_version)
            if first_versions != last_versions:
                patterns.append(PatternResult(
                    pattern_id=PatternId.POSTURE_CHANGES_OVER_TIME.value,
                    name="Security posture changes over time",
                    description=(
                        f"Server '{analysis.asset_key}' showed TLS version "
                        f"changes: {first_versions} early vs {last_versions} late"
                    ),
                    observations=[
                        f"Early TLS versions: {sorted(first_versions)}",
                        f"Late TLS versions: {sorted(last_versions)}",
                    ],
                    affected_session_ids=[t[0] for t in timestamps],
                    affected_asset_key=analysis.asset_key,
                    confidence=Confidence.MEDIUM,
                    possible_interpretations=[
                        "Server was reconfigured or upgraded between sessions",
                        "Different server instances were active at different times",
                        "An intermediary's policy changed over time",
                    ],
                    limitations=[
                        "Requires sufficient time span between sessions to be meaningful",
                        "Cannot determine if changes were planned or malicious",
                    ],
                    confidence_factors=[
                        "TLS versions changed across the capture time window",
                    ],
                ))

    return patterns
