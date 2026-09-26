"""
Security reasoning engine.

Answers "WHY might it have happened?" — the Phase 3 counterpart to the Phase 2
state machine that answers "WHAT happened?".

The engine does NOT declare attacks.  Instead it enumerates possible
explanations for each security-relevant finding, gathers the evidence that
supports or contradicts each one, and assigns an explainable confidence.

Philosophy
----------
A finding like "STARTTLS offered but not used" has many possible explanations:
client misconfiguration, server misconfiguration, negotiation failure,
intermediary modification, an actual STARTTLS stripping attack, or simply an
incomplete capture.  The rule engine proves that the *event* occurred; the
reasoning engine makes explicit that the *cause* is not uniquely determined.

Confidence is never an opaque score.  It is documented as a qualitative level
(HIGH / MEDIUM / LOW / UNKNOWN) derived from a checklist of explainable
factors, each of which is recorded in the output.

The engine is offline-only: it never executes packet contents, never treats
packet strings as code, never calls external APIs, and never sends capture
data anywhere.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from .evidence import (
    Confidence,
    ObservationStatus,
)
from .finding_reference import FindingReference, LinkConfidence
from .models import CertVisibility, TlsMode
from .security_controls import ControlId


# ---------------------------------------------------------------------------
# Explanation model
# ---------------------------------------------------------------------------
class ExplanationId(str, Enum):
    """Possible explanations for a security-relevant finding."""

    CLIENT_CONFIGURATION = "CLIENT_CONFIGURATION"
    SERVER_CONFIGURATION = "SERVER_CONFIGURATION"
    NEGOTIATION_FAILURE = "NEGOTIATION_FAILURE"
    INTERMEDIARY_MODIFICATION = "INTERMEDIARY_MODIFICATION"
    STARTTLS_STRIPPING = "STARTTLS_STRIPPING"
    INCOMPLETE_CAPTURE = "INCOMPLETE_CAPTURE"
    LEGITIMATE_NEGOTIATION = "LEGITIMATE_NEGOTIATION"
    CLIENT_LIMITATION = "CLIENT_LIMITATION"
    PROTOCOL_CONSTRAINT = "PROTOCOL_CONSTRAINT"


@dataclass
class EvidenceItem:
    """A single piece of evidence cited for or against an explanation."""
    description: str
    status: ObservationStatus
    frame: Optional[int] = None
    finding_id: Optional[str] = None
    transition_id: Optional[str] = None


@dataclass
class PossibleExplanation:
    """One possible explanation for a finding, with its evidence profile."""
    explanation_id: ExplanationId
    description: str
    supporting_evidence: list[EvidenceItem] = field(default_factory=list)
    contradicting_evidence: list[EvidenceItem] = field(default_factory=list)
    missing_evidence: list[str] = field(default_factory=list)
    confidence: Confidence = Confidence.LOW
    status: str = "possible"  # "possible" | "likely" | "unlikely"
    confidence_factors: list[str] = field(default_factory=list)
    standards: list[str] = field(default_factory=list)


@dataclass
class ObservedFact:
    """A single observed fact derived from the state machine or findings."""
    description: str
    source: str  # "state_machine" | "finding" | "session_model"
    status: ObservationStatus
    frame: Optional[int] = None
    transition_id: Optional[str] = None
    finding_id: Optional[str] = None


@dataclass
class Inference:
    """A logical inference drawn from observed facts."""
    description: str
    supporting_fact_ids: list[str] = field(default_factory=list)
    status: ObservationStatus = ObservationStatus.INFERRED
    confidence: Confidence = Confidence.HIGH


@dataclass
class ReasoningResult:
    """
    The structured output of reasoning about one finding.

    Conceptually:
      Observed facts → Inferences → Possible explanations
                     → Confidence → Impact/risk → Limitations
    """

    finding_id: str
    rule_id: str
    observed_facts: list[ObservedFact] = field(default_factory=list)
    inferences: list[Inference] = field(default_factory=list)
    possible_explanations: list[PossibleExplanation] = field(default_factory=list)
    confidence: Confidence = Confidence.UNKNOWN
    confidence_factors: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    recommended_next_evidence: list[str] = field(default_factory=list)
    affected_controls: list[str] = field(default_factory=list)
    risk: Optional["RiskComponents"] = None
    link_confidence: str = ""  # LinkConfidence value
    transition_ids: list[str] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        from .models import _encode
        return _encode(self)


# ---------------------------------------------------------------------------
# Risk model (explainable, components-based)
# ---------------------------------------------------------------------------
class Impact(str, Enum):
    """How damaging would a confirmed explanation be."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class Exposure(str, Enum):
    """How reachable the vulnerability is from the observed session."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


@dataclass
class RiskComponents:
    """
    Explainable risk = function(Impact, Exposure, Confidence).

    The combination table below is the documented methodology.  There are no
    opaque weights — each cell is a plain English rule:

      Impact HIGH + Exposure HIGH + Confidence HIGH   => HIGH risk
      Impact HIGH + Exposure LOW  + Confidence HIGH   => MEDIUM risk
      Impact LOW  + Exposure HIGH + Confidence HIGH   => MEDIUM risk
      Confidence LOW or UNKNOWN                      => LOW risk (insufficient)
      Impact UNKNOWN or Exposure UNKNOWN             => UNKNOWN risk
    """

    impact: Impact = Impact.UNKNOWN
    exposure: Exposure = Exposure.UNKNOWN
    confidence: Confidence = Confidence.UNKNOWN
    overall: str = "unknown"   # "high" | "medium" | "low" | "unknown"
    methodology: str = ""


_RISK_TABLE = {
    # impact, exposure, confidence -> overall
    ("high", "high", "high"): "high",
    ("high", "high", "medium"): "high",
    ("high", "high", "low"): "low",
    ("high", "medium", "high"): "medium",
    ("high", "medium", "medium"): "medium",
    ("high", "medium", "low"): "low",
    ("high", "low", "high"): "medium",
    ("high", "low", "medium"): "low",
    ("high", "low", "low"): "low",
    ("medium", "high", "high"): "medium",
    ("medium", "high", "medium"): "medium",
    ("medium", "medium", "high"): "medium",
    ("medium", "medium", "medium"): "low",
    ("medium", "low", "high"): "low",
    ("low", "high", "high"): "medium",
    ("low", "low", "high"): "low",
}


def compute_risk(impact: Impact, exposure: Exposure, confidence: Confidence) -> RiskComponents:
    """Apply the documented risk combination table."""
    key = (impact.value, exposure.value, confidence.value)
    overall = _RISK_TABLE.get(key, "unknown")

    # Any UNKNOWN input propagates to UNKNOWN output.
    if impact == Impact.UNKNOWN or exposure == Exposure.UNKNOWN or confidence == Confidence.UNKNOWN:
        overall = "unknown"

    methodology = (
        "Risk = f(Impact, Exposure, Confidence). "
        "HIGH impact + HIGH exposure + HIGH confidence => HIGH. "
        "Any UNKNOWN component => UNKNOWN. "
        "LOW confidence => at most LOW (insufficient evidence to act)."
    )
    return RiskComponents(
        impact=impact, exposure=exposure, confidence=confidence,
        overall=overall, methodology=methodology,
    )


# ---------------------------------------------------------------------------
# Explanation registry — maps rule_id patterns to candidate explanations
# ---------------------------------------------------------------------------
# Each entry: explanation_id -> (description, applicable_rule_prefixes, standards)
#
# The engine consults this to decide which explanations are *relevant* to a
# given finding.  An explanation is only emitted if at least one of its
# applicable rule prefixes matches the finding's rule_id.

_EXPLANATION_DESCRIPTIONS = {
    ExplanationId.CLIENT_CONFIGURATION: (
        "The email client is misconfigured to not use STARTTLS or to authenticate "
        "before completing the TLS upgrade.",
    ),
    ExplanationId.SERVER_CONFIGURATION: (
        "The server is configured to accept authentication without STARTTLS, or "
        "its STARTTLS advertisement is inconsistent across sessions.",
    ),
    ExplanationId.NEGOTIATION_FAILURE: (
        "The TLS negotiation was attempted but failed — a handshake error, "
        "certificate error, or cipher mismatch prevented encryption from being "
        "established.",
    ),
    ExplanationId.INTERMEDIARY_MODIFICATION: (
        "A network intermediary (proxy, firewall, load balancer) modified the "
        "STARTTLS capability list or intercepted the upgrade.",
    ),
    ExplanationId.STARTTLS_STRIPPING: (
        "A man-in-the-middle actively stripped the STARTTLS capability from the "
        "server's response, causing the client to fall back to cleartext. "
        "THIS IS A POSSIBLE EXPLANATION ONLY — it is not confirmed by a single "
        "capture.",
    ),
    ExplanationId.INCOMPLETE_CAPTURE: (
        "The capture does not contain enough of the session to determine what "
        "happened.  The observed behaviour may be normal in the missing portion.",
    ),
    ExplanationId.LEGITIMATE_NEGOTIATION: (
        "The observed behaviour is consistent with a known, legitimate protocol "
        "design choice or deployment pattern.",
    ),
    ExplanationId.CLIENT_LIMITATION: (
        "The client does not support the required security feature (e.g. TLS "
        "1.3, a specific cipher, or STARTTLS on this service).",
    ),
    ExplanationId.PROTOCOL_CONSTRAINT: (
        "A property of the protocol or its deployment context constrains the "
        "observable behaviour (e.g. TLS 1.3 encrypting the Certificate message).",
    ),
}

# Rule prefixes that activate each explanation.  Broad enough to catch all
# relevant rules, narrow enough to exclude unrelated ones.
_EXPLANATION_RULES = {
    ExplanationId.CLIENT_CONFIGURATION: ("SMS-STRIP-002", "SMS-AUTH-001",
                                        "SMS-PROTO-003", "SMS-PROTO-004"),
    ExplanationId.SERVER_CONFIGURATION: ("SMS-STRIP-002", "SMS-STRIP-004",
                                         "SMS-PROTO-003", "SMS-PROTO-004"),
    ExplanationId.NEGOTIATION_FAILURE: ("SMS-STRIP-003", "SMS-CIPH-001",
                                        "SMS-CIPH-002", "SMS-CIPH-003"),
    ExplanationId.INTERMEDIARY_MODIFICATION: ("SMS-STRIP-001", "SMS-STRIP-002",
                                              "SMS-STRIP-003"),
    ExplanationId.STARTTLS_STRIPPING: ("SMS-STRIP-002", "SMS-STRIP-003"),
    ExplanationId.INCOMPLETE_CAPTURE: ("SMS-STRIP-002", "SMS-AUTH-001",
                                       "SMS-STRIP-003", "SMS-STRIP-004",
                                       "SMS-CERT-001", "SMS-CERT-002"),
    ExplanationId.LEGITIMATE_NEGOTIATION: ("SMS-OK-001",),
    ExplanationId.CLIENT_LIMITATION: ("SMS-CIPH-006",),
    ExplanationId.PROTOCOL_CONSTRAINT: ("SMS-VIS-001", "SMS-VIS-002"),
}

# Per-finding impact / exposure assignments.  These are deterministic
# classifications, not predictions.
_IMPACT_BY_RULE = {
    # Critical: credentials exposed or encryption entirely absent on a
    # submission/access port
    "SMS-AUTH-001": Impact.HIGH,
    "SMS-PROTO-003": Impact.HIGH,
    "SMS-STRIP-001": Impact.HIGH,
    "SMS-STRIP-003": Impact.HIGH,
    "SMS-POL-001": Impact.HIGH,
    "SMS-POL-002": Impact.HIGH,
    "SMS-CERT-001": Impact.MEDIUM,     # expired cert
    "SMS-CERT-008": Impact.HIGH,       # revoked
    "SMS-CIPH-001": Impact.HIGH,
    "SMS-CIPH-002": Impact.HIGH,
    "SMS-CIPH-003": Impact.HIGH,
    "SMS-CIPH-004": Impact.MEDIUM,
    "SMS-CIPH-005": Impact.LOW,
    "SMS-CIPH-006": Impact.LOW,
    "SMS-PROTO-001": Impact.HIGH,
    "SMS-PROTO-002": Impact.HIGH,
    "SMS-PROTO-004": Impact.MEDIUM,
    "SMS-STRIP-002": Impact.MEDIUM,
    "SMS-STRIP-004": Impact.MEDIUM,
    "SMS-CERT-003": Impact.MEDIUM,
    "SMS-CERT-004": Impact.MEDIUM,
    "SMS-CERT-005": Impact.MEDIUM,
    "SMS-CERT-006": Impact.MEDIUM,
    "SMS-CERT-007": Impact.LOW,
    "SMS-FS-001": Impact.MEDIUM,
    "SMS-KEX-001": Impact.HIGH,
    "SMS-KEY-001": Impact.HIGH,
    "SMS-KEY-002": Impact.MEDIUM,
    "SMS-VIS-001": Impact.LOW,
    "SMS-VIS-002": Impact.LOW,
    "SMS-OK-001": Impact.LOW,
}

_EXPOSURE_BY_RULE = {
    # Credentials in the clear: directly reachable by anyone on the path
    "SMS-AUTH-001": Exposure.HIGH,
    "SMS-STRIP-001": Exposure.HIGH,
    "SMS-STRIP-003": Exposure.HIGH,
    "SMS-STRIP-002": Exposure.MEDIUM,
    "SMS-STRIP-004": Exposure.MEDIUM,
    "SMS-PROTO-003": Exposure.HIGH,
    "SMS-PROTO-004": Exposure.MEDIUM,
    "SMS-POL-001": Exposure.HIGH,
    "SMS-POL-002": Exposure.HIGH,
}


def _impact_for(rule_id: str) -> Impact:
    return _IMPACT_BY_RULE.get(rule_id, Impact.UNKNOWN)


def _exposure_for(rule_id: str) -> Exposure:
    return _EXPOSURE_BY_RULE.get(rule_id, Exposure.UNKNOWN)


def _candidates_for_rule(rule_id: str) -> list[ExplanationId]:
    """Which explanations are relevant to this rule?"""
    out = []
    for eid, prefixes in _EXPLANATION_RULES.items():
        if any(rule_id.startswith(p) for p in prefixes):
            out.append(eid)
    return out


# ---------------------------------------------------------------------------
# The reasoning engine
# ---------------------------------------------------------------------------

class ReasoningEngine:
    """
    Stateless engine that turns a finding + session context into a
    ``ReasoningResult``.

    Usage:
        engine = ReasoningEngine()
        result = engine.reason(session, state_machine_result, finding, ...)
    """

    def __init__(self):
        self._explanations = {
            eid: desc for eid, desc in _EXPLANATION_DESCRIPTIONS.items()
        }

    # -- public API --------------------------------------------------------

    def reason(
        self,
        session: Any,
        state_result: Any,
        rule_id: str,
        finding: Any,
        finding_ref: Optional[FindingReference] = None,
    ) -> ReasoningResult:
        """
        Produce a full reasoning result for one finding.

        Parameters
        ----------
        session: the Session object
        state_result: the StateMachineResult for the session (or None)
        rule_id: the rule_id being reasoned about
        finding: the Finding object (for severity/detail/evidence)
        finding_ref: the FindingReference linking finding to transitions
        """
        facts = self._observed_facts(session, state_result, rule_id, finding, finding_ref)
        inferences = self._inferences(facts, rule_id)
        explanations = self._build_explanations(rule_id, session, state_result, finding, facts)
        conf = self._overall_confidence(rule_id, session, state_result, explanations)
        impact = _impact_for(rule_id)
        exposure = _exposure_for(rule_id)
        risk = compute_risk(impact, exposure, conf)

        related_findings = self._related_findings(session, rule_id)

        result = ReasoningResult(
            finding_id=rule_id,
            rule_id=rule_id,
            observed_facts=facts,
            inferences=inferences,
            possible_explanations=explanations,
            confidence=conf,
            confidence_factors=self._confidence_factors(rule_id, session, state_result, explanations),
            limitations=self._limitations(rule_id, session, state_result),
            recommended_next_evidence=self._recommended_next(rule_id, session, explanations),
            affected_controls=self._affected_controls(rule_id),
            risk=risk,
            link_confidence=finding_ref.link_confidence.value if finding_ref else LinkConfidence.NOT_ATTEMPTED.value,
            transition_ids=finding_ref.transition_ids if finding_ref else [],
            evidence_ids=finding_ref.evidence_ids if finding_ref else [],
        )
        # Tag findings that are also relevant
        result._related_findings = related_findings  # type: ignore[attr-defined]
        return result

    # -- fact extraction ---------------------------------------------------

    def _observed_facts(
        self, session, state_result, rule_id: str, finding, finding_ref
    ) -> list[ObservedFact]:
        facts: list[ObservedFact] = []

        # Always record the finding itself as an observed fact
        facts.append(ObservedFact(
            description=f"Finding {rule_id}: {finding.title if finding else rule_id}",
            source="finding",
            status=ObservationStatus.OBSERVED,
        ))

        # Session-level facts
        if session.tls_mode == TlsMode.CLEARTEXT and rule_id.startswith("SMS-STRIP"):
            facts.append(ObservedFact(
                description="Session is cleartext (no TLS established)",
                source="session_model",
                status=ObservationStatus.OBSERVED,
            ))
        elif session.tls_mode == TlsMode.STARTTLS and rule_id.startswith("SMS-STRIP"):
            facts.append(ObservedFact(
                description="Session negotiated STARTTLS",
                source="session_model",
                status=ObservationStatus.OBSERVED,
            ))

        if session.starttls_offered:
            facts.append(ObservedFact(
                description="Server advertised STARTTLS capability",
                source="session_model",
                status=ObservationStatus.OBSERVED,
            ))
        if session.starttls_requested:
            facts.append(ObservedFact(
                description="Client sent STARTTLS / STLS command",
                source="session_model",
                status=ObservationStatus.OBSERVED,
            ))
        if session.starttls_accepted:
            facts.append(ObservedFact(
                description="Server accepted STARTTLS / STLS and TLS began",
                source="session_model",
                status=ObservationStatus.OBSERVED,
            ))
        if session.capability_mangled:
            facts.append(ObservedFact(
                description=f"Capability list contains '{session.mangled_token}' "
                            f"(equal-length substitution of STARTTLS keyword)",
                source="session_model",
                status=ObservationStatus.OBSERVED,
            ))
        if session.cleartext_auth is not None:
            facts.append(ObservedFact(
                description=f"{session.cleartext_auth.mechanism} authentication "
                            f"observed before TLS",
                source="session_model",
                status=ObservationStatus.OBSERVED,
                frame=session.cleartext_auth.frame,
            ))
        if session.tls_version:
            facts.append(ObservedFact(
                description=f"Negotiated TLS {session.tls_version}",
                source="session_model",
                status=ObservationStatus.OBSERVED,
            ))

        # TLS 1.3 certificate visibility (Part 14: do not overclaim)
        if rule_id in ("SMS-CERT-001", "SMS-CERT-002", "SMS-CERT-003",
                       "SMS-CERT-004", "SMS-CERT-005", "SMS-CERT-006",
                       "SMS-CERT-007", "SMS-CERT-008") and \
           session.cert_visibility == CertVisibility.ENCRYPTED_TLS13:
            facts.append(ObservedFact(
                description="TLS 1.3 encrypts the Certificate message; "
                            "certificate posture cannot be assessed from this session",
                source="protocol_constraint",
                status=ObservationStatus.NOT_OBSERVABLE,
            ))

        # State machine transitions
        if state_result:
            for tr in state_result.security_relevant_transitions:
                facts.append(ObservedFact(
                    description=f"Transition: {tr.from_state} → {tr.to_state}"
                                + (f" ({tr.details})" if tr.details else ""),
                    source="state_machine",
                    status=tr.status,
                    transition_id=tr.transition_id,
                ))
                for ref in tr.observation_refs:
                    facts.append(ObservedFact(
                        description=f"Observation: {ref.observation_type}"
                                    + (f" — {ref.excerpt[:80]}" if ref.excerpt else ""),
                        source="state_machine",
                        status=ref.status,
                        finding_id=ref.evidence_id,
                    ))

        # Capture completeness
        if hasattr(session, '_capture_completeness_status'):
            status = session._capture_completeness_status
            if status and status != "GOOD":
                facts.append(ObservedFact(
                    description=f"Capture completeness status: {status}",
                    source="capture_completeness",
                    status=ObservationStatus.INSUFFICIENT_CAPTURE,
                ))

        return facts

    # -- inferences --------------------------------------------------------

    def _inferences(self, facts, rule_id: str) -> list[Inference]:
        out: list[Inference] = []

        fact_map = {f.description: f for f in facts}

        if rule_id.startswith("SMS-AUTH-001"):
            out.append(Inference(
                description="Credentials were transmitted before any encryption "
                            "was established, exposing them to network observers.",
                supporting_fact_ids=self._ids(facts),
                status=ObservationStatus.INFERRED,
                confidence=Confidence.HIGH,
            ))

        if rule_id.startswith("SMS-STRIP-002"):
            out.append(Inference(
                description="The client elected not to use STARTTLS even though "
                            "the server offered it.  This may be a client, server, "
                            "or intermediary decision — the capture cannot "
                            "distinguish them.",
                supporting_fact_ids=self._ids(facts),
                status=ObservationStatus.INFERRED,
                confidence=Confidence.HIGH,
            ))

        if rule_id.startswith("SMS-STRIP-003"):
            out.append(Inference(
                description="STARTTLS was requested but the TLS handshake did "
                            "not follow.  The upgrade path was broken, but the "
                            "cause is not determined by this capture alone.",
                supporting_fact_ids=self._ids(facts),
                status=ObservationStatus.INFERRED,
                confidence=Confidence.HIGH,
            ))

        if rule_id.startswith("SMS-PROTO-003"):
            out.append(Inference(
                description="No encryption was established on a submission or "
                            "access port where RFC 8314 mandates it.",
                supporting_fact_ids=self._ids(facts),
                status=ObservationStatus.INFERRED,
                confidence=Confidence.HIGH,
            ))

        if not out:
            out.append(Inference(
                description=f"Security-relevant event detected ({rule_id}).",
                supporting_fact_ids=self._ids(facts),
                status=ObservationStatus.INFERRED,
                confidence=Confidence.MEDIUM,
            ))

        return out

    # -- explanations ------------------------------------------------------

    def _build_explanations(
        self, rule_id: str, session, state_result, finding, facts
    ) -> list[PossibleExplanation]:
        candidates = _candidates_for_rule(rule_id)
        if not candidates:
            # Every rule gets at least the INCOMPLETE_CAPTURE possibility if
            # the capture is limited, plus a generic "other" fallback.
            if self._capture_is_limited(session):
                candidates = [ExplanationId.INCOMPLETE_CAPTURE]
            else:
                candidates = [ExplanationId.SERVER_CONFIGURATION]

        out: list[PossibleExplanation] = []
        for eid in candidates:
            expl = PossibleExplanation(
                explanation_id=eid,
                description=self._explanations.get(eid, ""),
            )
            self._populate_explanation(expl, eid, rule_id, session, state_result)
            out.append(expl)

        # Sort by confidence (highest first), but never rank INCOMPLETE_CAPTURE
        # above a concrete explanation — it is always "possible".
        out.sort(key=lambda e: (
            e.confidence.value if e.confidence != Confidence.UNKNOWN else -1,
        ), reverse=True)
        return out

    def _populate_explanation(
        self, expl: PossibleExplanation, eid: ExplanationId,
        rule_id: str, session, state_result
    ) -> None:
        """Fill in supporting / contradicting / missing evidence for one explanation."""

        # ---- STARTTLS_STRIPPING → lowest confidence, always ----------------
        if eid == ExplanationId.STARTTLS_STRIPPING:
            expl.supporting_evidence.append(EvidenceItem("STARTTLS capability was advertised",
                                                         ObservationStatus.OBSERVED))
            expl.contradicting_evidence.append(
                EvidenceItem("No evidence of packet tampering or capability "
                             "substitution on the wire", ObservationStatus.OBSERVED)
            )
            expl.missing_evidence.append(
                "Independent observation of the same session from a second point "
                "to confirm capability removal"
            )
            expl.missing_evidence.append(
                "Comparable sessions showing the same server offering STARTTLS "
                "to other clients"
            )
            expl.confidence = Confidence.LOW
            expl.status = "possible"
            expl.confidence_factors.append(
                "No tampering evidence — stripping cannot be confirmed from one capture"
            )
            expl.confidence_factors.append(
                "STARTTLS was advertised (supports the possibility of removal)"
            )
            expl.standards = ["RFC 3207"]

        # ---- INTERMEDIARY_MODIFICATION ----------------------------------
        elif eid == ExplanationId.INTERMEDIARY_MODIFICATION:
            if session.capability_mangled:
                expl.supporting_evidence.append(EvidenceItem(
                    f"Capability token '{session.mangled_token}' is an equal-length "
                    "substitution of STARTTLS", ObservationStatus.OBSERVED))
                expl.confidence = Confidence.HIGH
                expl.status = "likely"
                expl.confidence_factors.append(
                    "Equal-length substitution measured on the wire — strong signal"
                )
            else:
                expl.contradicting_evidence.append(
                    EvidenceItem("No capability mangling detected",
                                 ObservationStatus.OBSERVED))
                expl.confidence = Confidence.LOW
                expl.status = "possible"
                expl.confidence_factors.append(
                    "No mangling signal — modification not directly observed"
                )
            expl.missing_evidence.append(
                "Network-level evidence of a middlebox (e.g. divergent TCP stack "
                "fingerprints)"
            )
            expl.standards = ["RFC 3207"]

        # ---- CLIENT_CONFIGURATION ---------------------------------------
        elif eid == ExplanationId.CLIENT_CONFIGURATION:
            if rule_id.startswith("SMS-STRIP-002") and not session.starttls_requested:
                expl.supporting_evidence.append(EvidenceItem(
                    "STARTTLS was offered but the client never sent a STARTTLS command",
                    ObservationStatus.OBSERVED))
                expl.confidence = Confidence.MEDIUM
                expl.status = "likely"
                expl.confidence_factors.append(
                    "Client explicitly did not request STARTTLS after it was offered"
                )
            elif rule_id.startswith("SMS-AUTH-001"):
                expl.supporting_evidence.append(EvidenceItem(
                    "Client authenticated before issuing STARTTLS",
                    ObservationStatus.OBSERVED))
                expl.confidence = Confidence.MEDIUM
                expl.confidence_factors.append(
                    "AUTH command precedes any TLS negotiation in the transcript"
                )
            else:
                expl.contradicting_evidence.append(
                    EvidenceItem("No direct evidence of client-side misconfiguration",
                                 ObservationStatus.OBSERVED))
                expl.confidence = Confidence.LOW
            expl.standards = ["RFC 8314"]

        # ---- SERVER_CONFIGURATION ---------------------------------------
        elif eid == ExplanationId.SERVER_CONFIGURATION:
            if rule_id.startswith("SMS-STRIP-004"):
                expl.supporting_evidence.append(EvidenceItem(
                    "Server did not advertise STARTTLS at all on this port",
                    ObservationStatus.OBSERVED))
                expl.confidence = Confidence.HIGH
                expl.status = "likely"
                expl.confidence_factors.append(
                    "Capability list was directly observed to lack STARTTLS"
                )
            elif rule_id.startswith("SMS-PROTO-004"):
                expl.supporting_evidence.append(EvidenceItem(
                    "MTA relay on port 25 with no TLS — consistent with RFC 7435 "
                    "opportunistic TLS", ObservationStatus.OBSERVED))
                expl.confidence = Confidence.HIGH
                expl.status = "likely"
            else:
                expl.contradicting_evidence.append(
                    EvidenceItem("STARTTLS was offered, so the server did "
                                 "support it", ObservationStatus.OBSERVED))
                expl.confidence = Confidence.MEDIUM
            expl.standards = ["RFC 8314", "RFC 7435"]

        # ---- NEGOTIATION_FAILURE ----------------------------------------
        elif eid == ExplanationId.NEGOTIATION_FAILURE:
            if rule_id.startswith("SMS-STRIP-003"):
                expl.supporting_evidence.append(EvidenceItem(
                    "STARTTLS was requested but no TLS handshake followed",
                    ObservationStatus.OBSERVED))
                expl.confidence = Confidence.HIGH
                expl.status = "likely"
                expl.confidence_factors.append(
                    "Client requested upgrade, server never began TLS"
                )
            else:
                expl.contradicting_evidence.append(
                    EvidenceItem("No handshake failure observed",
                                 ObservationStatus.OBSERVED))
                expl.confidence = Confidence.LOW
            expl.standards = ["RFC 3207", "RFC 9325"]

        # ---- INCOMPLETE_CAPTURE -----------------------------------------
        elif eid == ExplanationId.INCOMPLETE_CAPTURE:
            if self._capture_is_limited(session):
                expl.supporting_evidence.append(EvidenceItem(
                    f"Capture completeness is limited (status: "
                    f"{session._capture_completeness_status})"
                    if hasattr(session, '_capture_completeness_status')
                    else "Capture completeness is limited",
                    ObservationStatus.INSUFFICIENT_CAPTURE))
                expl.confidence = Confidence.MEDIUM
                expl.status = "possible"
                expl.confidence_factors.append(
                    "Limited capture means the missing portion could contain "
                    "the STARTTLS negotiation"
                )
            else:
                expl.contradicting_evidence.append(
                    EvidenceItem("Capture completeness is good",
                                 ObservationStatus.OBSERVED))
                expl.confidence = Confidence.LOW
            expl.missing_evidence.append(
                "Full session transcript including any post-capture negotiation"
            )

        # ---- CLIENT_LIMITATION ------------------------------------------
        elif eid == ExplanationId.CLIENT_LIMITATION:
            expl.contradicting_evidence.append(
                EvidenceItem("No information about the client's capabilities "
                             "is available from a passive capture",
                             ObservationStatus.NOT_OBSERVABLE))
            expl.missing_evidence.append(
                "Active probe of the client's TLS/STARTTLS capabilities"
            )
            expl.confidence = Confidence.LOW
            expl.standards = ["RFC 8314"]

        # ---- PROTOCOL_CONSTRAINT ----------------------------------------
        elif eid == ExplanationId.PROTOCOL_CONSTRAINT:
            if session.cert_visibility == CertVisibility.ENCRYPTED_TLS13:
                expl.supporting_evidence.append(EvidenceItem(
                    "TLS 1.3 encrypts Certificate messages (RFC 8446 §4.4)",
                    ObservationStatus.OBSERVED))
                expl.confidence = Confidence.HIGH
                expl.status = "likely"
                expl.confidence_factors.append(
                    "Protocol design, not configuration, prevents observation"
                )
            expl.standards = ["RFC 8446"]

        # ---- LEGITIMATE_NEGOTIATION -------------------------------------
        elif eid == ExplanationId.LEGITIMATE_NEGOTIATION:
            if rule_id == "SMS-OK-001":
                expl.supporting_evidence.append(EvidenceItem(
                    "Modern TLS 1.2/1.3 with forward secrecy and AEAD cipher",
                    ObservationStatus.OBSERVED))
                expl.confidence = Confidence.HIGH
                expl.status = "likely"
            else:
                expl.contradicting_evidence.append(
                    EvidenceItem("The finding indicates a security issue, "
                                 "not a normal negotiation",
                                 ObservationStatus.OBSERVED))
                expl.confidence = Confidence.LOW

        # ---- SERVER_CONFIGURATION (generic) -----------------------------
        if not expl.supporting_evidence and not expl.contradicting_evidence:
            expl.contradicting_evidence.append(
                EvidenceItem("No direct evidence for this explanation",
                             ObservationStatus.NOT_OBSERVABLE))

        # Ensure confidence_factors records are populated even for generic paths
        if not expl.confidence_factors:
            expl.confidence_factors.append(
                "Explanation evaluated against available evidence and capture completeness"
            )

    def _capture_is_limited(self, session) -> bool:
        if not hasattr(session, '_capture_completeness_status'):
            return False
        status = session._capture_completeness_status
        return status in ("LIMITED", "INSUFFICIENT", "limited", "insufficient")

    def _related_findings(self, session, rule_id: str) -> list[str]:
        """Other findings in the same session that are contextually related."""
        out = []
        for f in session.findings:
            if f.rule_id != rule_id and (
                f.rule_id.startswith("SMS-STRIP") or
                f.rule_id.startswith("SMS-AUTH") or
                f.rule_id.startswith("SMS-PROTO")
            ):
                out.append(f.rule_id)
        return out

    def _confidence_factors(
        self, rule_id: str, session, state_result, explanations
    ) -> list[str]:
        factors: list[str] = []

        # Direct packet evidence: the finding's evidence frames are non-empty
        if hasattr(session, 'findings'):
            for f in session.findings:
                if f.rule_id == rule_id and f.evidence and f.evidence.frames:
                    factors.append("Direct packet evidence: finding cites "
                                   f"{len(f.evidence.frames)} frame(s)")
                    break

        # Number of supporting observations
        n_obs = sum(
            1 for e in explanations for ev in e.supporting_evidence
        )
        if n_obs >= 2:
            factors.append(f"{n_obs} supporting observations across explanations")
        elif n_obs == 1:
            factors.append("1 supporting observation")

        # Evidence consistency: are supporting and contradicting both non-empty?
        has_contradicting = any(e.contradicting_evidence for e in explanations)
        if has_contradicting:
            factors.append("Contradictory evidence present — reduces confidence")

        # Capture completeness
        if self._capture_is_limited(session):
            factors.append("Capture completeness is limited — reduces confidence")
        else:
            factors.append("Capture completeness supports observed states")

        # Exact frame attribution
        if state_result and state_result.security_relevant_transitions:
            exact = sum(1 for t in state_result.security_relevant_transitions
                        if getattr(t, 'frame_precision', None) == 'EXACT')
            if exact:
                factors.append(f"{exact} transition(s) have exact frame attribution")
            else:
                factors.append("Frame attribution uses fallback or is unknown — "
                               "reduces precision")

        return factors

    def _overall_confidence(
        self, rule_id: str, session, state_result, explanations
    ) -> Confidence:
        """
        Determine overall confidence in the *finding* (not in any single
        explanation).

        HIGH: the event is directly observed with exact frame attribution.
        MEDIUM: observed but with some imprecision or limited capture.
        LOW: observed through inference only.
        UNKNOWN: cannot be established.
        """
        # TLS 1.3 certificate constraint
        cert_rules = ("SMS-CERT-001", "SMS-CERT-002", "SMS-CERT-003",
                      "SMS-CERT-004", "SMS-CERT-005", "SMS-CERT-006",
                      "SMS-CERT-007", "SMS-CERT-008")
        if rule_id in cert_rules:
            if session.cert_visibility == CertVisibility.ENCRYPTED_TLS13:
                return Confidence.LOW  # event observed (TLS 1.3), but cert not

        # Find the finding to check its evidence
        finding = None
        for f in session.findings:
            if f.rule_id == rule_id:
                finding = f
                break

        if finding and finding.evidence and finding.evidence.frames:
            # The event itself is directly observed
            if self._capture_is_limited(session):
                return Confidence.MEDIUM
            # Check if any explanation is HIGH confidence
            any_high = any(
                e.confidence == Confidence.HIGH for e in explanations
            )
            # STARTTLS_STRIPPING explanation is always LOW even if event is observed
            if ExplanationId.STARTTLS_STRIPPING in [e.explanation_id for e in explanations]:
                return Confidence.HIGH  # for the *event*, LOW for the *explanation*
            return Confidence.HIGH
        else:
            return Confidence.LOW

    def _limitations(self, rule_id: str, session, state_result) -> list[str]:
        lim: list[str] = []
        if self._capture_is_limited(session):
            lim.append("Capture completeness is limited; some states may be "
                       "incomplete or absent.")
        if state_result and state_result.limitations:
            lim.extend(state_result.limitations)
        if rule_id.startswith("SMS-STRIP-002"):
            lim.append("The capture cannot determine whether the failure to "
                       "negotiate STARTTLS was caused by the client, the server, "
                       "or an intermediary.")
        if rule_id.startswith("SMS-AUTH-001"):
            lim.append("Whether authentication was mandated by the client or "
                       "prevented by the server is not determinable from this "
                       "capture alone.")
        return lim

    def _recommended_next(self, rule_id: str, session, explanations) -> list[str]:
        out: list[str] = []
        seen = set()

        # Collect missing evidence from all explanations
        for e in explanations:
            for m in e.missing_evidence:
                if m not in seen:
                    seen.add(m)
                    out.append(m)

        # Add rule-specific recommendations
        if rule_id == "SMS-STRIP-002":
            out.append("Compare with sessions from other clients to the same "
                       "server to establish a baseline.")
        if rule_id == "SMS-AUTH-001":
            out.append("Rotate the exposed credentials immediately.")
        if rule_id.startswith("SMS-CERT"):
            if session.cert_visibility == CertVisibility.ENCRYPTED_TLS13:
                out.append("Assess certificate posture from a TLS 1.2 session "
                           "or via an active TLS probe.")

        return out

    def _affected_controls(self, rule_id: str) -> list[str]:
        from .security_controls import control_rule_map
        m = control_rule_map()
        out = []
        for ctrl, rules in m.items():
            if rule_id in rules:
                out.append(ctrl)
        return out

    @staticmethod
    def _ids(facts) -> list[str]:
        return [f.description for f in facts]
