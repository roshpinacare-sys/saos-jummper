"""Gate composition - connecting the two correct halves of the risk gate.

THE GAP, FROM docs/TRUST-GATE.md
--------------------------------
roshpina has two mechanisms that each do half the job:

    kernel/adapter/agent-adapter.ts   DERIVES risk server-side via
                                      classifyActionServerSide, overrides the
                                      client claim, fails closed - and never calls
                                      the confidence gate (0 references)
    kernel/risk/confidence-gate.ts    THRESHOLDS a confidence score against six
                                      minimums - and reads actionLevel from its
                                      input without deriving one

Neither is wrong. They are not connected. On the adapter path a client-supplied
riskClass is overridden, which is safe. On any path that calls the confidence gate
directly with an agent-supplied actionLevel, the effective threshold drops from
0.95 to 0.85 and a self-reported 0.9 auto-approves.

WHAT THIS DOES
--------------
One function that takes BOTH halves and composes them: derive, then take the
maximum severity of derived and supplied, then threshold the score against the
minimum for the composed class. A caller can escalate and can never de-escalate.

THE TAXONOMY IS AN INPUT, NOT A GUESS
--------------------------------------
The kernel's ActionRiskClass lives in lib/orchestrator/types.ts and its most
restrictive member is documented as "irreversible". Rather than hardcode a
taxonomy that was not read end to end, `order` is a required argument: the caller
supplies the severity ordering, least restrictive first, exactly as the kernel
declares it. A composition that guessed the ordering would be worse than no
composition, because it would look authoritative.

An unknown class is refused rather than mapped to a default - the kernel's own
rule is that an unmapped class resolves to deny, and silently treating an unknown
class as the least restrictive would invert that."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import riskgate as RG

AUTO = RG.AUTO
HUMAN = RG.HUMAN
DENY = RG.DENY


class GateComposeError(ValueError):
    pass


def _rank(order: Sequence[str], cls: Any, label: str) -> int:
    if not isinstance(cls, str) or cls not in order:
        raise GateComposeError("%s %r is not in the supplied severity ordering; "
                               "refusing rather than defaulting, because the kernel"
                               " resolves an unmapped class to deny" % (label, cls))
    return order.index(cls)


def compose_class(order: Sequence[str], derived: Any, supplied: Any = None) -> Dict[str, Any]:
    """Escalation-only composition of a server-derived class and a client claim.

    `order` is least restrictive first. The result is whichever of the two ranks
    higher, and the report says which one won and why."""
    if not isinstance(order, (list, tuple)) or len(order) < 2:
        raise GateComposeError("order must list at least two severity levels, least first")
    if len(set(order)) != len(order):
        raise GateComposeError("order contains duplicates")
    d = _rank(order, derived, "derived class")
    if supplied is None or supplied == "":
        return {"class": derived, "rank": d, "source": "derived",
                "reason": "no client-supplied class; the derived class stands"}
    s = _rank(order, supplied, "supplied class")
    if s > d:
        return {"class": supplied, "rank": s, "source": "supplied",
                "reason": "client escalated %s -> %s (permitted)" % (derived, supplied)}
    if s < d:
        return {"class": derived, "rank": d, "source": "derived",
                "deEscalationAttempted": True,
                "reason": "client attempted to DE-ESCALATE %s -> %s; refused, "
                          "escalation only" % (derived, supplied)}
    return {"class": derived, "rank": d, "source": "agreed",
            "reason": "the supplied class agrees with the derived class"}


def resolve_approval(risk_to_approval: Dict[str, str], cls: str) -> str:
    """Mirror of resolveApprovalClass: an unmapped class denies.

    The kernel documents this as fail-closed and it is the single most important
    line in the composition - a mapping table with a permissive default turns every
    unknown action into an allowed one."""
    if not isinstance(risk_to_approval, dict):
        raise GateComposeError("risk_to_approval must be a mapping")
    v = risk_to_approval.get(cls)
    if not v:
        return "deny"
    return v


def gate(order: Sequence[str], risk_to_approval: Dict[str, str], derived: Any,
         supplied: Any, score: Any, thresholds: Optional[Dict[str, float]] = None,
         irreversible: bool = False, financial: bool = False) -> Dict[str, Any]:
    """The composed decision: derive, escalate-only, resolve approval, threshold.

    Returns both halves of the answer - the approval class from the policy router
    and the confidence decision from the threshold - plus which one governs. A
    deny from either is a deny; the composition never loosens what either half
    decided on its own."""
    comp = compose_class(order, derived, supplied)
    approval = resolve_approval(risk_to_approval, comp["class"])
    th = thresholds or {}
    mins = [RG.DEFAULT_THRESHOLDS.auto]
    if comp["rank"] >= len(order) - 2:
        mins.append(float(th.get("high", RG.DEFAULT_THRESHOLDS.min_high_risk)))
    if irreversible:
        mins.append(float(th.get("irreversible", RG.DEFAULT_THRESHOLDS.min_irreversible)))
    if financial:
        mins.append(float(th.get("financial", RG.DEFAULT_THRESHOLDS.min_financial)))
    eff = max(mins)
    clean, why = RG.sanitize_score(score)
    if approval == "deny":
        decision = DENY
        reason = "the approval router denied this risk class"
    elif clean < RG.DEFAULT_THRESHOLDS.human:
        decision = DENY
        reason = "score below the human threshold"
    elif clean >= eff:
        decision = AUTO
        reason = "score %.3f meets the effective threshold %.3f" % (clean, eff)
    else:
        decision = HUMAN
        reason = "score %.3f is below the effective threshold %.3f" % (clean, eff)
    out = {"decision": decision, "approvalClass": approval,
           "composedClass": comp["class"], "classSource": comp["source"],
           "classReason": comp["reason"],
           "deEscalationAttempted": bool(comp.get("deEscalationAttempted")),
           "score": clean, "effectiveThreshold": eff, "reason": reason,
           "scoreProvenance": why or "agent",
           "signaturesVerified": False}
    if why:
        out["scoreWarning"] = why
    return out
