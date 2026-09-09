"""Risk-gate escalation - a caller may raise the risk of an action, never lower it.

THE GATE THIS WAS WRITTEN AGAINST
---------------------------------
roshpina/kernel/risk/confidence-gate.ts (10,765 chars, 293 lines) is a good
implementation. Verified in its body, not its docstring:

    sanitizeScore           missing / non-number / NaN / non-finite -> 0, reason recorded;
                            out-of-range clamped and reported
    effectiveActionLevel    missing or invalid level -> treated as high, documented in
                            the trace as "actionLevel missing -> treated as high"
    prohibited              -> deny unconditionally, BEFORE any score comparison
    traceability            every evaluation returns reasons[], scoreSource
                            (agent | default_low | policy_override) and effectiveThreshold

An earlier suspicion that a self-reported score of 1.0 could auto-approve a
prohibited action was WRONG. The relevant line is:

    return (level === "prohibited" ? "deny"
            : score >= effectiveThreshold ? "auto" : "human");

Prohibited short-circuits to deny before the comparison, and minForProhibited 1.0
is belt and braces on top of that. The gate is sound on every axis it claims.

THE ONE GAP
-----------
The gate never derives the risk level itself. Its inputs are:

    score, actionLevel, category, irreversible, financial, actorReputation,
    tenantOverride

`classifyAction` appears exactly once in the file, inside a comment showing the
intended caller usage. So a MISSING level is safely escalated to high, but a
SUPPLIED level is trusted verbatim. The header says the score is advisory and the
gate is the enforcement point - which is right about the score. The level is what
sets the threshold, and it arrives from the same place the score does.

With the real DEFAULT_CONFIDENCE_POLICY (auto 0.85, human 0.50, minForHighRisk
0.90, minForIrreversible 0.90, minForFinancial 0.95, minForProhibited 1.0):

    action declared informational, self-reported score 0.90
        effectiveThreshold = max(0.85, 0, 0, 0, 0, 0) = 0.85   ->  auto

    the same action correctly classified financial and irreversible
        effectiveThreshold = max(0.85, 0.90, 0.95)    = 0.95   ->  human

The difference between those two outcomes is one string the caller supplies.

THE RULE
--------
Escalation only. A gate must derive the level from the action itself and then take
the MAXIMUM severity of the derived level and any supplied level. A caller can
always raise the bar; it can never lower it. That preserves every legitimate use of
a supplied level - an operator marking something more dangerous than the catalogue
knows - while removing the ability to talk a gate down.

This module implements that rule and provides a detector for gates that accept a
caller-supplied level without deriving one.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

LEVELS: Tuple[str, ...] = ("informational", "routine", "sensitive", "high", "prohibited")
RANK: Dict[str, int] = {name: i for i, name in enumerate(LEVELS)}

AUTO = "auto"
HUMAN = "human"
DENY = "deny"


class RiskGateError(ValueError):
    pass


# Mirrors PROHIBITED_ACTIONS in kernel/risk/action-risk.ts. Kept short on purpose:
# this module is about the escalation rule, not about reproducing a catalogue that
# already exists and is better maintained there.
PROHIBITED_PATTERNS: Tuple[str, ...] = (
    r"rm\s+-rf\s+/(\s|$)",
    r"sudo\s+rm\s+-rf\s+/(\s|$)",
    r"dd\s+if=/dev/zero\s+of=/dev/",
    r"\bmkfs\b",
    r"chmod\s+-R\s+777\s+/(\s|$)",
    r"curl[^|]*\|\s*(ba)?sh",
    r"wget[^|]*\|\s*(ba)?sh",
    r"git\s+push\s+(--force|-f)\b",
)

FINANCIAL_PATTERNS: Tuple[str, ...] = (
    r"\btransfer\b", r"\bwithdraw\b", r"\bsend\b", r"\bpayment\b",
    r"\bbroadcast\b", r"\bswap\b", r"\bstake\b", r"\bunstake\b",
    r"\bconvert\b", r"\bmint\b", r"\bburn\b", r"\bescrow\b",
)

IRREVERSIBLE_PATTERNS: Tuple[str, ...] = (
    r"\bdelete\b", r"\bdrop\b", r"\bpurge\b", r"\brotate\b",
    r"account_update", r"\bforce\b", r"\brevoke\b",
)


def derive_level(command: Any) -> str:
    """Derive a risk level from the action itself.

    Deliberately conservative: a prohibited pattern wins, anything financial or
    irreversible is at least high, and an empty or non-string command is high
    rather than informational. A gate that cannot tell what it is being asked to
    approve must not assume the answer is benign.
    """
    if not command or not isinstance(command, str) or not command.strip():
        return "high"
    text = command.strip()
    for pat in PROHIBITED_PATTERNS:
        if re.search(pat, text, re.I):
            return "prohibited"
    financial = any(re.search(p, text, re.I) for p in FINANCIAL_PATTERNS)
    irreversible = any(re.search(p, text, re.I) for p in IRREVERSIBLE_PATTERNS)
    if financial or irreversible:
        return "high"
    return "routine"


def escalate_only(derived: str, supplied: Optional[str]) -> Tuple[str, str]:
    """Take the maximum severity. Returns (effective_level, why).

    An unrecognised supplied level is ignored rather than trusted, and the reason
    is returned so the caller can log it. Ignoring is safe here because the derived
    level is already in force; the supplied value could only have raised it.
    """
    if derived not in RANK:
        raise RiskGateError("derived level %r is not a known level" % derived)
    if supplied is None or supplied == "":
        return derived, "no level supplied; using the derived level"
    if supplied not in RANK:
        return derived, "supplied level %r is not a known level; ignored" % supplied
    if RANK[supplied] > RANK[derived]:
        return supplied, "caller escalated %s -> %s (permitted)" % (derived, supplied)
    if RANK[supplied] < RANK[derived]:
        return derived, ("caller attempted to DE-ESCALATE %s -> %s; refused, "
                         "escalation only" % (derived, supplied))
    return derived, "supplied level agrees with the derived level"


@dataclass(frozen=True)
class Thresholds:
    auto: float = 0.85
    human: float = 0.50
    min_high_risk: float = 0.90
    min_irreversible: float = 0.90
    min_financial: float = 0.95
    min_prohibited: float = 1.0


DEFAULT_THRESHOLDS = Thresholds()


def sanitize_score(value: Any) -> Tuple[float, Optional[str]]:
    """Missing, non-numeric or non-finite becomes 0 - the lowest confidence.

    Mirrors sanitizeScore in confidence-gate.ts, which is correct and worth
    reproducing exactly so the two implementations agree.
    """
    if value is None:
        return 0.0, "no score provided - treating as minimum confidence"
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 0.0, "non-numeric score %r - treating as minimum confidence" % (value,)
    f = float(value)
    if f != f or f in (float("inf"), float("-inf")):
        return 0.0, "non-finite score - treating as minimum confidence"
    if f < 0.0 or f > 1.0:
        return min(1.0, max(0.0, f)), "score out of range - clamped"
    return f, None


def evaluate(command: Any, supplied_score: Any, supplied_level: Optional[str] = None,
             irreversible: bool = False, financial: bool = False,
             thresholds: Thresholds = DEFAULT_THRESHOLDS) -> Dict[str, Any]:
    """Decide auto / human / deny. Escalation only; prohibited always denies."""
    derived = derive_level(command)
    level, why = escalate_only(derived, supplied_level)
    score, score_reason = sanitize_score(supplied_score)
    de_escalated = supplied_level in RANK and RANK[supplied_level] < RANK[derived]

    reasons: List[str] = []
    if score_reason:
        reasons.append(score_reason)
    reasons.append(why)

    if level == "prohibited":
        reasons.append("action is prohibited - denied regardless of score")
        return {"decision": DENY, "level": level, "derivedLevel": derived,
                "suppliedLevel": supplied_level, "score": score,
                "effectiveThreshold": thresholds.min_prohibited, "reasons": reasons,
                "deEscalationAttempted": de_escalated}

    mins = [thresholds.auto]
    if level == "high":
        mins.append(thresholds.min_high_risk)
    if irreversible:
        mins.append(thresholds.min_irreversible)
    if financial:
        mins.append(thresholds.min_financial)
    eff = max(mins)

    if score < thresholds.human:
        decision = DENY
        reasons.append("score below the human threshold - deny")
    elif score >= eff:
        decision = AUTO
    else:
        decision = HUMAN
        reasons.append("score %.3f is below the effective threshold %.3f" % (score, eff))

    return {"decision": decision, "level": level, "derivedLevel": derived,
            "suppliedLevel": supplied_level, "score": score, "effectiveThreshold": eff,
            "reasons": reasons, "deEscalationAttempted": de_escalated}


def gate_accepts_unverified_level(src: str) -> Dict[str, Any]:
    """Static check for the de-escalation gap.

    A gate is exposed when it reads a risk level from its input AND does not derive
    one from the action itself. Deriving and then taking the maximum is safe;
    trusting the input is not.

    Derivation requires an actual CALL on a code line. An earlier version of this
    detector counted any mention of PROHIBITED_ACTIONS as derivation and returned a
    false negative on the real file - referencing a blocklist for the deny
    short-circuit says nothing about where the LEVEL came from. Comments and
    docstrings are stripped before the search for the same reason.
    """
    if not src or not src.strip():
        raise RiskGateError("empty source; nothing to evaluate")
    NL = chr(10)
    code = NL.join(ln for ln in src.split(NL)
                   if not ln.strip().startswith(("*", "//", "#")))
    reads_input_level = bool(re.search(
        r"(input|req|request|payload|args|opts|options|body)\s*[.\[]\s*"
        r"(actionLevel|riskLevel|level|severity|risk)", code))
    derives = bool(re.search(r"\b(classifyAction|deriveLevel|derive_level|"
                             r"categoriseAction|categorizeAction|assessRisk)\s*\(", code))
    escalates = bool(re.search(r"Math\.max\s*\(\s*\w*[Ll]evel|escalate_only|"
                               r"max\s*\(\s*derived|maxSeverity|highestOf", code))
    prohibited_short_circuit = bool(re.search(
        r"(prohibited|PROHIBITED)[^;" + NL + r"]{0,80}(deny|DENY|reject|block)", src))
    exposed = reads_input_level and not (derives or escalates)
    # HONEST LIMITATION: this is a heuristic over source text. It returned
    # exposed=True for confidence-gate.ts in one run and exposed=False in another
    # after the comment-stripping and escalation patterns were tightened, which
    # means it is not yet stable enough to gate on. It is published as a review aid
    # with that caveat attached, not as an authority. The escalation rule in
    # escalate_only() and evaluate() IS tested and is the part to rely on.
    return {
        "calibrated": False,
        "caveat": "heuristic over source text; not stable enough to gate on - use as a review aid",
        "readsCallerSuppliedLevel": reads_input_level,
        "derivesLevelFromAction": derives,
        "escalationOnly": escalates,
        "prohibitedAlwaysDenies": prohibited_short_circuit,
        "exposed": exposed,
        "verdict": ("EXPOSED - reads a caller-supplied risk level and never derives "
                    "one, so a caller can lower the threshold by declaring a benign "
                    "level" if exposed else
                    "not exposed - reads no caller-supplied level" if not reads_input_level else
                    "derives or escalates - a caller cannot lower the level"),
    }
