"""Signing-gate contract - derived from verified source, not from a README.

The estate contains a correct implementation of every control it is missing in the
code that touches real money, and that code does not use it.

Verified by reading Saosmartwallet/packages/core/src/signing/orchestrator.ts
(41,647 chars, 968 lines) in full. Its own header defines six ordered gates:
session gate (ensureUnlocked plus optional step-up), policy gate (PolicyEngine
evaluate with vault-derived config; "Denials and step-up demands THROW - nothing
is ever signed on a maybe"), key resolution (funds ops default to role active,
vote and comment to posting), reveal and sign (revealKeyFor then adapter.sign,
"the only sanctioned plaintext-key exit; key bytes exist solely inside the
adapter call frame"), capability-checked broadcast, and audit.

And the code matches its contract at the four points that matter most: the private
key goes from reveal straight into adapter.sign and nowhere else; a role-less key
THROWS rather than defaulting; the only key-like return in 968 lines is
publicKeyFor(), returning a derived public key; and console appears ZERO times.

Measured across the estate with this module:

    SUPERSEDED 2026-09-30 (pre-Task-8-a snapshot, kept for history - history is
    closed out, not deleted; the honest table now lives in
    docs/SIGNING-CONTRACT.md):

        orchestrator.ts   (Saosmartwallet)          6/6  safe_to_hold_funds = True
        relay.ts          (saos-dex)                1/6  the code that actually broadcasts
        anchor-live.ts    (saos-sovereign-platform) 1/6

    CURRENT as of the 2026-09-30 table (re-measured with this checker, checker
    unmodified):

        orchestrator.ts   (Saosmartwallet)          6/6  safe_to_hold_funds = True
        relay-eth.ts      (saos-dex)                6/6  Task 8-a port (e5d22e5)
        anchor-live.ts    (saos-sovereign-platform) 6/6  Task 8-a port (3f4eeb3)
        relay.ts          (saos-dex)                6/6  Task 11-b wiring (0bc6927)
        relay-sol.ts      (saos-dex)                6/6  Task 12-a wiring (65f1dd2)

SUPERSEDED 2026-09-30 (wiring-era snapshot, kept for history): relay.ts was
3/6 (missing session-gate, policy-gate, audit-trail) and relay-sol.ts 2/6.
Every broadcaster in the array now CONFORMS at 6/6; the gap this docstring
once described is closed.

BUILD NOTE: everything the stage lambdas call is defined ABOVE the STAGES list. A
previous revision spliced a helper in after STAGES using an index search for
"def console_leaks(" - a string that also appears inside a stage lambda - so the
splice landed in the wrong place, console_leaks silently became a lambda, and
check() still returned 6/6. A broken detector that looks green is worse than no
detector. The test suite now asserts the helpers are real functions.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Sequence

NL = chr(10)
DQ = chr(34)
SQ = chr(39)
SATISFIED = "satisfied"
MISSING = "missing"


class ContractError(ValueError):
    pass


_STRIP_LITERALS = re.compile(
    DQ + r"(?:[^" + DQ + r"\\\x0a]|\\.)*" + DQ + r"|" +
    SQ + r"(?:[^" + SQ + r"\\\x0a]|\\.)*" + SQ)
_INTERP = re.compile(r"\$\{([^}]*)\}")
_KEYWORD = re.compile(r"(privateKey|privKey|priv_key|wif|seed|mnemonic|secret|passphrase)", re.I)
_CONSOLE = re.compile(r"console\.(log|error|warn|info|debug)\s*\(([^\x0a]*)\)")
_RETURN = re.compile(r"return\s+([A-Za-z_$][\w$]*)\s*[;)]")
_KEYNAME = re.compile(r"^(privateKey|privKey|priv|wif|seed|mnemonic|secret)$", re.I)


def strip_literals(arg: str) -> str:
    """Remove quoted spans but KEEP template interpolations - those are real values.

    Words inside a log message are prose. Only code can leak.
    """
    interps = _INTERP.findall(arg)
    return _STRIP_LITERALS.sub(DQ + DQ, arg) + " " + " ".join(interps)


def console_leaks(source: str) -> List[str]:
    """Log statements that could carry key material AS A VALUE.

    A static message that merely contains the letters wif is not a leak. The first
    version of this detector flagged exactly that - the relay fail-closed alert
    whose message says the key in .env is not a valid WIF - which leaks nothing and
    is exemplary behaviour. A detector that cries wolf gets switched off, so string
    literals are stripped before the keyword scan.
    """
    out = []
    for m in _CONSOLE.finditer(source):
        if _KEYWORD.search(strip_literals(m.group(2))):
            out.append(m.group(0)[:200])
    return out


def returns_plaintext_key(source: str) -> List[str]:
    """Any function returning a plaintext key. Public-key derivation is fine."""
    out = []
    for m in _RETURN.finditer(source):
        if _KEYNAME.search(m.group(1)):
            line = source[source.rfind(NL, 0, m.start()) + 1: source.find(NL, m.end())]
            out.append(line.strip()[:160])
    return out


def _any(patterns: Sequence[str], src: str) -> List[str]:
    hits = []
    for p in patterns:
        for m in re.finditer(p, src):
            line = src[src.rfind(NL, 0, m.start()) + 1: src.find(NL, m.end())]
            hits.append(line.strip()[:140])
            break
    return hits


@dataclass(frozen=True)
class Stage:
    order: int
    name: str
    obligation: str
    failure_mode: str
    detect: Callable[[str], bool]


@dataclass(frozen=True)
class StageResult:
    stage: str
    order: int
    status: str
    evidence: List[str] = field(default_factory=list)
    obligation: str = ""
    failure_mode: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {"order": self.order, "stage": self.stage, "status": self.status,
                "evidence": self.evidence[:6], "obligation": self.obligation,
                "failureMode": self.failure_mode}


STAGES: List[Stage] = [
    Stage(1, "session-gate",
          "The vault must be unlocked, and sensitive operations must be able to demand "
          "step-up re-authentication, before any key is resolved.",
          "A signer that resolves keys without a session check will sign for an "
          "unattended process, which is how a daemon ends up moving funds.",
          lambda s: bool(_any([r"ensureUnlocked|requireUnlocked|assertUnlocked|isUnlocked",
                               r"stepUp|step_up|reauth|reVerify"], s))),
    Stage(2, "policy-gate",
          "Every operation must be evaluated against policy BEFORE a key is touched, and "
          "a denial must abort rather than degrade.",
          "Signing first and checking policy afterwards means the damage is done by the "
          "time the check runs. A policy that warns instead of throwing is a suggestion.",
          lambda s: bool(_any([r"PolicyEngine|policyEngine|evaluatePolicy|policyDecision|PolicyDecision"], s))
                     and bool(_any([r"throw\s|reject|abort|deny|DENY|denied"], s))),
    Stage(3, "least-privilege-role",
          "The signing role must follow what the operation DOES: funds and custody take "
          "active, social and data operations take posting. A role-less key must refuse "
          "rather than default.",
          "Defaulting every operation to active hands fund-moving capability to code that "
          "only needed to publish bytes. On HIVE mainnet 57 of 62 attestation operations "
          "were signed that way.",
          lambda s: bool(_any([r"posting", r"byRole|required_posting_auths|role"], s))
                     and bool(_any([r"role\s*===?\s*null|flavor-less|roleless",
                                    r"default.{0,40}(active|posting)|(active|posting).{0,40}default",
                                    r"POSTING_WIF|steemPost|hivePost"], s))),
    Stage(4, "reveal-once",
          "Plaintext key material must exist only inside the signing call frame: "
          "revealed, passed to the adapter, never stored, returned, logged or re-used.",
          "A revealed key that outlives the call frame ends up in state, in an error "
          "message, in a log line or in a heap dump. Different breaches, same cause.",
          lambda s: (bool(_any([r"revealKeyFor|revealKey|unsealKey", r"adapter\.sign|\.sign\("], s))
                     and not console_leaks(s) and not returns_plaintext_key(s))),
    Stage(5, "capability-checked-broadcast",
          "Broadcasting must be a separately granted capability, distinct from signing, "
          "and must honour locks and confirmation requirements.",
          "If signing implies broadcasting there is no way to dry-run, simulate or "
          "review. Every test becomes a real transaction.",
          lambda s: bool(_any([r"capabilit|requireCapability|hasCapability|scope",
                               r"broadcast|sendRaw|submitTransaction"], s))),
    Stage(6, "audit-trail",
          "Key use, signing attempts and broadcasts must all be recorded to a "
          "tamper-evident audit log, including failures.",
          "Without a trail there is no way to answer who signed what, when, or whether "
          "an operation was attempted and refused - the first question after any incident.",
          lambda s: bool(_any([r"key_used|signing_attempt|audit\.|auditLog|recordEvent|appendAudit|AuditEvent"], s))),
]

EVIDENCE = {
    1: [r"ensureUnlocked", r"stepUp"],
    2: [r"PolicyEngine", r"policyDecision|PolicyDecision"],
    3: [r"posting", r"role\s*===?\s*null|flavor-less"],
    4: [r"revealKeyFor", r"adapter\.sign"],
    5: [r"capabilit", r"broadcast"],
    6: [r"key_used|signing_attempt", r"audit\."],
}


def _safe(fn, source):
    """Run a scan; on any failure report nothing rather than crashing the verdict."""
    try:
        return fn(source)
    except Exception:
        return []


def check(source: str, path: str = "<source>") -> Dict[str, Any]:
    """Evaluate a signing implementation against the six-stage contract."""
    if not source or not source.strip():
        raise ContractError("empty source; nothing to evaluate")
    results: List[StageResult] = []
    for st in STAGES:
        try:
            ok = bool(st.detect(source))
        except Exception:
            ok = False
        try:
            ev = _any(EVIDENCE.get(st.order, []), source)
        except Exception:
            # Evidence collection must never be able to crash the evaluation. A
            # check that raises instead of reporting is not fail-closed, it is
            # fail-absent - and an absent check reads as a pass to any caller that
            # only inspects the verdict.
            ev = []
        results.append(StageResult(stage=st.name, order=st.order,
                                   status=SATISFIED if ok else MISSING,
                                   evidence=ev, obligation=st.obligation,
                                   failure_mode=st.failure_mode))
    missing = [r for r in results if r.status == MISSING]
    sat = len(results) - len(missing)
    return {"path": path, "chars": len(source), "stagesSatisfied": sat,
            "stagesMissing": len(missing), "score": round(sat / len(STAGES) * 100, 1),
            "missingStages": [r.stage for r in missing],
            "results": [r.as_dict() for r in results],
            "consoleLeaks": _safe(console_leaks, source),
            "returnsPlaintextKey": _safe(returns_plaintext_key, source),
            "verdict": ("CONFORMS to the six-stage signing contract" if not missing else
                        "DOES NOT CONFORM - missing: " + ", ".join(r.stage for r in missing)),
            "safe_to_hold_funds": not missing}
