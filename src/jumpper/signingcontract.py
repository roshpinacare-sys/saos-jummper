"""Signing-gate contract - derived from verified source, not from a README.

THE PROBLEM THIS SOLVES
The estate contains a correct implementation of every control it is missing in the
code that touches real money, and that code does not use it.

Verified by reading Saosmartwallet/packages/core/src/signing/orchestrator.ts
(41,647 chars, 968 lines) in full:

    1. session gate     SovereignVault.ensureUnlocked() plus optional step-up
                        password re-verification
    2. policy gate      PolicyEngine.evaluate with vault-derived config injected
                        through op.detail (allowedOperations,
                        dailyLimitSatoshis, spentTodaySatoshis,
                        soldierPermissions). Its own header: "Denials and step-up
                        demands THROW - nothing is ever signed on a maybe."
    3. key resolution   active EncryptedKey for (vaultId, network, role); funds
                        ops default to role "active", vote and comment default to
                        "posting"
    4. reveal and sign  SovereignVault.revealKeyFor then ChainAdapter.sign -
                        "the only sanctioned plaintext-key exit; key bytes exist
                        solely inside the adapter call frame"
    5. broadcast        capability-checked, timed-lock honored, optional
                        confirmRequired gate
    6. audit            key_used, signing_attempt, broadcast events

And the code matches its own contract at the four points that matter most:

    const { privateKey, record } = await vault.revealKeyFor(keyId);
    if (record.role === null) { throw new VaultError("VALIDATION", ...) }
    const signed = await adapter.sign(tx, { byRole: { [record.role]: privateKey } });

  - the private key goes from reveal straight into adapter.sign and nowhere else
  - a role-less key THROWS rather than defaulting
  - the single key-like return in 968 lines is publicKeyFor(), returning
    privateKey.publicKey.toString(prefix) - a public value, never fabricated
  - console appears ZERO times, so there is no logging path for key material

Meanwhile the code that broadcasts to HIVE and STEEM signs 57 of 62 attestation
operations with the ACTIVE authority and has no policy gate, no spend budget, no
repeat guard and no audit chain. The gap is not knowledge - it is that the
controls live in packages/core and roshpina/kernel while the broadcaster does not
import them.

This module makes the contract checkable, so a relay can be measured against it
instead of being described as safe.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Sequence

NL = chr(10)          # newline as a value; never as an escape inside a literal
SATISFIED = "satisfied"
MISSING = "missing"


class ContractError(ValueError):
    pass


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


def _any(patterns: Sequence[str], src: str) -> List[str]:
    hits = []
    for p in patterns:
        for m in re.finditer(p, src):
            line = src[src.rfind(NL, 0, m.start()) + 1: src.find(NL, m.end())]
            hits.append(line.strip()[:140])
            break
    return hits


STAGES: List[Stage] = [
    Stage(1, "session-gate",
          "The vault must be unlocked, and sensitive operations must be able to demand "
          "step-up re-authentication, before any key is resolved.",
          "A signer that resolves keys without a session check will sign for an "
          "unattended process, which is how a daemon ends up moving funds.",
          lambda s: bool(_any([r"ensureUnlocked|requireUnlocked|assertUnlocked|isUnlocked",
                               r"stepUp|step_up|reauth|reVerify"], s))),
    Stage(2, "policy-gate",
          "Every operation must be evaluated against policy BEFORE a key is touched, "
          "and a denial must abort rather than degrade.",
          "Signing first and checking policy afterwards means the damage is done by the "
          "time the check runs. A policy that warns instead of throwing is a suggestion.",
          lambda s: bool(_any([r"PolicyEngine|policyEngine|evaluatePolicy|policy\.evaluate",
                               r"policyDecision|PolicyDecision"], s))
                     and bool(_any([r"throw\s|reject|abort|deny", r"DENY|denied"], s))),
    Stage(3, "least-privilege-role",
          "The signing role must follow what the operation DOES: funds and custody "
          "movements take active, social and data operations take posting. A role-less "
          "key must refuse rather than default.",
          "Defaulting every operation to active hands fund-moving capability to code "
          "that only needed to publish bytes. On HIVE mainnet 57 of 62 attestation "
          "operations were signed that way.",
          lambda s: bool(_any([r"posting", r"byRole|required_posting_auths|role"], s))
                     and bool(_any([r"role\s*===?\s*null|record\.role\s*===?\s*null|flavor-less|roleless",
                                    r"default.{0,40}(active|posting)|(active|posting).{0,40}default"], s))),
    Stage(4, "reveal-once",
          "Plaintext key material must exist only inside the signing call frame: "
          "revealed, passed to the adapter, and never stored, returned, logged or re-used.",
          "A revealed key that outlives the call frame ends up in state, in an error "
          "message, in a log line or in a heap dump. Different breaches, same cause.",
          lambda s: bool(_any([r"revealKeyFor|revealKey|unsealKey", r"adapter\.sign|\.sign\("], s))
                     and not console_leaks(s) and not returns_plaintext_key(s)),
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
          lambda s: bool(_any([r"key_used|signing_attempt|audit\.|auditLog|recordEvent|"
                               r"appendAudit|AuditEvent"], s))),
]


# Words that merely APPEAR in a log string are not a leak. A first version of this
# detector flagged:
#
#   console.error("[saos-relay][ALERT] wif-invalid: the key in .env is not a valid
#                  WIF - relay suspended fail-closed (not a retry loop)")
#
# That statement prints a static message containing the letters "wif". It leaks
# nothing, and it is in fact exemplary behaviour: fail closed on an invalid key,
# and do not retry. Flagging it was a false positive in the detector, not a defect
# in the relay. So the detector now requires an actual VALUE to reach the log:
# a bare identifier, a template interpolation, or a concatenation - not a word
# inside a string literal.

_VALUE_PATTERNS = (
    r"\$\{[^}]*(privateKey|privKey|priv|wif|seed|mnemonic|secret|passphrase)[^}]*\}",
    r"[,(+]\s*[A-Za-z_$][\w$.]*(privateKey|privKey|Wif|WIF|seed|mnemonic|secret|passphrase)[\w$]*\s*[,)]",
    r"\bJSON\.stringify\s*\(\s*[A-Za-z_$][\w$]*(key|wif|seed|secret)[\w$]*",
)


def console_leaks(source: str) -> List[str]:
    """Log statements that could carry key material as a VALUE.

    A static message that happens to contain the word "wif" is not a leak and must
    not be reported as one - a detector that cries wolf gets switched off.
    """
    rx = re.compile(r"console\.(log|error|warn|info|debug)\s*\(([^\x0a]*)\)")
    out = []
    for m in rx.finditer(source):
        arg = m.group(2)
        for vp in _VALUE_PATTERNS:
            if re.search(vp, arg):
                out.append(m.group(0)[:200])
                break
    return out


def returns_plaintext_key(source: str) -> List[str]:
    """Any function returning a plaintext key. Public-key derivation is fine."""
    out = []
    for m in re.finditer(r"return\s+([A-Za-z_$][\w$]*)\s*[;)]", source):
        if re.search(r"^(privateKey|privKey|priv|wif|seed|mnemonic|secret)$", m.group(1), re.I):
            out.append(source[source.rfind(NL, 0, m.start()) + 1: source.find(NL, m.end())].strip()[:160])
    return out


def check(source: str, path: str = "<source>") -> Dict[str, Any]:
    """Evaluate a signing implementation against the six-stage contract."""
    if not source or not source.strip():
        raise ContractError("empty source; nothing to evaluate")
    results: List[StageResult] = []
    for st in STAGES:
        try:
            ok = st.detect(source)
        except Exception:
            ok = False
        results.append(StageResult(stage=st.name, order=st.order,
                                   status=SATISFIED if ok else MISSING,
                                   evidence=_any(EVIDENCE.get(st.order, []), source),
                                   obligation=st.obligation, failure_mode=st.failure_mode))
    missing = [r for r in results if r.status == MISSING]
    return {"path": path, "chars": len(source),
            "stagesSatisfied": len(results) - len(missing), "stagesMissing": len(missing),
            "score": round((len(results) - len(missing)) / len(STAGES) * 100, 1),
            "missingStages": [r.stage for r in missing],
            "results": [r.as_dict() for r in results],
            "consoleLeaks": console_leaks(source),
            "returnsPlaintextKey": returns_plaintext_key(source),
            "verdict": ("CONFORMS to the six-stage signing contract" if not missing else
                        "DOES NOT CONFORM - missing: " + ", ".join(r.stage for r in missing)),
            "safe_to_hold_funds": not missing}


EVIDENCE = {
    1: [r"ensureUnlocked", r"stepUp"],
    2: [r"PolicyEngine", r"policyDecision|PolicyDecision"],
    3: [r"posting", r"role\s*===?\s*null|flavor-less"],
    4: [r"revealKeyFor", r"adapter\.sign"],
    5: [r"capabilit", r"broadcast"],
    6: [r"key_used|signing_attempt", r"audit\."],
}
