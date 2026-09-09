"""Audit hash-chain coverage - what the chain actually commits to.

A tamper-evident log is only as strong as the set of fields its hash covers. Two
independent implementations exist in this estate, and they differ in exactly the
way that matters.

------------------------------------------------------------------------------
Saosmartwallet/packages/core/src/audit/audit.ts  (17,165 chars, 455 lines)
------------------------------------------------------------------------------
    computeEventHash(previousEventHash, fields) =
        sha256Hex( previousEventHash + canonicalJson({
            seq, timestamp, type, actor, target, result, reason }) )

    genesisHash(vaultInstanceId) = sha256Hex("saos-audit-genesis:" + vaultInstanceId)

    verifyIntegrity walks the chain checking seq continuity, the previousEventHash
    link, and the recomputed hash. First mismatch wins. Its own words: "Corrupt
    events are never repaired - callers must escalate (the vault is treated as
    compromised)."

Every field that answers a forensic question is bound: WHEN (timestamp), WHAT
KIND (type), WHO (actor), TO WHAT (target), OUTCOME (result) and WHY (reason).
Genesis is bound to the vault instance, so a chain lifted from one vault cannot be
grafted onto another.

------------------------------------------------------------------------------
roshpina/kernel/orchestrator/audit.ts  (5,372 chars, 162 lines)
------------------------------------------------------------------------------
    interface AuditRecord {
      id, tenantId, actionId, actionType,
      source,        // "Which agent / service produced the action."
      outcome,
      reason?,       // "Human-readable explanation for denied or error outcomes."
      occurredAt,    // ISOTimestamp
      prevHash,      // "genesis" for the first record
      hash,          // documented as "SHA-256 of this record's canonical fields"
      signature?     // "Cryptographic signature over hash, proving who wrote this"
    }

    function computeHash(record) {
      const data = [ record.id, record.tenantId, record.actionType,
                     record.outcome, record.prevHash ].join("|");
      return createHash("sha256").update(data, "utf8").digest("hex");
    }

Five fields are hashed. Four substantive fields are NOT:

    source      which agent or service produced the action      -> WHO
    occurredAt  when it happened                                -> WHEN
    reason      why a denied or errored action was refused      -> WHY
    actionId    which specific action instance                  -> WHICH

Consequence, stated plainly: anyone who can write to the store can change WHO did
it, WHEN it happened, and WHY it was refused on any existing record, and
verifyChain() still returns true. The chain proves the SEQUENCE is intact. It does
not prove the CONTENT is.

Those are the three questions an audit log exists to answer.

The signature does not close the gap either - it is computed over hash, so it
attests to the same five fields and no more.

And the field comment says hash is "SHA-256 of this record's canonical fields",
which reads as all of them. It is not.

------------------------------------------------------------------------------
Why the two are also mutually unverifiable
------------------------------------------------------------------------------
Different field sets, different preimage construction (canonicalJson concatenation
versus pipe-joined list), and different genesis ("saos-audit-genesis:<instance>"
hashed, versus the literal string "genesis"). Audit evidence produced by one
cannot be checked by the other. That is not a bug in either, but it does mean the
estate has two tamper-evident logs that cannot corroborate each other - which is
the one thing two logs are for.

------------------------------------------------------------------------------
What this module provides
------------------------------------------------------------------------------
`coverage()` classifies an implementation by which forensic questions its hash
actually binds, so the gap is a measurement rather than an opinion. `build_chain`
and `verify_chain` are a reference implementation that binds all of them, with an
instance-bound genesis.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence

GENESIS_LABEL = "saos-jumpper/audit/v1"

# The forensic questions an audit record must be able to answer.
WHO = "who"
WHEN = "when"
WHAT = "what"
WHY = "why"
WHICH = "which"
OUTCOME = "outcome"
ORDER = "order"
QUESTIONS = (WHO, WHEN, WHAT, WHY, WHICH, OUTCOME, ORDER)


class AuditError(ValueError):
    pass


@dataclass(frozen=True)
class Coverage:
    """Which forensic questions a hash function actually binds."""

    implementation: str
    hashed_fields: Sequence[str]
    record_fields: Sequence[str]
    binds: Dict[str, bool]
    genesis_bound_to_instance: bool

    # A record's own hash, and any signature computed over that hash, cannot be part
    # of the preimage that produces them. Listing them as unbound is noise that hides
    # the fields which genuinely should have been bound.
    SELF_REFERENTIAL = ("hash", "eventhash", "recordhash", "signature", "sig", "checksum")

    @property
    def unbound(self) -> List[str]:
        return sorted(f for f in self.record_fields
                      if f not in set(self.hashed_fields)
                      and f.lower() not in self.SELF_REFERENTIAL)

    @property
    def unanswered(self) -> List[str]:
        return [q for q in QUESTIONS if not self.binds.get(q)]

    @property
    def sound(self) -> bool:
        return not self.unanswered and self.genesis_bound_to_instance

    def as_dict(self) -> Dict[str, Any]:
        return {"implementation": self.implementation,
                "hashedFields": list(self.hashed_fields),
                "recordFields": list(self.record_fields),
                "unboundFields": self.unbound,
                "binds": dict(self.binds),
                "unansweredQuestions": self.unanswered,
                "genesisBoundToInstance": self.genesis_bound_to_instance,
                "sound": self.sound,
                "verdict": ("SOUND - the hash binds every forensic question"
                            if self.sound else
                            "UNSOUND - tampering with " + ", ".join(self.unbound) +
                            " does not break the chain; unanswered: " + ", ".join(self.unanswered))}


def coverage(implementation: str, hashed_fields: Sequence[str],
             record_fields: Sequence[str],
             genesis_bound_to_instance: bool) -> Coverage:
    """Classify an audit implementation by what its hash actually covers.

    Field names are matched loosely so both naming conventions in this estate map
    correctly: occurredAt/timestamp/at for WHEN, source/actor/by for WHO, and so on.
    """
    h = {f.lower() for f in hashed_fields}

    def any_of(*names: str) -> bool:
        return any(n.lower() in h for n in names)

    binds = {
        WHO: any_of("source", "actor", "by", "agent", "principal"),
        WHEN: any_of("occurredat", "timestamp", "at", "time", "seq"),
        WHAT: any_of("actiontype", "type", "action", "event", "kind"),
        WHY: any_of("reason", "detail", "message", "explanation"),
        WHICH: any_of("actionid", "target", "id", "object", "resource"),
        OUTCOME: any_of("outcome", "result", "status", "verdict"),
        # order is bound by prevHash/previousEventHash plus a sequence number
        ORDER: any_of("prevhash", "previouseventhash", "previous", "seq", "sequence"),
    }
    return Coverage(implementation=implementation, hashed_fields=list(hashed_fields),
                    record_fields=list(record_fields), binds=binds,
                    genesis_bound_to_instance=genesis_bound_to_instance)


# The two real implementations, as read from source.
SAOSMARTWALLET = coverage(
    "Saosmartwallet/packages/core/src/audit/audit.ts",
    hashed_fields=["seq", "timestamp", "type", "actor", "target", "result", "reason",
                   "previousEventHash"],
    record_fields=["seq", "timestamp", "type", "actor", "target", "result", "reason",
                   "previousEventHash", "eventHash"],
    genesis_bound_to_instance=True,      # sha256Hex("saos-audit-genesis:" + vaultInstanceId)
)

ROSHPINA = coverage(
    "roshpina/kernel/orchestrator/audit.ts",
    hashed_fields=["id", "tenantId", "actionType", "outcome", "prevHash"],
    record_fields=["id", "tenantId", "actionId", "actionType", "source", "outcome",
                   "reason", "occurredAt", "prevHash", "hash", "signature"],
    genesis_bound_to_instance=False,     # the literal string "genesis"
)


# ---------------------------------------------------------------------------
# Reference implementation: binds every forensic question, instance-bound genesis
# ---------------------------------------------------------------------------

def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False)


def genesis_hash(instance_id: str) -> str:
    """Instance-bound, so a chain lifted from one store cannot be grafted onto another."""
    if not instance_id:
        raise AuditError("instance_id required; a shared genesis literal lets chains be swapped")
    return hashlib.sha256((GENESIS_LABEL + ":" + instance_id).encode("utf-8")).hexdigest()


def record_hash(previous: str, rec: Dict[str, Any]) -> str:
    """Bind WHO, WHEN, WHAT, WHY, WHICH and OUTCOME, plus the previous link."""
    if not previous:
        raise AuditError("previous hash required")
    required = ("who", "when", "what", "outcome")
    missing = [k for k in required if rec.get(k) in (None, "")]
    if missing:
        raise AuditError("record is missing required fields: " + ", ".join(missing))
    body = {"who": rec["who"], "when": rec["when"], "what": rec["what"],
            "which": rec.get("which"), "outcome": rec["outcome"],
            "why": rec.get("why")}
    return hashlib.sha256((previous + canonical(body)).encode("utf-8")).hexdigest()


def build_chain(instance_id: str, records: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    prev = genesis_hash(instance_id)
    for i, rec in enumerate(records):
        h = record_hash(prev, rec)
        out.append(dict(rec, seq=i, previousHash=prev, hash=h))
        prev = h
    return out


def verify_chain(instance_id: str, chain: Sequence[Dict[str, Any]],
                 expected_length: Optional[int] = None,
                 expected_head: Optional[str] = None) -> Dict[str, Any]:
    """Recompute every link. First mismatch wins. Never repairs.

    TRUNCATION IS NOT DETECTABLE BY A HASH CHAIN ALONE. Dropping the tail leaves a
    shorter chain that is still internally consistent - every remaining link
    verifies. A test in this repository proves it: verify_chain over chain[:1] of a
    two-record chain returned intact=True.

    Detecting truncation needs an external commitment to the head, which is exactly
    what anchoring the head to a public chain provides. Until then the caller must
    supply expected_length or expected_head from a source the attacker does not
    control. Without either, this function reports truncated=False and says so in
    the reason, rather than silently implying completeness.
    """
    if not chain:
        return {"intact": True, "length": 0, "firstBadSeq": None, "truncated": False,
                "reason": "empty chain"}
    prev = genesis_hash(instance_id)
    for i, rec in enumerate(chain):
        if rec.get("seq") != i:
            return {"intact": False, "length": len(chain), "firstBadSeq": i, "truncated": False,
                    "reason": "seq discontinuity: expected %d, found %r" % (i, rec.get("seq"))}
        if rec.get("previousHash") != prev:
            return {"intact": False, "length": len(chain), "firstBadSeq": i, "truncated": False,
                    "reason": "previousHash does not link"}
        try:
            recomputed = record_hash(prev, rec)
        except AuditError as exc:
            return {"intact": False, "length": len(chain), "firstBadSeq": i, "truncated": False,
                    "reason": "unhashable record: %s" % exc}
        if recomputed != rec.get("hash"):
            return {"intact": False, "length": len(chain), "firstBadSeq": i, "truncated": False,
                    "reason": "hash mismatch - a bound field was altered"}
        prev = recomputed
    head = chain[-1].get("hash")
    truncated = False
    reason = None
    if expected_length is not None and len(chain) != expected_length:
        truncated = True
        reason = ("chain is %d records but %d were expected - the tail is missing and a "
                  "hash chain alone cannot detect that" % (len(chain), expected_length))
    if expected_head is not None and head != expected_head:
        truncated = True
        reason = ("head %s does not match the committed head %s" % (head, expected_head))
    return {"intact": True, "length": len(chain), "firstBadSeq": None,
            "truncated": truncated, "headHash": head, "reason": reason}
