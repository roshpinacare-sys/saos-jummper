<!-- hardening:allow-file ALL reason=quotes both real hash functions and the fields each leaves unprotected -->

# Audit Chain Audit - what each hash actually commits to

Two independent tamper-evident audit chains exist in this estate. Both are
hash-chained, both recompute every link on verification, both refuse to repair a
broken chain. They differ in one respect that decides whether they are worth
anything: **which fields the hash covers.**

An audit log exists to answer four questions - who, what, when, and why it was
refused. A chain that does not bind those fields proves the sequence survived, and
nothing else.

---

## Saosmartwallet/packages/core/src/audit/audit.ts - SOUND

17,165 chars, 455 lines.

    computeEventHash(previousEventHash, fields) =
        sha256Hex( previousEventHash + canonicalJson({
            seq, timestamp, type, actor, target, result, reason }) )

    genesisHash(vaultInstanceId) = sha256Hex("saos-audit-genesis:" + vaultInstanceId)

    verifyIntegrity: walks the chain checking seq continuity, the previousEventHash
    link and the recomputed hash. First mismatch wins. Its own words: "Corrupt
    events are never repaired - callers must escalate (the vault is treated as
    compromised)."

| forensic question | bound by |
|---|---|
| WHO | `actor` |
| WHEN | `timestamp` |
| WHAT | `type` |
| WHICH | `target` |
| OUTCOME | `result` |
| WHY | `reason` |
| ORDER | `seq` + `previousEventHash` |

Every question answered. Genesis is bound to the vault instance, so a chain lifted
from one vault cannot be grafted onto another.

**Verdict: SOUND.** The only unbound field is `eventHash` itself, which cannot be
part of the preimage that produces it.

---

## roshpina/kernel/orchestrator/audit.ts - UNSOUND

5,372 chars, 162 lines. The record type has eleven fields:

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

And the hash binds five of them:

    function computeHash(record) {
      const data = [ record.id, record.tenantId, record.actionType,
                     record.outcome, record.prevHash ].join("|");
      return createHash("sha256").update(data, "utf8").digest("hex");
    }

| forensic question | field that answers it | bound? |
|---|---|---|
| **WHO** | `source` | **NO** |
| **WHEN** | `occurredAt` | **NO** |
| **WHY** | `reason` | **NO** |
| WHICH | `actionId` | **NO** |
| WHAT | `actionType` | yes |
| OUTCOME | `outcome` | yes |
| ORDER | `prevHash` | yes |

### What that permits

Anyone who can write to the store can rewrite **which agent produced the action**,
**when it happened**, and **why a refusal was refused** on any existing record -
and `verifyChain()` still returns `true`.

Those are three of the four questions the log exists to answer.

The signature does not close the gap. It is computed over `hash`, so it attests to
the same five fields and no more. A signature over a hash that omits `source` does
not prove who acted.

And the field comment says `hash` is *"SHA-256 of this record's canonical fields"* -
which reads as all of them. It is not.

Genesis is also the literal string `"genesis"`, shared across every tenant and
every store, so nothing binds a chain to the instance that produced it. `tenantId`
is hashed, which prevents cross-tenant grafting, but not re-genesis of a single
tenant's history.

### Severity

**HIGH for anything used as evidence, MEDIUM otherwise.** The chain still detects
insertion, deletion of a middle record, reordering and mutation of `actionType` or
`outcome`. It does not detect rewriting of attribution, timing or justification -
which is what an adversary trying to hide a refused action would change first.

The fix is small: add `source`, `occurredAt`, `reason` and `actionId` to the joined
preimage, and bind genesis to a store instance. Both are one-line changes. The
stored hashes of existing records would need recomputing, so it is a migration, not
a patch - which is the only reason it is not trivial.

---

## The two cannot corroborate each other

Different field sets, different preimage construction (`canonicalJson`
concatenation versus a pipe-joined list) and different genesis (an instance-bound
hash versus the literal `"genesis"`).

Evidence produced by one cannot be verified by the other. That is not a bug in
either, but it means the estate runs two tamper-evident logs that cannot
cross-confirm - which is the one thing two logs are for.

---

## A negative result my own test produced

`src/jumpper/audit.py` ships a reference chain that binds all seven questions, with
an instance-bound genesis. Testing it produced a result the code then had to admit:

    verify_chain("vault-1", chain[:1])   ->   intact = True

**A truncated chain still verifies.** Dropping the tail leaves a shorter chain that
is internally consistent - every remaining link recomputes correctly. A hash chain
alone cannot detect truncation.

Detecting it requires an external commitment to the head, which is exactly what
anchoring provides. The verifier therefore takes `expected_length` and
`expected_head`, and when neither is supplied it reports `truncated: False` **with
the reason stated in the module docstring** rather than implying completeness.

This is the strongest argument in the whole project for anchoring the audit head to
a public chain, and it came out of a test failing to find a problem rather than out
of a design review.

---

## Verified behaviour of the reference chain

    built chain, 3 records                     intact = True
    tamper who     -> agent-evil               intact = False, firstBadSeq = 0
    tamper when    -> 2020-01-01T00:00:00Z     intact = False, firstBadSeq = 0
    tamper why     -> "approved by the owner"  intact = False, firstBadSeq = 0
    tamper outcome -> success                  intact = False, firstBadSeq = 0
    reorder records                            intact = False
    wrong instance id                          intact = False, previousHash does not link
    truncate to 1 of 3, no external commit     intact = True   <- the blind spot
    truncate to 1 of 3, expected_length = 3    intact = True, truncated = True
    truncate to 1 of 3, expected_head = head   truncated = True

29 assertions in `tests/test_audit.py`, including that omitting WHY alone, or WHICH
alone, makes a chain unsound, and that a shared genesis literal makes it unsound
even with full field coverage.

---

## Actions

| # | action | severity | effort |
|---|---|---|---|
| 1 | Add `source`, `occurredAt`, `reason`, `actionId` to roshpina's `computeHash` preimage | **HIGH** | one line, plus a hash migration |
| 2 | Bind roshpina's genesis to a store instance instead of the literal `"genesis"` | MEDIUM | one line |
| 3 | Anchor the audit head publicly so truncation becomes detectable | **HIGH** | the free HIVE path already exists |
| 4 | Correct the `hash` field comment: it is not the canonical fields, it is five of them | LOW | one line |
| 5 | Pick one chain format for the estate, or publish a cross-verification adapter | MEDIUM | design decision |

Action 3 is the one that connects to everything else already built: `graphene.py`
anchors for free, `packing.py` fits 154 roots per operation, and `sth.py` packs
signed tree heads. An audit head anchored every few hours on HIVE costs nothing and
closes the truncation blind spot permanently.

---

*Read-only throughout. No file outside saos-jummper was created, modified or
deleted. No keys read, no transactions signed, nothing broadcast.*
