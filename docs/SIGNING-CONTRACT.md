<!-- hardening:allow-file ALL reason=quotes the signing patterns and the defective relays it measures -->

# The Six-Stage Signing Contract

Derived by reading all 968 lines of
`Saosmartwallet/packages/core/src/signing/orchestrator.ts`, then measured against
every other signing or broadcasting path in the estate.

Implemented in `src/jumpper/signingcontract.py`, with 17 assertions in
`tests/test_signingcontract.py`.

---

## The measured result

| file | repo | score | safe to hold funds | missing stages |
|---|---|---|---|---|
| `signing/orchestrator.ts` | Saosmartwallet | **6/6 (100%)** | **yes** | none |
| `policy/engine.ts` | Saosmartwallet | 2/6 (33%) | n/a - not a signer | role, reveal, broadcast, audit |
| `relay.ts` | **saos-dex** | **3/6 (50%)** | **no** | session-gate, policy-gate, audit-trail |
| `anchor-live.ts` | **saos-sovereign-platform** | **1/6 (17%)** | **no** | all but capability-broadcast |

**The code designed to hold funds conforms completely. The code that actually
broadcasts to HIVE and STEEM mainnet conforms to half of it.** They are not
connected to each other.

`policy/engine.ts` at 2/6 is not a deficiency - it is the policy layer, not a
signing path, so it legitimately does not reveal keys or broadcast. The contract
is written for signing paths and says so.

---

## The six stages

| # | stage | obligation | what breaks without it |
|---|---|---|---|
| 1 | session-gate | vault unlocked, step-up re-auth available, before any key is resolved | a signer resolves keys for an unattended process - how a daemon ends up moving funds |
| 2 | policy-gate | policy evaluated BEFORE a key is touched; denial aborts | signing first and checking after means the damage is done when the check runs |
| 3 | least-privilege-role | role follows what the operation DOES; a role-less key refuses | defaulting to active hands fund-moving capability to code that only needed to publish bytes |
| 4 | reveal-once | plaintext key exists only inside the signing call frame | a key that outlives the frame ends up in state, an error, a log line or a heap dump |
| 5 | capability-checked-broadcast | broadcasting is a separate capability from signing | if signing implies broadcasting there is no dry-run - every test is a real transaction |
| 6 | audit-trail | key use, attempts and broadcasts all recorded, including failures | no way to answer who signed what, when, or whether something was refused |

---

## What the orchestrator does at the four points that matter

    const { privateKey, record } = await vault.revealKeyFor(keyId);
    if (record.role === null) {
      throw new VaultError("VALIDATION", `key ${keyId} is flavor-less (role null)`);
    }
    const signed = await adapter.sign(tx, { byRole: { [record.role]: privateKey } });

- the private key goes from reveal straight into `adapter.sign` and nowhere else
- a role-less key **throws** rather than defaulting to something
- the only key-like `return` in 968 lines is `publicKeyFor()`, which returns
  `privateKey.publicKey.toString(prefix)` - a derived public value, never fabricated
- `console` appears **zero** times, so there is no logging path for key material

Its header also states: *"Denials and step-up demands THROW - nothing is ever
signed on a maybe."* That is the policy gate behaving correctly.

---
