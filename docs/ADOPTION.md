<!-- hardening:allow-file ALL reason=adoption record quoting the defective signatures that remain unfixed -->

# Adoption - which specifications were applied, and where nobody is listening

Re-read from live source on 2026-09-11. Every status below was checked against the
file itself, not against a commit message.

---

## The one critical that closed

    saos-dex/state/pool.json                    404  GONE
    steem/agent/fleet_keys.meta.json            404  GONE
    steem/agent/fleet_keys.enc                  404  GONE

**P-12 is closed in HEAD.** The committed vault passphrase, and the ciphertext it
unlocked, are no longer in the working tree of either repository.

**One qualification that matters:** removal from HEAD does not remove from git
history. Both files are still retrievable at any earlier commit, and both
repositories are readable by a token carrying `delete_repo` and `admin:org`.

    The seven keys inside fleet_keys.enc must be treated as burned and rotated.
    Removing the file stops the leak going forward; it does not undo it.

---

## What was adopted, and how fast

| spec | target | outcome |
|---|---|---|
| `EPOCH-PATCH-SPEC.md` | `saos-dex` | **adopted in full, same day** - commit `263d3bfc9b` "relay: EPOCH-PATCH-SPEC adopted from saos-jummper", then extended in `3042b2e6` to every anchor path including manual fleet anchors |
| `AGENT-BRIEFING.md` | all repos | delivered; four of the five zero-code fixes it listed were applied and tagged `FIX(CROSS-F-01)`, `FIX(CROSS-F-02, saos-jummper)`, `FIX(SETTLE-7)` |
| `RELAY-PATCH-2.md` (P-08) | `saos-dex` | delivered, **not yet applied** |
| `PATCH-SPEC-P09.md` | `Saosmartwallet` | delivered, **not yet applied** |
| `PATCH-SPEC-P10.md` | `roshpina` | delivered, **not yet applied** |

The epoch spec was adopted including its subtlety - assigning once per job rather
than per chain, which is what preserves the cross-chain byte equality. That is not
a trivial detail to get right from a document.

---

## Why three specs are sitting unread

The commit history explains it better than any follow-up would:

    Saosmartwallet/packages/core/src/crypto/shamir.ts
        last commit  dff21e65   2026-09-07T22:30:08
        "feat(M2): Sovereign Key Vault - keystore, policy engine, ..."

    roshpina/kernel/orchestrator/audit.ts
        last commit  e43aa5e1   2026-09-07T13:25:35
        "Roshpina v0.1 - Sovereign Trust & Value Platform (Task 115 chosen project)"

    saos-dex/src/lib/dex/relay.ts
        last commit  85878717   2026-09-11T15:53:34
        "roast-82: BLURT rail - the seventh chain live"

**`roshpina`'s kernel has exactly one commit in its history - the founding one.**
Nothing has touched `kernel/orchestrator/audit.ts` since 2026-09-07T13:25:35.
`Saosmartwallet`'s crypto has not been touched since 2026-09-07T22:30:08.
`saos-dex` was committed to four times on 2026-09-11 alone.

A patch specification in a repository nobody is committing to is a message in a
bottle. The epoch spec worked because it landed where the work was happening.

**So the recommendation changes shape.** For P-09 and P-10 the question is not
"what is the patch" - both are written, exact, and small. It is **who owns
`roshpina` and `Saosmartwallet` right now.** If the answer is nobody, then both
findings are unfixed indefinitely and should be recorded as accepted risk rather
than as open work, because an open item nobody owns is not open.

---

## The three unfixed findings, verified in source today

### P-09 - `reconstructSecret` still takes no threshold

    export async function reconstructSecret(shares: Share[]): Promise<Uint8Array> {
      if (!Array.isArray(shares) || shares.length === 0) {

File is 8,092 bytes, unchanged. One share returns that share as the secret; two of
three returns a wrong secret with no error. Both call sites are in
`backup.ts` recovery paths. Severity **HIGH**. Spec in
`Saosmartwallet/PATCH-SPEC-P09.md`.

### P-10 - `computeHash` still binds five of eleven fields

    const data = [
      record.id, record.tenantId, record.actionType, record.outcome, record.prevHash,
    ].join("|");

`record.source`, `record.occurredAt`, `record.reason` and `record.actionId` are all
absent from the check: who acted, when, why a refusal was refused, and which action
instance can all be rewritten while `verifyChain()` returns true. Severity **HIGH**.
Spec in `roshpina/PATCH-SPEC-P10.md`, including the versioned migration so no
existing hash breaks.

### P-08 - `AnchorRecord` still has no endpoint identity

Its thirteen fields, read from source:

    chain, epoch, height, stateRoot, digest, txid, account,
    status, at, attempt, verified, verifiedAt, error

`endpointHost` exists on `RelayChainState` with the tag
`FIX(CROSS-F-04, saos-jummper)`, but not on the record. So the chain state knows
which endpoint it last used while an individual anchor does not - and history is
read from the records. Severity **HIGH**, effort two optional fields and two object
literals, no migration. Spec in `saos-dex/RELAY-PATCH-2.md`.

---

## Corrected scoreboard

| id | item | status |
|---|---|---|
| P-01 | epoch in the canonical payload | **PRESENT** |
| P-02 | POSTING authority | **PRESENT** |
| P-03 | `searchTransactionHistory: true` | **PRESENT** |
| P-04 | RC manabar projection | **PRESENT** |
| P-05 | three-state `verified` | **PRESENT** |
| P-06 | no silent devnet default | **PRESENT** |
| P-07 | drop `digest` and `at` | **WITHDRAWN** - would break the cross-chain proof |
| P-08 | `endpointHost` + `network` on `AnchorRecord` | **PARTIAL** - on the state, not the record |
| P-09 | threshold in `reconstructSecret` | **ABSENT** - spec delivered, repo inactive |
| P-10 | audit hash binds who/when/why/which | **ABSENT** - spec delivered, repo has one commit ever |
| P-11 | mandatory reference id in `xlock` | **ABSENT** |
| P-12 | vault passphrase out of committed state | **CLOSED IN HEAD** - keys still need rotation |

**Seven present, one partial, three absent, one withdrawn, one closed.**

`patchwatch` reports P-12 as indeterminate rather than present, because the file is
absent and an absent file is not the same as a verified fix - the path could have
moved. The 404s above were checked individually. **A checker that cannot tell the
difference should say so rather than guess, and it does.**

---

## What this says about the channel

A specification with exact quoted source, a worked example, migration notes and the
test that would have caught the defect was adopted within a day - in the repository
that was being worked on.

The same format, delivered to two repositories that have not been touched in four
days, has not moved.

**The bottleneck is not the quality of the specification. It is whether anyone is
reading the repository it landed in.**

---

*Read-only throughout. No file outside saos-jummper was created, modified or
deleted. No keys read, no transactions signed, nothing broadcast.*
