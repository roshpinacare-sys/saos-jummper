<!-- hardening:allow-file ALL reason=quotes the on-chain memo strings and the reconciliation defects it reports -->

# XLock Audit - what a lock written in a memo actually locks

Read from HIVE mainnet on 2026-09-11T01:44Z via `api.openhive.network`,
`condenser_api.get_account_history` for account `headcorner`, **500 entries
spanning 2026-09-03T02:58:36 to 2026-09-11T01:44:33**. Read-only.

Four transfers in that history carry a cross-chain lock protocol entirely in the
memo field. All four are **self-transfers**.

---

## The complete protocol, as it exists on chain

| # | time | amount | memo | fields | trx |
|---|---|---|---|---|---|
| 49621 | 2026-09-04T19:20:21 | 0.001 HIVE | `saos:xlock:PHIVE:0.001` | 4 | `13141ef37777142f11622649d0e022c8402fa0ed` |
| 49625 | 2026-09-04T22:23:48 | 0.002 HIVE | `saos:xlock:PHIVE:0.002:rt66` | 5 | `bb3156cdc725b15785d9b67b6c3f47fcc8d12040` |
| 49626 | 2026-09-04T22:37:51 | 0.001 HIVE | `saos:xunlock:PHIVE:0.001:rt66:7bdec0aa...` | 6 | `454d2d22e7301561680efb66d99e43b37bcde227` |
| 49697 | 2026-09-07T11:49:39 | 0.050 HIVE | `saos:xlock:PHIVE:0.050` | 4 | `44be4de1e510cf50dd1d5e7a828000b043815d11` |

Three locks, one unlock. `PHIVE` appears in **exactly four entries** in 500 - all
four of these. Hive-Engine holds no PHIVE balance for this account and mentions
the token zero times; the account's Hive-Engine activity is `hivepegged_withdraw`,
which is a different mechanism.

---

## Finding 1 - a self-transfer locks nothing (critical)

Every operation is `headcorner -> headcorner`. HIVE transfers carry no fee, and
sender equals receiver, so **the balance does not change**. Nothing is held,
escrowed, time-locked or moved to a custodian.

    balance now       0.049 HIVE
    vesting_shares    33,110.489549 VESTS
    hbd_balance       0.001 HBD

The four operations moved 0.054 HIVE out of the account and 0.054 HIVE back into
it. The word `xlock` describes an intention recorded in a string. **It is not a
custody change, and calling it a lock is the kind of naming that gets trusted.**

Compare what a real lock looks like in this same estate:
`packages/core/src/crypto/shamir.ts` shards a secret so that fewer than threshold
shares cannot reconstruct it, and `escrow/escrow.ts` moves value through
orchestrated transfers with a strict state machine where dispute stops money
rather than moving it. Those are mechanisms. A memo is a claim.

---

## Finding 2 - nothing validates an unlock (critical)

Any account can write

    saos:xunlock:PHIVE:999:anyref:anyhash

into a transfer memo and it will be recorded on chain with exactly as much
authority as the real one. There is no contract, no signature check, no
counterparty, no state. **This is an attestation protocol, not an enforcement
protocol** - which is a legitimate design, and is precisely the distinction
`docs/FREE-OPERATIONS.md` draws. The problem is only the name.

---

## Finding 3 - the memo format is not stable (high)

Four operations, three different field counts: **4, 5, 6 and 4**.

    saos:xlock:PHIVE:0.001                                    <- no reference id
    saos:xlock:PHIVE:0.002:rt66                               <- reference id
    saos:xunlock:PHIVE:0.001:rt66:7bdec0aa64c7...             <- reference id + cited txid
    saos:xlock:PHIVE:0.050                                    <- no reference id

A positional parser cannot rely on field 5 being the reference id, because in two
of the four operations there is no field 5.

---

## Finding 4 - two of three locks can never be unlocked (high)

Locks #49621 (0.001 HIVE) and #49697 (**0.050 HIVE**) carry **no reference id**.
An unlock is matched by reference id - the one real unlock cites `rt66`. So there
is no way to write an unlock that these two locks could match.

**The largest lock in the protocol, 0.050 HIVE, has no reference id.** It is
permanently ununlockable by the protocol's own matching rule, or it will be
unlocked by something that cannot be tied back to it.

---

## Finding 5 - the unlock cites a transaction that is not any lock (medium)

    unlock #49626 cites   7bdec0aa64c761672680c7dfa7ffcdebacddac7e
    lock #49621 trx       13141ef37777142f11622649d0e022c8402fa0ed
    lock #49625 trx       bb3156cdc725b15785d9b67b6c3f47fcc8d12040
    lock #49697 trx       44be4de1e510cf50dd1d5e7a828000b043815d11

**It matches none of them.** Searched across all 500 history entries: the string
`7bdec0aa64c761672680` appears exactly **once** - inside the unlock's own memo.

It is 40 hex characters, which is the **Graphene** txid format (HIVE, STEEM,
BitShares) - not Ethereum, which would be 66 characters with a `0x` prefix. So it
is presumably a transaction on another Graphene chain, or on a PHIVE-side system.
**But the memo does not say which chain, so it cannot be followed.** A citation
without a network is not a citation. This is the same defect as `srcTxid` in the
`value_lock` attestation and as `RelayChainState.lastTxid` with no network field.

---

## Finding 6 - the amounts do not reconcile (high)

    reference rt66   locked 0.002   unlocked 0.001   delta 0.001

Half. A partial unlock is entirely legitimate **if it is tracked** - if there is a
remaining balance of 0.001 against `rt66` that a later unlock can claim. There is
no such record anywhere in these four operations, and the memo format has no field
for a remaining balance.

So either 0.001 is still locked against `rt66` with nothing recording that fact,
or the unlock was for the wrong amount. Neither can be determined from the chain.

---

## What a reconciliation of this ledger produces

| finding | severity | count |
|---|---|---|
| self-transfer locks nothing | critical | 4 |
| nothing validates an unlock | critical | protocol-wide |
| inconsistent memo format (4/5/6 fields) | high | 1 |
| lock with no reference id | high | 2 |
| amount mismatch on `rt66` | high | 1 |
| unlock cites a foreign txid with no chain named | medium | 1 |

Verdict: **does not reconcile.** Not because the arithmetic is hard, but because
the protocol does not carry the fields needed to make the arithmetic possible.

---

## What would make this real

None of this requires abandoning the design. A memo protocol is cheap, free, and
fine for what memos are: attestations. The fixes are about not calling it
something it is not, and about carrying enough information to be checked.

| # | change | effect |
|---|---|---|
| 1 | Rename `xlock` to something that does not imply custody - `xlock-claim`, `xintent` | stops the name from being trusted as a mechanism |
| 2 | Make the reference id **mandatory** on every lock | two of three locks become matchable |
| 3 | Fix the field count - one shape, always | a positional parser becomes safe |
| 4 | Put the chain in the cited txid field: `chain:txid` | the citation becomes followable |
| 5 | Record the remaining balance on partial unlocks | `rt66` becomes reconcilable |
| 6 | If real custody is wanted, use `escrow_transfer` or a Hive-Engine contract | an actual mechanism instead of an annotation |

Items 2 through 5 are memo-format changes. Item 6 is the only one that changes
what the protocol is - and it is the only one that would make the word `lock`
accurate.

---

## Scope and limits

- 500 history entries read, spanning 2026-09-03 to 2026-09-11. Operations before
  that were not examined.
- `PHIVE` was not found as a Hive-Engine token for this account. Whether it exists
  on another chain, and whether the cited txid resolves there, **was not verified**
  - the memo does not say where to look, which is finding 5.
- No reconciliation module was shipped with this document. The analysis above was
  performed directly against the fetched history; a machine-checkable
  implementation is still to be written, and this document says so rather than
  implying one exists.

---

*Read-only throughout. No keys read, no transactions signed, nothing broadcast. No
file outside saos-jummper was created, modified or deleted.*
