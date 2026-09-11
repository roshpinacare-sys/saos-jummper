<!-- hardening:allow-file ALL reason=live on-chain status report quoting the operations and balances it measured -->

# On-Chain Update - what changed since the last reading

Re-read from HIVE mainnet on 2026-09-11T01:07Z via `api.openhive.network`,
`condenser_api.get_account_history` for `headcorner`, **300 entries spanning
2026-09-04T14:00:21 to 2026-09-11T01:07:42**. Read-only.

Two of the findings in this repository were fixed on chain since they were
reported. One was fixed by exactly the mechanism the analysis identified. The
structural cause of the forks is still unaddressed.

---

## Fixed: the convert loop stopped

    last hive.convert 9.632    2026-09-08T20:43:06
    history now runs to        2026-09-11T01:07:42
    convert calls since        zero, over roughly 2.2 days
    total in this window       14

The loop that was burning roughly a third of the daily RC budget on an operation
that could never succeed is no longer running.

---

## Fixed: the RC saturation, by the correct mechanism

    #49758  2026-09-09T15:21:27  transfer_to_vesting           9.682 HIVE -> headcorner
    #49759  2026-09-09T15:21:27  transfer_to_vesting_completed  15,598.651254 VESTS received

| | before | after | change |
|---|---|---|---|
| vesting_shares | 17,511.838295 | **33,110.489549** | +89% |
| max_rc | 25,641,553,538 | **41,240,204,792** | +60.8% |
| regen | 59,355 RC/s = 5.13e9/day | **95,463 RC/s = 8.25e9/day** | **+61%** |
| HIVE balance | 9.682 | 0.049 | powered up |

**This is the mechanism the analysis named.** RC on HIVE derives from vesting
shares and nothing else - not from SWAP.HIVE, not from PIZZA, not from any
Hive-Engine token. The `rc-route` token transfers bought nothing; `transfer_to_vesting`
bought 61% more daily budget.

It also solves the `9.632` mystery. The loop was trying to power up, using the
wrong contract: Hive-Engine `hive.convert` unwraps SWAP.HIVE into HIVE, which is
not a power-up and not an asset the account held. The quantity 9.632 sat within
0.05 of the 9.682 HIVE balance the whole time. The correct operation eventually
ran, for 9.682 HIVE, and it worked.

---

## Fixed: the height counter is monotonic again

    last 12 heights   23028, 23772, 24480, 25212, 25932, 26460,
                      27072, 27984, 28596, 29712, 30492, 31164
    last backwards step   2026-09-09T22:10:06   (4488 -> 12)
    backwards steps total 6      repeats total 4

No resets in roughly 1.2 days.

---

## NOT fixed: the structural cause

### epoch is still absent from every anchor

    anchors examined                     173
    anchors carrying an "epoch" field      0
    last payload keys                      action, at, digest, height, protocol, stateRoot

Searched again in the relay sources: `relay.ts` (58,025 chars), `relay-sol.ts`
(12,981), `relay-eth.ts` (12,899), `chain.ts` (64,434) - the word `epoch` appears
**zero times in all four**.

### the eight forks are still there, and no new ones

    height     12 : 2 roots   2026-09-07T22:53:03 -> 2026-09-09T22:10:06
    height   552  : 3 roots   2026-09-07T21:57:33 -> 2026-09-07T22:04:36
    height  1224  : 2 roots   2026-09-07T23:58:54 -> 2026-09-09T17:54:12
    height  1392  : 2 roots   2026-09-08T03:35:09 -> 2026-09-09T18:02:36
    height  1416  : 2 roots   2026-09-07T14:42:57 -> 2026-09-09T18:03:48
    height  1476  : 2 roots   2026-09-09T18:06:48 -> 2026-09-09T23:24:36
    height  1668  : 2 roots   2026-09-09T18:19:18 -> 2026-09-09T18:22:36
    height  1764  : 2 roots   2026-09-09T18:27:21 -> 2026-09-09T18:27:51

**Still 8, and none newer than 2026-09-09T23:24:36.** No new fork in the ~1.2 days
since the counter went monotonic.

That is worth stating precisely, because it is easy to misread as fixed: **the
forks stopped because the process has not restarted, not because anything prevents
them.** The counter is per-process. The next restart begins it again at whatever
the state file says, and the first height it emits will collide with one already
on chain. `src/jumpper/epochguard.py` exists for exactly this and is tested
against this sequence: 7 bumps, 8 epochs, 15 unique pairs, zero collisions against
2 without it.

### the payload is still 250 bytes of an 8,192 budget

`digest` is recomputable by anyone and `at` is the operator's own clock where the
block timestamp is the authority. Both are still being published. 3.04% of the
free budget used.

---

## New activity observed

| operation | detail |
|---|---|
| `transfer` self, memo `saos:xlock:PHIVE:0.001` | 2026-09-04T19:20:21 |
| `transfer` self, memo `saos:xlock:PHIVE:0.002:rt66` | 2026-09-04T22:23:48 |
| `transfer` self, memo `saos:xunlock:PHIVE:0.001:rt66:7bdec0aa...` | 2026-09-04T22:37:51 |
| `transfer` self, memo `saos:xlock:PHIVE:0.050` | 2026-09-07T11:49:39 |
| `transfer` from `honey-swap` | 2026-09-10T23:31:30, a `hivepegged` contract call |
| `account_witness_vote` | `justyy`, approve true, 2026-09-04T15:03:30 |

The `saos:xlock` / `saos:xunlock` self-transfers with amounts and a reference id in
the memo are a cross-chain lock protocol carried entirely in memo text. The
`xunlock` memo carries a 40-hex reference. **Not audited.** Worth noting that a
lock protocol expressed only as a memo has no enforcement - it is an attestation,
and anyone can write one.

Protocol census over the same 300 entries:

    saos-dex.anchor.v1   173
    ssc-mainnet-hive      51
    saos.attest.v1        20
    saos                  14
    saos.weave.v1         14
    saos.id.v1             5

`last_owner_update` is unchanged at 2026-09-08T21:17:39 - no further key rotation.

---

## Scorecard against the recommendations

| recommendation | status |
|---|---|
| Stop the convert loop | **done** - silent since 2026-09-08T20:43:06 |
| Power up to raise the RC ceiling | **done** - 9.682 HIVE to VESTS, +61% daily RC |
| `STEEM_POSTING_WIF` / `HIVE_POSTING_WIF` | **done** - `FIX(CROSS-F-01)` in relay.ts |
| `searchTransactionHistory: true` | **done** - `FIX(CROSS-F-02, saos-jummper)` in relay-sol.ts |
| RC manabar projection | **done** - `Math.min(max, cur + (max / 432000) * elapsed)` |
| three-state `verified` | **done** - `boolean \| null`, null means not yet checked |
| devnet default | **done** - `FIX(SETTLE-7 rail-alignment)`, "was devnet by default" |
| **epoch in the anchor payload** | **NOT DONE** - 0 of 173 anchors |
| **drop `digest` and `at`, use tier-E** | **NOT DONE** - 250 bytes of 8,192 |
| **publish the fork correction** | **NOT DONE** - `remedy.py` builds it; nobody has broadcast it |
| `threshold` in `reconstructSecret` | NOT DONE |
| audit hash field coverage | NOT DONE |
| vault password out of the repo | NOT DONE |

**Four of the five zero-code fixes landed.** The three that did not are the ones
that change a payload format, which is why they need a decision rather than a
config change.

---

*Read-only throughout. No keys read, no transactions signed, nothing broadcast. No
file outside saos-jummper was created, modified or deleted.*
