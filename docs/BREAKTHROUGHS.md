# Breakthroughs - what our network does for free that others charge for

Read from LIVE HIVE mainnet on 2026-09-08 (read-only). Every figure is marked
MEASURED (read from the chain), DERIVED (exact arithmetic on a measured
constant), or UNMEASURED (pending one calibration).

---

## The question

What costs money everywhere else, and is free on our network?

The answer has two halves. The first is a category: `custom_json` on Graphene
chains carries **no fee field at all**. The second is a number: that free
operation may carry **8,192 bytes**, and we were sending 250.

---

## Breakthrough 1 - one free operation holds 154 Merkle roots (DERIVED)

Live protocol constant from `condenser_api.get_config`:

    HIVE_CUSTOM_JSON_DATA_MAX_LENGTH = 8192
    HIVE_MAX_TRANSACTION_SIZE        = 65536
    HIVE_BLOCK_INTERVAL              = 3
    HIVE_RC_ACCOUNT_SUBSIDY_TRIPLE_WINDOW = 432000   (= 5 days, confirms the regen model)

A tier-E root entry is 51 bytes plus 1 separator. 8192 // 53 = **154 roots per
single free operation**.

The pulse chain seals every 12 blocks, blocks are 3 s, so:

    seals per day                = 28800 / 12 = 2,400
    operations to anchor ALL of them = 2400 / 154 = **15.6 per day**

Today the cadence is roughly one anchor per 47 minutes - about 31 per day - and
it does not cover every seal. Packed, **every single seal can be anchored for
free in 16 operations a day**, and account history grows by 16 permanent
entries daily instead of 2,400.

---

## Breakthrough 2 - the wrapper was two thirds of every operation (DERIVED)

The custom_json envelope:

    {"required_auths":["headcorner"],"required_posting_auths":[],
     "id":"saos-dex.anchor.v1","json":""}

costs ~99 bytes and is paid **once per operation**. Sending one root per
operation spends two thirds of the bytes on the envelope.

| K roots | packed op | K separate ops | saving | ratio |
|---|---|---|---|---|
| 1 | 153 B | 149 B | 0.0% | 1.00x |
| 10 | 630 B | 1,490 B | 58.0% | 2.38x |
| 50 | 2,750 B | 7,450 B | 63.1% | 2.71x |
| 100 | 5,400 B | 14,900 B | 63.8% | 2.76x |
| **154** | **8,262 B** | **22,946 B** | **64.0%** | **2.78x** |

Combined with tier-E compaction (250 B to 51 B, MEASURED):

    today      351 bytes per anchored batch
    optimised   53.6 bytes per anchored batch
    **6.55x fewer bytes, 84.7% reduction**

---

## Breakthrough 3 - the HIVE blocker was a stale-read bug (MEASURED)

`rc_api.find_rc_accounts` returns `current_mana` **as of** `last_update_time`.
It is a snapshot, not a balance.

    stored current_mana =      1,392,041   at last_update_time 1788870714
    wall clock          =      1788871925  (1,211 s later)
    max_rc              = 25,641,553,538
    regen               = max_rc / 432000  = 59,355 RC/sec
    EFFECTIVE mana      =     73,271,489   = 52.6x the stored value

A gate comparing the raw snapshot to a constant read `924265 < 1000000` and
declared HIVE blocked, needing a power-up or an 8.9 hour wait. **It was never
blocked.** The account held tens of millions of RC the whole time.

    effective = min(max_rc, stored + (max_rc/432000) * (now - last_update_time))

The test pins this to the live figure exactly: round(effective) == 73271489.

---

## Breakthrough 4 - 100% of live anchors sign with the wrong key (MEASURED)

All 21 real anchors read from mainnet:

    required_auths         = [headcorner]   <- ACTIVE key
    required_posting_auths = []

A custom_json that publishes a Merkle root moves no value and changes no
ownership. It needs **POSTING** authority, not ACTIVE.

Graphene authorities are strictly ordered:

    posting  vote, follow, comment, custom_json with posting auth
    active   everything posting does, PLUS transfer, power up/down, market
             orders, account updates, key changes
    owner    everything, PLUS replacing the active and posting keys

So the anchor signer today holds a key that can drain the account, in order to
publish bytes.

| authority | can move funds | can change keys | severity if signer compromised |
|---|---|---|---|
| posting | no | no | low - can post and vote only |
| active | **yes** | no | **critical - can transfer every asset** |
| owner | yes | **yes** | total loss - permanent takeover |

**Cost of switching to posting: zero.** Same resource classes, same payload
size, same RC. RC does not care which authority signed.

This is the single highest-value free change in the estate: it removes
fund-moving capability from an automated broadcaster at no throughput cost.

---

## Breakthrough 5 - two fields on chain are not redundant, they are wrong (MEASURED)

| field | why it should go |
|---|---|
| `digest` | sha256 of the payload. Recomputable by anyone. Paying RC to store a derivable value is pure waste |
| `at` | our own ISO clock. The **block timestamp is the authority** and is the entire point of anchoring. Broadcasting our own clock is weaker AND costs bytes |

Removing both plus hex-to-base64url on the root takes 250 bytes to 51:

    1,12108,qMNCPNaOod8To-jw3RzIg_LlLI4KkPfATmSEBcYM1Q8

---

## Breakthrough 6 - RC is per-account, so the fleet is a multiplier (STRUCTURAL)

RC lives in each account's own manabar. N independently staked accounts give N
times the budget with no protocol change.

The estate already holds a fleet of 7 keys. If each account carries stake,
throughput scales linearly: 5,128 anchors/day floor for one account becomes
35,898 for seven.

Honest caveat: **delegation moves RC between accounts, it does not create it.**
Striping unstaked accounts spreads account-history growth and adds redundancy,
but does not multiply the budget. Only stake does.

---

## Breakthrough 7 - Graphene is the only truly free arbitrary-data anchor

| chain | arbitrary-data cost | evidence |
|---|---|---|
| **HIVE / STEEM / BLURT custom_json** | **$0.00 - no fee field exists** | MEASURED: 21 real anchors, zero fee |
| Ethereum calldata | $0.081 | MEASURED: exact to the wei vs block 25929672 |
| TRON memo | ~$0.05 one-time bandwidth floor, then near-free | their own measurement: unfunded at 0 sun |
| Solana memo | fractions of a cent, not free | not measured here |
| Stellar memo | fractions of a cent, not free | not measured here |
| Algorand note | fractions of a cent, not free | not measured here |
| Bitcoin OP_RETURN | pays full fee, expensive per byte | not measured here |

Only the first two rows are MEASURED by us. The rest are from general knowledge
and are marked accordingly - they are directionally right and should be measured
before anyone prices against them.

The structural point stands regardless: a chain where the data operation has
**no fee field at all** is categorically different from a chain where the fee
is merely small.

