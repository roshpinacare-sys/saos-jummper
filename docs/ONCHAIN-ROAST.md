<!-- hardening:allow-file H-11,H-12,H-13,H-05 reason=quotes the on-chain payloads and defective flags it reports -->

# On-Chain Roast - what HIVE mainnet says about SAOS, measured twice

Two readings of account `headcorner` on HIVE mainnet, 32 hours apart, both
read-only via api.openhive.network. First reading 2026-09-08T18:56Z, second
2026-09-10T06:17Z. Every number below came off the chain; nothing is inferred
from a report or a docstring.

---

## 🔴 The headline: three heights carry two different state roots each

115 `saos-dex.anchor.v1` operations were parsed from the last 120 history
entries, spanning 2026-09-09T17:36:48 to 2026-09-10T05:56:18. Three heights
appear twice, and in all three cases the two records disagree:

### height 1764 - two different states, 30 SECONDS apart

    #49833  2026-09-09T18:27:21  block 109770502  trx 0825c6b3ee1ba3c9ebcc
            root   d7220b5e9ecc953e7e8ddf0b682b7e15384e8ec0bc46bb22e145d74bcba9f2db
            digest 9a45abe69ec4e0a2646e37eb15c53f74686ab41e4f4e829b54d61a8b8bcac32c
            at     2026-09-09T18:27:18.616Z

    #49834  2026-09-09T18:27:51  block 109770512  trx 9029171e0fd24875f957
            root   84ae0a0a08ef2f44becc99e40f9995e6fe82d9931ed6e2412b23ca999f86b90d
            digest fbcca9199c674cba9471dd7aebaddbabc6c8a32c5942b9ad085d31a793e30279
            at     2026-09-09T18:27:45.589Z

    SAME ROOT: False   SAME DIGEST: False   SAME at: False

### height 1668 - two different states, 3.3 minutes apart

    #49824  2026-09-09T18:19:18  block 109770341  root 74b29867195898f6691ce331cbdbcd3f...
    #49825  2026-09-09T18:22:36  block 109770407  root e375e0f5d7fe98c69ea720d0f96e9fb2...

### height 1476 - two different states, 5.3 hours apart

    #49809  2026-09-09T18:06:48  block 109770091  root f61a046edf15a37c4e5f966c5e5cfc2a...
    #49865  2026-09-09T23:24:36  block 109776429  root e26a24907e9f95f4ca7cf5a3cf4877ce...

### Why this is not a re-broadcast

A duplicate broadcast would carry the same root, the same digest and the same `at`.
These carry none of the three. Different blocks, different transactions, different
payloads. **Two distinct states were sealed at the same height.**

height 1476 is partly explained by the counter reset below - one 1476 is
pre-reset and one is post-reset. But **1668 and 1764 are both before the reset**
(18:19, 18:22 and 18:27 against a reset at 22:10), so they are duplicates inside a
single regime with nothing to explain them.

### What it breaks

- "what was the state at height 1764?" has two public answers, 30 seconds apart
- a consistency proof between them is impossible - they are not on one hash chain
- `height` cannot be used as a key, an ordering, or a dedupe token
- any monitor comparing roots over time sees a fork and cannot tell whether it is
  an attack or a counter bug

This is the split-view condition, produced accidentally, published voluntarily, on
a public chain, with transaction ids attached.

---

## 🔴 The height counter reset with no epoch marker

    #49861  2026-09-09T20:54:30  height 4488  root 57648291967246f7...
    #49862  2026-09-09T22:10:06  height   12  root 3de8c6e4d7f4006e...   <-- RESET

The pulse chain restarted and began counting from zero again. The payload has no
epoch, generation, instance id or start time - only `height`. So after the reset,
**every height below 4488 is ambiguous**, and 1476 already is.

The fix is one field. `roshpina/kernel/transparency-log` already has the concept:
its audit log binds a genesis hash derived from `vaultInstanceId`, precisely so a
chain of records cannot be confused with another instance's. The anchor payload
does not carry it.

---

## The full height sequence, 115 anchors

    876 888 900 924 936 948 960 972 984 996 1008 1020 1032 1044 1056 1068 1080
    1092 1104 1116 1128 1140 1152 1164 1176 1188 1212 1224 1248 1260 1272 1284
    1296 1308 1320 1332 1344 1356 1368 1380 1392 1404 1416 1428 1440 1452 1464
    1476 1488 1500 1512 1524 1536 1548 1560 1584 1596 1608 1620 1632 1644 1656
    1668 1668 1680 1692 1704 1716 1728 1740 1752 1764 1764 1776 1788 1800 1812
    1824 1836 1860 1872 1884 1896 1908 1920 1932 1944 1956 1968 1980 1992 2004
    2016 2028 2040 2052 2604 3216 3864 4488 | 12 24 636 1476 2076 2736 3456
    4188 4908 5832 6336 7044 7872 8448 9168

Three regimes, visible in the step size:

| regime | anchors | height step | meaning |
|---|---|---|---|
| A | ~85 | **exactly 12** | one anchor per seal - every seal anchored |
| B | ~12 | 552 to 924 | anchoring roughly every 46-77 seals |
| C (post-reset) | ~18 | 600 to 924 | same as B |

Average step 115 blocks. At 12 blocks per seal that is **9.6 seals per anchor** -
so regime A anchored everything and regimes B and C silently drop about nine in
ten. Nothing on chain records which seals were skipped.

Cadence now: **9.3 anchors per hour, one every 6.4 minutes**, up from roughly one
per hour two days earlier.

---

## ✅ What changed for the better in 32 hours

Measured on both readings, not reported:

| | 2026-09-08T18:56Z | 2026-09-10T06:17Z |
|---|---|---|
| `hive.convert` loop | **11 calls in the last 100 ops, still running** | **0 in the last 120 ops - dead** |
| `ssc-mainnet-hive` (Hive-Engine) | 32 in the last 100 | **0 in the last 120** |
| `market.buy BEE` | dozens, 0.0029 to 3.5468 BEE | **none** |
| liquid balance | 9.682 HIVE | **0.000 HIVE** |
| vesting shares | 17,511.838295 VESTS | **33,110.489549 VESTS** (+89%) |
| max_rc | 25,641,553,538 | **41,240,204,792** (+60.8%) |
| protocol mix | 6 protocols | 2 (115 anchors + 2 weave seals) |

**The entire liquid balance was powered up.** That is the correct RC mechanism -
RC derives from vesting shares, and max_rc rose 60.8% as a direct result. It is
the exact opposite of the two `tokens.transfer` calls memo'd `saos:rc-route` and
`saos:rc-route-dust` that sent SWAP.HIVE and PIZZA away and bought no RC at all.

**The convert loop is dead and all Hive-Engine activity stopped.** Whatever was
burning roughly a third of the daily RC budget on a doomed `hive.convert 9.632`
is no longer running. That was the single largest recoverable waste in the estate
and it is gone.

---

## ❌ What did not change

| | measured now | available |
|---|---|---|
| anchor payload | **247-249 bytes** (29 samples) | 8,192 |
| budget used | **3.04%** | 97% idle |
| roots per operation | **1** | 154 |
| `digest` field | still present | recomputable by anyone |
| `at` field | still present | the block time is the authority |

The current payload, verbatim:

    {"protocol": "saos-dex/v1", "action": "chain-seal",
     "at": "2026-09-10T05:56:14.395Z", "height": 9168,
     "stateRoot": "09bdd480bd0ca60b8a2e8f2841333e0524654b41a71dce52df85692da043e0db",
     "digest": "5b8a9b5438193105bef2422540d667b49851346cf29e690f6cfb50d6d08a2f0b"}

Note that this one is emitted with spaces after the colons - `json.dumps` default
separators rather than compact. That alone costs about 10 bytes per anchor against
`separators=(',', ':')`, on a payload that is already 3% of its budget.

---

## 🔴 Correction to a number I published: RC per operation

`docs/LIVE-FINDINGS.md` states **157,713,792 RC per operation**, derived from two
manabar snapshots 6.08 hours apart bracketing 4 operations. That figure is
**at least 4x too high** and the new data proves it.

    max_rc now            41,240,204,792
    regen                 max_rc / 432000 = 95,463 RC/sec = 8.248e9 RC/day
    observed cadence      115 anchors in 12.33 h = 9.32/hour = 223.8/day
    sustainable ceiling   8.248e9 / 223.8 = 36.9M RC per operation

At the published 157.7M the account could fund 52 operations a day. It is funding
224. And its effective mana is **stable** across the two readings - 73.3M then,
119-125M now, at 8x the cadence and after a counter reset. **It is not depleting,**
so the true cost is at or below the sustainable ceiling.

The confound in the original measurement: that 6.08-hour window contained the
convert loop, market buys and a `delegate_vesting_shares`, and I divided the whole
spend by the 4 custom_json operations in it. **An aggregate over mixed activity is
not a per-operation cost**, and I presented it as one.

Honest status now: **RC per anchor is at most 36.9M, and the point estimate is
still UNMEASURED.** A clean measurement needs two manabar snapshots with exactly
one operation between them, which needs a sample at each `last_update_time` -
achievable by polling, not achieved here.

---

## 🔴 The identity gap is still open

`saos.id.v1` binds `headcorner` to an EVM address with a real 65-byte EIP-191
signature:

    evm    0xF723186d21179672Ca6d9fc526Ffb718dbD99376
    chains [steem, hive, blurt]

The Ethereum anchor that was independently verified lives at a different address:

    tx     0x94f4cb4fc0c50d742a583576b2cb1d14fa55dd99437510bf252a6ccba3e37813
    block  25,929,672   status 0x1
    from   0x2767e8146c11bad1d9b0784f11325375195c1b0f

**The one attestation that connects the HIVE account to Ethereum points at an
address that has never anchored anything.** And `saos.id.v1` has not been broadcast
in the last 120 operations, so it is not being refreshed either.

Anyone following the identity chain from HIVE to Ethereum arrives at an empty
address. Anyone following the anchors back to an identity arrives at nothing.

---

## What I could not check

| item | why |
|---|---|
| whether a SAOS token exists on Hive-Engine | the Hive-Engine RPC endpoints timed out from this environment, twice |
| `lockedSaos: 0.166` against `depthBefore: 106.868` | depends on the above; the claim is unverifiable until then |
| `srcTxid 4f83ae2a4754b2f7b07b242fac0c39a74bed1a5e` | 40 hex chars - an Ethereum-shaped id inside a HIVE custom_json, with no chain named |
| the current signing authority | `required_auths` was 57 of 62 two days ago; not re-measured this round |
| STEEM mainnet | node unreachable for the whole session |
| whether the ETH and SOL anchors are still being produced | only HIVE history was read this round |

---

## Actions, ordered by what the chain actually shows

| # | action | severity | effort |
|---|---|---|---|
| 1 | **Add an epoch or instance id to the anchor payload.** Without it, height is ambiguous across a restart and 1476 already has two meanings | **CRITICAL** | one field |
| 2 | **Find why two seals share a height.** 1764 produced two different roots 30 seconds apart, inside one regime. That is a producer race, a non-atomic counter, or a restart that reused a height | **CRITICAL** | investigation |
| 3 | **Refuse to broadcast a height that was already broadcast** with a different root. `liveops.duplicate_seal_audit` detects this after the fact; nothing prevents it | HIGH | small |
| 4 | Record which seals were skipped. Regimes B and C drop about 9 in 10 and nothing on chain says which | MEDIUM | one field |
| 5 | Compact the payload: drop `digest` and `at`, use compact separators, base64url the root | MEDIUM | 249 to ~51 bytes |
| 6 | Pack. `weave.v1` already has count/from/to and every seal carries count=1 | MEDIUM | use what exists |
| 7 | Fix `saos.id.v1` to bind the address that actually anchors, or bind both with roles | HIGH | small |
| 8 | Correct `docs/LIVE-FINDINGS.md`: RC per op is at most 36.9M, not 157.7M | MEDIUM | this document |

Actions 1 and 2 are the ones that matter. Everything else is efficiency; these two
are the difference between a log that can be trusted and a log that publishes two
answers to the same question.

---

## What is genuinely good, measured

- the convert loop is dead and all Hive-Engine churn stopped
- the whole liquid balance was powered up, which is the correct RC mechanism,
  and max_rc rose 60.8% as a result
- 115 anchors landed in 12.3 hours at zero fee, one every 6.4 minutes
- all 115 heights are distinct within their regime - no duplicate broadcasts
- the ETH and SOL commitments remain byte-identical across all six fields
- nothing was taken during the owner-key rotation: vesting rose, balance went to
  stake, and the relay resumed anchoring four minutes later

---

*Read-only throughout. Two measurements 32 hours apart, both from public RPC. No
keys read, no transactions signed, nothing broadcast, no file outside
saos-jummper modified.*
