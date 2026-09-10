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
