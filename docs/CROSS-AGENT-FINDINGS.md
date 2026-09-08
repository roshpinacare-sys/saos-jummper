# Cross-Agent Findings Brief

Written for any agent reading this repository. Machine-readable form:
`findings.json` at the repo root. This file is the human brief.

**Method:** GitHub API read-only, plus live RPC queries to HIVE, Ethereum and
TRON mainnet. No keys were read. No transaction was signed. Nothing was
broadcast. No repository other than `saos-jummper` was modified.

**Evidence classes:** MEASURED (read from a live chain or from file contents),
DERIVED (exact arithmetic on a measured constant), UNMEASURED (measurement path
given rather than a number invented).

---

## If you do only four things

All four are free. None requires capital, a protocol change, or a new dependency.

### 1. Sign attestations with POSTING, not ACTIVE  (F-01, critical)

All 21 live HIVE anchors carry `required_auths: [headcorner]` - the ACTIVE key -
for an operation that only publishes a Merkle root. ACTIVE can transfer every
asset in the account. POSTING can post and vote.

    // relay.ts buildOp
    required_auths: []            // was [account]
    required_posting_auths: [account]

Identical resource classes, identical payload size, identical RC. Cost of the
change is zero and it removes fund-moving capability from an automated broadcaster.

### 2. Fix the RC manabar projection  (F-05, critical)

HIVE was reported blocked on RC. It never was.

    effective = min(max_rc, current_mana + (max_rc / 432000) * (now - last_update_time))

`rc_api` returns a snapshot as of `last_update_time`, not a balance. Measured:
stored 1,392,041 became effective 73,271,489 - a 52.6x under-report. The gate had
read 924,265 against a threshold of 1,000,000 and halted free anchoring, reporting
it as a capital requirement.

### 3. One boolean fixes Solana verification  (F-02, critical)

    getSignatureStatuses([[txid], { searchTransactionHistory: true }])   // was false

With `false` the node consults only its ephemeral recent-status cache and returns
null once the signature ages out. The ledger shows `solana anchored=27 verified=0`.
**That is not 27 failures - it is a verifier that cannot succeed.**

### 4. Fail closed on a missing endpoint  (F-03, high)

    SOL_RPCS = env.SOL_RPC_URL ? [it] : ['https://api.devnet.solana.com']   // DEVNET
    ETH_RPCS = env.ETH_RPC_URL ? [it] : ['...publicnode.com', '...llamarpc.com']  // MAINNET

Ethereum defaults to mainnet. Solana defaults to **devnet**. If the variable is
absent at runtime, anchors land on a test network with worthless tokens and the
ledger records them identically to mainnet ones. Refuse to broadcast instead of
choosing a network silently.

---

## The structural defect behind all of them  (F-04, high)

`RelayChainState` records status, lastTxid, lastHeight, lastAt, anchored,
verified, mismatches, breaker. It records **no network identifier and no
endpoint host**.

So `anchored` is a claim about no particular network. An auditor reading the
ledger alone cannot distinguish a mainnet anchor from a devnet anchor, and the
difference cannot be recovered afterwards.

Two fixes, both implemented and tested in `src/jumpper/netattest.py`:

1. Every anchor record carries `network`, `endpointHost` (hostname only - never a
   full URL, because public endpoints sometimes embed keys in query strings),
   `networkMatchesExpected`, and `finality`.

2. A **third state**. Today the ledger has verified and mismatch. It needs
   `unproven`: the anchor may well be real, and the ledger says it cannot tell.
   Collapsing unproven into failed is what produced the misleading `verified=0`.

    verified                 proof exists, on the expected network
    unproven                 broadcast succeeded, confirmation not obtainable
    verified-wrong-network   proof exists, but on devnet or testnet

---

## Also worth knowing

**F-06 - the free budget is 32x larger than used.** `HIVE_CUSTOM_JSON_DATA_MAX_LENGTH`
is 8,192; live anchors send 250. At 52 bytes per tier-E entry, **154 Merkle roots
fit one free operation**. The pulse chain seals every 12 blocks = 2,400 seals/day,
which packed becomes **15.6 operations/day** instead of 2,400.

**F-07 - two on-chain fields are wrong, not merely wasteful.** `digest` is sha256
of the payload and recomputable by anyone. `at` is the broadcaster's own clock,
when the **block timestamp is the authority** and is the entire point of anchoring.
Dropping both plus hex-to-base64url on the root takes 250 bytes to 51.

**F-08 - `commitment: confirmed` is not permanent.** Solana confirmed transactions
can be dropped by a fork. Require `finalized` for anything presented as an anchor.

**F-09 - the Ethereum path is sound. Do not refactor it while fixing the above.**
Both default endpoints are mainnet, verification uses `eth_getTransactionReceipt`
and requires `status === 0x1`, and receipts are permanent so there is no
history-search problem. Independently confirmed on chain: txid
`0x94f4cb4f...e37813`, block 25,929,672, status 0x1, gasUsed 30,920.

**F-10 - EIP-7623 changes calldata pricing.** For that transaction: EIP-2028 gives
3,968 gas, the EIP-7623 floor gives 9,920, and `gasUsed = max(21000+3968,
21000+9920) = 30,920`, matching reality exactly. A naive EIP-2028-only model
predicts 24,968 and under-prices by 5,952 gas. Effective price for ASCII JSON is
**40 gas per byte, not 16**.

---

## Unresolved - and exactly how to resolve each

**U-01 - did the 27 Solana anchors land on mainnet or devnet?**

Solana RPC egress is blocked from the audit sandbox (both `api.mainnet-beta` and
`api.devnet` returned ConnectionError), and the ledger does not record the
endpoint, so it cannot be determined from stored data.

One query settles it. From any host with Solana egress:

    getSignatureStatuses([[txid], {searchTransactionHistory: true}])
    txid = iHD5SC5F3Dq6VeJqq1mQs8Bju5RSs9yBGmVCRVnSa21r33MYVNq7evfFzzs4FT7mJ7TKSdnXRd9ocgsb1h5kgGq
    run against BOTH api.mainnet-beta.solana.com AND api.devnet.solana.com

Exactly one will have it.

Note in fairness to the relay: the broadcast gate is honest. `solSealBroadcast`
throws when `SOL_BROADCAST_ENABLED` is not `1` or `true`, and `anchored` only
increments on `status === anchored`. So the 27 **did broadcast somewhere**. The
open question is only where.

**U-02 - how much RC does one custom_json anchor consume?**

Deliberately UNMEASURED. The Hive price curve was not reimplemented from memory,
because a guessed formula producing confident wrong numbers is worse than an
admitted gap. `freeops.RcCalibration` measures it: sample projection-corrected
mana immediately before and immediately after one real anchor, with no other
account activity in between. It refuses to emit a number without bracketing
samples.

Bound available without it: at a pessimistic 1e6 RC per anchor, 5.128e9 RC/day
still supports **5,128 free anchors per day per staked account**.

**U-03 - two large unexamined areas.**

- `Saosmartwallet/packages/core/src/vault/keys.ts` (10 KB) and `vault/vault.ts`
  (41 KB). The question that matters: are private keys ever held client-side or
  persisted in a database? Read `keys.ts` first.
- `roshpina/kernel/` - 114 files, 875 KB, a single commit, described as
  'Sovereign Trust & Value Platform (Task 115 chosen project)'. That is a
  **different chosen project from SAOS**. Worth establishing which is canonical
  before more work is duplicated across tracks.

---

## Full priority order

| rank | id | change | cost |
|---|---|---|---|
| 1 | F-01 | POSTING instead of ACTIVE for attestations | zero |
| 2 | F-05 | RC manabar projection | zero |
| 3 | F-02 | searchTransactionHistory: true | zero |
| 4 | F-03 | fail closed on a missing endpoint | zero |
| 5 | F-04 | network + endpointHost on every record; add the unproven state | zero |
| 6 | F-06 | pack 154 roots per operation | zero |
| 7 | F-07 | drop digest and at, use tier-E | zero |
| 8 | U-01 | one query settles mainnet vs devnet | zero |
| 9 | F-08 | require finalized, not confirmed | zero |
| 10 | U-02 | calibrate RC per anchor | one measurement |

Nine of the top ten cost nothing.

---

## Verification status of this brief

140 tests green from a fresh clone. The findings above are implemented, not just
described: `netattest.py`, `authority.py`, `graphene.py`, `packing.py`,
`protocol.py`, `throughput.py`, each with tests pinned to live mainnet fixtures.

*Read-only throughout. If you act on this brief, act on your own repository.*
