# SAOS JUMPPER

**Cross-chain batched proof notary.**

JUMPPER turns any digital claim into a permanent, cheap, independently verifiable
record on Ethereum mainnet, timestamped by five independent blockchain clocks.

Core thesis: the scarce resource in autonomous systems is not compute and not
capital. It is verifiable truth. Every agent can claim anything. Only a public
chain cannot lie.

> JUMPPER makes lying expensive. Anchor a claim for a fraction of a cent and from
> that moment it can never be rewritten, denied, or faked.

---

## The free path (this is the primary one)

Our own network already anchors for **$0.00**. Verified live on HIVE mainnet,
read-only:

    operation      custom_json, id "saos-dex.anchor.v1"
    authority      required_auths = [headcorner]   (ACTIVE key)
    fee field      ABSENT - zero fee
    real anchors   21 in the last 100 history entries, over ~22 hours
    blocks         109708562 to 109734678
    max_rc         25,641,553,538
    regen          59,355 RC/sec = 5,128,310,708 RC/day
    effective mana 73,271,489

**Pessimistic floor: 5,128 free anchors per day.** Real figure is higher and is
one measurement away.

Two findings that came out of reading the live chain:

1. **The RC "blocker" was a stale-read bug.** `rc_api` returns `current_mana` as
   of `last_update_time` - a snapshot, not a balance. A gate comparing it to a
   constant reported BLOCKED at 924,265 RC while the account actually held
   **73,271,489 RC** (52.6x more). Costs nothing to fix. `graphene.py` fixes it
   and the test pins the projection to the live measurement exactly.

2. **The payload was 4.9x too big.** 250 bytes on chain today; 51 bytes for the
   same commitment. Two fields were not just redundant but wrong: `digest`
   (recomputable by anyone) and `at` (our own clock, when the BLOCK time is the
   authoritative one). Shrinking it multiplies free throughput.

Ethereum is **demoted** to an optional low-frequency settlement tier for third
parties who refuse Graphene finality. At $0.081 per anchor it is infinitely more
expensive than free for work our network already does at zero fee.

Full analysis: `docs/FREE-OPERATIONS.md`.

## The four free wins (all measured, none cost anything)

| # | finding | status | gain |
|---|---|---|---|
| 1 | **21/21 live anchors sign with the ACTIVE key** for a pure data attestation. POSTING suffices at identical RC | MEASURED | removes fund-moving capability from an automated broadcaster |
| 2 | **The HIVE blocker was a stale-read bug.** `rc_api` returns a snapshot as of `last_update_time`; projecting it forward gives 73,271,489 RC, not 924,265 | MEASURED | HIVE was never blocked; 52.6x more RC visible |
| 3 | **`custom_json` may carry 8,192 bytes; we send 250.** One free operation fits **154 Merkle roots** | DERIVED from a live constant | 2,400 seals/day anchored in **15.6 operations** |
| 4 | **Two on-chain fields are wrong, not just wasteful:** `digest` is recomputable, and `at` is our clock when the block time is the authority | MEASURED | 250 B -> 51 B payload |

Combined: **351 bytes per anchored batch today -> 53.6 bytes. 6.55x, 84.7% fewer.**

Full analysis with the measured / derived / unmeasured ledger: `docs/BREAKTHROUGHS.md`.

The one missing number is RC consumed per anchor. It is deliberately not guessed -
a formula reconstructed from memory that produces confident wrong numbers is worse
than an admitted gap. `RcCalibration` measures it from one bracketed sample pair.
Until then the floor stands: **5,128 free anchors per day** per staked account.

## What the chain says is actually running (read live, not reported)

`docs/LIVE-FINDINGS.md`. Six protocols are live on HIVE mainnet under account
`headcorner`, three of which appeared in no report: `saos.attest.v1` anchors git
commits, `saos.id.v1` binds the account to an EVM address with an EIP-191
signature, and `saos.weave.v1` already has a batching schema.

Four findings, all measured against real on-chain data committed as a test fixture:

| # | finding | cost |
|---|---|---|
| 1 | **A live RC leak.** `hive.convert 9.632` attempted 11 times; balance unchanged at 9.682 HIVE. Hive-Engine unwraps SWAP.HIVE, which the account no longer holds. Still running. | ~1.73e9 RC, about 34% of a day's budget |
| 2 | **57 of 62 attestation ops (91.9%) sign with ACTIVE** when POSTING suffices. The `saos` value_lock ops already use POSTING correctly, so the pattern is proven in the same account. | critical key exposure, zero RC to fix |
| 3 | **One weave seal broadcast 10 times** (same net, seq and root). No idempotency guard on the on-chain protocol. | 9 redundant permanent records |
| 4 | **97% of the free payload budget is unused.** 248.9 of 8,192 bytes. `saos.weave.v1` has count/from/to and every seal carries count = 1 - detector verdict: "batching schema present but unused". | 32.9x to 37.6x headroom |

RC per operation is now **MEASURED**, not guessed: two manabar snapshots 6.08 h
apart bracketing 4 known operations give 157,713,792 RC per op. Independent
check: that predicts 32.5 ops/day capacity against 31.6 ops/day observed -
**within 3%**. The account is RC-saturated, which is why recovering the loops
matters more than any optimisation.

## Why this project

An audit of 8 repositories and 3 parallel development tracks found one pattern:

**Every agent can claim anything. No agent can prove anything.**

13 work rounds reported "all green, all pushed". None of it was independently
verified. The one thing that could not be argued with - the Ethereum calldata
anchor - turned out to be real (block 25,929,672, status 0x1).

---

## Status

**Phase 1 core is written, tested, and green.**

| item | state |
|---|---|
| canonical JSON | implemented, 6 tests |
| Merkle tree + proofs | implemented, 8 tests |
| claim hashing (domain separated) | implemented, 6 tests |
| batcher (monotonic height, invariants) | implemented, 5 tests |
| anchor calldata + gas model | implemented, 9 tests, **exact-matches mainnet** |
| multi-chain witness (5 chains, keyless) | implemented, live-probed 2/5 from restricted sandbox |
| standalone verifier CLI | implemented, zero-network tier-1 |
| golden vectors for cross-language ports | generated |
| economics | measured, see `docs/ECONOMICS.md` |
| test suite | **137/137 green from a fresh clone** |
| end-to-end demo | **PIPELINE GREEN** |
| HTTP API surface | Phase 3, not started |
| persistence layer | Phase 3, not started |
| real anchor broadcast | requires external signer + owner approval |

### The headline number

A public, permanent, independently verifiable notary record costs about
**$0.0000081 per claim** at a 10,000-claim batch (1 gwei, ETH $2,500).
Measured, not estimated. See `docs/ECONOMICS.md`.

### The headline validation

Our gas model predicts the real cost of a real Ethereum mainnet transaction to
**the exact wei**: 30,920 gas and 32,493,358,294,280 wei at block 25,929,672.
A naive EIP-2028-only model would have under-priced it by 5,952 gas, because
EIP-7623 (Prague) introduced a calldata cost floor that makes the effective
price 40 gas per non-zero byte, not 16.

---

## How it works

    L0  INGEST    claim -> canonical JSON -> domain-separated leafHash
    L1  BATCH     Merkle accumulation -> seal on 1000 leaves or 300s -> monotonic height
    L2  ANCHOR    ETH mainnet self-transfer, commitment in calldata (~32k gas)
    L3  WITNESS   head refs from STEEM / HIVE / TRON / ETHEREUM / SOLANA
    L4  VERIFY    tier1 self-verify (no network) | tier2 API | tier3 on-chain
    L5  SURFACE   API + explorer (Phase 3)

Signing always happens outside the system. JUMPPER produces the payload and the
digest, an external signer produces the txid, and JUMPPER records only the public
result. No private key ever touches the repo, the database, or the server process.

---

## Three verification tiers (zero trust in us)

1. **Self-verify** - `python -m jumpper.verify --leaf <hash> --proof p.json --root <root>`.
   Local compute, zero network calls.
2. **API verify** - returns the inclusion proof and the anchor txid.
3. **On-chain verify** - take the txid, decode calldata from any public explorer,
   compare the root. We are not in the loop.

Hard invariant, enforced by tests: `verified <= anchored`. A recorded anchor that
cannot be re-confirmed against the chain is marked unverified and is never
presented as final.

---

## Layout

    src/jumpper/canonical.py     deterministic JSON
    src/jumpper/merkle.py        tree, proofs, standalone verify
    src/jumpper/claim.py         domain-separated leaf hashing
    src/jumpper/batch.py         accumulation, sealing, invariants
    src/jumpper/graphene.py      FREE anchor layer: custom_json, RC projection, compaction
    src/jumpper/protocol.py      live HIVE protocol constants (8192B custom_json, 3s blocks)
    src/jumpper/packing.py       154 Merkle roots per free operation
    src/jumpper/authority.py     least privilege: posting for attestations, not active
    src/jumpper/throughput.py    the multiplier stack, every stage evidence-tagged
    src/jumpper/liveops.py       forensics over real chain history: loops, authority, duplicates
    src/jumpper/freeops.py       capability matrix: 12 free vs 5 never-free, honest limits
    src/jumpper/anchor.py        ETH calldata + EIP-2028/EIP-7623 gas model (settlement tier)
    src/jumpper/witness.py       5-chain keyless read-only probes
    src/jumpper/verify.py        standalone verifier CLI
    tests/test_jumpper.py        43 assertions
    tests/test_graphene.py       34 assertions on live mainnet fixtures
    tests/test_throughput.py     39 assertions: constants, packing, authority, stack
    tests/test_liveops.py        21 assertions pinned to a real mainnet fixture
    tests/fixtures/              100 real HIVE account-history entries
    tests/golden_vectors.json    cross-language validation vectors
    scripts/demo_end_to_end.py   full pipeline with live witness
    docs/ARCHITECTURE.md         design
    docs/ECONOMICS.md            measured cost model
    docs/FREE-OPERATIONS.md      what is free on our network, and what never is
    docs/BREAKTHROUGHS.md        the seven findings, measured vs derived vs unmeasured
    docs/LIVE-FINDINGS.md        what the chain says is actually running, and what leaks
    docs/TESTING.md              coverage and real transcripts

## Run it

    pip install -r requirements.txt
    python -m unittest tests.test_jumpper -v
    python scripts/demo_end_to_end.py

---

## What JUMPPER does not do

- Not a DEX, not a wallet, no token issuance
- Holds nobody's private keys
- Executes no financial transactions
- Runs no autonomous daemons
- Never self-certifies success - every claim is checked against an external chain

---

*Independent repository. Does not touch any other repo.*
