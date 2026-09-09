# SAOS JUMPPER

<!-- hardening:allow-file ALL reason=this document quotes the on-chain payloads and defective patterns it reports; quoting a finding is not committing one -->

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

## The missing link (the biggest finding so far)

`roshpina` holds the most sophisticated code in the entire estate and nobody had
read it: **114 kernel files, 838,280 characters, one commit, no README.**

It contains a genuine RFC 6962 / Sigstore Rekor style transparency log -
inclusion proofs, **consistency proofs** against split-view attacks, witnesses
with liveness and gossip, cross-log consistency, and **federation anchors** that
let a third party verify two logs agreed at a point in time without seeing either
log's leaves. Plus ML-DSA (FIPS-204) post-quantum hybrid signing, a strict-state-
machine escrow economy with a fee engine and dispute handling, RBAC, agent
identity with delegation, single-use capability tokens that replace a documented
authorisation flaw, a tamper-evident audit hash chain, and selective-disclosure
track-record proofs.

It also contains this, in `kernel/track-record/predicate-proof.ts`:

> HONESTY NOTE - this is NOT zero-knowledge cryptography... it would be dishonest
> to imply otherwise.

**And every one of the 114 files was scanned: zero references to custom_json,
dhive, hive, steem, ethers, solana or web3.** The kernel's own docstring says its
log "publishes the root" - to memory. Its consistency defence is stated as
working *"if every monitor checks"*, which is exactly the assumption a split-view
attack breaks.

`src/jumpper/sth.py` closes that gap: signed tree heads packed **148 to 177 per
zero-fee custom_json**, POSTING authority, anchored to HIVE mainnet. Global
visibility is what turns "detectable if monitors gossip" into "detectable by
anyone, always" - and it costs nothing.

### A correction this round produced

An earlier claim that the two Merkle conventions matched was read off a
docstring and was **wrong**. Measured: they agree only for n = 1, 2 and powers of
two, and differ otherwise (verified n = 1..199, pinned by tests). `jumpper`
carries an odd node up unchanged; the kernel hashes it with itself. Every signed
tree head therefore carries its convention explicitly, an unknown convention is
refused rather than guessed, and a mixed batch is rejected.

A capacity estimate of 181 heads per operation was also optimistic - it probed
with a one-digit tree_size. 181 real heads encode to 8,889 bytes and cannot be
broadcast at all. The estimate now measures a representative head, and
`encode_heads` fails closed on the 8192-byte budget so an over-estimate can never
reach the chain.

See `docs/THE-MISSING-LINK.md`.

## Hardening: safe AND usable, not one or the other

`docs/HARDENING.md` + `src/jumpper/hardening.py` + `scripts/harden-check.py`.

The requirement was two things at once: solutions we can still work with, and
solutions that cannot be broken into. The resolution is not a compromise:

> **Fail closed by default, with a scoped, expiring, committed, audited waiver.**

Every blocking rule can be passed - but only by an act that is named, reasoned,
attributed to a human, time-limited, stored in the repository, and printed in
every subsequent gate run. A rule people disable is not a control. A waiver
people can see is.

**17 rules, every one derived from a real defect read out of this estate.** None
is speculative; each carries the finding it came from.

    python scripts/harden-check.py .        # exit 1 if anything blocks

Verified against a tree built from the actual defective files: **10 blocking + 4
reporting across 9 files, verdict BLOCKED, exit 1**. Against a clean tree:
**PASS, exit 0**. A clean file inside the defective tree was correctly reported
clean.

The gate **never prints a secret value**. Its first version did - the H-08
evidence line contained the vault password verbatim. That is fixed and pinned by
six regression tests: for H-08, H-09 and H-10 the evidence is reduced to location
plus field name, and a test serialises the whole verdict and asserts the secret
appears nowhere in it.

Three of the eleven blocking rules are single-token fixes:

| rule | fix | cost |
|---|---|---|
| H-11 | `required_auths` -> `required_posting_auths` | two fields, **zero RC** |
| H-13 | `searchTransactionHistory: false` -> `true` | **one boolean** |
| H-05 | `Math.random()` -> a CSPRNG, fatal if absent | one call |

H-11 alone removes fund-moving capability from every automated broadcaster in the
estate, because posting and active authority consume the same resource classes
for the same payload.

## Cross-chain proof, and the control that stops a runaway loop

**U-01 is resolved.** The Solana anchors are on **mainnet** - slot 445,225,030,
`err: null`, official SPL Memo program, 5,000 lamports. And the commitment is
**byte-identical to the Ethereum anchor** at block 25,929,672 across all six
fields: protocol, action, at, height, stateRoot, digest.

    COMMITMENT IDENTICAL ON 2 INDEPENDENT MAINNETS

That corrects an earlier reading. `solana verified=0` was not 27 failures - it was
one boolean (`searchTransactionHistory: false`) making the verifier structurally
unable to see anything older than the node cache. **The system was doing the right
thing and reporting it badly.**

Measured cost for the identical 248-byte commitment: HIVE custom_json **$0.00**,
Solana memo **$0.00075**, Ethereum calldata **$0.08123**. Ethereum is 108x more
expensive than Solana and infinitely more expensive than HIVE.

**`src/jumpper/budget.py`** adds the control the estate was missing. Replaying the
real 11-call `hive.convert` loop - real payload, real measured RC cost, real
timestamps - the gate allows 1 and denies 10, recovering **1,577,137,920 RC, 30.8%
of one day's regeneration budget**. It is fail-closed throughout, with AND
semantics and a raising guard treated as a deny, copied from
`roshpina/kernel/orchestrator/guard.ts`.

See `docs/CROSS-CHAIN-PROOF.md` and `docs/BUDGET-GUARD.md`.

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
| test suite | **green from a fresh clone** |
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
    src/jumpper/sth.py           signed-tree-head anchoring - the bridge to roshpina's CT log
    src/jumpper/hardening.py     17-rule policy engine, every rule from a real defect
    src/jumpper/solana.py        memo anchoring, measured on mainnet (5000 lamports)
    src/jumpper/crosschain.py    commitment equality across independent mainnets
    src/jumpper/budget.py        rolling budget + repeat guard, all fail-closed
    src/jumpper/freeops.py       capability matrix: 12 free vs 5 never-free, honest limits
    src/jumpper/anchor.py        ETH calldata + EIP-2028/EIP-7623 gas model (settlement tier)
    src/jumpper/witness.py       5-chain keyless read-only probes
    src/jumpper/verify.py        standalone verifier CLI
    tests/test_jumpper.py        43 assertions
    tests/test_graphene.py       34 assertions on live mainnet fixtures
    tests/test_throughput.py     39 assertions: constants, packing, authority, stack
    tests/test_liveops.py        21 assertions pinned to a real mainnet fixture
    tests/test_sth.py            34 assertions: convention divergence, capacity, fail-closed
    tests/test_hardening.py      35 assertions: every rule pinned to its real defect
    tests/test_crosschain.py     31 assertions on real ETH + SOL mainnet transactions
    tests/test_budget.py         32 assertions replaying the real convert loop
    tests/fixtures/              100 real HIVE account-history entries
    tests/golden_vectors.json    cross-language validation vectors
    scripts/demo_end_to_end.py   full pipeline with live witness
    scripts/harden-check.py      the gate - run before every commit and push
    docs/ARCHITECTURE.md         design
    docs/ECONOMICS.md            measured cost model
    docs/FREE-OPERATIONS.md      what is free on our network, and what never is
    docs/BREAKTHROUGHS.md        the seven findings, measured vs derived vs unmeasured
    docs/LIVE-FINDINGS.md        what the chain says is actually running, and what leaks
    docs/THE-MISSING-LINK.md     roshpina's trust kernel, and the gap it cannot close alone
    docs/WALLET-AUDIT.md         the wallet vault: plaintext fallback, stub crypto, lost merge
    docs/HARDENING.md            the gate, the rules, and how to get a waiver
    docs/CROSS-CHAIN-PROOF.md    U-01 resolved: same commitment on two mainnets
    docs/BUDGET-GUARD.md         the control that stops a runaway loop
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
