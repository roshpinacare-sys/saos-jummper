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
| test suite | **43/43 green** |
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
    src/jumpper/anchor.py        calldata + EIP-2028/EIP-7623 gas model
    src/jumpper/witness.py       5-chain keyless read-only probes
    src/jumpper/verify.py        standalone verifier CLI
    tests/test_jumpper.py        43 assertions
    tests/golden_vectors.json    cross-language validation vectors
    scripts/demo_end_to_end.py   full pipeline with live witness
    docs/ARCHITECTURE.md         design
    docs/ECONOMICS.md            measured cost model
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
