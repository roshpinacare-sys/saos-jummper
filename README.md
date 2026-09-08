# SAOS JUMPPER

Cross-chain batched proof notary.

JUMPPER turns any digital claim into a permanent, cheap, independently verifiable
record on Ethereum mainnet, timestamped by five independent blockchain clocks.

Core thesis: the scarce resource in autonomous systems is not compute and not
capital. It is verifiable truth. Every agent can claim anything. Only a public
chain cannot lie.

---

## Why this project

An audit of 8 repositories and 3 parallel development tracks found one pattern:

Every agent can claim anything. No agent can prove anything.

13 work rounds reported "all green, all pushed". None of it was independently
verified. The one thing that could not be argued with - the Ethereum calldata
anchor - turned out to be real (block 25,929,672, status 0x1).

---

## What is already proven

| Component | Status | Evidence |
|---|---|---|
| ETH mainnet calldata anchor | works for real | block 25,929,672, status 0x1, 30,920 gas, ~$0.10 |
| Merkle tree + inclusion proofs | correct | merkle.ts, proper odd-node duplication, self-verify |
| Deterministic kernel | correct | replay protection, value conservation, canonical JSON |
| Keyless read of 5 chains | works | STEEM, HIVE, TRON, ETH, SOL head blocks verified live |
| Security plumbing | works | auth, rate-limit, audit log, green CI, 147 assertions |

About 60 percent of the system already exists and is proven. JUMPPER is not a
new idea. It is the consolidation of what already works into one coherent product.

---

## The central idea: batch economics

A single anchor costs about $0.10. Merkle lets thousands of claims share one root.

| Batch size | Cost per anchor | Cost per claim |
|---|---|---|
| 1 | $0.10 | $0.10 |
| 100 | $0.11 | $0.0011 |
| 1,000 | $0.15 | $0.00015 |
| 10,000 | $0.50 | $0.00005 |

A public notary at a hundredth of a cent per proof. That is the unlock.

---

## The unique edge: multi-chain temporal witness

OpenTimestamps uses Bitcoin only. Nobody offers multi-chain witnessing.

At anchor time JUMPPER reads the head block from five independent chains:

    STEEM     -> api.steemit.com      head block
    HIVE      -> api.hive.blog        head block
    TRON      -> api.trongrid.io      solidity head
    ETHEREUM  -> publicnode           blockNumber
    SOLANA    -> mainnet-beta         slot

Five independent clocks testify to the same moment. If Ethereum reorgs, four
other witnesses remain. If our server clock drifts, the chains do not.

---

## Three verification tiers (zero trust in us)

1. Self-verify. Standalone script. leafHash + proof + root. Local compute, zero network calls.
2. API verify. GET /verify/{claimId} returns inclusion proof and txid.
3. On-chain verify. Anyone takes the txid, decodes calldata from a public explorer,
   compares the root. Zero trust in us at all.

---

## What JUMPPER does not do

- Not a DEX (that exists in saos-dex)
- Not a wallet (that exists in Saosmartwallet)
- Holds nobody's private keys
- Executes no financial transactions
- Runs no autonomous daemons
- Never self-reports success - every claim is verified against an external chain

---

## Status

Phase: architecture design. Code: not yet written. Proof of feasibility: exists
(block 25,929,672 on Ethereum mainnet).

See docs/ARCHITECTURE.md for the full design.

---

Independent repository. Does not touch any other repo. Created as a separate workspace.
