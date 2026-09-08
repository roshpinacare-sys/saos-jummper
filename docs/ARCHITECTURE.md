# SAOS JUMPPER - Architecture

<!-- hardening:allow-file ALL reason=this document quotes the on-chain payloads and defective patterns it reports; quoting a finding is not committing one -->

Version 0.1 (design). No production code written yet.
Feasibility already demonstrated on Ethereum mainnet: block 25,929,672, status 0x1.

---

## 1. Problem statement

Autonomous agents produce enormous amounts of state and claims. None of it is
independently verifiable. In the audited estate, three parallel tracks each
reported success; two of them reported "live anchors" that could not be
distinguished from local file writes. One track had genuinely anchored to
Ethereum mainnet, and that was the only claim that survived verification.

The gap is not capability. It is provability.

JUMPPER exists to make any claim cheaply, permanently, and independently provable.

---

## 2. Design principles

P1. Zero trust in the operator. Every output must be verifiable without running our code.
P2. Never hold user keys. We anchor hashes, not assets.
P3. Batch by default. Single-claim anchoring is an edge case, not the design center.
P4. Honest degradation. If a probe fails, report unreachable. Never invent a value.
P5. No autonomous financial action. Anchoring costs gas; that is the only spend, and it is bounded.
P6. Append-only. History is never rewritten. Forks are reported, not repaired.
P7. Independent verification over self-report. Every subsystem must be checkable from outside.

---

## 3. Layered architecture

    L0  INGEST      claim submission, canonicalization, leaf hashing
    L1  BATCH       Merkle accumulation, batch sealing, monotonic height
    L2  ANCHOR      Ethereum mainnet self-transfer with calldata
    L3  WITNESS     multi-chain head capture at anchor time
    L4  VERIFY      three-tier proof verification
    L5  SURFACE     API + explorer UI

### L0 - Ingest

    POST /claim
      body: { payload: any, schema?: string, source?: string, public?: boolean }
      returns: { claimId, leafHash, batchId, position }

Canonicalization: deterministic JSON (sorted keys, -0 normalized to 0,
non-finite numbers rejected). Port canonical-json.ts from the foundry codebase;
it is already correct.

    leafHash = sha256("saos-jumpper/claim/v1" + canonical(payload) + isoTimestamp)

If public=false, only the leafHash is stored. The payload is returned to the
submitter and discarded. This allows private claims to be anchored without
disclosure - the hash commits without revealing.

### L1 - Batch

Leaves accumulate into an open batch. A batch seals when either condition hits:

    maxLeaves  (default 1000)
    maxAge     (default 300 seconds)

On seal:
  - build Merkle tree (port merkle.ts - correct odd-node duplication)
  - assign monotonic height from max(existing) + 1 inside a transaction
  - persist root, leafCount, per-leaf inclusion proofs
  - emit sealed event

Concurrency: the foundry already solved this. Transactional append behind a
write mutex, retry on unique-constraint and lock-contention errors, idempotency
key so a repeated batch submission returns the existing root. Port that pattern
directly; it is proven (8/8 concurrent seals, contiguous heights).

### L2 - Anchor

Ethereum mainnet self-transfer, 0 ETH value, calldata carries the commitment:

    {
      "protocol": "saos-jumpper/v1",
      "action": "batch-anchor",
      "height": H,
      "root": "<64 hex>",
      "leafCount": N,
      "witness": { "steem": ..., "hive": ..., "tron": ..., "eth": ..., "sol": ... },
      "at": "<iso8601>"
    }

Proven cost: 30,920 gas at 1.051 gwei = 0.0000325 ETH, roughly $0.10.

The self-transfer pattern is deliberate:
  - no contract deployment, no contract risk, no upgrade path to break
  - no counterparty, no approval, no allowance
  - calldata is permanent in block history (unlike EIP-4844 blobs, which expire)
  - verifiable by anyone from any public explorer

Signing happens OUTSIDE the system. JUMPPER produces the payload and the digest;
an external signer produces the txid; JUMPPER records only the public result.
The signing key never touches the repo, the database, or the server process.

### L3 - Witness

At anchor time, before broadcasting, capture head state from five chains:

    STEEM     condenser_api.get_dynamic_global_properties   head_block_number
    HIVE      condenser_api.get_dynamic_global_properties   head_block_number
    TRON      soliditynode getnowinfo / getblock            block num
    ETHEREUM  eth_blockNumber                               blockNumber
    SOLANA    getSlot                                       slot

All keyless public endpoints. Timeout 2.5s each. Hostname only in logs, never
full URLs (some public endpoints embed keys in query strings).

If a chain is unreachable, record `unreachable` and continue. A witness is
corroborating evidence, not a gate. Never fabricate a value.

Why this matters:
  - Reorg resistance. Ethereum reorgs are shallow and rare, but four other
    witnesses pin the moment independently.
  - Clock independence. Our server clock is not trusted; five chain clocks are.
  - Novelty. OpenTimestamps uses Bitcoin only. No known service offers
    five-chain temporal witnessing.

### L4 - Verify

Tier 1 - self-verify (zero trust, zero network):

    npx saos-jumpper-verify <leafHash> <proofJson> <root>

Recomputes the Merkle path locally. Exits 0 on match. Ships as a standalone
script with no dependency on our service.

Tier 2 - API verify:

    GET /verify/{claimId}
      -> { leafHash, proof[], root, height, anchorTxid, anchorBlock, witness, status }

Tier 3 - on-chain verify (zero trust in us entirely):

Take anchorTxid. Fetch from any public explorer. Decode calldata as UTF-8.
Compare root. Done. We are not in the loop.

Critical invariant, learned from the audit: a recorded anchor that cannot be
re-verified against the chain is marked `unverified` and is never presented as
final. The audited estate had a ledger claiming verified=18 against anchored=16,
and a chain claiming 18 anchors with 0 verifications. Counters must be derived
from verification results, never incremented optimistically.

    anchored   = number of batches we broadcast
    verified   = number of batches we successfully re-confirmed on chain
    invariant  = verified <= anchored, always

### L5 - Surface

API surface:

    POST /claim                  submit a claim
    GET  /claim/{id}             claim status and proof
    GET  /batch/current          open batch state
    GET  /batch/{height}         sealed batch
    GET  /verify/{claimId}       full verification bundle
    GET  /anchors                anchor history with on-chain status
    GET  /witness/{height}       multi-chain witness for a height
    GET  /health                 service and chain reachability
    GET  /metrics                counters, costs, throughput

Explorer UI: batch timeline, anchor list with live on-chain status, witness
grid, claim lookup, verification walkthrough.

---

## 4. Data model

    Claim       id, leafHash, batchId, position, public, createdAt, payloadHash
    Batch       height (unique, monotonic), root, leafCount, sealedAt, status
    Anchor      batchHeight (unique), txid, blockNumber, blockHash, gasUsed,
                costWei, broadcastAt, confirmations, verifyStatus, verifiedAt
    Witness     anchorHeight, chain, headRef, capturedAt, reachable
    AuditEvent  id, actor, action, target, at, meta (never secrets)

Anchor has a unique constraint on batchHeight: one batch anchors at most once.
Forks are reported, never repaired - append-only.

---

## 5. Economics

Cost model per anchor (Ethereum mainnet, calldata self-transfer):

    base           ~21,000 gas
    calldata       ~16 gas per non-zero byte, 4 per zero byte
    1 claim        ~30,900 gas   -> ~$0.10 at 1 gwei
    1,000 claims   same anchor   -> ~$0.0001 per claim

Optional fast tier: anchor to an L2 (Base, Arbitrum) for roughly $0.001 per
batch. Inherits L2 security. Offered as "fast", with L1 as "sovereign".

Revenue shapes (not decided, listed for analysis):
  - per-claim fee at scale
  - subscription for high-volume submitters
  - enterprise API with SLA
  - free tier with public batches, paid tier with private/exclusive batches

---

## 6. Reuse plan (what ports from the audited estate)

Port from saos-sovereign-foundry, which is the disciplined track:

    src/lib/saos/merkle.ts            -> lib/merkle.ts          (as-is, correct)
    src/lib/saos/canonical-json.ts    -> lib/canonical.ts       (as-is, correct)
    src/lib/saos/receipt-store.ts     -> lib/batch-store.ts     (transactional append + mutex)
    src/lib/saos/networks/live-probes.ts -> lib/witness.ts      (5-chain keyless probes)
    src/lib/saos/rate-limit.ts        -> lib/rate-limit.ts      (as-is)
    src/lib/saos/auth.ts              -> lib/auth.ts            (hash-only, fail-closed)
    scripts/api-check.mjs pattern     -> tests/api-check.mjs    (contract testing approach)

Do NOT port:
    anything from the fleet/daemon/autonomous-trading layer
    anything that holds or derives private keys
    anything that self-reports success without external verification

---

## 7. Explicit non-goals

    - no DEX, no order book, no liquidity
    - no wallet, no custody, no key management for users
    - no token issuance
    - no autonomous agents or daemons
    - no financial transactions of any kind
    - no rewriting of history, ever
    - no self-certified success

---

## 8. Build order

Phase 1 - the loop that matters (working notary):
    1. claim ingest + canonical hashing
    2. Merkle batcher with transactional seal
    3. ETH calldata anchor (external signing, record-only)
    4. standalone verifier script

Phase 2 - the edge:
    5. multi-chain witness capture
    6. witness embedded in calldata and persisted

Phase 3 - the product:
    7. public verify API
    8. explorer UI
    9. batch dashboard and cost metering

Phase 4 - scale:
    10. L2 fast tier
    11. auth tiers, rate limits, billing hooks

---

## 9. Success criteria

A build is only done when:

    - a claim submitted to the API can be independently verified from the
      Ethereum block calldata by someone who has never seen our code
    - verified <= anchored holds as a hard invariant, enforced in tests
    - all five witness chains report reachable or unreachable honestly
    - the standalone verifier passes with zero network access
    - no private key exists anywhere in the repo, database, or server process
    - the full test suite is green in CI on a fresh clone

---

## 10. The one-sentence version

JUMPPER makes lying expensive. Any agent, any process, any claim - commit it to
Ethereum for a tenth of a cent, and from that moment it can never be rewritten,
denied, or faked.

---

Design document. Independent workspace. Does not modify any other repository.
