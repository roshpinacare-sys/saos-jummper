# Testing


## Run everything

    pip install -r requirements.txt
    python -m unittest tests.test_jumpper -v
    python scripts/demo_end_to_end.py

## Latest verified run

    Ran 43 tests in 0.043s

    OK

## What is covered

| area | tests | notable cases |
|---|---|---|
| canonical | 6 | key order, nesting, -0 normalization, 1.0 -> 1, non-finite rejected, no whitespace |
| merkle | 8 | every leaf proves at n = 1..100, odd-node duplication, tamper, cross-tree, order sensitivity, empty rejected |
| claim | 6 | determinism, key-order independence, timestamp sensitivity, private hides payload but reports size |
| anchor gas | 5 | **exact match to mainnet gasUsed AND cost in wei**, EIP-7623 floor binds, naive model would under-price by 5,952 gas |
| anchor payload | 4 | roundtrip, verify match/reject on every field, witness embedded, invalid inputs rejected |
| batch economics | 3 | gas near-flat across 6 orders of magnitude, root size constant, per-claim cost falls as 1/n |
| batcher | 5 | max_leaves seal, max_age seal, force seal, invariants after 20 batches, all proofs valid |
| golden vectors | 6 | canonical, merkle root, merkle proofs, claim hashes, gas model, payload bytes |
| **total** | **43** | |

## Golden vectors

`tests/golden_vectors.json` exists so a port to TypeScript, Rust, or Go can be
validated byte-for-byte instead of trusted. Any implementation that reproduces
those vectors is correct by construction on the parts that matter.

The vectors are generated from the reference implementation, never hand-edited.

## The anchor gas test is the important one

It does not check our code against a specification we read optimistically. It
checks our code against a transaction that actually happened on Ethereum mainnet:

    txid      0x94f4cb4fc0c50d742a583576b2cb1d14fa55dd99437510bf252a6ccba3e37813
    block     25,929,672
    model     30,920 gas / 32,493,358,294,280 wei
    actual    30,920 gas / 32,493,358,294,280 wei

If a future hard fork changes calldata pricing, this test fails loudly instead of
silently mis-pricing every anchor the product sells.

## End-to-end demo

`scripts/demo_end_to_end.py` runs the full pipeline and prints real results:
ingest, batch, live multi-chain witness capture, anchor pricing, three-tier
verification.

It performs a **real read-only** witness call to public chain endpoints and
reports unreachable chains honestly rather than inventing values.

It never signs and never broadcasts.

### Latest demo output (abridged, real run)

    [L0 INGEST]  5 claims hashed, 1 public / 4 private
    [L1 BATCH]   height=1 leaves=5 reason=max_leaves
                 root = 491103b91acb719641dd7ddaf260db2c680244d6d4e937bb9eaa28a465aa6550
                 invariants: heights contiguous, roots unique, all proofs valid
    [L3 WITNESS] TRON     OK   headRef=86056447
                 ETHEREUM OK   headRef=25930210
                 STEEM    FAIL ConnectionError (honest degradation - value NOT invented)
                 HIVE     FAIL ConnectionError (honest degradation - value NOT invented)
                 SOLANA   FAIL ConnectionError (honest degradation - value NOT invented)
    [L2 ANCHOR]  268 bytes -> 31,720 gas -> 0.000031720 ETH @ 1 gwei
                 binding rule: EIP-7623-floor (tokens=1072, eip2028=4288, floor=10720)
                 NOT SIGNED. NOT BROADCAST. External signer only.
    [L4 VERIFY]  tier1 self-verify inclusion : True  (no network, no trust in us)
                 tier3 on-chain shape match  : True  (anyone can run from an explorer)
                 tamper rejected             : True
    RESULT: PIPELINE GREEN

STEEM, HIVE and SOLANA were unreachable from the sandbox that produced this run
(restricted egress). The witness recorded `null` for them and said so. That is the
designed behaviour: an unreachable chain is reported as unreachable, never guessed.

## What is NOT tested yet

- STEEM / HIVE / SOLANA egress from restricted sandboxes (probe correctly returns unreachable)
- the production persistence layer (SQLite/Postgres); the in-memory Batcher enforces the same invariants
- concurrent multi-process sealing (single-process lock is tested; the production pattern is documented in `batch.py`)
- HTTP API surface (Phase 3)
- CI workflow (Phase 3)
