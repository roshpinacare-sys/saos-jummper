# Free Operations

What costs money elsewhere and is free on our network.

The full analysis lives in code, not prose, so it cannot drift:

- `src/jumpper/freeops.py` - capability matrix, 17 entries,
  12 free attestation-class operations and 5 that are never free,
  each with its honest limit stated inline.
- `src/jumpper/graphene.py` - the free anchor layer, the RC manabar
  projection fix, and payload compaction.
- `tests/test_graphene.py` - 34 assertions pinned to live mainnet fixtures.

## The one distinction

custom_json buys an ATTESTATION, not ENFORCEMENT.

- Is the value the PROOF? Then it is free on our network.
- Is the value the EFFECT? Then it needs capital. No free lunch.

A test enforces this: no capability tagged enforcement may be
marked free. If someone later marks escrow as free, the suite fails.

## Verified baseline (live HIVE mainnet, read-only)

    account          headcorner
    operation        custom_json, id saos-dex.anchor.v1
    authority        required_auths = [headcorner]  (ACTIVE key)
    fee field        ABSENT - zero fee
    real anchors     21 in the last 100 history entries
    block range      109708562 to 109734678
    window           about 22 hours
    payload          247 to 250 bytes, mean 248.8
    max_rc           25,641,553,538
    regen            59,355 RC/sec = 5,128,310,708 RC/day
    effective mana   73,271,489 (stored snapshot 1,392,041)

Real transactions, verifiable in any public explorer:

    block 109732622  trx 48982c950f5532fb879c26d52d7c79be9df38dd1
    block 109733604  trx 0c66e2c59e65cc4bcb753cb7768b1fc991547ea4
    block 109734678  trx 0eafff4632773d90d4c1f788036a4257c885ea96

## The bug that was blocking free anchors

rc_api returns current_mana AS OF last_update_time. It is a snapshot,
not a balance. Measured live:

    stored   1,392,041   at 1788870714
    now      1788871925  (1,211 s later)
    regen    59,355 RC/sec
    EFFECTIVE 73,271,489  = 52.6x the stored value

A gate comparing the raw snapshot to a constant reports BLOCKED while the
account holds tens of millions of RC. The earlier reading of 924265 against
a threshold of 1000000 declared HIVE blocked. That was a stale-read bug,
not a resource shortage, and it costs nothing to fix.

    effective = min(max_rc, stored + (max_rc/432000) * (now - last_update))

The test pins this to the live figure exactly.

## Payload compaction - a free throughput multiplier

RC consumption scales with transaction bytes. Measured on a real anchor root:

| tier | shape | bytes | vs on-chain today |
|---|---|---|---|
| legacy | protocol, action, at, height, stateRoot hex, digest | 250 | baseline (live now) |
| D | JSON, root as base64url, no digest, no at | 67 | -73.2% |
| E | bare CSV: version,height,rootB64u | 51 | -79.6% |

Two legacy fields are not merely redundant, they are wrong to send:

- **digest** - sha256 of the payload. Anyone can recompute it. Paying RC to
  store a derivable value is pure waste.
- **at** - our own ISO clock. The BLOCK timestamp is the authoritative time and
  is the entire point of anchoring. Broadcasting our own clock is weaker and
  costs bytes.

Tier E, exact round-trip tested:

    1,12108,qMNCPNaOod8To-jw3RzIg_LlLI4KkPfATmSEBcYM1Q8

## Cost comparison, real numbers

| path | cost per anchor | verification |
|---|---|---|
| HIVE / STEEM custom_json | **$0.00** (RC only, regenerates free from stake) | 21 real anchors read from mainnet |
| Ethereum calldata self-transfer | $0.081 (32,320 gas at 1 gwei) | gas model exact-matches mainnet block 25929672 to the wei |

Ethereum is not a bit more expensive. For attestation-class work it is
infinitely more expensive than free, and it buys nothing our network does not
already provide - unless the counterparty refuses to accept Graphene finality.

**Recommendation: Graphene is the primary anchor path. Ethereum is demoted to an
optional low-frequency settlement tier** for third parties who need it - daily
or weekly, amortised to a few dollars a year.

## What is free: 12 attestation-class operations

Each is specified in `src/jumpper/freeops.py` with its honest limit inline.

| # | capability | replaces | honest limit |
|---|---|---|---|
| 1 | Document notarization / proof of existence | ETH calldata, OriginStamp, commercial notary | proves the hash existed at block time; does not store the document |
| 2 | Trusted timestamping | RFC 3161 TSA, OpenTimestamps | trust anchor is Graphene finality (~60s irreversible), not Bitcoin PoW |
| 3 | Immutable audit log with non-repudiation | AWS QLDB, tamper-evident log services | binds only the signing account |
| 4 | Commit-reveal randomness / sealed bids | Chainlink VRF, contract commit-reveal | no verifiable randomness beacon; withholding a reveal is not punishable without collateral |
| 5 | Credential registry and revocation | on-chain revocation registries | publishes status; nothing forces a verifier to honour it |
| 6 | Signed approvals, multisig coordination, quorum signalling | Safe txs, contract voting | coordination is free; execution still needs the chain holding the asset |
| 7 | Merkle batch commitment (unlimited claims, one root) | per-item anchoring | proofs must be distributed out of band; chain stores the root, not the leaves |
| 8 | Heartbeat / dead-man-switch attestation | Chainlink Keepers, Gelato | the chain will not ACT on a missed heartbeat; an external watcher must |
| 9 | Name / handle claim (first-come registry) | ENS ($5/yr plus gas), Unstoppable | a dated assertion, not a property right; no uniqueness enforcement |
| 10 | Cross-chain relay between endpoints YOU control | LayerZero, Wormhole, Axelar | trust is your watcher, not a decentralized validator set |
| 11 | Software licence key registry | licence contracts, SaaS licence servers | the binary must still check and decide |
| 12 | Public data availability for small payloads | Arweave, IPFS pinning | RC scales with bytes; tier E gives ~51 B. Not a file store |
