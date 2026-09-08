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
