<!-- hardening:allow-file ALL reason=quotes the on-chain fork records and the correction payload it publishes -->

# Broadcasting the fork correction - the artifact is built

`state/fork-correction-op.json` holds the complete, ready-to-sign operation. It was
generated from `forks.json` by `src/jumpper/remedy.py` and verified end to end.

    payload      831 bytes of an 8,192-byte free budget  (10.14%)
    authority    POSTING   required_auths: []
    fee          0         (HIVE custom_json has no fee field at all)
    id           saos-height-correction.v1
    corrections  8 heights, 17 roots, all AMBIGUOUS
    retracts     false

**One zero-fee operation publishes the entire correction record.**

---

## The eight heights, from the real chain

| height | roots | first committed | last committed | span |
|---|---|---|---|---|
| 1764 | 2 | 2026-09-09T18:27:21 | 2026-09-09T18:27:51 | **30 s** |
| 1668 | 2 | 2026-09-09T18:19:18 | 2026-09-09T18:22:36 | **198 s** |
| 552 | **3** | 2026-09-07T21:57:33 | 2026-09-07T22:04:36 | 7 min |
| 1476 | 2 | 2026-09-09T18:06:48 | 2026-09-09T23:24:36 | 5.3 h |
| 1392 | 2 | 2026-09-08T03:35:09 | 2026-09-09T18:02:36 | 1.6 d |
| 1224 | 2 | 2026-09-07T23:58:54 | 2026-09-09T17:54:12 | 1.7 d |
| 12 | 2 | 2026-09-07T22:53:03 | 2026-09-09T22:10:06 | 2.0 d |
| 1416 | 2 | 2026-09-07T14:42:57 | 2026-09-09T18:03:48 | 2.1 d |

Read from 173 `saos-dex.anchor.v1` anchors on HIVE mainnet for account
`headcorner`. Source data in `forks.json`, detector in `src/jumpper/forkwatch.py`.

---

## Why no canonical root is declared

`remedy.py` refuses to publish `CANONICAL` unless the operator supplies a root, and
refuses a supplied root that is not among the committed ones.

The reasoning is not caution for its own sake. Two signed commitments at one height
are both real. Which one the state machine actually produced is a fact about the
operator's process, not about the ledger - and picking the earliest would be a
convention dressed as a finding. A verifier who trusted it would be trusting us
rather than the chain.

So all eight publish as `AMBIGUOUS` with every root listed. A verifier reading the
chain sees the contradiction and all of its terms, which is more than they can see
today.

If the operator later determines which root is authoritative for a given height,
`remedy.py` accepts it - `CANONICAL` with a `canonical_root` that is one of the
committed roots - and `apply_corrections` then reports that height as resolved
rather than ambiguous.

---

## What it does not do

`retracts: false`, and that is deliberate. The eight original anchors are permanent
and stay readable. **A correction that hides the original is worse than the
original**, because it removes the evidence that a correction was needed.

---

## How to broadcast it

The artifact carries the operation exactly as `custom_json` expects it:

    [ "custom_json",
      { "required_auths": [],
        "required_posting_auths": ["headcorner"],
        "id": "saos-height-correction.v1",
        "json": "1|saos-dex.anchor.v1|AMBIGUOUS|12:2:<b64u roots>,552:3:..." } ]

Sign with the **POSTING** key of `headcorner` and broadcast. Nothing else is needed:
no fee, no active authority, no second operation.

`remedy.py` never signs and never broadcasts - it builds the operation and hands it
to an external signer, and `plan()` says so in its own output:

    "signing": "external-only",
    "broadcast": "never-performed-here"

To decode the payload afterwards:

    version | logId | status | height:rootCount:root1B64u+root2B64u , ...

Roots are base64url of the 32-byte digest, 43 characters instead of 64 hex. The log
id and the status appear once per batch. `remedy.py` has no decoder for this format
yet - the round trip is tested in `tests/test_remedy.py` through `encode_corrections`
and `apply_corrections`, but a standalone `decode_corrections` is still to be
written, and this says so rather than implying one exists.

---

## The epoch fix that stops the next one

This correction records eight forks. It does not prevent a ninth. The prevention is
the epoch field, which **is** now in `saos-dex/src/lib/dex/relay.ts` - adopted from
`EPOCH-PATCH-SPEC.md` in commit `263d3bfc9b`, assigned once per job rather than per
chain so the cross-chain byte equality is preserved.

So the sequence is: the epoch stops new forks, and this correction publishes the
eight that already happened. Both halves are needed; neither replaces the other.

---

*Read-only throughout. This document and the artifact describe an operation. Nothing
was signed and nothing was broadcast. No file outside saos-jummper was created,
modified or deleted.*
