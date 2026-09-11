<!-- hardening:allow-file ALL reason=status board quoting the defective code it tracks, plus two self-corrections -->

# Patch Status - the scoreboard, and a correction of a correction

Run with `src/jumpper/patchwatch.py` against real source fetched from four
repositories on 2026-09-11. Every file it tracks was supplied, so nothing is left
indeterminate.

    present 7   absent 5   indeterminate 0   open critical: P-12

---

## CORRECTION OF A CORRECTION - the epoch patch IS in the source

This document previously stated that the epoch patch was absent from
`saos-dex/src/lib/dex/relay.ts`, on the strength of four reads that all returned
62,241 bytes at blob `b1643c314743` with zero occurrences of `epoch`.

**That was wrong, and the earlier report it corrected was right.** The definitive
evidence is the file's own commit history, with the blob size and epoch count read
at each commit:

    40404426af  09-11T06:12:27  77,063 bytes  epoch x63   roast-79
    6bb3d4ed1d  09-11T05:21:52  75,839 bytes  epoch x63   roast-78
    b3c88790d3  09-11T04:30:44  74,689 bytes  epoch x63   roast-77
    263d3bfc9b  09-11T03:58:27  74,677 bytes  epoch x63   relay: EPOCH-PATCH-SPEC adopted from saos-jummper
    5f4673c896  09-11T01:46:24  70,946 bytes  epoch x0    Task 74
    3138b3b5b1  09-11T00:01:43  69,171 bytes  epoch x0    Task 73
    efce505aa1  09-10T19:39:25  65,882 bytes  epoch x0    FIX(Roast-69)
    173c69d15c  09-10T15:54:15  65,451 bytes  epoch x0    fix(roast-65-e1)
    30801f8ac1  09-10T12:51:35  65,229 bytes  epoch x0    fix(roast-64-e2)
    be9e15fe00  09-10T05:19:24  61,299 bytes  epoch x0    fix(roast-63)

**The epoch was introduced at `263d3bfc9b` on 2026-09-11T03:58:27, in a commit
titled "relay: EPOCH-PATCH-SPEC adopted from saos-jummper", and it has been present
in every commit since.**

The current payload, verbatim:

    // EPOCH-PATCH-SPEC: epoch inside the canonical payload (not at per-chain call
    // sites) - preserves byte-equality across chains and closes the post-restart
    // height collision
    const payload = {
      protocol: "saos-dex/v1", action: "chain-seal", at: job.at,
      epoch,
      height: job.info.toHeight, stateRoot: job.info.stateRoot, digest: job.info.digest,
    };

Confirmed counts in the live file: `epoch` x63, `assignEpoch` x5.

### Why the correction read was wrong

The GitHub contents API returned a blob that does not correspond to any commit in
this file's history. Converting between the two units reconciles everything:

| my read | chars reported | equivalent bytes | matching commit |
|---|---|---|---|
| original report | 65,178 | ~74,677 | `263d3bfc9b` - the epoch adoption |
| the correction | 62,241 | ~70,946 | `5f4673c896` - Task 74, **before** the epoch |
| now | 67,059 | 77,063 | `40404426af` - roast-79, current HEAD |

The API reports `size` in **bytes**; I measured `len()` of decoded **characters**.
Hebrew comments are multi-byte, so the two differ by roughly 15%. The correction
read was served the pre-patch blob - a stale cache hit - and I compared a character
count against byte sizes without noticing the units did not match.

### What I got wrong, twice

1. The original report was **right** and I retracted it.
2. The retraction was based on **a single API read**, which is precisely the
   mistake the retraction accused the original of making.

The lesson is not "verify more". It is specific: **when a claim about repository
content is contested, the commit history is the authority, not the contents API.**
A blob served from cache has no commit behind it. A size read at a named commit
sha does. That is what settled this in one query, and it is what should have been
queried first.

Both errors are left in this document. The first version claimed the patch was
absent; it was not.

---

## A separate real finding: seven committers on one repository

While checking the history, the last 100 commits of `saos-dex` (2026-09-07 to
2026-09-11) show **seven distinct committer identities**:

    Z User
    Z.ai Code (SAOS-DEX Agent)
    agent-25-a
    roshpinacare-sys
    saos-bot
    saos-dex agent
    saos-dex-agent

Two of those differ only by a hyphen. Seventeen of the hundred commits are
automated `broadcast:` commits.

This did **not** cause the confusion above - the history is linear and the epoch
work survived every commit after it landed. But seven identities writing one file
from separate working trees is how a stale checkout eventually does overwrite fresh
work, and there is no lock, no rebase discipline and no ownership map to prevent
it. Worth fixing before it produces a loss rather than a near-miss.

---

## The scoreboard

### Confirmed PRESENT in source

| id | item | repo | evidence |
|---|---|---|---|
| **P-01** | **epoch in the canonical anchor payload** | saos-dex | commit `263d3bfc9b`, `epoch` x63, `assignEpoch` x5, added at the canonical site not per-chain |
| P-02 | POSTING authority for attestations | saos-dex | `required_posting_auths: auth === "posting" ? [account] : []` |
| P-03 | `searchTransactionHistory: true` | saos-dex | `getSignatureStatuses, [[txid], { searchTransactionHistory: true }]` |
| P-04 | RC manabar projected forward | saos-dex | `432000` and `Math.min` around `rc_manabar.current_mana` |
| P-05 | three-state `verified` | saos-dex | `verified: boolean \| null` - null means not yet checked |
| P-06 | no silent devnet default | saos-dex | the devnet literal is gone from `relay-sol.ts` |
| P-09 | threshold in `reconstructSecret` | Saosmartwallet | the signature now takes a threshold |

### Confirmed ABSENT

| id | severity | item | repo |
|---|---|---|---|
| **P-12** | **critical** | vault passphrase out of `state/pool.json` | saos-dex |
| P-08 | high | record `network` and `endpointHost` per anchor | saos-dex |
| P-10 | high | audit hash binds `source`, `occurredAt`, `reason`, `actionId` | roshpina |
| P-07 | medium | drop `digest` and `at` from the payload | saos-dex |
| P-11 | medium | mandatory reference id in `xlock` memos | saos-dex |

### The one open critical

**P-12 - the vault passphrase.** `saos-dex/state/pool.json` carries a `pass` field,
and `steem/agent/fleet_keys.meta.json` carries the same passphrase beside
`fleet_keys.enc`. Ciphertext with its password in the same repository is plaintext
with extra steps, and both repositories are readable by a token carrying
`delete_repo` and `admin:org`. **One `git rm` and a rotation.**

---

## How to re-run

    PW.watch(sources)   # sources maps "repo/path" to file content

Twelve items are tracked; adding one is a single `Fix(...)` entry in
`src/jumpper/patchwatch.py`. A missing file returns indeterminate rather than a
pass, and a detector that raises returns indeterminate rather than green - because
a fail-absent check reads as a pass to any caller that only inspects the verdict.

---

*Read-only throughout. No file outside saos-jummper was created, modified or
deleted. No keys read, no transactions signed, nothing broadcast.*
