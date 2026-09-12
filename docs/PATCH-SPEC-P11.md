<!-- hardening:allow-file ALL reason=patch specification quoting the exact memo-construction lines it changes -->

# Patch Spec P-11 - `wrapped.cjs` writes a reference id at two of five sites and reads it at zero

Every line below was read out of `steem/agent/wrapped.cjs` (55,061 chars, 880
lines). This is the precise location of the xlock findings, narrowed by
`docs/XLOCK-AUDIT-CORRECTION.md` from "the protocol" to one script.
`roundtrip.cjs` already does this correctly - `const RT = 'rt66'` on every lock,
cited on the unlock. **`wrapped.cjs` does not.**

---

## The five write sites, verbatim

PHIVE on Hive - two sites, **neither** carries a reference id:

    memo: 'saos:xlock:PHIVE:' + hiveLockAmt.toFixed(3)
    memo: 'saos:xlock:PHIVE:' + lockAmt.toFixed(3)

These are the two referenceless locks on chain - 0.001 HIVE on 2026-09-04 and
**0.050 HIVE on 2026-09-07, the largest in the protocol.**

WSBD on Steem - three sites, inconsistent:

    'saos:xlock:WSBD:' + sbd.toFixed(3)                                      // NO ref id
    'saos:xlock:WSBD:' + lockedSbd.toFixed(3) + ':' + Date.now().toString(36)  // ref id
    'saos:xlock:WSBD:' + addAmt.toFixed(3)    + ':' + Date.now().toString(36)  // ref id

Both of the sites that include one use `Date.now().toString(36)` - a base-36
millisecond timestamp, about eight characters. **Two locks in the same millisecond
produce the same "id". It is a timestamp wearing the name of an identifier.**

## The read side parses no reference id at all

    if (memo.startsWith('saos:xlock:WSBD')) { ... }
    if (memo.startsWith('saos:xlock:PHIVE') && from === ACCOUNT && to === ACCOUNT)
      out.selfLocksPhive.push({ amount: amt, txid: e.trx_id, at: e.timestamp });

Both use `startsWith` and capture `amount`, `txid`, `at`. **Neither extracts a
reference id**, so the two sites that write one write it for nobody. And
`selfLocksPhive` is a list keyed by nothing, so two locks of the same amount are
indistinguishable.

> **The whole defect in one sentence: the reference id is written at two of five
> sites and read at zero.**

---

## The patch

**1. One memo format, versioned, fixed field count**

    saos:xlock:1:<TOKEN>:<amount>:<refId>
    saos:xunlock:1:<TOKEN>:<amount>:<refId>:<chain>:<txid>

Five and seven fields, always. The version field lets a reader refuse a format it
does not understand instead of mis-parsing it positionally.

**2. A reference id that is actually an identifier**

    const { randomUUID } = require('node:crypto');
    const refId = randomUUID().replace(/-/g, '').slice(0, 16);

Sixteen hex characters, generated per lock. If a monotonic counter is preferred for
memo budget it must be **persisted** - a counter that restarts with the process
reproduces exactly the fork problem the anchor stream already had.

**3. The five write sites** - append `+ ':' + refId` to each, and keep the `refId`
beside the lock in the state file so the unlock can cite it.

**4. The unlock names its chain**

    'saos:xunlock:1:PHIVE:' + amt.toFixed(3) + ':' + refId + ':' + chain + ':' + txid

`roundtrip.cjs` writes `... + ':' + RT + ':' + st.s4.txid`, where `st.s4.txid` is a
**Steem** transaction and nothing says so. That is why `XLOCK-AUDIT.md` reported it
as unresolvable and the correction had to retract the framing. **The citation was
correct; the memo just did not say where to look.** One field fixes it.

**5. The reader parses what the writer emits**

    const XLOCK = /^saos:x(?:lock|unlock):1:([A-Z]+):([0-9.]+):([0-9a-f]{16})(?::([a-z]+):([0-9a-f]{40,66}))?$/;
    const m = XLOCK.exec(memo);
    if (!m) { /* not a v1 xlock memo - skip, do not guess */ }

Index accumulated locks by `refId` instead of appending to a list, so an unlock
matches exactly one lock.

---

## What this does NOT fix

Finding 1 of `XLOCK-AUDIT.md` stands and this patch does not touch it: **a
self-transfer moves nothing.** `wrapped.cjs` says so itself - *"הנעילה =
transfer-עצמי עם ממו נעילה — נראה לעין"*. The lock is a public witness marker; in
`roundtrip.cjs` the real value movement is the mint and burn on Steem.

That is a legitimate design. It is an **attestation**, and this patch makes the
attestation parseable, referenceable and reconcilable. **It does not make it
custody.** Custody would be `escrow_transfer` or a Hive-Engine contract - a
different and bigger change.

And the naming should follow the mechanism: `xlock` reads as custody to anyone who
has not read `wrapped.cjs`. `xlock-claim` or `xwitness` would not. That is a rename,
and the cheapest change here.

---

## Effort

| change | size |
|---|---|
| versioned fixed-shape format | one helper |
| real ref id at all five write sites | five lines |
| chain field on the unlock | one line, in both scripts |
| parsing reader indexed by refId | one regex, one map |
| rename away from `xlock` | search and replace |

No migration: the version field lets a reader tell a v1 memo from a legacy one and
handle each explicitly rather than guessing from the field count.

---

*Read-only throughout. No file outside saos-jummper was created, modified or
deleted. This document specifies a patch; it does not apply one.*
