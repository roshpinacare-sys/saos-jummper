<!-- hardening:allow-file ALL reason=correction to the xlock audit, quoting the protocol source it misread -->

# CORRECTION - the xlock audit misread the protocol

`docs/XLOCK-AUDIT.md` reported six findings about the `saos:xlock` / `saos:xunlock`
memo protocol. **Three of them were wrong or partly wrong, because the audit read
four on-chain operations and inferred a protocol, instead of reading the code that
produces them.**

The producer is `steem/agent/roundtrip.cjs` (15,425 chars, Task 66). Its header
describes a seven-link cross-chain roundtrip:

    H1 (Hive)   lock       - self-transfer 0.002 HIVE, memo saos:xlock:PHIVE:0.002:rt66
    S1 (Steem)  mint       - PHIVE +0.002, ref=H1-txid   (saos.wrap/v1)
    S2 (Steem)  pay        - @haran pays credit to treasury for 0.001 PHIVE (saos/v1)
    S3 (Steem)  fill       - @haran crosses the ask      (saos.wrap/v1, payRef=S2)
    S4 (Steem)  burn       - @haran burns 0.001 PHIVE    (requires holding, from replay)
    H2 (Hive)   unlock     - self-transfer 0.001 HIVE, memo saos:xunlock:PHIVE:<S4-txid>
    S5 (Steem)  unlock-ack - release declaration on the bus, ref=H2-txid

    conservation at the end:
      locked 0.003 - unlocked 0.001 = 0.002 = supply (0.003 - burn 0.001)

    guards: 3.4 s between ops, DRY by default (--live), idempotent by state+chain

And the memo construction, verbatim:

    const memo = 'saos:xlock:PHIVE:'   + LOCK_AMT.toFixed(3) + ':' + RT;
    const memo = 'saos:xunlock:PHIVE:' + TRADE_AMT.toFixed(3) + ':' + RT + ':' + st.s4.txid;

with `const RT = 'rt66'` and `const LOCK_AMT = 0.002`, `const TRADE_AMT = 0.001`.

---

## Finding 5 was WRONG - the unlock cites the burn, not a lock

The audit reported:

> the unlock cites `7bdec0aa64c761672680c7dfa7ffcdebacddac7e`, which matches none
> of the three lock transaction ids ... a citation without a network is not a
> citation

**The cited txid is `st.s4.txid` - the S4 burn on Steem.** That is the protocol's
design: you unlock against the burn that proves the wrapped asset was destroyed,
not against the lock that created it. The audit looked for the reference among the
lock txids because it assumed an unlock points at a lock. It does not.

The `xlock.py` detector that produced this finding is named
`unlock-cites-foreign-txid` and it fires whenever the cited txid is not a lock
txid. **For this protocol that is a false positive by construction.** The finding
still contains one true part - the memo does not say which chain the cited txid is
on, so a reader cannot resolve it - but the framing ("matches no lock, therefore
unfollowable") was wrong.

## Finding 6 was PARTLY WRONG - the remainder is tracked by an invariant

The audit reported:

> reference rt66 locked 0.002 but unlocked 0.001 ... either 0.001 is still locked
> against rt66 with nothing recording that fact, or the unlock was for the wrong
> amount. Neither can be determined from the chain.

The header states the conservation explicitly: `locked 0.003 - unlocked 0.001 =
0.002 = supply (0.003 - burn 0.001)`. **The remainder is the supply.** A partial
redemption is the designed behaviour, and the roundtrip is idempotent by state and
chain, so the remainder is tracked in the script's own state file rather than in
the memo.

What the audit got right: **the memo format has no field for the remainder**, so
someone reading only the chain cannot reconstruct it. That is a real limitation of
the on-chain record. It is not an unexplained discrepancy.

## Finding 1 is still correct, and the source agrees

> A self-transfer is economically a no-op ... the balance does not change

`steem/agent/wrapped.cjs` says so itself:

> saos:xlock:WSBD. הנעילה = transfer-עצמי עם ממו נעילה — נראה לעין

"The lock is a self-transfer with a lock memo - visible to the eye."

**That is the design, and the design is an attestation, not custody.** In the
roundtrip the value movement happens on Steem through mint and burn; the Hive
self-transfer is a public witness marker so that anyone can see the lock and
unlock happened. Calling it a lock is a naming problem, not a mechanism problem -
and `docs/XLOCK-AUDIT.md` said exactly that. That part stands.

## Finding 3 is still correct but narrower than stated

The four on-chain operations carry 4, 5, 6 and 4 fields. But they come from **two
different producers**:

| producer | memo shape | reference id |
|---|---|---|
| `roundtrip.cjs` | `saos:xlock:PHIVE:<amt>:rt66` | **always present** (`RT = 'rt66'`) |
| `wrapped.cjs` | `saos:xlock:PHIVE:<amt>` | **absent** |

So the inconsistency is between two scripts, not within one. The two referenceless
locks the audit flagged - including the largest at 0.050 HIVE - come from
`wrapped.cjs`. **The finding is real and its location is now precise.**

## Finding 4 follows from finding 3 and is unchanged

Two of three locks carry no reference id, so no unlock could cite them. They come
from `wrapped.cjs`.

---

## What `xlock.py` gets wrong, and what that means

`src/jumpper/xlock.py` reconciles memo-lock ledgers. It was calibrated against
four real operations and reported eight findings. **One of those findings
(`unlock-cites-foreign-txid`) is a false positive for a protocol whose unlocks
reference burns.**

The module cannot know that, because it was written from the memos alone. It has no
model of a multi-chain roundtrip where the unlock's citation points at a different
chain and a different step.

Two honest options, and the module should say which it is doing:

1. **Treat the citation as opaque.** Report that it does not match a lock txid in
   the supplied history, and stop there - do not call it foreign or unfollowable.
   This is what the data supports.
2. **Model the protocol.** Accept a chain map so `chain:txid` can be resolved, and
   accept that an unlock may cite a burn on another chain. This is more work and
   needs the protocol specification, which now exists in `roundtrip.cjs`'s header.

Until one of those is done, `xlock.py` should be read as **"here are the
inconsistencies in this memo ledger"**, not as "here is what is wrong with this
protocol". `docs/XLOCK-AUDIT.md` presented it as the latter, and that was the error.

---

## The meta-lesson, which is the same one as before

Four on-chain operations were read and a protocol was inferred from them. The
inference was reasonable and it was wrong in three places, because the code that
produces the memos was never opened.

This is the sixth time in this engagement that a conclusion drawn from one side of
an interface was wrong:

1. two Merkle conventions assumed equal because a docstring said so
2. a wallet reported as having no cryptography because one directory held placeholders
3. H-11 reported as a code gap when it was an unset environment variable
4. R-05 passing because the word threshold appeared somewhere in the file
5. the epoch patch reported absent on the strength of one stale API read
6. **an unlock reported as citing a foreign txid because the audit assumed it should cite a lock**

Every one was a partial read presented as a complete finding. The fix each time was
the same: go and read the other side.

---

*Read-only throughout. No file outside saos-jummper was created, modified or
deleted. No keys read, no transactions signed, nothing broadcast.*
