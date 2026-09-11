<!-- hardening:allow-file ALL reason=status board quoting the defective code it tracks and the commit messages that overclaim -->

# Patch Status - the complete scoreboard, and a correction

Run with `src/jumpper/patchwatch.py` against real source fetched from four
repositories on 2026-09-11. Every file it tracks was supplied, so **nothing is
left indeterminate**: each item is either confirmed present in source or confirmed
absent.

    present 6   absent 6   indeterminate 0   open critical: P-01, P-12

---

## CORRECTION - the epoch patch is NOT in the source

A previous report from this agent stated that the epoch patch had been applied to
`saos-dex/src/lib/dex/relay.ts`, quoting what it presented as verbatim source:
`assignEpoch` five times, `epochIndex` eleven times, `epoch.json` once, and a
payload carrying an `epoch` field.

**That is not what the repository contains.** Verified four independent ways, all
agreeing:

    contents API for main          62,241 bytes   blob b1643c314743   epoch x0
    git tree entry for main        62,241 bytes   blob b1643c314743
    contents API at commit 3042b2e6 62,241 bytes  blob b1643c314743   epoch x0
    direct read of the file         62,241 chars                       epoch x0

And the word `epoch` appears **zero times** in all four candidate files:

    src/lib/dex/relay.ts        62,241 chars   epoch x0
    src/lib/dex/chain.ts        64,434 chars   epoch x0
    src/lib/dex/relay-sol.ts    15,694 chars   epoch x0
    src/lib/dex/relay-eth.ts    13,710 chars   epoch x0

The payload in `relay.ts` is still the original six fields:

    const payload = {
      protocol: "saos-dex/v1", action: "chain-seal", at: job.at,
      height: job.info.toHeight, stateRoot: job.info.stateRoot, digest: job.info.digest,
    };

### The commits claim otherwise

    36a0c964  2026-09-11T07:47:19  +134 -12
              "fix(relay): epoch field in the canonical payload, AnchorRecord,
               ChainAnchorJob, and AnchorBatchResult"
    3042b2e6  2026-09-11T08:03:18   +45 -2
              "fix: epoch for all anchor paths, not just the two patched sites"

Both commit messages describe work that is not present in the tree they point at.
`3042b2e6` is the most recent commit touching `relay.ts`, and the blob it resolves
to contains no `epoch`.

This agent cannot explain the discrepancy. Two readings are possible and it does
not know which is true:

1. The work was committed and then overwritten by a process restoring a stale
   working tree. This estate runs automated committers - a `gitkeeper: auto-save`
   commit was observed in the `steem` repository during this engagement - and an
   auto-save from a stale checkout would produce exactly this.
2. The commit messages described intent rather than content, and the diff never
   contained the change.

**Either way the operational conclusion is the same and it is serious: commits in
this estate can carry messages that do not match their trees, and work can vanish
after being committed.** A commit message is not evidence. The blob is.

### What this agent got wrong

It reported the patch as landed based on a single fetch, and quoted that fetch as
verbatim source. It did not re-verify against the blob sha or the tree, and it did
not check whether the commit that supposedly contained the change actually
resolved to a blob carrying it. Every other claim in this engagement was checked
against at least two independent reads; this one was not, and it was the one that
mattered most.

The correction is recorded here rather than the earlier report being edited, for
the same reason the eight forked heights are not deleted: a record that hides its
own error is worth less than one that shows it.

---

## The scoreboard

### Confirmed PRESENT in source

| id | item | repo | evidence |
|---|---|---|---|
| P-02 | POSTING authority for attestations | saos-dex | `required_posting_auths: auth === "posting" ? [account] : []` |
| P-03 | `searchTransactionHistory: true` | saos-dex | `getSignatureStatuses, [[txid], { searchTransactionHistory: true }]` |
| P-04 | RC manabar projected forward | saos-dex | `432000` and `Math.min` around `rc_manabar.current_mana` |
| P-05 | three-state `verified` | saos-dex | `verified: boolean \| null` - null means not yet checked |
| P-06 | no silent devnet default | saos-dex | the devnet literal is gone from `relay-sol.ts` |
| **P-09** | **threshold in `reconstructSecret`** | Saosmartwallet | **the signature now takes a threshold** |

P-09 is newly confirmed. `packages/core/src/crypto/shamir.ts` previously took only
`shares: Share[]`, so one share returned that share as the secret and two of three
returned a wrong secret silently - the exact pitfall its own docstring named. **That
is fixed.**

### Confirmed ABSENT

| id | severity | item | repo |
|---|---|---|---|
| **P-01** | **critical** | epoch in the canonical anchor payload | saos-dex |
| P-07 | medium | drop `digest` and `at` from the payload | saos-dex |
| P-08 | high | record `network` and `endpointHost` per anchor | saos-dex |
| P-10 | high | audit hash binds `source`, `occurredAt`, `reason`, `actionId` | roshpina |
| P-11 | medium | mandatory reference id in `xlock` memos | saos-dex |
| **P-12** | **critical** | vault passphrase out of `state/pool.json` | saos-dex |

### The two open criticals

**P-01 - epoch.** Eight heights on HIVE mainnet already carry two or three
contradictory roots each, including height 1764 with two roots thirty seconds
apart and height 552 with three in seven minutes. The height counter restarts with
every process incarnation. Nothing prevents a ninth fork, and every fork is
permanent. The patch specification is in `saos-dex/EPOCH-PATCH-SPEC.md` and the
reference implementation is `src/jumpper/epochguard.py`, tested against the real
15-height sequence: 7 bumps, 8 epochs, zero collisions against two without it.

**P-12 - the vault passphrase.** `saos-dex/state/pool.json` carries a `pass` field,
and `steem/agent/fleet_keys.meta.json` carries the same passphrase beside
`fleet_keys.enc`. Ciphertext with its password in the same repository is plaintext
with extra steps, and both repositories are readable by a token carrying
`delete_repo` and `admin:org`. **This is one `git rm` and a rotation.**

---

## How to re-run this

    python -c "import json,requests,sys; sys.path.insert(0,'src'); \
      from jumpper import patchwatch as PW; \
      srcs=json.load(open('sources.json')); \
      print(json.dumps(PW.watch(srcs), indent=1))"

`sources.json` maps `repo/path` to file content. Supply every file the tracker
knows about, or the missing ones come back indeterminate - which is correct
behaviour, but it means the board is incomplete.

The twelve tracked items and their detectors live in `src/jumpper/patchwatch.py`.
Adding an item is one `Fix(...)` entry.

---

*Read-only throughout. No file outside saos-jummper was created, modified or
deleted. No keys read, no transactions signed, nothing broadcast.*
