
# On-Chain Forks - the anchor stream contradicts itself, publicly

Read from HIVE mainnet on 2026-09-10T12:47Z via `api.openhive.network`,
`condenser_api.get_account_history` for account `headcorner`, 400 entries spanning
2026-09-03T15:52:12 to 2026-09-10T12:37:12.

Detector: `src/jumpper/forkwatch.py`. 23 assertions in `tests/test_forkwatch.py`.

    verdict : FORKED - 8 height(s) carry contradictory roots, 2 within 5 minutes
    anchors : 153     distinct heights: 144
    epochs  : none    (the payload carries no epoch field)

---

## The forks

Eight heights carry more than one distinct `stateRoot`, all signed by the same
account, all permanent:

| height | anchors | distinct roots | span | severity |
|---|---|---|---|---|
| **1764** | 2 | **2** | **30 seconds** | **critical** |
| **1668** | 2 | **2** | **198 seconds** | **critical** |
| 552 | 3 | **3** | 423 s | high |
| 1476 | 2 | 2 | 5.3 h | high |
| 1392 | 2 | 2 | 1.6 d | medium |
| 1224 | 2 | 2 | 1.7 d | medium |
| 12 | 2 | 2 | 2.0 d | medium |
| 1416 | 2 | 2 | 2.1 d | medium |

The two critical ones, verbatim from the chain:

    height 1764
      #49833  2026-09-09T18:27:21  root d7220b5e9ecc953e7e8ddf0b...
      #49834  2026-09-09T18:27:51  root 84ae0a0a08ef2f44becc99e4...

    height 1668
      #49824  2026-09-09T18:19:18  root 74b29867195898f6691ce331...
      #49825  2026-09-09T18:22:36  root e375e0f5d7fe98c69ea720d0...

    height 552  -  THREE roots in seven minutes
      #49715  2026-09-07T21:57:33  root 20f4a62f4d394adc8d354bf5...
      #49716  2026-09-07T22:02:12  root b426703955dc08503f2dad7f...
      #49717  2026-09-07T22:04:36  root 647ac665dceb6b32910da2f3...

A verifier asking "what was the state at height 1764?" receives two contradictory
answers, thirty seconds apart, both signed, both permanent. **Anyone can pick
whichever suits them, and the ledger supports both.**

---

## The cause: the height counter is per-process, not global

Ten non-increasing steps in the sequence:

    1416  -> 552        2026-09-07T21:57:33
    552   -> 552 -> 552 three anchors, one height, three roots
    552   -> 12         2026-09-07T22:53:03
    2088  -> 444        2026-09-08T02:47:45
    14304 -> 4920       2026-09-08T21:21:39   <- four minutes after the key rotation
    6276  -> 876        2026-09-09T17:36:48
    4488  -> 12         2026-09-09T22:10:06   <- reset to 12 again
    plus three more

**6 resets, 4 repeats.** The pulse chain restarts and its counter begins again
near 12. Each restart re-publishes low heights with fresh roots, colliding with
heights already committed under different roots.

Median positive step is 12 - the chain seals every 12 blocks, exactly as designed.
**The counter is correct within a process lifetime. It is simply not a global
identifier, and it is published to a permanent public ledger as though it were.**

---

## The fix: namespace the height

    {"protocol":"saos-dex/v1","action":"chain-seal",
     "epoch":<process-or-day id>,"height":1764,"stateRoot":...}

Then `(epoch, height)` is unique across restarts, and a restart becomes visible as
a new epoch instead of appearing as a contradiction. Cost: about 12 bytes in a
payload that currently uses **248.9 of 8,192 bytes - 3.04% of its budget.**

`forkwatch.py` already treats `(epoch, height)` as the key, and a test proves that
two different epochs carrying the same height are **not** a fork while the same
epoch carrying two roots **is**.

---

## Why this is the worst finding in the estate

`roshpina/kernel/transparency-log/` is 93,118 characters of anti-fork machinery:
inclusion proofs, consistency proofs whose docstring names the split-view attack
explicitly, witnesses with liveness and gossip, cross-log consistency, and
federation anchors.

**None of it touches a public chain.** Zero references to any blockchain across
838,280 characters.

Meanwhile the component that DOES publish to a public chain forked eight times in
four days - twice within five minutes.

> The two halves of this system are aimed at each other's exact problem and have
> never met. The kernel can prove a log did not fork; it cannot see the log that
> did. The relay publishes a log that forks; it has no way to notice.

---

## What got FIXED on chain since the last reading

Two days passed between measurements, and the estate moved. Verified, not assumed:

| before (2026-09-08) | after (2026-09-10) |
|---|---|
| 57 of 62 attestations signed with **ACTIVE** | **30 anchors now POSTING**; the last 10 custom_json ops are all posting. First posting-signed anchor: #49745, 2026-09-08T21:21:39 - four minutes after the key rotation |
| `hive.convert 9.632` looping, ~34% of daily RC | **zero convert calls** in the last 400 operations. The loop is dead |
| balance 9.682 HIVE, vesting 17,511.838295 | balance **0.000 HIVE**, vesting **33,110.489549** - `transfer_to_vesting` of 9.682 HIVE at #49758, 2026-09-09T15:21:27 |
| max_rc 25,641,553,538 | max_rc **41,240,204,792** (+61% RC capacity) |
| ~31 operations per day, RC-saturated | 105 anchors on 2026-09-09, 21 by 12:37 on 09-10 |

**Three of the five zero-code fixes were executed.** The power-up is the correct
response to RC being derived from vesting shares rather than tokens.

Still ACTIVE where POSTING would do: `saos.id.v1` (25), `saos.attest.v1` (20),
`saos.weave.v1` (12 of 14). `ssc-mainnet-hive` (69) correctly uses ACTIVE because
it moves tokens.

---

## And a correction I owe

I wrote that the "rc-route" token transfers showed a misunderstanding of the
resource model, because RC comes from vesting shares and not from tokens. The
token part was right - sending SWAP.HIVE or PIZZA buys no RC.

**But I had only read 100 operations. At 400 the delegations appear:**

    #49604  2026-09-04T13:38:03  delegate_vesting_shares  -> ynet   3,000.000000 VESTS
    #49641  2026-09-05T14:39:03  delegate_vesting_shares  -> tov    6,000.000000 VESTS

**9,000 VESTS delegated, which does route RC to those accounts.** The strategy is
real and correct; I called it broken because my window was too small. That is the
sixth time the same error appears in this engagement: a conclusion drawn from what
was in front of me, without asking whether what was in front of me was the whole
thing.

---

## New finding: the xlock ledger does not balance

State is being committed through self-transfers with structured memos:

    #49621  2026-09-04T19:20:21  0.001 HIVE  saos:xlock:PHIVE:0.001
    #49625  2026-09-04T22:23:48  0.002 HIVE  saos:xlock:PHIVE:0.002:rt66
    #49626  2026-09-04T22:37:51  0.001 HIVE  saos:xunlock:PHIVE:0.001:rt66:7bdec0aa64c761672680c7dfa7ffcdebacddac7e
    #49697  2026-09-07T11:49:39  0.050 HIVE  saos:xlock:PHIVE:0.050

**3 locks, 1 unlock, 2 unmatched.** And the one unlock does not reconcile: `rt66`
was locked for 0.002 and unlocked for 0.001.

The unlock carries a 40-hex identifier - Ethereum-shaped - inside a HIVE memo,
with no chain named and no block. It is not verifiable from here.

Using memos as a state machine is defensible: it is free-ish, permanent and public.
But an unbalanced ledger that only exists as a sequence of memos has no invariant
enforcement at all. Nothing prevents a fourth lock with no unlock, and nothing
would notice.

---

## Also noted

- `saos.attest.v1` - the git-commit provenance anchor, the genuinely valuable one -
  **stopped after 2026-09-07**. 20 total. Meanwhile anchor volume tripled.
- `saos.id.v1` stopped after 2026-09-06, `saos` value_lock after 2026-09-07,
  `ssc-mainnet-hive` after 2026-09-08. Only `saos-dex.anchor.v1` and a little
  `saos.weave.v1` are still live.
- An inbound transfer from `lassecashmagi` at 2026-09-07T19:35:45 carrying a
  message in the memo. Not investigated.
- The `at` field in every anchor is within 30 seconds of the block time across 60
  samples checked, so the operator's clock is honest. It is still redundant - the
  block time is authoritative - and still costs bytes.

---

## Actions

| # | action | effort | what it closes |
|---|---|---|---|
| **1** | **Add an `epoch` field to the anchor payload** | ~12 bytes | the eight forks; a restart becomes visible instead of contradictory |
| 2 | Persist the height counter across restarts, or derive it from the chain | small | the resets that cause the forks |
| 3 | Run `forkwatch.audit()` on every anchor batch before broadcast | already built | refuse to publish a root that contradicts one already on chain |
| 4 | Move `saos.id.v1`, `saos.attest.v1`, `saos.weave.v1` to POSTING | configuration | 57 more operations stop holding fund-moving authority |
| 5 | Reconcile or abandon the xlock memo ledger | small | an unbalanced state machine with no invariants |
| 6 | Restart `saos.attest.v1` | configuration | code provenance anchoring, the highest-value use of the primitive |
| 7 | Compact the payload (drop `digest` and `at`) and pack roots | already built | 3.04% of budget in use; 105 anchors/day could be a handful |

Action 3 is the one that makes the rest stick: `forkwatch.py` exists, is tested
against this exact stream, and refuses a contradictory root before it is published
rather than reporting it afterwards.

---

*Read-only throughout. No file outside saos-jummper was created, modified or
deleted. No keys read, no transactions signed, nothing broadcast.*
