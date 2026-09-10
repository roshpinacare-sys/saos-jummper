
# Budget Guard - the control that stops the loop

## The defect it exists for, measured on mainnet

Eleven identical calls to Hive-Engine `hive.convert` with quantity `9.632`,
broadcast over 31 hours by account `headcorner`, every one of them doomed (the
account holds no SWAP.HIVE), every one landing on chain and consuming RC:

    idx 49696  2026-09-07T11:49:39
    ...
    idx 49740  2026-09-08T18:28:09      still running when read

At the measured aggregate cost of 157,713,792 RC per operation that is
**1,734,851,712 RC** - about **34% of one day's entire regeneration budget** -
spent on an operation that can never succeed.

Nothing stopped it, because nothing was counting. Each individual call passed
every check that existed: well-formed, correctly signed, correctly authorised,
small. **The damage was in the repetition and in the cumulative total, and no
control in the estate looked at either.**

## The insight, already written down in your own kernel

`roshpina/kernel/policy/spend-budget-guard.ts` states it exactly:

> Per-action value thresholds stop ONE big action. They do NOT stop a runaway
> agent making thousands of individually-small actions whose SUM is enormous -
> the exact pattern behind the surprise five-figure bills people get from a loop
> gone wrong or a mispriced call.

That kernel built the control for fiat and API spend. `src/jumpper/budget.py`
builds the same control for the resources the free anchor path actually consumes:
**RC on Graphene, lamports on Solana, gas on Ethereum.**

## What the gate does

Three guards, AND-composed, evaluated BEFORE the broadcast:

| guard | question it answers | fail-closed behaviour |
|---|---|---|
| network | is this endpoint provably mainnet? | empty, devnet, testnet, or unrecognised all deny |
| repeat | has this identical operation already gone out? | un-fingerprintable operation denies |
| budget | does this spend fit the remaining rolling budget? | zero, negative, non-integer and unconfigured all deny |

Semantics copied from `roshpina/kernel/orchestrator/guard.ts`:

- **AND**: every guard must allow. Any deny denies.
- **A guard that raises is a deny**, never a pass.
- **No budget and no repeat guard configured is a deny.** A network check alone is
  routing, not spend control.

A denial carries the number the caller needs - exact overage, exact prior count,
the window - so it can act instead of guessing.

## Replaying the real loop through the gate

The test suite does not simulate a hypothetical. It replays the actual defect:
the real operation payload, the real measured RC cost, the real eleven attempts
at one-hour intervals.

    allowed : 1
    denied  : 10
    RC recovered : 1,577,137,920   (30.8% of one day's regeneration budget)

The first call is allowed, because the first call might be legitimate. The second
is denied as a repeat within the window. The caller sees:

    decision : deny
    guard    : repeat
    reason   : identical operation already broadcast 1 time(s) in window
    detail   : priorCount 1, fingerprint ..., hint "a repeating identical
               operation is a loop, not a decision"

## Why `check` and `commit` are separate

`check()` never records. `commit()` records, and is called only after the
broadcast actually succeeded. That separation matters:

- a check that records would consume budget for operations that never happened
- a commit before success would hide failures, and failures are exactly what a
  loop produces
- the eleventh convert attempt failed every time, and a correct ledger must show
  eleven attempts, not eleven successes

The same split exists in the kernel's escrow, where money moves only through
orchestrated transfers and never by mutating a balance.

## Configuring it for the three anchor paths

| path | unit | limit source | measured budget |
|---|---|---|---|
| HIVE / STEEM custom_json | rc | `max_rc / 432000 * 86400` | 5,128,310,708 RC/day for `headcorner` |
| Solana memo | lamports | current balance | 23,981,117 lamports = 4,796 anchors |
| Ethereum calldata | wei | gas x price x daily cap | 30,920 gas per 248-byte anchor |

For Solana and Ethereum the budget is a **balance**, so the window should be long
and the limit should be the balance minus a reserve. For Graphene the budget
**regenerates**, so a 24-hour rolling window with the daily regeneration as the
limit is the right shape, and unused budget returns on its own.

## What this does not do

- does not sign, broadcast, or read a key
- does not decide whether an operation is *correct*, only whether it is allowed
  to proceed now
- does not replace the per-operation checks that already exist; it adds the two
  they were missing: repetition and cumulative total
- does not persist across a restart. State is in memory, so a process restart
  clears the repeat window. A durable store is the obvious next step and is
  listed as such rather than pretended to be solved.

## Tests

32 assertions in `tests/test_budget.py`, centred on the replay above:

- only the first of eleven identical calls is allowed
- the exact RC recovered matches the measured waste
- a different payload is not a repeat
- repeats outside the window are allowed again
- exactly at the limit is allowed; one unit over is denied with the exact overage
- window expiry frees budget
- `check` never records; `commit` does
- devnet, testnet, empty and unrecognised networks all deny
- a raising guard denies rather than passes
- a denial preserves the denying guard's numbers
- a network-only gate still denies

Two defects in this module were found by its own tests before it was pushed: the
composed verdict was discarding the denying guard's detail (so the caller got a
denial with no number), and `require_mainnet` alone was counting as a control (so
an anchor with no budget guard was allowed). Both are the fail-open-by-accident
pattern, and both are now pinned.
