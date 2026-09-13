<!-- hardening:allow-file ALL reason=correction to FLEET-HEALTH, quoting the loop.ts code that already implements what it recommended -->

# CORRECTION - the fleet already does what FLEET-HEALTH.md recommended

`docs/FLEET-HEALTH.md` read 193 rows of `GateRun`, counted the outcomes, tabulated
the recorded errors and recommended five changes. **Two of the five were already
implemented, in a more sophisticated form than what was recommended, and the
snapshot the recommendations were drawn from may predate the fixes.**

The runner is `Saosmartwallet/src/lib/gate/harness/loop.ts` (43,963 chars). It was
not read before the recommendations were written.

---

## Recommendation 1 was already implemented - `brainChatRetry`

The recommendation was "Retry-After-aware backoff plus a concurrency cap". The code:

    // r39 — the audit found anchor-agent burning 6 runs on 429s within 48h: ONE
    // polite retry (r34) was not enough for nvidia's bursty rate-limits. Now a
    // 3-attempt ladder (4s → 10s, jittered) converts provider turbulence into
    // progress while non-transient throws keep standing honest.
    let delay = 4000 + Math.floor(Math.random() * 800);
    for (let attempt = 1; attempt <= 3; attempt++) {
      try {
        return await brainChat(b, messages, opts);
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        if (attempt < 3 && /429|rate|timeout|fetch failed|network/i.test(msg)) {
          await new Promise((r) => setTimeout(r, delay));   // transient — polite backoff
          delay = 10000 + Math.floor(Math.random() * 2000); // growing
          continue;
        }
        throw e;   // non-transient (or exhausted) — the honest throw stands
      }
    }

**This is better than what was recommended in two respects:**

1. It distinguishes transient from non-transient by message and lets the honest
   throw stand. A blanket retry would mask real failures.
2. The delay is jittered at both steps, so a fleet of scheduled runs firing on one
   cadence does not all retry at the same instant - which was the specific concern
   the recommendation raised.

**And there is a fix the recommendation did not think of**, `r14` brain failover:

    // a run that crashed once usually died to its brain's ENVIRONMENT, not its plan
    // (proven live: the zai:default fleet starved on sustained 429 windows — 18
    // failed — while nvidia delivered 37 done; and a re-queued anchor-agent run died
    // to the SAME 429 wall on attempt 2 — retrying on the starved brain is
    // deterministic failure). A recovered run (attempt ≥ 2) now flips its maker to a
    // different brain by a deterministic map

Retrying against a rate-limited provider is not a backoff problem, it is a provider
problem. **Switching providers is the correct answer and backoff is the fallback.**
`ratelimit.py`, built in the previous round on the strength of recommendation 1,
models the fallback well and does not model this at all.

### The one part of recommendation 1 that is genuinely missing

The ladder is fixed at 4s then 10s. **It never reads `Retry-After`.** When a
provider says "come back in 30 seconds", waiting 4 guarantees another 429 and burns
an attempt. `ratelimit.py::parse_retry_after` and `backoff(retry_after=...)` do
exactly this, and wiring them in is the one change here that would add something.

---

## Recommendation 5 was already diagnosed and fixed - `r28` and `r30`

The recommendation was "record a verdict on every run, including blocked ones",
because 48 of 193 rows had a NULL verdict. The code already says why, and already
fixed it:

    // r28 — brain-call retry: a 429/hiccup on the checker's brain call used to
    // escape runChecker entirely (the r30 rescue only guards JSON garbage AFTER a
    // reply arrives). Live-measured: 12 of 62 blocked runs were checker-silent
    // (5× "429 Too many requests", 7× protocol garbage that also threw) — every one
    // graded "blocked" with NO verdict, feeding the repair chase an empty gaps list.
    // One polite backoff retry on THROW — the call-level sibling of the r30 rescue —
    // costs nothing and converts silence into a verdict.

    // r30 — the checker gets the same free protocol-rescue the maker always had
    // (FREE_RESQUE_LIMIT = 2). Live-caught (r30): three runs whose maker steps were
    // ALL proven (e.g. the 05:40 scout — 4/4 ok) were graded blocked because the
    // checker brain's SINGLE reply was protocol garbage — extractJson threw, verdict
    // stayed null, and the repair round never even ran. One flaky reply voided real,
    // evidenced work.

**The 48 NULL verdicts are the symptom those two fixes address, and the diagnosis in
the code is more precise than the one in the report**: the null verdict is not a
missing write, it is a checker that could not produce one. The status logic is
correct as written:

    const status = verdict ? (verdict.done ? "done" : "blocked") : "blocked";

And `ROAST r8` already fixed the adjacent failure:

    // this path used to die MUTE (error set, report NULL). A run that exhausted its
    // attempts must confess in Hebrew like every other terminal failure — the bridge
    // reads REPORTS, not error columns.

It now writes both `error` and `report`.

---

## What this means for the snapshot

`db/custom.db` moved five times during this engagement: 290,816 → 327,680 →
4,685,824 → 3,788,800 → 3,944,448 bytes. It is a live database being snapshotted at
arbitrary points.

**The 193 rows read may predate `r28`, `r30`, `r34`, `r39` and `ROAST r8`.** The
17 runs that died on `429` and the 48 with no verdict could both be historical.
Nothing in the report established when those rows were written relative to those
fixes, and the `createdAt` column was not read.

So the honest statement is not "52% of runs fail". It is: **at some point in this
database's history, 101 of 193 recorded runs did not reach `done`, and the code now
contains five documented fixes aimed at exactly the causes tabulated.** Whether the
rate has improved since is measurable and was not measured.

---

## What survives from FLEET-HEALTH.md

| recommendation | status |
|---|---|
| 1. Retry-After-aware backoff + jitter | **already implemented**, better than recommended. The one gap: `Retry-After` is never read, the ladder is fixed at 4s → 10s |
| 2. Do not schedule runs that need an unlocked vault | **unverified** - not checked against the scheduler |
| 3. Stop committing a live database | **stands, and is now stronger** - the five size changes are the evidence, and a snapshot of a live DB makes every measurement of it unreliable |
| 4. Validate the auth header before sending | **unverified** - 2 recorded `401 missing X-Token` |
| 5. Record a verdict on every run | **already diagnosed and fixed** by r28/r30, more precisely than recommended |

**One recommendation survives intact, one survives as a narrower gap, and two were
never checked.**

---

## The pattern, for the tenth time

A recommendation was written from an aggregate over recorded outcomes, without
reading the code that produces those outcomes. The aggregate was real. The
recommendations were not.

This is the same shape as P-07, which recommended deleting `digest` and `at` from
the anchor payload without reading what consumes them - and would have broken the
six-field cross-chain equality verified between Ethereum block 25,929,672 and Solana
slot 445,225,030.

Both times the fix was the same: **go and read the other side.** `loop.ts` was one
API call away the whole time.

The correction is recorded here rather than `FLEET-HEALTH.md` being edited, for the
reason every other correction in this engagement was: a record that hides its own
error is worth less than one that shows it.

---

*Read-only throughout. No file outside saos-jummper was created, modified or
deleted. No secret value is reproduced; the quoted code is the retry and verdict
logic, which contains none.*
