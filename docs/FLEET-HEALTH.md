<!-- hardening:allow-file ALL reason=fleet health report quoting the recorded error strings from the committed database -->

# Fleet Health - 52% of recorded agent runs did not complete

Read from `Saosmartwallet/db/custom.db` (3,944,448 bytes) on 2026-09-12. 193 rows of
`GateRun`, 27 columns each. This is a functionality report, not a security one: the
question is whether the fleet works, and the recorded answer is that it works about
half the time.

---

## Outcome distribution

    status    done       92   (47.7%)
              blocked    65   (33.7%)
              failed     36   (18.7%)

**101 of 193 runs did not reach `done`.**

    verdict   {"done":true,...}    92
              {"done":false,...}   53
              NULL                 48

Forty-eight runs recorded no verdict at all - not a failure verdict, an absent one.
A run with no verdict and a `done` status of `blocked` leaves nothing for a reviewer
to act on except the free-text error.

    attempts  20 runs needed more than one attempt
    duration  mean 48,966 ms   max 238,213 ms

---

## The recorded errors, by frequency

    17  API request failed with status 429: {"error":"Too many requests, pleas...
    11  watchdog: הרצה קרסה יותר מדי פעמים — הוחזרה לתור ונכשלה בכנות
     3  הכספת נעולה — התחבר מחדש עם מפתח
     2  API request failed with status 401: {"error":"missing X-Token header"}
     1  lease expired — dev-server sqlite FD went stale-readonly (SQLITE_READO...
     1  watchdog: חריגה מ-3 ניסיונות — נכשל בכנות
     1  watchdog: חריגה מ-1 ניסיונות — נכשל בכנות

Four causes account for 35 of the 36 errors.

### 1. Rate limiting - 17 runs, 47% of all errors

`429 Too many requests`. The fleet is issuing more requests than the upstream
allows, and the runs die rather than backing off. 100 of the 193 runs have
`origin = schedule`, so this is automated traffic on a fixed cadence hitting a limit
that is not modelled.

`src/jumpper/budget.py` exists for exactly this shape of problem - it measures a
resource, projects regeneration, and refuses a plan that would exceed it - and the
same discipline applies to an HTTP rate limit as to a Resource Credit budget. A
`Retry-After`-aware backoff with a concurrency cap would remove the largest single
failure cause.

### 2. The watchdog - 13 runs

`watchdog: הרצה קרסה יותר מדי פעמים — הוחזרה לתור ונכשלה בכנות` ("the run crashed too
many times - returned to the queue and failed honestly"), plus two attempt-limit
exceedances.

**This one is working correctly and should be left alone.** A watchdog that returns
a crashed run to the queue, gives up after a bounded number of attempts, and records
an honest failure is the right behaviour. The alternative - a run that retries
forever, or one that reports success after crashing - is worse. Thirteen honest
failures are not a defect in the watchdog; they are the watchdog reporting a defect
elsewhere.

### 3. The vault is locked - 3 runs

`הכספת נעולה — התחבר מחדש עם מפתח` ("the vault is locked - reconnect with a key").
Three scheduled runs found the vault locked and could not proceed. For an
`origin = schedule` run this is a hard stop: there is no operator present to unlock.

Either the vault should stay unlocked for the duration of a scheduled window, or
scheduled runs that need it should be deferred rather than failed, or the runs that
need the vault should not be scheduled at all.

### 4. A stale read-only file descriptor - 1 run

    lease expired — dev-server sqlite FD went stale-readonly (SQLITE_READONLY)

This one is a direct consequence of committing a live database. A dev server held an
open file descriptor on `db/custom.db`, the file was replaced underneath it by a
commit, and the descriptor went read-only. The lease then expired.

**A database that is simultaneously being written by a running process and committed
to version control will keep producing this.** The file size moved three times
during this engagement - 290,816, then 327,680, then 4,685,824, then 3,788,800, now
3,944,448 - which is the signature of a live SQLite file being snapshotted at
arbitrary points.

### 5. Missing auth header - 2 runs

`401 missing X-Token header`. Two runs were issued without the token the endpoint
requires. Small in count, but it means a caller can construct a request that was
never going to succeed, and the failure is discovered on the network rather than
before sending.

---

## Concentration

    agentName   harness-rider     109   (56.5%)
                anchor-agent       32
                verifier-agent     14
                vault-rider         9
                zai-code            8
                ui-test-agent       8
                door-diplomat       6
                ui-verify           4
                scribe-agent        3

    origin      schedule          100
                manual             55
                idle               24
                trigger            11
                proposal            3

**One agent - `harness-rider` - accounts for 56.5% of all recorded runs.** Whatever
its failure rate is, it dominates the fleet's numbers, and a fleet-level success
rate is close to meaningless without splitting it out. The columns needed to do
that are present (`agentName`, `status`, `verdict`, `error`); this document does not
attempt the per-agent breakdown because the sample per agent other than the top two
is small enough that the percentages would not mean much.

---

## What would move the number

| # | change | runs it would affect |
|---|---|---|
| 1 | Retry-After-aware backoff plus a concurrency cap on the upstream API | 17 - the largest single cause |
| 2 | Do not schedule runs that need an unlocked vault, or keep it unlocked for the window | 3, plus any that fail silently for the same reason |
| 3 | Stop committing a live database; snapshot it deliberately or keep it out of git | 1 recorded, and the class of failure it represents |
| 4 | Validate the auth header before sending rather than discovering a 401 | 2 |
| 5 | Record a verdict on every run, including blocked ones | 48 runs currently have none |

Item 5 is the cheapest and the most useful. **Forty-eight runs with no verdict
cannot be triaged**, and a verdict is a single write at the point the run ends -
including when it ends by being blocked.

---

## What this report does not claim

It does not claim the fleet is broken. 92 runs completed with a `done: true`
verdict, the watchdog fails honestly rather than silently, and the mean run takes
about 49 seconds, which is reasonable for the work described in the `goal` column.

It claims that **52% of recorded runs did not complete, that 47% of the recorded
errors are one upstream rate limit, and that 48 runs recorded no verdict at all** -
and that all three are addressable without changing what the agents do.

---

*Read-only throughout. No file outside saos-jummper was created, modified or
deleted. The database was opened read-only; no row was changed. Error strings are
quoted as recorded and truncated; no credential, token or key value appears.*
