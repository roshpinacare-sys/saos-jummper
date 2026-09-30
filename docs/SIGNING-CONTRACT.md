
# The Six-Stage Signing Contract

Derived by reading all 968 lines of
`Saosmartwallet/packages/core/src/signing/orchestrator.ts`, then measured against
every other signing or broadcasting path in the estate.

Implemented in `src/jumpper/signingcontract.py`, with 17 assertions in
`tests/test_signingcontract.py`.

---

## The measured result

**Re-measured 2026-09-30** with `src/jumpper/signingcontract.py` (the canonical
checker, unmodified) against the committed sources on `main` of each repo. The
blob SHAs of the measured files were verified identical between the local
working trees and remote `main` via the GitHub API, so these scores describe
remote `main` as of the re-measure date. Old scores are kept below, marked
superseded - history is not deleted, it is closed out.

| file | repo | score (re-measured 2026-09-30) | safe to hold funds | missing stages |
|---|---|---|---|---|
| `signing/orchestrator.ts` | Saosmartwallet | **6/6 (100%)** | **yes** | none |
| `policy/engine.ts` | Saosmartwallet | 2/6 (33%) | n/a - not a signer | role, reveal, broadcast, audit |
| `relay-eth.ts` (`src/lib/dex/`) | **saos-dex** | **6/6 (100%)** - re-measured 2026-09-30 | **yes** (post-wiring) | none |
| `relay.ts` (`src/lib/dex/`) | **saos-dex** | **3/6 (50%)** - re-measured 2026-09-30, unchanged | **no** | session-gate, policy-gate, audit-trail - **not yet wired** (Task 8-a covered `relay-eth.ts`, not this file) |
| `anchor-live.ts` (`src/lib/saos/`) | **saos-sovereign-platform** | **6/6 (100%)** - re-measured 2026-09-30 | **yes** (post-wiring) | none |

Superseded scores, as originally published (kept for the record):

| file | score at original measurement | status |
|---|---|---|
| `relay.ts` | 3/6 (50%) | superseded 2026-09-30 - re-measured, still 3/6, no change |
| `anchor-live.ts` | 1/6 (17%) | superseded 2026-09-30 - Task 8-a port brought it to 6/6 |
| `relay-eth.ts` | 2/6 (baseline measured during Task 8-a; never had its own row above) | superseded 2026-09-30 - Task 8-a port brought it to 6/6 |

**Original finding (now superseded in part):** the code designed to hold funds
conforms completely, the code that actually broadcasts to HIVE and STEEM mainnet
conforms to half of it, and they are not connected to each other.

**Update 2026-09-30 (Task 8-a):** the gap was closed by porting the six-stage
orchestrator into the two broadcast paths that measured non-conforming -
`saos-dex relay-eth.ts` (ETH seal broadcast, pushed as e5d22e5) and
`saos-sovereign-platform anchor-live.ts` (STEEM/HIVE anchor, pushed as 3f4eeb3).
Both now measure 6/6 with this checker, verified again at the 2026-09-30
re-measure (repos since advanced to 4fa6366 / d3119da; the measured files are
byte-identical to the Task 8-a ports - blob SHAs checked against remote main).
`relay.ts` - the dex STEEM/HIVE relay - was NOT part of Task 8-a and still
measures 3/6, so actions 2-5 below still apply to that one file.

`policy/engine.ts` at 2/6 is not a deficiency - it is the policy layer, not a
signing path, so it legitimately does not reveal keys or broadcast. The contract
is written for signing paths and says so.

---

## The six stages

| # | stage | obligation | what breaks without it |
|---|---|---|---|
| 1 | session-gate | vault unlocked, step-up re-auth available, before any key is resolved | a signer resolves keys for an unattended process - how a daemon ends up moving funds |
| 2 | policy-gate | policy evaluated BEFORE a key is touched; denial aborts | signing first and checking after means the damage is done when the check runs |
| 3 | least-privilege-role | role follows what the operation DOES; a role-less key refuses | defaulting to active hands fund-moving capability to code that only needed to publish bytes |
| 4 | reveal-once | plaintext key exists only inside the signing call frame | a key that outlives the frame ends up in state, an error, a log line or a heap dump |
| 5 | capability-checked-broadcast | broadcasting is a separate capability from signing | if signing implies broadcasting there is no dry-run - every test is a real transaction |
| 6 | audit-trail | key use, attempts and broadcasts all recorded, including failures | no way to answer who signed what, when, or whether something was refused |

---

## What the orchestrator does at the four points that matter

    const { privateKey, record } = await vault.revealKeyFor(keyId);
    if (record.role === null) {
      throw new VaultError("VALIDATION", `key ${keyId} is flavor-less (role null)`);
    }
    const signed = await adapter.sign(tx, { byRole: { [record.role]: privateKey } });

- the private key goes from reveal straight into `adapter.sign` and nowhere else
- a role-less key **throws** rather than defaulting to something
- the only key-like `return` in 968 lines is `publicKeyFor()`, which returns
  `privateKey.publicKey.toString(prefix)` - a derived public value, never fabricated
- `console` appears **zero** times, so there is no logging path for key material

Its header also states: *"Denials and step-up demands THROW - nothing is ever
signed on a maybe."* That is the policy gate behaving correctly.

---

## A correction to my own earlier finding (H-11)

I reported that 57 of 62 attestation operations on HIVE mainnet were signed with
the ACTIVE authority, and recommended swapping two fields in `buildOp`.

**That recommendation was wrong.** Reading `saos-dex/src/lib/dex/relay.ts` shows
the least-privilege logic is already implemented:

    const steemPost = (process.env.STEEM_POSTING_WIF || "").trim();
    const hivePost  = (process.env.HIVE_POSTING_WIF  || "").trim();
    const steemRaw  = steemPost || (process.env.STEEM_ACTIVE_WIF || "").trim();
    const hiveRaw   = hivePost  || (process.env.HIVE_ACTIVE_WIF  || "").trim();
    ...
    const steemAuth = steemPost ? "posting" : "active";
    const hiveAuth  = hivePost  ? "posting" : "active";

It prefers the POSTING key and falls back to ACTIVE only when no posting key is
configured, deriving the authority from whichever key was found. That is exactly
the right design.

**So the 57/62 ACTIVE anchors are a CONFIGURATION gap, not a code gap.** The fix
is to set `STEEM_POSTING_WIF` and `HIVE_POSTING_WIF`. No code change at all, and
the authority flips to posting on the next run.

The same file is also fail-closed on a bad key, with no retry loop:

    if (!steemWif || !hiveWif) {
      console.error("[saos-relay][ALERT] wif-invalid: ... relay suspended
                     fail-closed (not a retry loop)");
      return null;
    }

That is good engineering, and it is why `relay.ts` scores 3/6 rather than 1/6.
What it genuinely lacks is a session gate, a policy gate and an audit trail - the
three stages that would have caught the convert loop.

---

## Three defects in this module, all found by its own tests

### 1. A splice silently replaced a helper with a lambda - and check() still said 6/6

A revision inserted `console_leaks` after the `STAGES` list by searching for the
text `def console_leaks(`. That string also appears **inside a stage lambda**, so
the splice landed in the wrong place. `console_leaks` became a lambda, stage 4
degraded to "not (audit-pattern-present)", and `check()` returned **6/6 on the real
orchestrator** - a broken detector that looked green.

Fixed by rebuilding the module with every helper defined above `STAGES`, and pinned
by a test asserting the helpers are real functions and that `def console_leaks(`
appears before `STAGES: List[Stage]` in the source.

**This is the same failure mode as the ledger that recorded verified=18 against
anchored=16.** A check that cannot fail is not a check.

### 2. The leak detector flagged prose

The first version matched the letters `wif` anywhere in a console argument, so it
flagged the relay's own fail-closed alert - a static message that leaks nothing and
is exemplary behaviour. A detector that cries wolf gets switched off.

Fixed by stripping string literals before the keyword scan while keeping template
interpolations, which are real values. Calibrated in both directions: four real
leak forms are caught, three prose forms are not.

### 3. Evidence collection could crash the verdict

`check()` wrapped each stage detector in try/except but collected evidence outside
it, so a hostile source raised instead of returning a non-conforming verdict. **A
check that raises instead of reporting is not fail-closed, it is fail-absent - and
an absent check reads as a pass to any caller that only inspects the verdict.** The
evidence scan and both leak scans are now guarded.

---

## What to do with this

| # | action | effort | effect |
|---|---|---|---|
| 1 | Set `STEEM_POSTING_WIF` and `HIVE_POSTING_WIF` | **configuration only** | 57 attestation ops stop using the ACTIVE key; no code change |
| 2 | Give `relay.ts` an audit trail | small | answers who signed what, and whether an op was refused |
| 3 | Put the budget and repeat guard from `budget.py` in front of `relay.ts` | small | stops the convert-loop class permanently |
| 4 | Add a policy gate before key resolution in `relay.ts` | medium | stage 2 of 6; the orchestrator shows the shape |
| 5 | Route relays through `packages/core` instead of reimplementing | large | 6/6 instead of 3/6, and one signing path for the whole estate |

Action 1 alone removes fund-moving capability from the automated broadcaster, and
it is a configuration change.

---

*Read-only throughout. No keys read, no transactions signed, nothing broadcast.*
