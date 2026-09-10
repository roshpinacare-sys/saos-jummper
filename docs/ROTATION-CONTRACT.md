
# Rotation Contract - the control that was missing on 2026-09-08

Implemented in `src/jumpper/rotation.py`, 30 assertions in
`tests/test_rotation.py`. Contains no cryptography: it is policy only. It never
derives, holds, reads or writes a private key.

---

## The incident, in one paragraph

At 2026-09-08T21:17:42 the account `headcorner` had all four authorities replaced
on HIVE mainnet (block 109,745,168, trx
`92654439d97f4cd30a70a5ced46b2bd93488b722`). Nothing was taken - balance stayed at
9.682 HIVE, vesting at 17,511.838295 VESTS. It was the estate's own
`steem/agent/keyrotate.cjs`, run with no `--account`, which falls back to its
default target. The owner could not learn the new keys, because the evidence file
that script writes stores them **masked**. Recovery succeeded only because the
scheme happens to be deterministic and the master happened to be on a reachable
machine. That was luck of design, not a control.

Full forensics in `docs/KEY-INCIDENT.md`.

---

## The three controls

### 1. No default account

    const ACCOUNT = (process.env.AGENT_ACCOUNT || 'headcorner').toLowerCase();

A rotation with no explicit target is refused. The refusal detail names the cause
so it cannot be misread as a bug:

> no account supplied; refusing to fall back to a default. The 2026-09-08 rotation
> happened because AGENT_ACCOUNT was unset and the script defaulted to the primary
> account

A **primary account** additionally requires its own separate confirmation, because
`confirm_primary` is not the same decision as "rotate something". Rotating the
account that holds the funds should never be one flag away from rotating a soldier.

### 2. A handoff the owner can actually use

`rotation_evidence.json` stores masked public keys:

    "before": { "hive": { "owner": "STM86gwPfu\u2026", "active": "STM5ct91t6\u2026", ... } }

A masked key cannot be compared against anything, so even the evidence cannot
confirm a recovery. The handoff artifact requires:

- all four roles present on **every** chain being rotated
- every public key **unmasked and at full length** - a key containing an ellipsis or
  shorter than 40 characters is refused with the reason stated
- the derivation **scheme name** (`sha256(username+role+master) via steem-js
  getPrivateKeys`) so the owner knows how to re-derive, **never the master value** -
  a scheme string containing an assignment is refused
- the recovery deadline, computed as `rotated_at + 30 days`, matching the Hive and
  Steem `recover_account` window from `last_owner_update`
- the transaction ids, once known
- a destination path **outside the repository tree**

And the artifact is secret-scanned before emission. It must contain no WIF, no
extended private key, no PEM private key, no master value and no 12-word mnemonic.
A handoff is meant to be readable by the owner and storable offline; if it carries
secret material it becomes a second breach surface instead of a recovery aid.

### 3. A gate that runs before the broadcast

AND-composed, fail-closed, with a refusal recorded either way:

| check | what it requires |
|---|---|
| explicit-account | a named target, never a default |
| primary-confirmation | a second confirmation when the target is primary |
| chains-declared | at least one chain named |
| backup-verified | a verified backup exists before an irreversible change |
| handoff-built | usable, outside the repo, secret-free |

Replaying the real rotation:

    decision : DENY
    failed   : primary-confirmation, backup-verified, handoff-built
    passed   : explicit-account (headcorner), chains-declared (hive)

With every control satisfied: `ALLOW`.

A refused rotation is still recorded, with the actor:

    { "event": "key_rotation_attempt", "account": "headcorner",
      "decision": "deny", "actor": "keyrotate.cjs",
      "failedChecks": [...], "reason": "refused: ..." }

A refusal that is not recorded is indistinguishable from a rotation nobody
attempted, and the second is what an operator assumes.

`dry_run` reports the same denial. It does not authorise anything.

---

## Two fail-closed gaps this module had, both found by its own tests

### A check that cannot be evaluated was passing

With `repo_root=None` the gate could not tell whether the handoff path was inside
the repository. The expression was `bool(repo_root and _inside(...))`, which
short-circuits to `False` - so **an unverifiable location counted as a safe one and
the gate returned ALLOW.**

Fixed: `inside` is now `None` when it cannot be determined, and `None` denies with
the reason stated. This is the same rule as `is_mainnet_endpoint` returning `None`
rather than assuming mainnet, and the same rule the signing contract applies to a
raising detector.

> **A check that cannot run is not a pass. It is an unevaluated check, and
> unevaluated means deny.**

### A malformed handoff crashed the gate instead of denying

Passing an object that could not be inspected raised out of `rotation_gate`,
leaving the caller with no verdict at all. That is worse than a denial: a denial
stops the rotation, an exception stops the program and the caller may retry without
the gate.

Fixed: the handoff inspection is wrapped, and a failure becomes a denial with
`could not be evaluated` in the detail. This is the third time this exact class has
appeared in this repository - `signingcontract.check()` had it in its evidence
collection, and the hardening gate had it in its waiver loading. It now has a name
in the codebase: **fail-absent is not fail-closed.**

---

## How this connects to the rest of the system

`keyrotate.cjs` is the most consequential operation in the estate and currently has
no policy gate, no audit trail outside a local JSON file, and no confirmation step.
Meanwhile `Saosmartwallet/packages/core/src/policy/engine.ts` implements exactly
the semantics needed, verified in its body rather than its docstring:

    if (!outcome.pass) {
      if (outcome.action === "require_approval") approvals = Math.max(...);
      else if (outcome.action === "step_up_auth") stepUp = true;
      else hardDeny = true; // deny, missing, or "allow" - fail closed
    }

A failing outcome whose action is missing, or explicitly `"allow"`, is still a hard
deny. That is the strictest possible reading, and it is the first docstring claim in
this engagement that matched its implementation exactly on first verification.

So the wiring is: **rotation goes through the policy engine, the policy engine
consults this contract, and the handoff is written outside the repository.** None of
that requires new cryptography.

---

## What to change in keyrotate.cjs

| # | change | effort |
|---|---|---|
| 1 | Remove the `\|\| 'headcorner'` default. Require `--account`. | one line |
| 2 | Refuse to run at all when the target is in a primary-account list without `--confirm-primary` | small |
| 3 | Write the handoff artifact (unmasked public keys, scheme name, recovery deadline) to a path outside the repo, on every rotation | small |
| 4 | Stop masking the public keys in `rotation_evidence.json`. Public keys are public; masking them destroys the only verification path the owner has | one line |
| 5 | Emit an audit record for refused rotations too | small |
| 6 | Route the whole operation through `policy/engine.ts` | medium |

Change 4 is the one that would have made the 2026-09-08 recovery trivial instead of
dependent on the derivation still working.

---

*Read-only throughout. No file outside saos-jummper was created, modified or
deleted. No private key, seed, master or vault password was read, derived, printed
or committed. Public keys and file paths only.*
