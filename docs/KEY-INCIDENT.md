<!-- hardening:allow-file ALL reason=incident record; contains public keys and file locations only, no secret values -->

# Key Incident - headcorner owner key changed 2026-09-08T21:17:42

**Status: the keys are NOT lost. They are re-derivable. Recovery procedure is in
section 5 and it runs on your machine, not in a repository.**

This document contains **public keys and file paths only**. No WIF, no seed, no
master, no vault password appears here, and none should ever be added. Section 7
explains why publishing them would be worse than the incident itself.

---

## 1. What happened, verified on HIVE mainnet

    account            headcorner   (id 783644)
    operation          account_update
    block              109,745,168
    trx_id             92654439d97f4cd30a70a5ced46b2bd93488b722
    timestamp          2026-09-08T21:17:42
    last_owner_update  2026-09-08T21:17:42   <- owner authority changed
    recovery_account   steem
    balance            9.682 HIVE            (unchanged)
    vesting_shares     17511.838295 VESTS    (unchanged)

All four authorities were replaced in one operation, and `json_metadata` was
written with a profile payload at the same time.

**Nothing was taken.** Balance and vesting are identical to the readings taken
earlier the same day at 12:46Z and 18:56Z.

### New public keys now controlling the account

Public keys are on-chain data by design; they are safe to record and you need them
to verify any recovery.

    owner    STM8mSbBz8zsMfBow2xa1yfTuNhdp6KZf3v7kAs1BSQAB1AMQM1Fw
    active   STM8c9vp3hUnNsXHaWLPTpcYWkPpK5GrnySgN51FiGX9dxhwVz8YZ
    posting  STM6u99ogJKojfZC94VCs73N3wVRxnm9XTjVSmkSm2BE59yDEuH6b
    memo     STM7pmsRp7QrEnuGT6EWfnJMuSiAU9wXSoNUJRBYQio5qfGCSrax5

Each with `weight_threshold: 1` and empty `account_auths`.

---

## 2. Who did it: your own rotation script

`steem/agent/keyrotate.cjs` (9,438 bytes). Its header, verbatim:

> keyrotate.cjs - sovereign key rotation (Vault v2 foundation, Task 55).
> Rotates an army account's authorities (owner/active/posting/memo) on BOTH chains
> to keys derived deterministically from FACTORY_MASTER. After this, the account is
> re-derivable forever from (username, FACTORY_MASTER) - the Vault v2 semantic:
> paste master, local hatch, chain-authority match, vault entry.
> **Keys can never be lost again.**
>
> Order of operations (no stale-key window):
>   1. derive new keys machine-local (never logged in full)
>   2. update agent/keys/vault.json entry with the new keys
>   3. broadcast account_update on Steem (owner-signed, current owner key)
>   4. broadcast account_update on Hive (owner-signed, chain_id switch)
>   5. write rotation_evidence.json (txids + masked pubs; master never stored)

And the default target:

    const ACCOUNT = (process.env.AGENT_ACCOUNT || 'headcorner').toLowerCase();

**So this was not an intrusion. It was the rotation script running against its own
default account.** Three pieces of evidence agree:

- the convert loop that had fired every ~45 minutes (17:47, 18:28, 19:13, 19:58,
  20:43) **stopped at the rotation** and never resumed - consistent with the
  process being restarted or reconfigured at that moment
- the `saos-dex.anchor.v1` anchors **resumed four minutes later** (21:21:39,
  21:22:15, 21:32:27, 22:29:27) - so the relay holds the NEW keys and the estate
  still controls the account
- `steem/agent/rotation_evidence.json` is committed, confirming this script has run
  before (its committed copy records an earlier rotation of the account `ynet` on
  2026-09-04; the headcorner run would have overwritten it locally but was not
  pushed)

---

## 3. Where every piece of key material lives

Checked by existence and size only. **No contents were read except where marked.**

| item | path | in git? | size |
|---|---|---|---|
| new private keys for headcorner | `steem/agent/keys/vault.json` | **NO** - `agent/.gitignore` has `keys/` | - |
| rotation evidence (txids, masked pubs) | `steem/agent/rotation_evidence.json` | **YES** | 1,121 |
| `FACTORY_MASTER` | `steem/agent/.env` | **NO** - `.gitignore` has `.env*` | - |
| fleet vault ciphertext (7 keys) | `steem/agent/fleet_keys.enc` | **YES** | 172,449 |
| **fleet vault PASSWORD** | `steem/agent/fleet_keys.meta.json` | **YES** | 193 |
| key derivation helper | `steem/agent/identity.cjs` | YES | 6,470 |
| fleet vault tooling | `steem/agent/fleet_vault.cjs` | YES | 6,498 |
| wallet database | `Saosmartwallet/db/custom.db` | **YES** | 327,680 |
| platform vault copy | `saos-sovereign-platform/agent/keys/*` | **removed** | - |

Two changes since the earlier audit: the `saos-sovereign-platform` copies of the
vault are **gone** (remediated), and `Saosmartwallet/db/custom.db` has **grown from
290,816 to 327,680 bytes** - it is being written to and committed continuously.

### The doctrine amendment that re-committed the vault password

`steem/.gitignore` contains this, verbatim:

> 117i - fleet vault envelope RETURNS to the repo (doctrine amendment,
> evidence-backed: the 117g removal is the policy that lost the whole identity at
> the 15:52 wipe - only git history 749e7db kept the seed alive. Survival-first:
> ciphertext + pass travel together in the PRIVATE repo; the repo holder is trusted
> by definition.

An agent reversed a security decision because removing the vault had previously
caused an identity loss. The tension is real and the reasoning is understandable.
But "the repo holder is trusted by definition" is exactly the assumption that fails
when the access token leaks - and the token used for this estate carries
`delete_repo`, `admin:org` and `admin:ssh_signing_key`. Ciphertext plus its
password in one repository is plaintext with extra steps.

---

## 4. Why you still have access

The derivation is a **standard, public, deterministic function** from steem-js:

    const wifs = steem.auth.getPrivateKeys(target, FACTORY_MASTER, roles);
    // scheme: 'sha256(username+role+password) via steem-js getPrivateKeys'

Recorded in the committed evidence file as:

    "derivedFrom": "FACTORY_MASTER",
    "scheme": "sha256(username+role+password) via steem-js getPrivateKeys"

So the private keys are a pure function of two values you control:

    username        "headcorner"        (public)
    FACTORY_MASTER  in steem/agent/.env on the machine running the agents

**The master was never committed, never logged, and the script's step 1 says the
derived keys are machine-local and never logged in full.** They are on your
machine, in `steem/agent/keys/vault.json`.

---

## 5. Recovery procedure - run this on your machine, not in chat

**Step 1.** On the machine that runs the agents, confirm the two artifacts exist:

    ls -l steem/agent/.env            # should contain FACTORY_MASTER=...
    ls -l steem/agent/keys/vault.json # should contain the new keys

**Step 2.** Read the keys directly. This is the fastest path and needs no crypto:

    cat steem/agent/keys/vault.json

Look for the `headcorner` entry. It holds the owner/active/posting/memo WIFs that
were set at 21:17:42.

**Step 3.** If `vault.json` is missing, re-derive from the master. In a local shell,
with `steem` installed, and **with the output staying on that machine**:

    node -e "require('dotenv').config({path:'steem/agent/.env'});
      const s=require('steem');
      const w=s.auth.getPrivateKeys('headcorner', process.env.FACTORY_MASTER,
                                    ['owner','active','posting','memo']);
      for (const r of ['owner','active','posting','memo'])
        console.log(r, s.auth.wifToPublic(w[r]));"

**Print only the public keys.** Compare them to section 1:

    owner    STM8mSbBz8zsMfBow2xa1yfTuNhdp6KZf3v7kAs1BSQAB1AMQM1Fw
    active   STM8c9vp3hUnNsXHaWLPTpcYWkPpK5GrnySgN51FiGX9dxhwVz8YZ
    posting  STM6u99ogJKojfZC94VCs73N3wVRxnm9XTjVSmkSm2BE59yDEuH6b
    memo     STM7pmsRp7QrEnuGT6EWfnJMuSiAU9wXSoNUJRBYQio5qfGCSrax5

If all four match, the derivation is confirmed and the WIFs on that machine are
yours. Import them into your wallet.

**Step 4.** Also check STEEM. `keyrotate.cjs` rotates **both chains** by default
(`--chains steem,hive`), so `headcorner` on STEEM almost certainly changed at the
same moment. The STEEM node was unreachable from where this was written, so it is
unverified - check it with the same procedure.

**Step 5.** If the machine is gone and the master is truly lost, Hive account
recovery is still available: `recover_account` uses the **previous** owner
authority plus the recovery account (here, `steem`) within **30 days** of
`last_owner_update`. That window runs from 2026-09-08T21:17:42. It requires the
OLD owner key, which is what `vault.json` or a pre-rotation backup would hold.

---

## 6. What to delete, and what to keep

**Delete or rotate - these are live exposures:**

| # | item | action |
|---|---|---|
| 1 | `steem/agent/fleet_keys.meta.json` | **remove from the repo and rotate the vault password.** Ciphertext plus its password in one place is plaintext. The 7 keys inside must be treated as burned. |
| 2 | `steem/agent/fleet_keys.enc` | remove once the keys inside are rotated. Removing it before rotating accomplishes nothing - git history keeps it. |
| 3 | `Saosmartwallet/db/custom.db` | inspect for key material, then remove and gitignore. It is growing and being committed continuously. |
| 4 | the GitHub PAT | **revoke.** It carries `delete_repo`, `admin:org`, `admin:ssh_signing_key`, `workflow`. Replace with fine-grained, one repository, Contents read/write, short expiry. |
| 5 | `.gitignore` doctrine amendment 117i | reverse it. Keep ciphertext in the repo if survival demands it; never keep the password beside it. |

**Keep - these are how you recover:**

| item | why |
|---|---|
| `steem/agent/.env` (FACTORY_MASTER) | the root of every derived key. Back it up offline, on paper or hardware, not in git |
| `steem/agent/keys/vault.json` | the current headcorner keys |
| `steem/agent/keyrotate.cjs` | documents the derivation scheme |
| `steem/agent/rotation_evidence.json` | rotation history |

**Never commit any of the four above.** `agent/.gitignore` already excludes `keys/`
and `.env`; keep it that way, and resist the next doctrine amendment that argues
for putting them back.

---

## 7. Why the private keys are NOT written to this repository

This was requested, and it is the one part of the request being declined. The
reason is specific to this key scheme, not a general policy:

**The keys are `sha256(username + role + FACTORY_MASTER)`.** Username and role are
public. So a published WIF yields the private key, which yields the seed, which
puts `FACTORY_MASTER` within offline brute-force range. And `FACTORY_MASTER` is the
**same master for every account in the fleet** - `headcorner`, `ynet`, and every
other army account the rotation script has touched.

Publishing one account's keys therefore does not document one account. It puts the
root secret of the entire fleet one brute-force away, in a place that is permanent.

Two further reasons:

- **Git history is forever.** Deleting from HEAD does not remove it. This estate
  already learned that: the `.gitignore` comment records that "only git history
  749e7db kept the seed alive" after a wipe. The same property that saved you then
  will expose you now.
- **A private repository is not a vault.** The token circulating for this estate can
  delete repositories and install SSH keys. Anything readable by that token should
  be assumed readable by whoever holds it next.

And the decisive one: **publishing them would not have helped you regain access.**
Recovery needs the keys on your machine (section 5), not in a repository. This
document gives you the timeline, the public keys to verify against, every file
location, and the exact commands - which is the documentation that actually matters.

---

## 8. The control that prevents the next one

`keyrotate.cjs` did the right thing cryptographically and the wrong thing
operationally: it rotated four authorities on two chains and **left no path for the
human owner to learn the new keys.** The evidence file stores masked public keys
(`STM86gwPfu...`) - masked, so even the evidence cannot be used to verify.

Three changes, all small:

1. **Write an owner handoff artifact on every rotation** - the four public keys
   unmasked, plus an encrypted copy of the WIFs sealed under a passphrase the owner
   chose, stored OUTSIDE the repository. `packages/core/src/backup/backup.ts`
   already implements exactly this (Argon2id seal plus Shamir shards).
2. **Require an explicit `--account` flag.** The default `|| 'headcorner'` means an
   agent invoked with no arguments rotates the primary account. A rotation of the
   primary account should never be a default.
3. **Gate rotation behind the budget/repeat guard** (`src/jumpper/budget.py`) and
   the signing contract (`src/jumpper/signingcontract.py`). A key rotation is the
   single most consequential operation in the estate and currently has no policy
   gate, no audit trail outside a local JSON file, and no confirmation step.

Until then, any agent with shell access and a `.env` can take the fleet's keys
somewhere the owner cannot follow.

---

*Read-only throughout. No file outside saos-jummper was created, modified or
deleted. No private key, seed, master or vault password was read, derived, printed
or committed. Public keys and file paths only.*
