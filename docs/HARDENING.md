# Hardening - how to stay unbreakable without stopping work


The requirement was two things at once: solutions we can still work with, and
solutions that cannot be broken into. Those pull against each other. A gate
strict enough to be safe gets disabled; a gate loose enough to be convenient
catches nothing.

The resolution is not a compromise. It is a different shape:

> **Fail closed by default, with a scoped, expiring, committed, audited waiver.**

Every blocking rule can be passed - but only by an act that is named, reasoned,
attributed to a human, time-limited, stored in the repository, and printed in
every subsequent gate run. That is how the gate stays on and work still happens.

A rule people disable is not a control. A waiver people can see is.

---

## Running it

    python scripts/harden-check.py .                  # scan a tree
    python scripts/harden-check.py path/to/file.ts    # scan one file
    python scripts/harden-check.py --list-rules       # what exists and why
    python scripts/harden-check.py . --json           # machine-readable verdict

Exit codes:

    0  PASS      no blocking violations
    1  BLOCKED   fix it, or file a waiver
    2  usage or IO error

Wire it into pre-commit and into CI. The same command, the same verdict.

---

## The 17 rules

Every rule was derived from a real defect read out of this estate during the
2026-09-08 audit. None is speculative. Each carries the finding it came from, so
nobody has to guess why it exists.

| id | severity | action | title | real origin |
|---|---|---|---|---|
| H-01 | critical | BLOCK | Plaintext storage fallback instead of fail-closed | secure-storage.ts falls back to localStorage and calls itself DANGEROUS_PLAINTEXT_MODE |
| H-02 | critical | BLOCK | Crypto function is a throwing stub with a real signature | deriveBip32FromMnemonic and deriveEvmPrivateKey declare full signatures, then throw |
| H-03 | high | BLOCK | Merge-conflict markers committed | vault.ts.orig states markers were committed and the file would not compile |
| H-04 | high | BLOCK | Merge-tool artifact committed | vault.ts.orig became the only surviving copy of a lost design |
| H-05 | medium | BLOCK | Math.random used for key material, salt or nonce | makeSalt falls back to Math.random plus Date.now |
| H-06 | medium | REPORT | Security provider injected via a mutable global | window.__SAOS_SECURE_BACKEND__ read at first use, unauthenticated |
| H-07 | high | BLOCK | Database file committed to the repository | db/custom.db, 290,816 bytes, inside a wallet repo |
| H-08 | critical | BLOCK | Secret stored adjacent to the ciphertext it protects | fleet_keys.meta.json holds the vault password beside fleet_keys.enc, in three repos |
| H-09 | critical | BLOCK | Private key or seed material in a tracked file | the estate holds a 7-key fleet vault and an active EVM signer |
| H-10 | high | BLOCK | Token in a file inside the repository tree | a PAT was read from upload/ inside the tree; another was embedded in a stale clone's .git/config |
| H-11 | critical | BLOCK | Attestation signed with ACTIVE authority | 57 of 62 attestation operations on HIVE mainnet used ACTIVE |
| H-12 | high | BLOCK | Testnet or devnet used as a silent default | relay-sol.ts defaults to api.devnet.solana.com; the ledger cannot tell it from mainnet |
| H-13 | high | BLOCK | Verifier cannot reach transaction history | searchTransactionHistory false pins verified at 0; ledger showed anchored 27, verified 0 |
| H-14 | medium | REPORT | Non-final confirmation accepted as verified | the Solana verifier accepts confirmed, which a fork can roll back |
| H-15 | medium | REPORT | Quota snapshot compared without projecting elapsed time | a gate read 924,265 RC and declared HIVE blocked while 73,271,489 was available |
| H-16 | medium | REPORT | Counter that can exceed its own source | the ledger recorded verified 18 against anchored 16 |
| H-17 | high | REPORT | Automation token with administrative scopes | the push token carried admin:org, delete_repo, admin:ssh_signing_key and more |

11 block. 6 report. Reporting rules are not weaker rules - they are the ones
where a human judgement is genuinely required, so the gate surfaces them instead
of guessing.

---

## Waivers - deliberately hard to get, deliberately easy to see

    python scripts/harden-check.py --waive H-07 --glob 'db/*.db' \
        --reason 'ticket SAOS-77, removal scheduled' --by owner --days 7

What is enforced, with tests:

| constraint | behaviour |
|---|---|
| expiry | **mandatory**. `--days 0` is refused: "a waiver without an expiry is a disabled rule" |
| scope | **mandatory**. `*` and `**` are refused: "a global waiver disables the rule everywhere" |
| attribution | a named approver is required; empty is refused |
| reason | required, and expected to reference a ticket |
| visibility | every waiver, valid or expired, is printed in every gate run |
| isolation | a waiver for H-01 never suppresses H-02, even on the same file |
| storage | `waivers.json` is committed. A hidden waiver is a disabled rule |

Expired waivers do not silently lapse into suppression. They stop working, and
the gate says so in the same output that lists them.

---

## The gate never prints a secret

A scanner that echoes the value it just found turns one exposure into two. The
first version of this engine did exactly that: the H-08 evidence line contained
the vault password verbatim.

That is now fixed and pinned by six regression tests.

**And then the same mistake was made again, in this document.** The first
committed version of this runbook illustrated the before/after with the real
vault password spelled out in full - a document about never printing secrets,
printing one. The gate caught it: H-08 fired on `docs/HARDENING.md` itself. The
value has been removed and replaced with a description. The lesson is recorded
rather than quietly edited away, because a runbook that hides its own incident is
worth less than one that shows it.

The general rule this produced: **a finding is described by its location and its
shape, never by its value.** That applies to documentation exactly as much as to
scanner output. For the secret-bearing
rules - H-08, H-09, H-10 - evidence is reduced to **location plus field name**:

    before:  line 1: pass": "<the vault password, printed in full>"
    after :  line 1: pass":[REDACTED]

The useful part of a secret finding is WHERE it is, not WHAT it is. A test
serialises the entire verdict to JSON and asserts the secret value appears
nowhere in it.

---

## Verified, not asserted

The engine was run against a tree built from the actual defective files:

    files scanned : 9
    blocking      : 10
    reporting     : 4
    by severity   : critical 4, high 6, medium 4, low 0
    verdict       : BLOCKED          exit 1

    H-01 critical block  packages/core/src/vault/secure-storage.ts:4
    H-06 medium  report  packages/core/src/vault/secure-storage.ts:3
    H-02 critical block  packages/core/src/vault/key-derivation.ts:3
    H-05 medium  block   packages/core/src/vault/key-derivation.ts:6
    H-03 high    block   packages/core/src/vault/vault.ts.orig:1
    H-04 high    block   packages/core/src/vault/vault.ts.orig
    H-07 high    block   db/custom.db
    H-08 critical block  agent/keys/fleet_keys.meta.json:1   pass":[REDACTED]
    H-12 high    block   src/lib/dex/relay-sol.ts:1
    H-13 high    block   src/lib/dex/relay-sol.ts:2
    H-16 medium  report  src/lib/dex/relay-sol.ts:3
    H-11 critical block  src/lib/dex/relay.ts:2
    H-15 medium  report  src/lib/dex/relay.ts:1
    H-17 high    report  docs/token-scopes.txt:1

And against a clean tree:

    files scanned : 1
    blocking      : 0
    verdict       : PASS             exit 0

A clean file in the middle of the defective tree was correctly reported clean.
No false positive on code that uses os.urandom and posting authority.

---

## What "can still work" means concretely

The gate is not a wall. For each blocking rule there is a small, local change
that satisfies it:

| rule | the change | size |
|---|---|---|
| H-01 | make the missing-backend path throw instead of falling back | a few lines |
| H-02 | delete the stub, or make the module fail to import | a few lines |
| H-03 | resolve the conflict and build before committing | process |
| H-04 | recover the lost design into real source, delete the artifact, gitignore | one pass |
| H-05 | use a CSPRNG and make its absence fatal | one call |
| H-07 | inspect, remove, gitignore | one pass |
| H-08 | move the passphrase to an env var or external store; rotate the keys | config |
| H-10 | keep tokens outside the working tree | config |
| H-11 | required_auths -> required_posting_auths | **two fields, zero RC cost** |
| H-12 | refuse to start when no endpoint is configured | a few lines |
| H-13 | searchTransactionHistory true | **one boolean** |

Three of the eleven - H-11, H-13 and H-05 - are single-token changes. H-11 in
particular removes fund-moving capability from every automated broadcaster in the
estate and costs zero RC, because posting and active authority consume the same
resource classes for the same payload.

If a rule genuinely cannot be satisfied this week, that is what the waiver is
for. It buys time visibly instead of silently.

---

## Rollout

1. Run the gate on each repository and record the verdict. Do not fix anything yet.
2. Fix the single-token items first: H-11, H-13, H-05.
3. Then the fail-closed items: H-01, H-02, H-12. Each is a few lines and each
   converts a silent downgrade into a loud failure.
4. Then the hygiene items: H-03, H-04, H-07, H-10, plus gitignore entries for
   `*.orig`, `*.rej`, `*.db`, `.env`.
5. Then the secret items: H-08. Rotate every key the exposed passphrase protected.
6. Add the gate to pre-commit and CI. From that point the estate cannot regress.
7. File waivers for anything genuinely deferred, with a ticket and an expiry.

Steps 2 and 3 are the ones that matter most, and they are the smallest.

---

## Scope of this document

Written from files read directly out of the repositories. Read-only throughout:
no file in any repository other than saos-jummper was created, modified or
deleted. The defect tree used for verification was built in a scratch directory
and is not committed.

27 assertions in `tests/test_hardening.py` pin every rule to the real defect it
came from, and every waiver constraint listed above.
