<!-- hardening:allow-file ALL reason=status snapshot describing exposures by path and size, printing no secret value -->

# Status - what is still live, what was fixed, what is waiting

Re-read from the repositories on 2026-09-12. Every line below is a direct API
result, not a recollection. No secret value is reproduced anywhere in this document.

---

## 🔴 Still committed - the critical exposure is live and growing

    steem/agent/recovery-meta.json                        865 bytes   (was 845)
        contains keysZipPass <32 chars> and keysBackupPass <32 chars>, plaintext

    steem/agent/vault/KEYS-BACKUP-2026-09-09.tar.enc  145,760 bytes   header "Salted__"
    steem/agent/vault/KEYS-ZIP-2026-09-10.zip.enc     252,656 bytes   header "Salted__"
    steem/agent/vault/KEYS-ZIP-README-HE.md             4,382 bytes   (was 3,271)

    Saosmartwallet/db/custom.db                       4,751,360 bytes
        grew 290,816 -> 327,680 -> 4,685,824 -> 4,751,360 during this engagement

**Both archive passphrases sit in a JSON file two directories above the archives
they open, in the same repository.** The README beside them states the password is
not stored in any file, while its own decryption command reads it out of that JSON.

`recovery-meta.json` grew by 20 bytes and the README by 1,111 bytes between two
reads. **This is not a stale artifact - it is being actively written.**

`db/custom.db` holds 239 AES-256-GCM encrypted vault entries (39 owner, 39 active,
40 posting, 39 memo, 13 master-password), the master key material with its KDF salt
and 12 key seals, and the whole autonomous control plane with `autonomyEnabled = 1`
and ten agents carrying financial tiers. The key material itself is properly
encrypted - **zero bare WIFs and zero raw keys across all 239 rows** - and all
twelve free-text tables were scanned with no seed phrase, private key, API token or
password literal found. The nine 12-word-pattern matches in `GateRun` were each
tested and all nine are ordinary prose in the `steps` and `verdict` columns.

The problem is not the encryption. **It is that the database, the archives and the
archive passphrases are all in version control.**

---

## ✅ Removed - three fixes confirmed

    steem/agent/fleet_keys.enc             404   GONE
    steem/agent/fleet_keys.meta.json       404   GONE
    saos-dex/state/pool.json               404   GONE

The first instance of the pattern was found and fixed. **The second and third
instances of the same pattern survived**, because the search looked for the filename
`fleet_keys` rather than for the pattern *an encrypted archive plus its passphrase
in one repository*. There were three. One was fixed.

**Removal from HEAD does not remove from git history.** All three files remain
retrievable at earlier commits, so the seven keys inside `fleet_keys.enc` still need
rotating.

---

## 🔴 The token is still a classic PAT

    GET /user                          200   login roshpinacare-sys
    GET /users/<org>/installation      401   not a fine-grained app token

It carries `admin:org`, `admin:enterprise`, `delete_repo`, `admin:ssh_signing_key`,
`admin:public_key`, `workflow`, `write:packages`, `codespace` and `audit_log`.

**That is a master key, not a push token.** Anyone holding it can delete every
repository in the organisation, install SSH signing keys, and read the three files
above. It has been pasted into this conversation repeatedly.

---

## The four delivered specifications - none applied yet

| id | item | target file | size | status |
|---|---|---|---|---|
| P-08 | `endpointHost` + `network` on `AnchorRecord` | `saos-dex/src/lib/dex/relay.ts` | 71,027 | **not yet** |
| P-09 | `threshold` in `reconstructSecret` | `Saosmartwallet/packages/core/src/crypto/shamir.ts` | 8,092 | **not yet** |
| P-10 | audit hash binds source/occurredAt/reason/actionId | `roshpina/kernel/orchestrator/audit.ts` | 5,372 | **not yet** |
| P-11 | reference id at every xlock memo site | `steem/agent/wrapped.cjs` | 55,061 | **not yet** |

`shamir.ts`, `audit.ts` and `wrapped.cjs` are byte-for-byte the same size as when
the specifications were written, so none of the three files has been touched.

For contrast, `EPOCH-PATCH-SPEC.md` was adopted the same day it was delivered, in
commit `263d3bfc9b` titled "relay: EPOCH-PATCH-SPEC adopted from saos-jummper", and
then extended in `3042b2e6` to every anchor path including manual fleet anchors.
**The channel works when the repository is being worked on.**

`roshpina/kernel/orchestrator/audit.ts` has one commit in its entire history - the
founding commit `e43aa5e1` of 2026-09-07T13:25:35. `shamir.ts` was last touched
2026-09-07T22:30:08. **A specification in a repository nobody commits to is a
message in a bottle.**

---

## Ready and waiting on one decision

`state/fork-correction-op.json` holds the complete, ready-to-sign operation that
publishes the eight forked heights and their seventeen roots:

    payload       831 bytes of an 8,192-byte free budget   (10.14%)
    authority     POSTING        required_auths: []
    fee           0
    id            saos-height-correction.v1
    corrections   8 heights, 17 roots, all AMBIGUOUS, no canonical root declared
    retracts      false

Verified by round trip in both directions: `decode_corrections` reads the real
831-byte payload back into eight heights and seventeen roots, and
`encode_corrections` of the result is byte-identical to the input. 20 assertions in
`tests/test_remedy_decode.py`.

**Everything is built. What is missing is an external signer and the decision to
broadcast.**

---

## Actions, in order

| # | action | severity | effort |
|---|---|---|---|
| 1 | **Rotate every key in the two archives.** Treat all 239 vault entries as burned. | **critical** | hours |
| 2 | **Remove `recovery-meta.json` and both `.enc` archives** from the working tree | **critical** | minutes |
| 3 | **Revoke the classic PAT**; issue fine-grained, one repository, Contents read/write, short expiry, no admin scopes | **critical** | one minute |
| 4 | **Delete or gitignore `Saosmartwallet/db/custom.db`** - 4.75 MB and growing on every commit | **critical** | minutes |
| 5 | Reverse `.gitignore` amendment 117i and the 2026-09-10 instruction that moved custody into the files | high | one edit |
| 6 | Store passphrases outside every repository - hardware, paper, or a password manager | high | policy |
| 7 | Populate `AuditEvent`. The hash-chained implementation exists and scores 8 of 8; 717 actions are recorded in an unchained table instead | high | small |
| 8 | Broadcast `state/fork-correction-op.json` | high | one signature |
| 9 | Apply P-08, P-09, P-10, P-11 | high/medium | four small patches, all specified |
| 10 | **Decide who owns `roshpina` and `Saosmartwallet`** | **critical process** | one decision |

Actions 1 through 4 are one activity: **get key material out of version control.**
They do not require a single line of application code.

---

*Read-only throughout. No file outside saos-jummper was created, modified or
deleted. No keys read, no archives opened, no transactions signed, nothing
broadcast, nothing decrypted.*
