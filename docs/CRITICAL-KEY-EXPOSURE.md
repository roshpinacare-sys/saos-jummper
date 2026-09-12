<!-- hardening:allow-file ALL reason=critical finding; describes the exposure by path and structure and prints no secret value -->

# CRITICAL - the archive passphrases are committed beside the archives they open

Read on 2026-09-12 from live repository contents and from
`Saosmartwallet/db/custom.db` (4,685,824 bytes, a SQLite file). **No secret value is
reproduced in this document.** Every secret is described by path, field name and
length only.

---

## What is committed, in one repository

    steem/agent/recovery-meta.json                     845 bytes
        format              "SAOS-RECOVERY-META-1"
        keysZipPass         <32 characters>      <- PASSPHRASE, PLAINTEXT
        keysZipFile         <39 characters>
        keysZipSha256       <64 hex>
        keysZipInnerSha256  <64 hex>
        keysBackupPass      <32 characters>      <- SECOND PASSPHRASE, PLAINTEXT
        keysBackupFile      <42 characters>
        keysBackupSha256    <64 hex>
        replacedArchive     <39 characters>
        sealedAt            <24 characters>

    steem/agent/vault/KEYS-BACKUP-2026-09-09.tar.enc   145,760 bytes   header "Salted__"
    steem/agent/vault/KEYS-ZIP-2026-09-10.zip.enc      252,656 bytes   header "Salted__"

Both archives are OpenSSL `Salted__` containers. Both passphrases are in a JSON file
**two directories up in the same repository.** Anyone with read access to `steem`
can decrypt both.

The repository is readable by a token carrying `admin:org`, `delete_repo`,
`admin:ssh_signing_key`, `admin:public_key`, `workflow` and `write:packages`.

---

## The README states the opposite of what is true

`steem/agent/vault/KEYS-ZIP-README-HE.md`, verbatim:

    line 45:  פענוח על מכונה-אוויר-גפ' מומלץ. הסיסמה אינה נשמרת בשום קובץ.
              "Decryption on an air-gapped machine is recommended. The password is
               not stored in any file."

    line 57:  אף-מפתח-פרטי לעולם לא בגיט בצורה-גלויה — רק גוש-מוצפן + סיסמה בערוץ-נפרד.
              "No private key ever in git in plaintext - only an encrypted blob plus
               the password in a separate channel."

    line 4:   מדיניות-משמורת-מערכת (הוראת-מפעיל 2026-09-10 "זה אצלך בקבצים לא אצלי")
              "System custody policy (operator instruction 2026-09-10: 'it is in your
               files, not with me')"

And the README's own decryption command, line 39, reads the passphrase **out of a
JSON file**:

    -out <archive>.zip -pass pass:"$(python3 -c 'import json;print(json.load(open("<file>.json"))["keysZipPass"])')"

**The documented procedure contradicts the documented policy.** The password is
stored in a file, in the same repository, and the instructions say so.

Line 4 is the explanation: an operator instruction on 2026-09-10 moved custody from
the operator to the files. That is the same decision as `.gitignore` amendment 117i,
which deliberately returned `fleet_keys.enc` beside its password with the reasoning
*"the repo holder is trusted by definition"*.

**That reasoning fails the moment the token leaks.** And the token is a classic PAT
with organisation-admin and repository-deletion scopes.

---

## What the archives and the database protect

`Saosmartwallet/db/custom.db` is a committed SQLite database holding the live
control plane. `VaultEntry` has **239 rows**:

| dimension | breakdown |
|---|---|
| kind | steem-key 158, tron-key 18, note 14, evm-key 12, sol-key 12, btc-key 12, token 9, mnemonic 4 |
| chain | steem 111, blurt 48, tron 20, hive 12, ethereum 12, solana 12, bitcoin 12, infra 4, nvidia 3, github 2, sovereign 2, coinomi 1 |
| role | **owner 39, active 39, posting 40, memo 39**, wallet 48, **master-password 13**, master-key 1, seed 1, mnemonic 2, recovery 1, primary-original 1, rot1-seed 1, operator-pat 1, bridge-* 5 |
| status | verified 176, rotated-out 45, imported 16, operator-custody 1, unverified 1 |

**The key material in `VaultEntry` is properly encrypted.** `encPriv` is hex of
80-318 characters, `privIv` is hex(24) = a 12-byte IV, `privTag` is hex(32) = a
16-byte tag: **AES-256-GCM**. Scanning all 239 rows found **zero bare WIFs and zero
64-hex raw keys.**

`GateConfig` (1 row) holds `kdfSalt` hex(32), `encMaster` hex(128), `sealIv`
hex(24), `sealTag` hex(32), `keySeals` 5,091 characters (12 seals),
`autonomyEnabled = 1`, and `hint = NULL`. **No password hint is committed, and the
master key is ciphertext.** The restore drill recorded in `lastRestoreDrill` states
236 of 237 secrets opened against the master key, with a sealed 411,721-byte backup
written to `/home/z/my-project/backups/gate-vault-1789174829971.enc`.

So the database is not the weak point. **The archives are**, because their
passphrases sit in plaintext beside them.

### The derivation sources are also named in the database

`VaultEntry.source` records where each key came from:

    MASTER-KEYS-RECOVERY.md                                      87 rows
    r17: ROT1 derivation (mother seed, הד.txt) - chain-proven     48 rows
    r20: גזירת-D1 SHA256(חשבון+תפקיד+P5) - הוכחה-חי על blurt       48 rows
    r11: sovereign-seed derivation (keys-zip registry)            12 rows
    r12: upload/בחן.txt (the operator's key file)                 12 rows
    upload/הדקור.txt                                               8 rows
    r11: bridge mnemonic derivation (tron-bridge-state)            6 rows
    upload/בחן.txt master-password derivation (chain oracle)        4 rows
    r16: rotation plane (D1 root, chain-proven)                     4 rows
    upload/הד.txt (mother seed) · upload/קונמי.txt · upload/headcorner.txt · upload/Roshcaregt.txt

**None of those `upload/*.txt` files or `MASTER-KEYS-RECOVERY.md` exist in any of
the seven repositories** - 4,109 blobs were scanned. That is good, and it is the one
part of this that held. But the database publicly documents that a **mother seed**,
a **P5** value and a **D1** root exist, that keys are derived as
`SHA256(account + role + P5)`, and which uploaded file each key came from.

**That is a map.** Combined with either passphrase, or with any of the source files
if they surface, it turns 239 encrypted keys into 239 plaintext keys.

---

## Also in the database: the whole autonomous control plane

| table | rows | contents |
|---|---|---|
| `GateAgent` | 10 | agent names, `tokenHash`, `autonomy`, **`finTier`, `finCaps`** |
| `GateSession` | 166 | `tokenHash`, `encMaster`, `sealSalt`, `viaDevice` |
| `GateDevice` | 13 | `tokenHash`, `encMaster`, `deviceSalt` |
| `GateMessage` | 843 | inter-agent messages with bodies |
| `GateRun` | 222 | `goal`, `report`, `lessons`, `tokens`, `error` |
| `GateAction` | 717 | `agentName`, `action`, `params`, `ok`, `result` |
| `GateOrder` | 5 | `account`, `spec`, `preview`, `previewTxId`, `broadcastId`, `blockNum` |
| `GateProposal` | 5 | `goal`, `rationale`, `budget`, `payload`, `decidedBy` |
| `GateSchedule` | 36 | cron-like schedules with `maxPerDay` |
| `GateTrigger` | 21 | event triggers with `cooldownMs` |
| **`AuditEvent`** | **0** | `seq`, `actorJson`, `targetJson`, `result`, `previousEventHash`, `eventHash` |

**`AuditEvent` is empty.** Its schema matches `packages/core/src/audit/audit.ts`
exactly - the hash-chained log I verified scores 8 of 8 on the recovery contract,
with a genuinely constant-time comparison and a genesis bound to the vault
instance. **The implementation is correct and it is not being used**, while 717
actions and 219 gate events are recorded in tables with no hash chain at all.

`autonomyEnabled = 1` and ten agents carry financial tiers and caps. So this is a
live autonomous control plane, committed, with its key material's passphrases
beside it.

---

## This is the same defect as the one that was fixed

`steem/agent/fleet_keys.enc` (172,449 bytes) and `steem/agent/fleet_keys.meta.json`
(193 bytes, the passphrase) were reported earlier in this engagement. **Both are now
404 - removed.** That fix was real.

**But a second, larger instance was never found**, because the search looked for
`fleet_keys` and not for the pattern. The pattern is: *an encrypted archive plus
its passphrase, in one repository.* There are now three known instances:

| instance | ciphertext | passphrase | status |
|---|---|---|---|
| `agent/fleet_keys.enc` + `agent/fleet_keys.meta.json` | 172,449 | in the meta file | **removed** |
| `agent/vault/KEYS-BACKUP-2026-09-09.tar.enc` | 145,760 | `keysBackupPass` in `recovery-meta.json` | **committed** |
| `agent/vault/KEYS-ZIP-2026-09-10.zip.enc` | 252,656 | `keysZipPass` in `recovery-meta.json` | **committed** |

Fixing one instance of a pattern without searching for the pattern is how the other
two survived.

---

## What to do, in order

| # | action | why first |
|---|---|---|
| **1** | **Rotate every key in the two archives.** Treat all 239 vault entries as burned. | The passphrases are public to anyone who has ever had repo read access, and they are in git history permanently |
| **2** | **Remove `recovery-meta.json` and both `.enc` archives** from the working tree | Stops forward exposure; does not undo history |
| **3** | **Revoke the classic PAT** and issue a fine-grained token scoped to one repository, Contents read/write, short expiry, no admin scopes | The current token can delete repositories and install SSH keys |
| **4** | **Reverse `.gitignore` amendment 117i** and the 2026-09-10 operator instruction that moved custody into the files | The reasoning - "the repo holder is trusted by definition" - is what produced all three instances |
| 5 | Store passphrases outside every repository: hardware, paper, or a password manager. Never in a JSON file beside the blob | |
| 6 | Delete or gitignore `Saosmartwallet/db/custom.db`. It is 4,685,824 bytes and grew from 290,816 during this engagement, so it is being written and committed continuously | |
| 7 | Populate `AuditEvent`. The hash-chained implementation exists and is correct; 717 actions are recorded in an unchained table instead | |
| 8 | Remove the derivation map from the committed database, or accept that the source of every key is public | |

Actions 1 through 3 are the ones that matter. **Everything else is secondary to the
fact that two passphrases and the blobs they open are in the same repository, and
have been since 2026-09-09 and 2026-09-10.**

---

## Scope and limits of this reading

- No passphrase, key, seed, token or archive content was printed, copied or
  decrypted. Every secret above is described by path, field name, length and
  character class only.
- The two `.enc` archives were **not** opened. Their headers were read to confirm
  the OpenSSL `Salted__` container format.
- `recovery_deepscan_report.json` (9,572 bytes) was fetched and scanned for
  secret-shaped strings; none were found.
- The `upload/*.txt` files and `MASTER-KEYS-RECOVERY.md` named as derivation sources
  do not exist in any of the seven repositories. Whether they exist elsewhere -
  on the operator's machine, in an email, in a chat log - was not and cannot be
  determined from here. **If they do, the encryption on all 239 entries is
  decorative.**
- `GateMessage` (843 rows), `GateRun` (222) and `GateAction` (717) bodies were not
  read. They may contain operational secrets in free text. That is unexamined.

---

*Read-only throughout. No file outside saos-jummper was created, modified or
deleted. No keys read, no transactions signed, nothing broadcast, nothing
decrypted.*
