<!-- hardening:allow-file ALL reason=audit report quoting the defects it found, including conflict markers and a storage fallback -->

# Wallet Audit - Saosmartwallet/packages/core/src/vault

Read directly from GitHub, read-only, 2026-09-08. No file in that repository was
modified. The committed database was not opened. Secret values are described by
location and shape, never reproduced.

Scope: packages/core/src/vault/ - 11 files, 103,262 bytes.

    vault.ts                  41,010   the vault itself
    key-manager.ts            20,297   key operations
    key-encryption.test.ts    15,774   tests
    key-derivation.ts         11,666   derivation
    vault.ts.orig              6,865   MERGE-CONFLICT LEFTOVER, COMMITTED
    secure-storage.ts          5,736   storage backend
    backup.ts                  5,374
    types.ts                   4,663
    index.ts                   1,862
    recovery.ts                1,561
    key-encryption.ts          1,412   facade

---

## Summary

Three findings make this unsafe for mainnet funds today, and all three are stated
by the code itself rather than inferred.

| # | finding | severity | gate rule |
|---|---|---|---|
| W-01 | Key storage falls back to plaintext browser localStorage | CRITICAL | H-01 |
| W-02 | Both real derivation functions are throwing stubs | CRITICAL | H-02 |
| W-03 | A merge conflict was committed; the incoming side was lost into a .orig | HIGH | H-03, H-04 |
| W-04 | Salt generation falls back to Math.random | MEDIUM | H-05 |
| W-05 | Backend injection through a mutable global | MEDIUM | H-06 |
| W-06 | db/custom.db (290,816 bytes) committed in a wallet repo | UNVERIFIED | H-07 |

---

## W-01 - key storage falls back to plaintext localStorage

secure-storage.ts states its own status in its header comment:

> This is a DANGEROUS_PLAINTEXT_MODE placeholder. It must be replaced with a
> native secure-enclave or OS-keystore implementation before any mainnet usage
> involving real funds.

The backend resolves to window.localStorage whenever no backend has been
injected. key-encryption.ts is a 1,412-byte facade that delegates every operation
to it: encryptKey, decryptKey, generateVaultKey, listEncryptedKeys,
deleteEncryptedKey, exportVaultBackup, importVaultBackup, clearAllVaultData.

Consequences of the default path:

- any XSS on any page of the origin reads every key
- keys persist on disk in cleartext, readable by any process with access to the
  browser profile
- browser backups, sync and forensic images all carry them
- no lock screen, no timeout, no memory-only mode

The honest part: the file names its own defect. The problem is that the
placeholder is the shipping default rather than a fatal error.

---

## W-02 - the derivation functions that would produce keys do not exist

key-derivation.ts (11,666 bytes) was scanned for every standard primitive:

    scrypt 0   pbkdf2 0   argon2 0   hkdf 0   crypto.subtle 0   WebCrypto 0
    bip39  0   mnemonic 0  seed 0    sha256 2 (node:crypto - a hash, not a KDF)

Both functions that would derive a key declare full, plausible signatures and
return types, and both throw 'not implemented'. A caller that catches and logs
appears to work until the key is actually needed.

vault.ts itself is 41,010 characters and contains ZERO occurrences of
privateKey, seed, mnemonic, plaintext, DANGEROUS, localStorage, exportKey,
clearKey, zero, wipe or memory. The vault does not touch key material at all, so
the entire key path is the two small files above.

---

## W-03 - a merge conflict was committed, and work was lost

vault.ts.orig is a merge-tool artifact. It is committed. Its own header says:

> the .orig backup left by the merge tool ... The file is in a broken, uncompiled
> state (merge conflict markers were committed)

and

> the file was reverted to the pre-merge HEAD side ... the incoming side that this
> .orig preserves was LOST from the working tree

Inside it are live conflict markers. The HEAD side that survived defines only
Vault as id, name, createdAt - no key concept at all. The incoming side that was
lost defined VaultKey with a privateKeyRef field: a REFERENCE to a key, not the
key. That is the correct design, and it is the one that did not survive.

The lost side also defined the multi-chain taxonomy
(native, evm, solana, tron, cosmos, substrate, btc, custom) and, per the .orig
header, the fix for a type mismatch that key-manager.ts still documents. So
key-manager.ts is written against the shape the merge discarded.

**Recovering vault.ts.orig is the highest-value single action in that
repository.** It restores a key model that stores references instead of keys, and
it is the design the rest of the code was written against.

---

## W-04 - salt generated with Math.random

makeSalt prefers crypto.randomUUID but falls back to Math.random().toString(36)
concatenated with Date.now(). Math.random is not cryptographically secure and
Date.now is guessable to within milliseconds. The fallback engages exactly when
crypto is unavailable - which is also when nothing else in the file can be
trusted.

Note also that this is a salt, not a KDF. sha256 is applied once. A salt passed
through a single SHA-256 does not make derivation slow, and slowness is the
entire point of a KDF.

---

## W-05 - backend injection through a mutable global

window.__SAOS_SECURE_BACKEND__ is read at first use with no authentication, so
any script in the page can become the storage backend for every subsequent key
operation. That is both an exfiltration path and a key-substitution path. The
mechanism is not wrong - it is the intended injection point for a real secure
backend. The absence of any authentication on it is.

---

## W-06 - a committed database in a wallet repository

db/custom.db, 290,816 bytes. Its contents were NOT read. A committed database in
a wallet repository must be inspected for key material, seeds or user records
before anything else, then removed and gitignored. If it was ever pushed, removal
from HEAD does not remove it from history.

---

## Repository hygiene

    total                  62,657,131 bytes   1,360 files
    skills/design          54,190,023 bytes     561 files   (86.5% of the repo)
      largest single file  20,339,759 bytes   a waitlist HTML template
    packages/core             266,416 bytes      25 files   (the actual wallet)
    packages/chains           121,498 bytes      18 files
    db/custom.db              290,816 bytes       1 file

86.5% of the repository is design templates unrelated to a wallet. That makes it
expensive to clone, expensive to audit, and easy to hide a committed database or
a .orig artifact inside.

---

## Actions, in order

| # | action | gate rule |
|---|---|---|
| 1 | Do not put mainnet funds behind this vault. The code itself says so. | - |
| 2 | Recover vault.ts.orig - restore VaultKey with privateKeyRef, then delete the artifact | H-04 |
| 3 | Replace the localStorage fallback with a refusal. No backend must mean the vault cannot start. | H-01 |
| 4 | Implement or remove the two derivation stubs. A throwing stub with a full signature is worse than an absent function. | H-02 |
| 5 | Make the Math.random fallback fatal, and use a real KDF (scrypt or argon2id) rather than one SHA-256 | H-05 |
| 6 | Authenticate backend injection - module scope, not a mutable window global | H-06 |
| 7 | Inspect db/custom.db for secrets, then remove and gitignore | H-07 |
| 8 | Gitignore *.orig, *.rej, *.db, .env | H-03, H-04, H-07 |
| 9 | Move the 54 MB of design templates to a separate asset repo | - |

Actions 2, 3, 4, 6 and 8 are small, local, and need no new dependency. Action 3
is a few lines and converts a critical exposure into a loud startup failure.

---

## What this audit did not do

- did not open db/custom.db
- did not read key-manager.ts (20,297) or backup.ts line by line
- did not run the wallet or its 15,774-byte test file
- did not read the 80 files in src/components/vault/, including
  backup-recovery-dialog.tsx (34,215) and vault-setup-wizard.tsx (30,769)
- did not verify whether real funds are currently held by keys created here

Every claim above is a quotation from, or a measured scan of, a file read directly
from the repository. No file in Saosmartwallet was created, modified or deleted.
