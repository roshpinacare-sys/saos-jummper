<!-- hardening:allow-file ALL reason=quotes the defective reconstruction signature and the public-keyed MAC it reports -->

# Recovery Audit - the path you only use after everything else has failed

Read out of real source, 2026-09-08:

    packages/core/src/backup/backup.ts    26,905 chars / 652 lines
    packages/core/src/vault/vault.ts      43,402 chars / 1,128 lines
    packages/core/src/crypto/shamir.ts     8,092 chars
    packages/core/src/crypto/kdf.ts        5,334 chars
    packages/core/src/encoding.ts          4,195 chars
    packages/bridges/router.ts            16,560 chars / 401 lines

Contract implemented in `src/jumpper/recovery.py`, 24 assertions in
`tests/test_recovery.py`.

Verdict on the recovery package:

    DOES NOT CONFORM - missing: R-05    (7 of 8 properties present)

---

## The defect: threshold reconstruction cannot check the threshold

`packages/core/src/crypto/shamir.ts`, as written:

    export async function reconstructSecret(shares: Share[]): Promise<Uint8Array> {
      if (!Array.isArray(shares) || shares.length === 0) {
        throw new VaultError("SHAMIR_INVALID", "no shares provided");
      }
      // validates each share: index in [1,255], valid base64, non-empty, no duplicate
      const secretLength = Math.max(...parsed.map((p) => p.data.length));
      const secret = new Uint8Array(secretLength);
      for (let bytePos = 0; bytePos < secretLength; bytePos++) {
        const points = parsed.filter((p) => p.data.length > bytePos);
        secret[bytePos] = lagrangeAtZero(points, bytePos);
      }
      return secret;
    }

Verified by inspection of the function body:

| question | answer |
|---|---|
| does the signature take a threshold? | **no** |
| does the body mention threshold at all? | **no** |
| is there any guard on share COUNT? | only `shares.length === 0` |
| does it interpolate whatever it is given? | **yes**, via `lagrangeAtZero` |
| how is the output length chosen? | `Math.max` over the shares supplied |

Consequences:

- **1 share** fits a degree-0 polynomial and returns **that share's bytes as the secret**
- **2 shares of a 3-of-5** fits a line and returns a **wrong secret**, with no error
- the output length is derived from the shares given, so a short reconstruction is
  not even length-checked against the original

And the module's own header names this exact pitfall:

> a reconstruction from too few shares silently produces a WRONG secret

**The docstring states the danger. The function signature makes guarding against it
impossible, because it never receives the threshold.**

`shardSecret` validates its inputs correctly (threshold at least 1, totalShares at
least 1, threshold not greater than totalShares, not greater than 254), so the
split side is sound and the rejoin side is not.

### Why this matters more than it looks

Social recovery is the last resort: the password is gone, the device is gone, and
t of n guardians are producing shares. That is exactly when a wrong-but-plausible
secret is worst, because:

- the reconstruction **succeeds** and returns bytes
- the caller then tries to open the AEAD envelope with those bytes
- the envelope fails, and the failure reads as "the shares are wrong" or "the
  backup is corrupt"
- the real cause - too few shares were supplied - is never reported

The user is told their recovery failed at the exact moment they have no other
option. And a 2-of-3 attempt looks identical to a 3-of-3 attempt from outside.

### The fix

One parameter and one guard:

    export async function reconstructSecret(
      shares: Share[], threshold: number
    ): Promise<Uint8Array> {
      if (!Array.isArray(shares) || shares.length === 0) {
        throw new VaultError("SHAMIR_INVALID", "no shares provided");
      }
      if (shares.length < threshold) {
        throw new VaultError("SHAMIR_INVALID",
          "insufficient shares: " + shares.length + " of " + threshold + " required");
      }
      ...
    }

Every caller already knows the threshold - it is stored with the shares, because
`shardSecret` was given it. So this is plumbing, not design.

---

## The second finding: the outer package MAC is keyed by public data

    packageSignature  = HMAC-SHA256(key = utf8(metadata.checksum), msg = packagePreimage)
    metadata.checksum = sha256(canonicalJson(encryptedState))

Both the key and the message are fields of the package itself. Anyone holding the
backup file can recompute the checksum and then the signature. It detects
**accidental corruption** - a truncated download, a bit flip - but authenticates
nothing against an adversary.

The docstring says the key is sha256 of the canonical INNER JSON. The code hashes
`encryptedState`, the OUTER ciphertext. That wording matters: "inner" implies the
key is unavailable without decrypting, and it is not.

**Severity LOW**, and the reason is specific: the real integrity boundary is the
AEAD envelope, which is correctly keyed. Tampering with `encryptedState` fails
AEAD decryption. What an adversary could alter undetected is limited to `format`,
`version`, `createdAt` and metadata fields - none secret, though a tampered
`version` could in principle steer restore-path selection.

Fix: key the outer HMAC with something the package does not contain, or drop it
and state plainly that AEAD is the only integrity boundary.

---

## What was verified as genuinely correct

Read in source, not taken from docstrings.

**`encoding.ts` - `bytesEqual` is really constant time:**

    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    return diff === 0;

XOR-accumulate over every byte, no early exit. Only length leaks, which is
standard. The timing-safe-compare claim holds.

**Keys:** wrapping and recovery keys are `randomBytes(32)`, zero-filled after use,
never persisted - only Shamir shares leave the process.

**Restore:** fails closed into a **fresh, never-initialized** vault only, after
every integrity check passes.

**The secrets are inside the envelope, not beside it:**

    encryptedState = seal(utf8(canonicalJson(state)), wrappingKey, { keyId: "backup-wrap-v1" })
    payload        = sealJson(state, recoveryKey,      { keyId: "social-recovery-v1" })

The whole state document is sealed, so the **dead-man-switch config and the
beneficiary list are inside authenticated encryption**. The audit record stores
`beneficiaries.length` - a count, not the list.

**`vault.ts`:** Argon2id derivation into volatile memory only, zero-fill on
`lock()`, idle auto-lock timer, optional step-up re-verification before sealing,
`getStatus()` and `getState()` secret-free by construction, genesis hash binding
the state lineage.

**`router.ts` anti-mock contract held on all four clauses:** every fee leg carries
`source` (22 occurrences), unexecutable rails return readiness gated with a
`gateReason` (38), `assertExecutable` exists, and numbers come from live
measurement (35). Its own header: never silently omitted, never faked.

---

## And the fourth time the same lesson caught me

R-05 shipped asking "does threshold reconstruction refuse too-few shares?" and
answered by searching **the whole file** for the word threshold plus a length
comparison. `backup.ts` passes a threshold to `shardSecret`, so the property read
as **satisfied** - while the function that actually reconstructs, in a different
file, cannot check it at all.

The recovery package scored **8/8 CONFORMS** with a real defect inside it.

Fixed by scoping the check to the reconstruction function's brace-matched body.
The package now scores **7/8, DOES NOT CONFORM, missing R-05** - which is correct.

Same shape four times running:

1. assumed two Merkle conventions matched because a docstring said so
2. concluded the wallet had no cryptography because one directory held placeholders
3. recommended editing `buildOp` for H-11 when the relay already prefers posting
   and the real gap was an unset environment variable
4. let R-05 pass because the threshold appeared somewhere in the file

**In every case the error was answering a narrower question than the one asked.**
A property about a function must be checked in that function.

---

## Actions

| # | action | severity | effort |
|---|---|---|---|
| 1 | Add `threshold` to `reconstructSecret` and refuse too-few shares | **HIGH** | one parameter, one guard |
| 2 | Report the shortfall in the error message (N of T required) | HIGH | same change |
| 3 | Add a unit test that 2-of-3 shares throw rather than return bytes | HIGH | one test |
| 4 | Re-key or remove the outer package HMAC | LOW | small |
| 5 | Correct the docstring: inner JSON becomes outer encryptedState | LOW | one line |

Action 3 is the one that would have caught this before it shipped: a test that
hands `reconstructSecret` fewer shares than the threshold and asserts a throw.
Without it the function is correct for every input its author tried.

---

*Read-only throughout. No file outside saos-jummper was created, modified or
deleted. No keys read, no transactions signed, nothing broadcast.*
