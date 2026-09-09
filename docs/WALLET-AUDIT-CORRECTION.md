<!-- hardening:allow-file ALL reason=correction document quoting the code it supersedes -->

# CORRECTION - the wallet audit was wrong about the current repository

**`docs/WALLET-AUDIT.md` is superseded by this document. Read this first.**

## What happened

`WALLET-AUDIT.md` reported three critical findings about
`Saosmartwallet/packages/core/src/vault/`: a plaintext localStorage fallback, two
throwing derivation stubs, and a committed merge conflict that lost a design.

Those files no longer exist. `packages/core/src/vault/` now contains four files -
`vault.ts` (43,518), `keys.ts` (10,182), `defaults.ts` (3,532), `index.ts` (744) -
and the paths the audit quoted (`secure-storage.ts`, `key-derivation.ts`,
`key-encryption.ts`, `vault.ts.orig`, `key-manager.ts`) all return **404**.

So the audit was accurate for what it read, and the repository has since been
restructured. Both are true. What is not acceptable is leaving the audit standing
as a current assessment, because its headline conclusion - that the wallet has no
real cryptography - is now flatly wrong, and acting on it would mean discarding
working code.

## What is actually there

`Saosmartwallet/packages/core` is a six-layer sovereign key vault. I read the
crypto source directly rather than trusting its README:

### kdf.ts (5,334 bytes) - Argon2id

Memory-hard password KDF. Its own header states the budget: 64 MiB x 3 passes,
roughly one second per derivation, so an offline attacker pays about a
GPU-second per guess. Verifiers store only the hash output, params and salt.
Comparison is constant-time via `timingSafeEqual` with length-safe padding, and
`verifyPassword` **returns false on mismatch instead of throwing** - so a wrong
password cannot be distinguished from a right one by timing or by error type.

Exports: `DEFAULT_KDF_PARAMS`, `randomBytes`, `deriveMasterKey`,
`deriveVerifier`, `verifyPassword`.

### shamir.ts (8,092 bytes) - Shamir Secret Sharing over GF(256)

Pure TypeScript, zero dependencies. A secret of L bytes is split byte-wise: for
each byte position an independent random polynomial of degree threshold-1 over
GF(2^8) with p(0) = the secret byte. Share i records the vector of p_i(x) values.

Its header names the classic pitfall explicitly: fewer than `threshold` shares
reveal nothing, so **a reconstruction from too few shares silently produces a
WRONG secret**. That is the failure mode most implementations get wrong, and this
one documents it.

Exports: `shardSecret`, `reconstructSecret`.

### cipher.ts (17,172 bytes) - AEAD envelope encryption

One payload format, two algorithms: AES-256-GCM via node:crypto, and
ChaCha20-Poly1305 via node:crypto when available with a **pure-TypeScript RFC 8439
fallback** - ChaCha20 block function plus Poly1305 plus the section 2.8 AEAD
construction.

The header explains why the fallback exists: Bun, the project server runtime,
ships a reduced OpenSSL cipher list that does not expose chacha20-poly1305. That
is a real runtime constraint discovered and solved rather than papered over.
`NODE_CHACHA20_SUPPORTED` is probed at module load. Zeroize appears in the file.

Exports: `seal`, `open`, `sealJson`, `openJson`, `sha256`,
`tsChacha20Poly1305Seal`, `tsChacha20Poly1305Open`, `ENVELOPE_VERSION`.

### zk.ts (8,867 bytes) - Fiat-Shamir Schnorr over secp256k1

A genuine non-interactive zero-knowledge proof of password knowledge. The
construction as written in the source:

    enrollment  x = H(password || salt || context) mod n
                X = x * G                       (public commitment)
    prove       r <- random scalar mod n
                A = r * G
                c = H(X || A || context)        (Fiat-Shamir)
                z = r + c * x mod n
    verify      X_stored == proof.commitment
                c' == H(X || A || context)
                z * G == A + c * X

That is textbook-correct Schnorr identification with a Fiat-Shamir transform. The
design rationale is also correct and worth quoting: only the curve commitment is
stored or transmitted, so there is **no hash an attacker could brute-force
offline** - which is exactly the weakness a stored-password-hash scheme has.

Exports: `deriveCommitment`, `generateZKProof`, `verifyZKProof`.

### keys.ts (10,109 bytes) - the only sanctioned path for key material

Its header states the invariant: `VaultKeys` is the ONLY path for key material to
enter or leave the vault state document. Enter via `addKey` (WIF in, sealed
payload out). Leave via `revealKey` (sealed payload in, PrivateKey out, session
key required, used exclusively by the signing orchestrator after policy approval).

> The plaintext WIF exists only inside the sealing/revealing call frame - it is
> never written to state, logs or error messages.

Each key is sealed under its own fresh content key.

## What the package claims about itself, and what that is worth

`packages/core/README.md` declares STATUS: LIVE with six layers - vault hierarchy
(master ed25519 with 3-of-5 guardians, plus 5 network, 13 soldier and 4 purpose
vaults), crypto engine, policy engine (fail closed), signing orchestrator
(reveal-once, capability-checked broadcast), backup and recovery (Shamir-sharded,
social recovery, dead-man switch, air-gapped QR frames), and hash-chained audit
with `firstBadSeq` tamper reporting.

It also states: **"The DEX terminal signs through this package - the M1 SIGNING
LOCKED gate is gone."**

`src/lib/vault-runtime.ts` confirms the wiring: it references `packages/core`
five times and imports the chain adapters from `../../packages/chains`.

**I verified the crypto source. I did NOT verify the README's claims about the
signing orchestrator or the policy engine** - `signing/orchestrator.ts` is 41,819
bytes and `policy/engine.ts` is 20,564 bytes and neither was read. Treat those two
layers as claimed, not confirmed.

## One structural finding that survives the correction

`package.json` declares `"name": "nextjs_tailwind_shadcn_ts"` and **no
`workspaces` field**. `packages/core` and `packages/chains` are consumed by
relative path (`../../packages/chains`), not as declared dependencies.

That is a monorepo-shaped directory that is not a monorepo. Consequences:

- the crypto engine has no version, no publishable artifact, no dependency edge
- nothing forces `packages/core` to build before the app imports it
- a rename or move breaks imports silently at runtime rather than at install
- the six layers cannot be consumed by any other repository, including the ones
  that need them most

This is worth fixing independently of everything else, and it is cheap: declare
workspaces, give each package a name and a version, and import by name.

## Corrected severity table

| # | original finding | corrected status |
|---|---|---|
| W-01 | plaintext localStorage fallback | **SUPERSEDED** - the file no longer exists; `keys.ts` states plaintext exists only in the call frame |
| W-02 | derivation functions are throwing stubs | **SUPERSEDED** - Argon2id, Shamir GF(256), AEAD envelopes and Schnorr ZK are all implemented |
| W-03 | committed merge conflict, lost design | **SUPERSEDED as a current defect.** The `.orig` is gone. The lost `VaultKey`/`privateKeyRef` design appears to have been realised: `keys.ts` seals keys and the state document holds sealed envelopes only |
| W-04 | Math.random salt | **UNVERIFIED** - `kdf.ts` exports `randomBytes`; the old `makeSalt` no longer exists |
| W-05 | global window backend injection | **UNVERIFIED** - `secure-storage.ts` no longer exists; persistence now runs through `storage/types.ts` bound to Prisma |
| W-06 | `db/custom.db` committed | **STILL OPEN** - 290,816 bytes, contents never read |
| NEW | no npm workspaces despite monorepo layout | **OPEN**, low effort, see above |
| NEW | signing orchestrator and policy engine unread | **OPEN** - 62,383 bytes of claimed fail-closed control flow, unverified |

## What this correction means for the earlier recommendation

The earlier advice was: do not put mainnet funds behind this vault. That advice
was based on a placeholder that no longer exists.

The corrected position: **`packages/core` is credible cryptography and the app
imports it, but two of its six layers - signing and policy - have not been read,
and one committed database has not been inspected.** Do not treat it as audited.
Treat it as the most promising unaudited code in the estate, which is a very
different thing from the most dangerous.

Read `signing/orchestrator.ts` and `policy/engine.ts` before trusting a signature
path. Inspect `db/custom.db` before trusting the storage layer. Neither is hard.

---

## The lesson, recorded rather than quietly fixed

This is the second time in this engagement that a confident conclusion was drawn
from a partial read:

1. I claimed the jumpper and roshpina Merkle conventions matched, because a
   docstring said so. Measured, they differ for every leaf count that is not 1, 2
   or a power of two.
2. I concluded the wallet had no real cryptography, because the vault directory I
   read contained placeholders. The real crypto was one directory over, in
   `packages/core/src/crypto/`, and I never listed it.

Both errors have the same shape: **a claim taken from what was in front of me,
without asking whether what was in front of me was the whole thing.** The fix in
both cases was the same - go and look. A security assessment that does not
enumerate the directory it is assessing is not an assessment.

`WALLET-AUDIT.md` is kept, unedited below this correction, because deleting it
would hide the error. Its findings were real when read, they are quoted accurately,
and the record of having been wrong is worth more than a clean history.
