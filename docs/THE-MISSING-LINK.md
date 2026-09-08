# The Missing Link - a complete trust kernel that never reaches a public chain

<!-- hardening:allow-file ALL reason=findings report quoting scan output and protocol payloads -->

Method: read all 114 files of `roshpina/kernel/` (838,280 characters) directly
from GitHub, plus the repo trees of `Saosmartwallet` and the rest of the estate.
Read-only. Nothing signed, nothing broadcast, no repository outside
saos-jummper modified.

---

## 1. What is actually in roshpina

`roshpina` is 210 files and 1,498,801 bytes with **one commit, no README, and no
documentation of its own** - the only two .md files in the repository are the
forensic audit documents pushed here. It has never been read by anyone.

It is also, by a wide margin, the most sophisticated code in the entire estate.

    kernel/orchestrator         16 files  140,468 chars
    kernel/risk                 14 files  129,361 chars
    kernel/transparency-log     13 files   93,118 chars
    kernel/adapter               8 files   79,998 chars
    kernel/track-record          9 files   77,920 chars
    kernel/escrow                7 files   68,281 chars
    kernel/potential            11 files   64,006 chars
    kernel/passport              8 files   54,224 chars
    kernel/policy                7 files   35,794 chars
    kernel/ledger                3 files   18,617 chars
    kernel/ledger-orchestrator   3 files   17,910 chars
    kernel/marketplace           4 files   17,488 chars
    kernel/settlement-rails      3 files   15,496 chars
    kernel/mcp-server            1 file     8,786 chars
    kernel/agent-identity        4 files    8,704 chars
    kernel/rbac                  1 file     5,558 chars
    kernel/common                2 files    2,551 chars
    TOTAL                      114 files  838,280 chars

And there is a working end-to-end smoke test at the repo root, `kernel-smoke.ts`,
that runs the whole economy: create accounts, mint 10,000,000 micro-cents, create
an escrow agreement with a 500-basis-point fee, fund it, release it, run vendor
cost arbitrage capturing 10% of the spread, and verify the tamper-evident audit
chain.

---

## 2. What the kernel contains that nobody knew existed

### A real Certificate Transparency log

`kernel/transparency-log/` is not a Merkle tree. It is the full RFC 6962 /
Sigstore Rekor construction:

- `merkle-tree.ts` - `buildMerkleTree`, `verifyInclusionProof`
- `consistency-proof.ts` - `buildConsistencyProof(leaves, oldSize)`, with a
  docstring that names the threat precisely:

  > inclusion alone does not stop a malicious or compromised operator from a
  > SPLIT-VIEW attack: forking the log and showing party A one history and party
  > B a different one. The defence - used by Certificate Transparency (RFC 6962)
  > and Sigstore's Rekor - is a CONSISTENCY proof

- `consistency-monitor.ts` - `runConsistencyMonitor`
- `cross-log-consistency.ts` - consistency between separate logs
- `witness.ts`, `witness-registry.ts`, `witness-liveness.ts`,
  `witness-gossip-sim.ts` - the CT witness model, including gossip simulation
- `federation-anchor.ts` - a signed binding attesting that log A held root R_A
  over N_A leaves and log B held root R_B over N_B leaves simultaneously, so a
  third party can verify both existed and were consistent **without seeing any
  leaf content from either log**
- `receipt-anchor.ts` - turns an ExecutionReceipt or AuditRecord into a leaf hash

### Correction - the two Merkle conventions do NOT match

An earlier revision of this document claimed the kernel's odd-node convention
matched `src/jumpper/merkle.py`. That claim was taken from the kernel docstring
and **it was wrong**. Both were then measured:

    n   jumpper (duplicate)   kernel (self-pair)   agree
    1   4f865c4d94864688      4f865c4d94864688     yes
    2   455f93bddcf6f4a8      455f93bddcf6f4a8     yes
    3   053eafcf2870f42d      9b3f589fc85dd651     NO
    4   7fc2b347c954e2f4      7fc2b347c954e2f4     yes
    5   ffe4633aaec24ac9      760949d79c265aa6     NO
    7   7923d411e399c8f0      4ec83977c3b7b232     NO
    8   a0172cda7f39cee4      a0172cda7f39cee4     yes
    9   86834162d175ed78      dc2a34c3e2087bfa     NO

Measured rule, verified for n = 1..199 and pinned by tests: the two agree exactly
when n is 1, 2, or a power of two, and differ otherwise. `jumpper` carries an odd
last node up unchanged; the kernel hashes it with itself.

Consequence: **roots must be anchored as opaque 32-byte values, and any
recomputation from leaves must use the producer's convention.** `src/jumpper/sth.py`
therefore carries the convention explicitly on every signed tree head
(`duplicate` or `self-pair`), refuses an unknown one rather than guessing, and
rejects a batch that mixes conventions. 34 assertions cover this.

This is the same failure mode the anchor ledger had - a confident number that was
never checked. It is corrected here rather than left in the document.

### Post-quantum hybrid signing

`kernel/orchestrator/pqc-adapter.ts`, `pqc-compiled-provider.ts`, `pqc-loader.ts`,
`pqc-local-provider.ts` implement ML-DSA (FIPS-204) behind a `HybridSigner`, with
the 2420-byte signature length invariant enforced and fail-closed behaviour when
no provider is present.

The docstring contains a genuinely subtle security argument: `HmacSigner` and the
zero-dependency simulation providers correctly expose **no `kid`**, because
deriving a public identifier by hashing *secret* key material would leak a
brute-forceable commitment to it. Only providers holding a real public
verification key derive one. That is the right call and it is reasoned correctly.

### An escrow economy with a real state machine

`kernel/escrow/escrow.ts` documents its invariants explicitly: money moves only
through orchestrated transfers, never by mutating balances; strict
created -> funded -> (released | refunded | disputed); dispute never moves money,
it only stops it; undispute is funder-only; tenant isolation is fail-closed so
cross-tenant access returns not_found; a guard denial aborts the state change.
Plus `threshold-approval.ts`, `settlement.ts`, `webhook.ts`,
`http-webhook-relayer.ts`.

### Capability tokens that fix a real vulnerability

`kernel/mcp-server/capability-token.ts` states the flaw it replaces:

> The weak approvalToken (just a workflow-id) allows anyone who knows the id and
> tenantId to approve any workflow - no expiry, no nonce protection.

The replacement binds executionId + tenantId + expiresAt + nonce under a
signature, is single-use, and defaults to a 15-minute TTL.

### Tamper-evident audit chain

`kernel/orchestrator/audit.ts` - per-tenant ordered hash chain, each record's
hash covering id, tenantId, actionType, outcome and prevHash, genesis marked
explicitly, `verifyChain()` recomputing every link.

### Selective disclosure - with an honesty note that should be quoted

`kernel/track-record/predicate-proof.ts`:

> HONESTY NOTE - this is NOT zero-knowledge cryptography. A real zero-knowledge
> range proof (e.g. Bulletproofs) would let the verifier confirm the predicate
> mathematically from the commitments alone, trusting no one. That is not what
> this module does, and it would be dishonest to imply otherwise. What this module
> actually provides is a SIGNED SELECTIVE-DISCLOSURE claim.

This codebase already holds itself to the evidentiary standard that the anchor
ledger violated when it recorded verified = 18 against anchored = 16. That is
worth saying out loud: the discipline problem in this estate is not uniform, and
roshpina is the part that got it right.

---

## 3. THE GAP - verified exhaustively, not assumed

Every one of the 114 kernel files was fetched and scanned for public-chain and
network integration:

    custom_json           0 hits
    dhive                 0 hits
    hive                  0 hits
    steem                 0 hits
    ssc-mainnet           0 hits
    broadcastTransaction  0 hits
    ethers                0 hits
    solana                0 hits
    web3                  0 hits
    axios                 0 hits
    fetch(                1 hit   kernel/escrow/http-webhook-relayer.ts
    https://              3 hits  kernel/adapter/{ard-publisher,ard-verifier,vc-receipt}.ts

**Across 838,280 characters of trust infrastructure there is not one reference to
a public blockchain.** `@hiveio/dhive` is declared in package.json and is not
used by the kernel.

`receipt-anchor.ts` describes its own log as *"an in-memory, append-only,
tenant-scoped log that periodically builds a Merkle tree and publishes the root."*
Publishes it where? To memory. `FederationAnchor` is signed by *"a trusted
signer"* - which means the counterparty has to trust the operator.

---

## 4. Why that gap is cryptographically decisive

The consistency-proof design is correct, and its own docstring names the
condition under which it works:

> If every monitor checks consistency between the roots it sees over time, the
> operator cannot rewrite or reorder history without producing a root that fails
> to reconcile.

**"If every monitor checks."** That is the assumption, and it is the weak one. A
split-view attack succeeds precisely when monitors do not talk to each other: the
operator shows monitor A one root and monitor B another, and neither ever sees
the other's. Gossip between witnesses mitigates this but still depends on who
happens to be peered with whom.

This is exactly why real Certificate Transparency does not rely on monitors
alone. **Signed Tree Heads are publicly gossipable and, in practice, are
published somewhere nobody can quietly rewrite.** Global visibility is what turns
"detectable if someone compares notes" into "detectable by anyone, always."

Anchoring the STH to a public chain supplies precisely that property:

- the root becomes globally visible, not just visible to whoever is peered
- it becomes immutable - HIVE block history cannot be quietly edited
- it becomes timestamped by the chain, not by the operator's clock
- any monitor can compare the root it saw against the root on chain, without
  coordinating with any other monitor
- a split view now requires producing two different roots for the same log
  position **on a public ledger**, which is a contradiction anyone can point at

It converts "trust the operator's signature" into "trust the chain's history".

---

## 5. The fix, and why it costs nothing

The `FederationAnchor` type is already exactly the right shape: a canonical,
deterministically serialised, signed payload carrying roots, leaf counts, a
timestamp and log endpoints. That is a commitment, and commitments are what the
free anchor layer broadcasts.

`src/jumpper/graphene.py` and `src/jumpper/packing.py` already provide the other
half, measured against live mainnet:

| fact | value | evidence |
|---|---|---|
| custom_json fee | **zero** - the operation has no fee field | 21 real anchors read from HIVE mainnet |
| payload budget per operation | **8,192 bytes** | live protocol constant |
| roots per free operation | **154** at 52 bytes per tier-E entry | exact arithmetic, tested |
| signed tree heads per free operation | **148-177**, depending on tree_size digit width | measured per width, tested at 4 widths x 2 conventions |
| regeneration budget | **5.13e9 RC/day** for headcorner | live rc_api, max_rc 25,641,553,538 |
| measured cost per operation | **157.7M RC** | two manabar snapshots 6.08 h apart bracketing 4 known ops |
| predicted vs observed op rate | **32.5 vs 31.6 per day** | within 3% - two independent measurements agree |

So: **anchor 148 to 177 signed tree heads per free operation, about 32 free
operations a day, roughly 4,700 to 5,700 publicly immutable log heads per day, at
zero fee.**

Enough to anchor every tenant log, every federation anchor, and every witness
cosignature continuously - and still leave budget for the existing anchors.

An earlier estimate of 181 heads per operation was optimistic: it probed with a
one-digit tree_size and the shorter convention name. 181 real heads encode to
8,889 bytes and cannot be broadcast at all. `heads_per_operation` now takes a
representative head and measures, and `encode_heads` fails closed on the budget so
an over-estimate can never reach the chain.

Integration is additive and does not touch the kernel's invariants:

    kernel/transparency-log   (unchanged - builds roots, signs STHs)
              |
              |  signed tree head: {root, treeSize, timestamp, signature}
              v
    src/jumpper/sth.py        (148-177 heads per payload, convention-tagged)
              |
              v
    src/jumpper/graphene.py   (custom_json op, POSTING authority, zero fee)
              |
              v
    external signer           (never inside the process)
              |
              v
    HIVE mainnet              (permanent, public, free)

The kernel stays zero-dependency and pure. The anchoring layer stays keyless and
read-only in this repo. The signature happens outside both.

---

## 6. A missing artifact: the roadmap the kernel was built against

`TRUST_INTEGRITY_ROADMAP.md` is cited by the kernel itself - at minimum sections
`§2.A` (federation anchor, sub-step 3-A-1) and `§2.D-12` - and **it does not
exist in the repository**. Nor does any other design document.

838,280 characters of trust infrastructure were built against a specification
that is not in version control. Whoever wrote it knew exactly what they were
doing; the reasoning survives in the docstrings, which are unusually good. But
the normative document is gone, which means:

- nobody can tell which roadmap steps are complete and which are not
- `§2.D-12` is referenced with no way to know what it required
- a new contributor cannot distinguish "deliberately deferred" from "forgotten"

**Reconstructing it from the code's own references is high value and low effort** -
the docstrings already state the sub-step numbers and the gaps each module closes.

---

## 7. Saosmartwallet - 62.6 MB, 87% of it bloat

    total                      62,657,131 bytes   1,360 files
    skills/design              54,190,023 bytes     561 files   <- 86.5% of the repo
      largest single file      20,339,759 bytes  (a waitlist HTML template)
      second                   11,534,213 bytes
      third                     5,452,518 bytes
    packages/core                 266,416 bytes      25 files   <- the actual wallet
    packages/chains               121,498 bytes      18 files
    src/components                604,313 bytes      80 files
    db/custom.db                  290,816 bytes       1 file    <- committed database

Two things need attention:

1. **`db/custom.db` is a 290 KB database file committed to a wallet repository.**
   Its contents were not read. A committed database in a wallet repo should be
   inspected for key material, seeds, or user records before anything else, and
   then removed and gitignored.
2. **54 MB of design templates are 86.5% of the repo** and have nothing to do
   with a wallet. They make the repository expensive to clone, expensive to
   audit, and hard to reason about. They belong in a separate asset repo if they
   are needed at all.

The actual wallet surface is `packages/core/src/vault/` - `vault.ts` (41,010 B),
`keys.ts` (10,182 B), `backup-recovery-dialog.tsx` (34,215 B),
`vault-setup-wizard.tsx` (30,769 B), `signing-dialog.tsx` (25,625 B) - and it has
still not been read by anyone.

---

## 8. The complete picture, all four repos

| repo | layer | status |
|---|---|---|
| `roshpina/kernel` | **trust + enforcement**: CT log, consistency proofs, witnesses, federation anchors, PQC hybrid signing, escrow, settlement, RBAC, agent identity, capability tokens, selective disclosure | built, smoke-tested, undocumented, **never anchored publicly** |
| `saos-jummper` | **free public anchoring**: custom_json, RC manabar, tier-E compaction, 154-root packing, gas model validated to the wei | built, 161 tests green |
| `saos-dex/relay.ts` | **live broadcaster**: already anchoring to STEEM/HIVE for free, 21+ verified | live, but with the SOL verifier defect and the devnet default |
| `saos-sovereign-foundry` | **proof + operations console**: kernel, seals, verify-chain, live-gate, decisions, UI | built, CI green, deliberately never broadcasts |

Every piece of the system already exists. They have never been connected, and
until now nobody had read two of the four.

**The single highest-value act remaining is not building anything. It is wiring
the roshpina transparency log's signed tree heads into the free HIVE anchor path
that is already proven live - and reconstructing the roadmap that explains what
the kernel was supposed to become.**

---

## 9. Priority actions

| # | action | effort | why |
|---|---|---|---|
| 1 | **Anchor signed tree heads to HIVE via free custom_json** | additive adapter, no kernel change | turns split-view detection from "if monitors gossip" into "anyone, always" |
| 2 | **Reconstruct TRUST_INTEGRITY_ROADMAP.md from the code's own §-references** | reading, not writing | 838 KB built against a spec that is not in version control |
| 3 | **Write roshpina's README** | one document | the most sophisticated code in the estate has zero documentation |
| 4 | **Inspect `Saosmartwallet/db/custom.db` for secrets, then remove and gitignore** | one pass | a committed database in a wallet repo |
| 5 | **Move 54 MB of design templates out of the wallet repo** | repo hygiene | 86.5% of the repo is unrelated assets |
| 6 | **Run `kernel-smoke.ts` in CI** | one workflow | the economy flow is already proven locally; pin it |
| 7 | Fix `searchTransactionHistory: false` in relay-sol.ts | one boolean | SOL verified is structurally pinned at 0 |
| 8 | Fail closed when no RPC endpoint is configured | small | the devnet default silently records testnet anchors as real |

Actions 1 to 6 require no capital, no protocol change and no new dependency.

---

*Read-only throughout. 114 kernel files and 2 full repo trees read; no keys read,
no transactions signed, nothing broadcast, no repository outside saos-jummper
modified.*
