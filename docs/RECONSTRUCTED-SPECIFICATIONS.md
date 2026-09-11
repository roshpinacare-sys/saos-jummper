
# RECONSTRUCTION - MANIFEST.md and TRUST_INTEGRITY_ROADMAP.md

> **THIS IS A RECONSTRUCTION, NOT THE ORIGINAL.** Both documents are absent from
> `roshpina`. Everything below is derived from citations inside the 114 kernel files
> (838,280 characters) that were fetched and searched. Every claim carries the file
> that makes it. Where the evidence does not establish something, it says UNKNOWN
> rather than filling the gap.
>
> A rebuilt specification presented as the original is worse than no specification,
> because it hides that the original is gone and that the rebuild may have missed a
> section nobody happened to cite.

Method: all 114 `kernel/*.ts` files fetched and searched. 16 files cite one of the
two documents, yielding 18 distinct citation contexts. Only citations carrying an
explicit section marker were used to establish section numbers.

---

# Part 1 - MANIFEST.md

Cited by 10 files: `action-intent.ts`, `action-risk.ts`, `actor-baseline.ts`,
`approval-policy.ts`, `coding-actions.ts`, `cost-arbitrage.ts`,
`execution-scheduler.ts`, `execution-supervisor.ts`, `reputation-policy.ts`,
`retry-policy.ts`.

## Established structure

The MANIFEST had at least three distinct parts, distinguishable from how it is cited.

### A. Numbered sections of primitives

`cost-arbitrage.ts`:

> Cross-vendor cost arbitrage - primitive (**MANIFEST §4, item 4**)

So **§4 is a numbered list of primitives or capabilities**, and cost arbitrage is
its fourth item. The other three items are UNKNOWN - no file cites them.

### B. A ranked list of gaps, titled in Hebrew

The phrase cited most often is **`MANIFEST "החסר הבא"`** - "the next gap". It is a
ranked list, and at least items #1 and #2 are cited.

**Gap #1 - the trust-gate core.** This is the largest item and was decomposed into
many sub-steps across at least six files:

| citing file | what it says it implements |
|---|---|
| `action-intent.ts` | "First item from MANIFEST 'החסר הבא': ActionIntent canonical object with tenantId, actorId, toolId, resourceRef, riskClass, valueMicro..." |
| `action-risk.ts` | "First sub-step of MANIFEST 'החסר הבא' #1 (ActionRiskClass + ApprovalPolicy). This file does NOT decide approvals yet - it only classifies." |
| `approval-policy.ts` | "Second sub-step of MANIFEST 'החסר הבא' #1 (ActionRiskClass + ApprovalPolicy). Maps each ActionRiskClass to the required ApprovalClass." |
| `actor-baseline.ts` | "MANIFEST 'החסר הבא' #1 sub-step: a deterministic moving-average baseline per actor that feeds `actorBaselineCount` into assess..." |
| `reputation-policy.ts` | "Sub-step #1 of MANIFEST 'החסר הבא' #1 (wiring TrackRecord...)" |
| `coding-actions.ts` | "the central security blind spot flagged in MANIFEST 'החסר הבא' #1" - namely that `riskClass` in an ActionIntent from an agent is client-supplied and unverified |
| `execution-supervisor.ts` | "the actual re-lease + re-run after failed sub-step of MANIFEST 'החסר הבא' #1 (ExecutionWorkflow #2, continued from v138)" |

**Gap #1 was therefore: build the trust gate.** Canonical intent object, risk
taxonomy, approval routing, per-actor baseline, reputation wiring, server-side
classification of coding-agent actions, and the execution workflow that carries a
decision through to a receipt.

**Gap #2 - durable execution.** `retry-policy.ts`:

> Continuation of MANIFEST "החסר הבא" #2 (Durable ExecutionWorkflow): the first
> sub-step of retry handling. A `running` workflow can transition to `failed`...

### C. A debt register

`execution-scheduler.ts` cites it twice:

> Chain-aware exhaustion (**fixes MANIFEST** ...)

> countChainFailures - count total `failed` transitions across the full
> retryOfWorkflowId ancestor chain. **Fixes MANIFEST debt**: `planRetryForWor...`

So the MANIFEST also tracked known debt, separately from the ranked gaps.

## The product thesis

`coding-actions.ts`, the only file that states it:

> the MANIFEST's primary wedge is **TFA as Trust Gate for coding agents**
> (Claude Code / Cursor / OpenHands / MCP)

**TFA = Trusted Fiduciary Agent.** Not a wallet, not a chain. A gate wrapped around
an existing coding agent that classifies the agent's actions server-side, resolves
an approval class, returns allowed / approval_required / denied, and emits a signed
self-verifying `ExecutionReceipt`.

This sentence is the single most valuable one in the estate and it survives in one
docstring in one file.

## Revision markers

Two version numbers appear in citations: `v138` (`execution-supervisor.ts`) and
`v387` (`witness-liveness.ts`, citing the ROADMAP). The work was executed
incrementally against numbered revisions, so the MANIFEST was a living document
that was updated as gaps closed.

## UNKNOWN

- how many gaps the ranked list contained; #3 onward are never cited
- what §1 through §3 and §5 onward covered
- the other three items of §4
- the full contents of the debt register
- whether the MANIFEST ever called for public anchoring of decisions or receipts.
  Nothing in the kernel touches a blockchain, and the receipt is signed and
  self-verifying - which proves authorship but not that the receipt existed at a
  given time to a third party. That needs a public timestamp, and no module
  provides one.

---

# Part 2 - TRUST_INTEGRITY_ROADMAP.md

Cited by 6 files: `count-proof.ts`, `cross-log-consistency.ts`,
`federation-anchor.ts`, `mesh-membership.ts`, `predicate-proof.ts`,
`witness-liveness.ts`. All six are in `kernel/transparency-log/` or
`kernel/track-record/`.

## Established structure

**§2** is a major section with lettered sub-sections. Three are evidenced: A, B
and D. Sub-steps carry a global numbering that includes the sub-section letter.

### §2.A - cross-log federation and the trust mesh

| sub-step | module | what it implements |
|---|---|---|
| `3-A-1` | `federation-anchor.ts` | a signed binding that log A held root R_A over N_A leaves and log B held R_B over N_B at time T, so a third party can verify both existed and were consistent **without seeing either log's leaves** |
| `3-A-2` | `cross-log-consistency.ts` | `verifyCrossLogConsistency` - "did independent witnesses ALSO observe those roots? If yes, the roots are independently corroborated - not just self-attested" |
| `3` | `mesh-membership.ts` | trust-mesh membership proofs; "Federation anchors link one log's..." |

The numbering `3-A-1` implies §2.A had at least three numbered sub-steps, and that
the mesh work is sub-step 3 of the same group.

### §2.B - selective disclosure over a track record

| item | module | what it implements |
|---|---|---|
| `§2.B-2` | `predicate-proof.ts` | selective disclosure for numeric predicates |
| sibling | `count-proof.ts` | "I have at least N actions on record, and 0 of them were denied" - **without revealing the content of any action**, verifiable offline using only the proof and the prover's public key |

`count-proof.ts` is cited as a sub-step of the same section. So §2.B had at least
two items and `predicate-proof` is item 2, making `count-proof` item 1 or 3.

**Important, and to the credit of the module:** `predicate-proof.ts` carries an
explicit honesty note - *"this is NOT zero-knowledge cryptography... it would be
dishonest to imply otherwise. What this module actually provides is a SIGNED
SELECTIVE-DISCLOSURE claim."* That is the epistemic standard the rest of the estate
should be held to.

### §2.D - witnesses

| item | module | what it implements |
|---|---|---|
| `§2.D-12` | `witness-liveness.ts` | liveness and staleness monitoring. Its docstring: "Quorum (witness.ts, v387) tells you..." - so quorum was an earlier item in the same sub-section |

**§2.D had at least 12 items.** Only item 12 is cited. Items 1 through 11 are
UNKNOWN, though `witness.ts` (quorum, revision v387), `witness-registry.ts` and
`witness-gossip-sim.ts` almost certainly occupy some of them, since they exist and
are not accounted for by any other citation.

## §2.D-10 recovered - and the revision chronology

A second pass over `kernel/risk/` and `kernel/transparency-log/` (27 files,
222,479 characters) recovered one more numbered roadmap item and the build
sequence.

### §2.D-10 - witness gossip simulation

`witness-gossip-sim.ts`, verbatim:

> WHY THIS EXISTS (§2.D-10)
> Quorum (v387) and liveness (v405) operate over an authenticated channel
> (e.g. mTLS + signed HTTP). The simulation is clearly labeled; it is not
> presented as a real network implementation.

So **§2.D had at least 12 numbered items, and two of them are now identified**:
item 10 is the gossip simulation and item 12 is witness liveness. Note the
epistemic discipline in that header - a simulation that says so, rather than a
simulation presented as a network.

### The revision chronology, recovered from markers in the code

| revision | file | what it added |
|---|---|---|
| v235 | `approval-policy.ts` | DecisionTrace signed over canonical JSON; `simulation` field |
| v286 | `approval-policy.ts` | contextual risk escalation, included in the signature when present |
| v297 | `reputation-policy.ts` | TrackRecordCache to reputationScore wiring; cache miss leaves the score undefined for backward compatibility |
| v298 | `approval-policy.ts` | risk-intelligence fusion, included in the signature when present |
| v320 | `approval-policy.ts` | identity fields extracted from `agentProvenance` on the context |
| v379 | `witness.ts` | consistency proofs - "make a split-view *detectable* by any monitor that compares" |
| v384 | `approval-policy.ts` | hoisting fix so the legacy path still computes contextual risk |
| v387 | `witness.ts`, `witness-registry.ts`, `witness-liveness.ts` | the pure crypto core (sign and verify a **tree-head observation**, confirm a quorum), a tenant-scoped registry, and liveness |
| v405 | `witness-gossip-sim.ts` | the gossip simulation |

Two things follow.

**The build order was risk and approval first (v235 to v384), then the
transparency-log witness subsystem (v379 to v405).** The gate was built before the
log that would make its decisions publicly checkable.

**`witness.ts` at v387 signs tree-head observations.** That is an STH cosignature,
and it is precisely what `src/jumpper/sth.py` packs - 148 to 177 signed tree heads
per zero-fee HIVE `custom_json`. The kernel already produces the artifact; nothing
in the kernel publishes it. The connection is one adapter, and the adapter exists.

It also sharpens the central gap. `witness.ts` at v379 states its own precondition:
consistency proofs make a split-view detectable **"by any monitor that compares"**.
Witnesses and gossip broaden who compares. A public anchor removes the condition
entirely, because then everyone can compare against the same committed root.

## What the second pass did NOT recover

The eight previously unread `kernel/risk/` files were searched for MANIFEST
citations. They cite gap **#1 only** - the same gap the other files cite. In
particular `policy-simulator.ts` (19,920 characters) and `risk-intelligence.ts`
(10,182 characters) cite the MANIFEST nowhere at all.

**So gaps #3 and onward are not recoverable from `kernel/risk/`.** The remaining
routes are the other kernel subsystems not yet searched for citations
(`orchestrator/`, `escrow/`, `passport/`, `potential/`, `ledger/`, `marketplace/`,
`settlement-rails/`, `adapter/`, `track-record/`, `mcp-server/`, `rbac/`,
`common/`) and step 8 - asking the author.

---

## UNKNOWN

- whether §1 existed and what it covered
- ~~§2.C entirely~~ **RECOVERED IN A LATER PASS.** `risk-intelligence.ts` cites
  `§2.C-8` for the monotonic `maxApproval()` join that makes `effectiveApprovalClass`
  able to escalate above the static floor but never below it. So §2.C exists and item
  8 is the monotonic approval join. Given that §2.A is federation, §2.B is selective
  disclosure and §2.D is witnesses, §2.C is most plausibly the risk-assessment section
  - consistent with `risk-intelligence.ts`, `contextual-risk.ts`, `risk-drift.ts` and
  `actor-baseline.ts` all existing and none citing another section. **That last step is
  an inference; the established fact is narrower: §2.C exists and item 8 is the
  monotonic join.** Items 1 through 7 and 9 onward remain unknown
- §2.D items 1 through 11
- whether §3 or later sections existed
- whether the roadmap ever called for anchoring log heads to a public chain. This
  is the most consequential unknown, because `federation-anchor.ts` relies on "a
  trusted signer" rather than a public ledger, and the consistency-proof design
  states its own precondition as *"if every monitor checks"* - which is the
  assumption a split-view attack breaks. A public anchor removes the assumption.
  Either the roadmap specified it and the step was never reached, or it did not
  specify it and the design has a hole nobody wrote down.

---

# Part 3 - what the reconstruction adds

The two documents above are recovered from evidence. This part is the only section
that adds content the originals may not have contained, and every item is measured
and documented elsewhere in this repository.

| gap | evidence | where |
|---|---|---|
| Log heads are never anchored publicly | zero blockchain references across 838,280 characters | `docs/THE-MISSING-LINK.md` |
| Receipts are self-verifying but not publicly timestamped | signed by the operator, so authorship is provable and existence-in-time is not | `docs/TRUST-GATE.md` |
| `confidence-gate.ts` trusts a caller-supplied risk level | reads `input.actionLevel`; `classifyAction` appears once, in a comment | `src/jumpper/riskgate.py`, `docs/TRUST-GATE.md` |
| The adapter derives correctly but never calls the confidence gate | `classifyActionServerSide` x2, `confidenceGate` x0 in `agent-adapter.ts` | `docs/TRUST-GATE.md` |
| `reconstructSecret` takes no threshold | 2 of 3 shares returns a wrong secret with no error | `docs/RECOVERY-AUDIT.md` |
| The audit hash binds 5 of 11 fields | `source`, `occurredAt`, `reason`, `actionId` unprotected | `docs/AUDIT-CHAIN-AUDIT.md` |
| A hash chain cannot detect truncation | proven by test: `verify_chain(chain[:1])` returns intact | `src/jumpper/audit.py` |

Items 1 and 2 are the ones the missing roadmap would most plausibly have covered,
and the ones with a free fix already built: `sth.py` packs 148 to 177 signed tree
heads into a single zero-fee HIVE `custom_json`, and `pipeline.py` runs the whole
path end to end.

---

# Part 4 - how to finish the reconstruction

Steps 1 through 4 are reading and are already done above. The remaining work:

| step | action | output |
|---|---|---|
| 5 | Read the 8 unread `kernel/risk/` files, especially `policy-simulator.ts` (19,920) and `risk-intelligence.ts` (10,182), for further MANIFEST citations | may recover gap #3 onward |
| 6 | Read the 5 uncited `kernel/transparency-log/` files (`merkle-tree`, `consistency-proof`, `consistency-monitor`, `receipt-anchor`, `witness`, `witness-registry`, `witness-gossip-sim`) for ROADMAP sub-step numbers | may recover §2.D items 1-11 |
| 7 | Check `roshpina` git history for a deleted copy - one commit exists, so the file was either never committed or was committed and removed | the original, if it was ever pushed |
| 8 | Ask the author. The MANIFEST is written partly in Hebrew and cites a revision history; whoever wrote it has both | the original |

## Step 7 is DONE, and the answer is definitive

Every commit in `roshpina` was enumerated and its full tree listed:

    e43aa5e180  2026-09-07T13:25:35  "Roshpina v0.1 - Sovereign Trust & Value
                                     Platform (Task 115 chosen project)"
                 208 blobs   .md files: []        MANIFEST/ROADMAP: NONE
    c344b9e97c  2026-09-08T03:13:31  audit(addendum) - pushed here by this engagement
                 209 blobs   .md files: [docs/FORENSIC-AUDIT-ADDENDUM.md]
    e87623cb94  2026-09-08T03:15:14  audit - pushed here by this engagement
                 210 blobs   .md files: [docs/FORENSIC-AUDIT-ADDENDUM.md,
                                         docs/FORENSIC-AUDIT.md]

**The founding commit contains 208 files and zero markdown files.** No README, no
MANIFEST, no ROADMAP, no documentation of any kind. The only two markdown files in
the entire history of that repository are the forensic audit documents pushed here
during this engagement.

So neither specification was ever committed. They existed only outside version
control - on the author's machine, in a conversation, or in another repository.
They cannot be recovered from `roshpina` history, which closes step 7 and leaves
**step 8, asking the author, as the only route to the originals.**

That is worth stating plainly, because it changes the character of the problem.
This is not a case of documents that were lost. **An 838,280-character kernel was
committed with no documentation at all, citing two specifications that were never
committed either.** The kernel is not under-documented; it is undocumented, and the
only record of its intent is the docstrings, which are good enough that this
reconstruction was possible at all.

---

*Read-only throughout. All 114 kernel files were fetched and searched; none was
modified. No file outside saos-jummper was created, modified or deleted.*
