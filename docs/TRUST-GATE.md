
# Trust Gate - two correct halves that are not connected

Read out of `roshpina/kernel/risk/coding-actions.ts` (22,067 chars, 427 lines) and
`roshpina/kernel/adapter/agent-adapter.ts` (22,293 chars, 508 lines), plus the
earlier reading of `kernel/risk/confidence-gate.ts` (10,765 chars, 293 lines).

This refines the finding recorded in `src/jumpper/riskgate.py`. The earlier
statement was that the confidence gate trusts a caller-supplied risk level. That is
true of the gate. It is not true of the adapter. The two are simply not wired to
each other.

---

## The product thesis, recovered from a document that does not exist

`coding-actions.ts` states it twice:

> the MANIFEST's primary wedge is **TFA as Trust Gate for coding agents**
> (Claude Code / Cursor / OpenHands / MCP)

and

> Without server-side classification of THESE action types, `riskClass` in an
> `ActionIntent` from an agent is client-supplied and unverified - the central
> security blind spot flagged in MANIFEST "the next gap" #1

So **TFA is a Trusted Fiduciary Agent**: a gate you wrap around an existing coding
agent, which decides allowed / approval_required / denied and emits a signed,
self-verifying receipt.

**`MANIFEST.md` returns 404 at the repo root, at `kernel/`, at `docs/`, and bare.**
That is the second normative document the kernel was built against which is not in
version control - the first is `TRUST_INTEGRITY_ROADMAP.md`, cited by the
transparency log at sections 2.A and 2.D-12.

838,280 characters of trust infrastructure, built against two specifications that
cannot be read. The reasoning survives in the docstrings, which are unusually good,
but nobody can now tell which ranked gap was #2, or what section 2.D-12 required.

---

## What is verified correct

### `coding-actions.ts` - server-side classification, fail-closed

Coding agents name actions in their own vocabulary (`delete_file`, `shell_exec`,
`git_push`, `db_migration`, `edit_env`). This module classifies those server-side:

- `CODING_ACTION_TYPES` - the canonical vocabulary, as DATA
- `CODING_ACTION_RISK_MAP` - every action type to a risk class
- `classifyCodingAction(actionType)` - **an unmapped or unknown type returns
  MOST_RESTRICTIVE_RISK_CLASS ("irreversible"), never silently safe**
- `isCodingAction(actionType)`
- `CODING_ACTION_METADATA` - description and danger rationale per type
- `classifyActionServerSide(actionType)`

Its stated invariant: *"Taxonomy is DATA (plain objects/constants), not code paths.
Changing the risk of an action type requires only a map change - no control-flow
rewrites."* That is the right shape for a policy that has to be reviewed.

### `agent-adapter.ts` - derives, overrides, and fails closed

It imports `classifyActionServerSide` and uses it. Its own invariants:

> fail-closed: an invalid intent throws (validateActionIntent); an undefined or
> unmapped risk class resolves to "deny", giving decision "denied".
> money is BigInt micro-cents, serialized as a decimal string in the receipt.
> the receipt signature is deterministic and self-verifying via signer.verify.

Flow: `ActionIntent -> resolveApprovalClass(riskClass) -> decision + signed
DecisionTrace -> signed ExecutionReceipt`. Zero external dependencies.

**This is exactly the escalation-only rule `riskgate.py` implements**, arrived at
independently. The adapter derives the class server-side and overrides the client's
claim.

---

## The gap, stated precisely

| mechanism | derives the level? | thresholds on confidence? | called by the adapter? |
|---|---|---|---|
| `agent-adapter.ts` | **yes**, via `classifyActionServerSide` | no | - |
| `confidence-gate.ts` | **no**, reads `input.actionLevel` | **yes**, six thresholds | **no** |

Verified by reference count in `agent-adapter.ts`:

    classifyActionServerSide   x2      <- derivation is wired
    riskClass                  x16
    override                   x3
    client-supplied            x2
    confidenceGate             x0      <- the gate is never called
    ConfidenceGate             x0
    evaluate(                  x0
    GuardEvaluator             x0
    guard                      x0

So the adapter derives correctly but applies no confidence threshold, and the
confidence gate thresholds correctly but derives nothing. **Neither is wrong. They
are not connected.**

The consequence is conditional, and worth stating conditionally rather than
dramatically:

- On the **adapter path**, a client-supplied `riskClass` is overridden by the
  server-derived class. Safe.
- On **any path that calls `confidence-gate.evaluate` directly** with an
  agent-supplied `actionLevel`, the threshold drops from 0.95 to 0.85 for the same
  action and a self-reported 0.9 auto-approves. That path does not exist in the
  adapter today. It is one import away, and the gate is a reusable component with
  no guard against it.

The fix is composition, not repair: derive the level as the adapter does, threshold
the score as the confidence gate does, and take the **maximum severity** of the
derived and supplied levels so a caller can escalate but never de-escalate.
`src/jumpper/riskgate.py` implements precisely that, with 32 assertions.

---

## Why this matters more than the individual files

The estate has now been found, three separate times, to contain a correct
implementation of a control sitting beside a component that lacks it:

| control | correct implementation | component that lacks it |
|---|---|---|
| least-privilege authority | `relay.ts` prefers POSTING and derives the authority from the key it found | 57 of 62 live attestation ops signed with ACTIVE, because `STEEM_POSTING_WIF` is unset |
| free public anchoring | `relay.ts` broadcasts `custom_json` at zero fee, 21 verified anchors | `roshpina/kernel` - 838,280 chars, zero public-chain references |
| server-side risk derivation | `agent-adapter.ts` + `coding-actions.ts`, fail-closed | `confidence-gate.ts`, which trusts its input |

**The pattern is not missing capability. It is missing wiring.** Each time, the
hard part was already solved somewhere in the estate, and the gap was a connection
nobody made because nobody had read both sides.

That is what this repository has been doing all session: reading both sides.

---

## Actions

| # | action | effort |
|---|---|---|
| 1 | Compose the two: derive in the gate, or pass the derived class into it, and take the maximum severity | small - `riskgate.py` is the reference |
| 2 | **Reconstruct `MANIFEST.md`** from the code's own references - it defines the product and ranks the gaps | reading, not writing |
| 3 | Reconstruct `TRUST_INTEGRITY_ROADMAP.md` from the sections the transparency log cites (2.A, 2.D-12) | reading, not writing |
| 4 | Add a test that `confidence-gate.evaluate` cannot be reached with an un-derived level | small |
| 5 | Set `STEEM_POSTING_WIF` and `HIVE_POSTING_WIF` | configuration only |

Actions 2 and 3 are the ones that unlock everything else. A kernel built against an
unreadable specification cannot be extended safely, and both documents are
reconstructible from the citations already in the code.

---

*Read-only throughout. No file outside saos-jummper was created, modified or
deleted. No keys read, no transactions signed, nothing broadcast.*
