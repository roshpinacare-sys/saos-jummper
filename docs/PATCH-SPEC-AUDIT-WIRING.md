<!-- hardening:allow-file ALL reason=patch specification quoting the audit API and the unchained action table it should cover -->

# Patch Spec - wire 717 unchained actions into the audit chain that already exists

`Saosmartwallet/db/custom.db` holds two tables that should be one story:

    GateAction    717 rows    agentName, action, params, ok, result
    AuditEvent      0 rows    seq, timestamp, type, actorJson, targetJson, result,
                              reason, previousEventHash, eventHash

`packages/core/src/audit/audit.ts` (17,165 chars) implements a hash-chained audit
log, and it is good. Verified earlier in this engagement against the recovery
contract: **8 of 8**, including a genuinely constant-time comparison and a genesis
bound to the vault instance.

**The implementation is sound and it is not being used.** Every action an
autonomous agent takes is recorded in a table with no hash chain, no previous-event
link and no way to detect an edit.

---

## The API that already exists

    export class AuditSystem {
      genesisHash(vaultInstanceId: string): string
      log(input: LogAuditInput): Promise<AuditEvent>
      query(filters: AuditQueryFilters): Promise<AuditEvent[]>
      count(filters: AuditQueryFilters): Promise<number>
      head(): Promise<AuditEvent | null>
      verifyIntegrity(vaultInstanceId: string): Promise<AuditIntegrityResult>
      generateReport(period, format): Promise<ComplianceReport>
      buildOperationContext(vaultInstanceId, base): Promise<OperationContext>
    }

    export interface LogAuditInput {
      type: AuditEventType;
      actor: AuditActor;            // who acted - vault/key/device identity
      target: AuditTarget;          // what was acted upon + free-form detail
      result: "success" | "failure" | "blocked";
      reason?: string;              // hash-bound, surfaces in reports
      vaultInstanceId: string;      // anchors the chain genesis for a fresh store
    }

    export interface AuditIntegrityResult {
      integrityOk: boolean;
      eventsChecked: number;
      firstBadSeq: number | null;
    }

    export interface AuditStore {
      append(event: AuditEvent): Promise<void>;   // must preserve seq ordering
      query(filters: AuditQueryFilters): Promise<AuditEvent[]>;
      count(filters: AuditQueryFilters): Promise<number>;
      head(): Promise<AuditEvent | null>;
      all(): Promise<AuditEvent[]>;               // ascending seq, integrity walks
    }

Everything needed is already exported. **Nothing has to be written except the glue.**

---

## Step 1 - implement `AuditStore` over the table that already exists

The committed `AuditEvent` schema matches `AuditEvent` field for field:

    seq · timestamp · type · actorJson · targetJson · result · reason
    previousEventHash · eventHash

So the store is a thin adapter, not a migration:

    class SqliteAuditStore implements AuditStore {
      async append(e: AuditEvent): Promise<void> {
        // INSERT OR ABORT on a UNIQUE(seq) constraint. ABORT, not REPLACE:
        // a silent upsert would let a rewrite look like an append.
        await db.run(
          `INSERT INTO AuditEvent
             (seq, timestamp, type, actorJson, targetJson, result, reason,
              previousEventHash, eventHash, vaultInstanceId)
           VALUES (?,?,?,?,?,?,?,?,?,?)`,
          [e.seq, e.timestamp, e.type, JSON.stringify(e.actor),
           JSON.stringify(e.target), e.result, e.reason ?? null,
           e.previousEventHash, e.eventHash, e.vaultInstanceId]);
      }
      async head(): Promise<AuditEvent | null> {
        const r = await db.get(`SELECT * FROM AuditEvent ORDER BY seq DESC LIMIT 1`);
        return r ? rowToEvent(r) : null;
      }
      async all(): Promise<AuditEvent[]> {
        const rs = await db.all(`SELECT * FROM AuditEvent ORDER BY seq ASC`);
        return rs.map(rowToEvent);
      }
      // query/count filter on type, result, actor, target and time range
    }

`UNIQUE(seq)` with `INSERT OR ABORT` matters. Without it a rewrite is
indistinguishable from an append, and the chain's only defence against a deleted
middle row is the seq continuity check inside `verifyIntegrity`.

## Step 2 - log at the action boundary

Wherever a `GateAction` row is written, write the audit event in the same
transaction:

    await audit.log({
      type: "agent_action",
      actor: { kind: "agent", id: action.agentName },
      target: { kind: "action", id: String(action.id), detail: action.action },
      result: action.ok ? "success" : "failure",
      reason: action.error ?? undefined,
      vaultInstanceId: VAULT_INSTANCE_ID,
    });

**Same transaction, not after.** An action that succeeds and an audit record that
fails to write is the exact asymmetry that produced `verified=18` against
`anchored=16` in the anchor ledger - two counters that could drift because nothing
forced them to move together.

## Step 3 - verify on startup and refuse to operate on failure

    const integrity = await audit.verifyIntegrity(VAULT_INSTANCE_ID);
    if (!integrity.integrityOk) {
      // audit.ts states its own policy: corrupt events are never repaired,
      // callers must escalate, and the vault is treated as compromised.
      await halt("audit chain failed integrity at seq " + integrity.firstBadSeq);
    }

The module's own comment is the right policy and it should be honoured rather than
logged and ignored. **A control that reports a failure and continues is a
telemetry line.**

## Step 4 - anchor the head, or the chain cannot detect truncation

This is the step that connects to everything else in this repository, and it is the
one that cannot be skipped.

A hash chain **cannot detect truncation**. Proven by test in
`src/jumpper/audit.py`:

    verify_chain("vault-1", chain[:1])   ->   intact = True

Dropping the tail leaves a shorter chain that is still internally consistent.
Detecting it needs an external commitment to the head - and `audit.head()` already
returns exactly the value to commit.

`src/jumpper/sth.py` packs 148 to 177 signed tree heads into one zero-fee HIVE
`custom_json`, and `src/jumpper/pipeline.py` runs the whole path end to end:

    audit.head().eventHash  ->  sth.pack  ->  custom_json, POSTING, fee 0

At the measured 157,713,792 RC per operation and the account's current 8.25e9 RC
daily budget, that is roughly 52 anchored heads a day for nothing. **Anchoring every
few hours closes the truncation window permanently, and it costs zero.**

---

## What about the 717 rows already in `GateAction`

Three options, and the honest one is the second:

1. **Back-fill them into `AuditEvent`.** Produces a chain whose hashes were computed
   now, not then. It proves nothing about when the actions happened, and it looks
   identical to a chain that was written at the time. **Do not do this without
   labelling it.**
2. **Leave them unchained and record the fact.** Write one `AuditEvent` of type
   `chain_genesis_note` stating that actions 1 through 717 predate the chain and are
   not covered by it. That is verifiable, it is honest, and it costs one row.
3. **Delete them.** Destroys the only record of what the agents did.

Option 2. A chain that starts now and says so is worth more than a chain that
pretends to have started earlier.

---

## Effort

| step | size |
|---|---|
| `SqliteAuditStore` over the existing table | one file, five methods |
| `audit.log` at the action boundary | one call, in the same transaction |
| `verifyIntegrity` on startup with a halt | three lines |
| anchor `head().eventHash` | `sth.py` and `pipeline.py` already do it |
| genesis note for the 717 pre-chain rows | one row |

No new cryptography. No schema change - the table already matches. No migration.
**The implementation was written, verified sound, and then not called.**

---

## Why this one matters more than its size suggests

`autonomyEnabled = 1`. Ten agents carry financial tiers and caps. 717 actions have
been executed. The record of what they did sits in a table that can be edited
without leaving a trace, in a database that is committed to a repository, and that
repository is readable by a token carrying `delete_repo`.

**An unauditable log of autonomous financial actions is not a log.** The chain is
built. It needs to be called.

---

*Read-only throughout. No file outside saos-jummper was created, modified or
deleted. This document specifies a patch; it does not apply one.*
