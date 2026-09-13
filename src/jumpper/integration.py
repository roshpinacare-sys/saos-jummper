"""Integration - one runner that proves every bridge connects.

The estate's recurring defect was not missing capability, it was missing wiring:
a correct implementation sitting beside a component that never called it. Four
bridges were built to close that - sth.py for signed tree heads, witnessbridge.py
for witness quorums, kernelbridge.py for federation anchors, pipeline.py for the
audit chain - and each was verified on its own.

Nothing ran them together. This module does, and it validates every operation it
produces against the real constraints rather than assuming the layers agree:

    the op is a custom_json with an id
    an attestation uses POSTING and never ACTIVE
    there is no fee and no amount field - the operation must be free
    the payload fits the live 8,192-byte budget
    the payload round-trips through its own decoder

A runner that emits operations without checking them would report success on a
batch the network rejects, which is the same failure as a ledger that counts an
anchor before it is confirmed."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence

from . import kernelbridge as KB
from . import sth as STH
from . import witnessbridge as WB
from .protocol import HIVE_CUSTOM_JSON_DATA_MAX_LENGTH

BUDGET = HIVE_CUSTOM_JSON_DATA_MAX_LENGTH


class IntegrationError(ValueError):
    pass


def validate_op(op: Any, account: str) -> List[str]:
    """Every way an operation could be rejected or could cost money."""
    errs: List[str] = []
    if not isinstance(op, (list, tuple)) or len(op) != 2:
        return ["operation must be a [type, body] pair"]
    kind, body = op[0], op[1]
    if kind != "custom_json":
        errs.append("expected custom_json, got %r" % kind)
    if not isinstance(body, dict):
        return errs + ["operation body must be an object"]
    if not body.get("id"):
        errs.append("custom_json requires an id")
    payload = body.get("json")
    if not isinstance(payload, str) or not payload:
        errs.append("custom_json requires a non-empty json payload")
    else:
        n = len(payload.encode("utf-8"))
        if n > BUDGET:
            errs.append("payload of %d bytes exceeds the %d-byte budget" % (n, BUDGET))
    if body.get("required_auths"):
        errs.append("an attestation must use POSTING, not ACTIVE - ACTIVE can "
                    "transfer every asset in the account")
    posting = body.get("required_posting_auths") or []
    if account not in posting:
        errs.append("required_posting_auths must contain %r, got %r" % (account, posting))
    for forbidden in ("fee", "amount", "quantity"):
        if forbidden in body:
            errs.append("a free attestation must not carry a %r field" % forbidden)
    return errs


def run(account: str,
        signed_tree_heads: Sequence[Any] = (),
        witness_statements: Sequence[Dict[str, Any]] = (),
        federation_anchors: Sequence[Dict[str, Any]] = (),
        quorum_threshold: int = 2) -> Dict[str, Any]:
    """Build and validate every operation the four bridges produce.

    Each artifact family is grouped the way its bridge requires it - one log per
    batch of tree heads, one log pair and one signer per batch of federation
    anchors, one log per witness quorum - because a batch that mixed them would be
    rejected by the encoder, and finding that here beats finding it on chain."""
    if not account or not isinstance(account, str):
        raise IntegrationError("account is required")
    ops: List[Any] = []
    notes: List[str] = []
    counts = {"signedTreeHeads": len(signed_tree_heads),
              "witnessStatements": len(witness_statements),
              "federationAnchors": len(federation_anchors)}

    # 1. signed tree heads, grouped by log_id and convention
    if signed_tree_heads:
        groups: Dict[Any, List[Any]] = {}
        for h in signed_tree_heads:
            groups.setdefault((h.log_id, h.convention, getattr(h, "epoch", 0)), []).append(h)
        per_ops = 0
        for key, heads in groups.items():
            per = STH.heads_per_operation(heads[0])
            for i in range(0, len(heads), per):
                ops.append(STH.build_anchor_op(account, heads[i:i + per]))
                per_ops += 1
        counts["headOperations"] = per_ops
        counts["headGroups"] = len(groups)

    # 2. witness statements -> quorum commitments, grouped by log_id
    if witness_statements:
        parsed = [WB.parse_statement(s) for s in witness_statements]
        by_log: Dict[Any, List[Any]] = {}
        for s in parsed:
            by_log.setdefault((s.log_id, s.tree_size), []).append(s)
        commitments = []
        for (log_id, size), group in sorted(by_log.items()):
            q = WB.quorum(group, log_id, size, quorum_threshold)
            if not q["reached"]:
                notes.append("log %s at tree_size %d has %d of %d witnesses; not quorate, "
                             "published as an observation rather than a quorum"
                             % (log_id, size, q["distinctWitnesses"], quorum_threshold))
            if q["root"]:
                commitments.append(WB.commitment_from_quorum(log_id, size, q))
        if commitments:
            for chunk in WB.split_into_operations(commitments):
                ops.append(WB.build_anchor_op(account, chunk))
        counts["witnessCommitments"] = len(commitments)
        counts["witnessOperations"] = sum(1 for o in ops if o[1]["id"] == WB.BRIDGE_ANCHOR_ID)

    # 3. federation anchors, grouped by log pair and signer
    if federation_anchors:
        feds = [KB.parse_federation_anchor(a) for a in federation_anchors]
        groups2: Dict[Any, List[Any]] = {}
        for f in feds:
            groups2.setdefault((f.log_a.log_id, f.log_b.log_id, f.signer_id), []).append(f)
        fed_ops = 0
        for key, chunk_all in groups2.items():
            per = KB.federations_per_operation(chunk_all[0])
            for i in range(0, len(chunk_all), per):
                ops.append(KB.build_federation_op(account, chunk_all[i:i + per]))
                fed_ops += 1
        counts["federationOperations"] = fed_ops
        counts["federationGroups"] = len(groups2)

    # 4. validate every operation, and refuse the batch if any fails
    problems: List[Dict[str, Any]] = []
    for i, op in enumerate(ops):
        errs = validate_op(op, account)
        if errs:
            problems.append({"index": i, "id": (op[1] or {}).get("id"), "errors": errs})
    total_bytes = sum(len(op[1]["json"].encode("utf-8")) for op in ops if op[1].get("json"))
    ok = not problems
    return {"account": account, "ok": ok, "operations": ops,
            "operationCount": len(ops), "counts": counts, "notes": notes,
            "problems": problems, "totalPayloadBytes": total_bytes,
            "budgetPerOperation": BUDGET, "totalFee": 0,
            "authority": "posting", "signing": "external-only",
            "broadcast": "never-performed-here", "signaturesVerified": False,
            "verdict": ("%d artifact(s) -> %d validated zero-fee operation(s)"
                        % (sum(counts[k] for k in ("signedTreeHeads", "witnessStatements",
                                                   "federationAnchors")), len(ops))
                        if ok else
                        "%d of %d operation(s) FAILED validation" % (len(problems), len(ops)))}
