"""Forensic analysis of LIVE chain operations.

This module exists because the estate's own reports described its state, and the
chain described something different. Reading real account history from HIVE
mainnet on 2026-09-08 surfaced findings no self-report contained.

The detectors here are generic. They take a list of operations read from the
chain and report what is actually happening - loops, authority misuse, protocol
inventory, packing headroom. They never broadcast anything.

==============================================================================
WHAT THE CHAIN SAID (real data, account headcorner, last 100 history entries)
==============================================================================

Protocol inventory by custom_json id:

    ssc-mainnet-hive     32   Hive-Engine sidechain contract calls
    saos-dex.anchor.v1   23   Merkle root anchors
    saos.attest.v1       20   chain attestations (stateRoot + git commit)
    saos.weave.v1        11   batched seals with a count/from/to range
    saos                  5   value_lock records - signed with POSTING
    saos.id.v1            3   identity binding to an EVM address, EIP-191 signed

Non-custom_json: delegate_vesting_shares 1, fill_convert_request 1, transfer 2,
vote 1, effective_comment_vote 1.

Three findings that no self-report mentioned:

1. RC LEAK. `hive.convert` with quantity 9.632 was attempted 11 times across
   2026-09-07 and 09-08. The HIVE balance did not move (9.682 before and after).
   The only successful conversion in the window is a NATIVE
   `fill_convert_request` (0.445 HBD -> 9.673 HIVE) at 2026-09-07T09:34:30.
   Hive-Engine's `hive.convert` unwraps SWAP.HIVE into HIVE; it is not the native
   HBD conversion. The account had already transferred its SWAP.HIVE away on
   09-06. So every one of those 11 calls was doomed, and every one still landed
   on chain and still consumed RC. At the measured aggregate cost that is roughly
   1.7e9 RC - about a third of a full day's regeneration budget - spent on an
   operation that can never succeed. It was still running at the time of reading.

2. POSTING AUTHORITY IS ALREADY IN USE - just not for anchors. The `saos`
   value_lock operations are signed with required_posting_auths. The 23 anchors
   and 20 attestations use required_auths (ACTIVE). So the migration is not new
   engineering; the pattern already exists in the same account's history.

3. THE PACKING SCHEMA ALREADY EXISTS. `saos.weave.v1` seals carry
   count / from / to - a range of leaves under one root. Every observed seal has
   count = 1. The format supports batching; the usage does not batch.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from . import authority as AU


class LiveOpsError(ValueError):
    pass


# --------------------------------------------------------------------------
# Operation normalisation
# --------------------------------------------------------------------------

def normalise(history: Sequence[Any]) -> List[Dict[str, Any]]:
    """Accept condenser account_history rows and return a flat op list.

    Handles both shapes seen in the wild:
      [index, {"op": [name, data], "timestamp": ..., "block": ..., "trx_id": ...}]
      [index, {"operations": [[name, data]], ...}]
    """
    out: List[Dict[str, Any]] = []
    for row in history:
        if not isinstance(row, (list, tuple)) or len(row) < 2:
            continue
        idx, tx = row[0], row[1]
        if not isinstance(tx, dict):
            continue
        raw = tx.get("op")
        ops = [raw] if isinstance(raw, list) and raw else tx.get("operations") or []
        for op in ops:
            if not isinstance(op, (list, tuple)) or len(op) < 2:
                continue
            name, data = op[0], op[1]
            blob = json.dumps(op, separators=(",", ":"))
            out.append({
                "index": idx,
                "timestamp": tx.get("timestamp"),
                "block": tx.get("block"),
                "trx_id": tx.get("trx_id"),
                "op": name,
                "data": data if isinstance(data, dict) else {},
                "serialised_bytes": len(blob.encode()),
            })
    return out


def inventory(ops: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """What protocols are actually running, by custom_json id."""
    by_op = Counter(o["op"] for o in ops)
    by_id: Counter = Counter()
    id_bytes: Dict[str, int] = defaultdict(int)
    id_auths: Dict[str, Dict[str, int]] = defaultdict(lambda: {"active": 0, "posting": 0})
    for o in ops:
        if o["op"] != "custom_json":
            continue
        i = o["data"].get("id") or "<none>"
        by_id[i] += 1
        id_bytes[i] += o["serialised_bytes"]
        if o["data"].get("required_auths"):
            id_auths[i]["active"] += 1
        if o["data"].get("required_posting_auths"):
            id_auths[i]["posting"] += 1
    return {
        "totalOps": len(ops),
        "byOpType": dict(by_op),
        "byCustomJsonId": dict(by_id.most_common()),
        "bytesById": dict(id_bytes),
        "authorityById": {k: dict(v) for k, v in id_auths.items()},
    }


# --------------------------------------------------------------------------
# RC leak detection: identical payloads repeated with no observable effect
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class LoopFinding:
    fingerprint: str
    op: str
    custom_json_id: Optional[str]
    occurrences: int
    first_timestamp: Optional[str]
    last_timestamp: Optional[str]
    total_bytes: int
    verdict: str


def loop_key(o: Dict[str, Any]) -> str:
    """Identity of an operation for repeat detection: op + full payload."""
    return o["op"] + "|" + json.dumps(o["data"], sort_keys=True, separators=(",", ":"))


def find_repeat_loops(ops: Sequence[Dict[str, Any]], min_occurrences: int = 3) -> List[LoopFinding]:
    """Identical operations repeated >= min_occurrences times.

    A repeated identical operation is a strong smell: either it is idempotent work
    being redone, or it is failing and being retried forever. Both burn RC. This
    detector does not decide which - it reports the fingerprint and the count and
    leaves the verdict to the caller, who must check whether state actually moved.
    """
    if min_occurrences < 2:
        raise LiveOpsError("min_occurrences must be >= 2")
    groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for o in ops:
        groups[loop_key(o)].append(o)
    out: List[LoopFinding] = []
    for fp, g in groups.items():
        if len(g) < min_occurrences:
            continue
        first, last = g[0], g[-1]
        out.append(LoopFinding(
            fingerprint=fp,
            op=first["op"],
            custom_json_id=first["data"].get("id"),
            occurrences=len(g),
            first_timestamp=first.get("timestamp"),
            last_timestamp=last.get("timestamp"),
            total_bytes=sum(x["serialised_bytes"] for x in g),
            verdict="repeated-identical-operation",
        ))
    out.sort(key=lambda f: -f.occurrences)
    return out


def estimate_loop_waste(loops: Sequence[LoopFinding], rc_per_op: float,
                        keep: int = 1) -> Dict[str, Any]:
    """Cost of the repeats beyond the first legitimate attempt.

    rc_per_op must come from measurement, never from a guessed price curve.
    """
    if rc_per_op <= 0:
        raise LiveOpsError("rc_per_op must be a positive measured value")
    if keep < 0:
        raise LiveOpsError("keep must be >= 0")
    wasted_ops = sum(max(0, f.occurrences - keep) for f in loops)
    return {
        "loopCount": len(loops),
        "redundantOps": wasted_ops,
        "rcPerOp": rc_per_op,
        "estimatedRcWasted": wasted_ops * rc_per_op,
        "basis": "MEASURED rc_per_op required; a guessed price curve is refused",
    }


# --------------------------------------------------------------------------
# Authority audit against real operations
# --------------------------------------------------------------------------

def audit_authority(ops: Sequence[Dict[str, Any]], op_class: str = AU.ATTESTATION) -> Dict[str, Any]:
    """How many real operations used more authority than their class needs."""
    need = AU.authority_for(op_class)
    over: List[Dict[str, Any]] = []
    correct = 0
    for o in ops:
        if o["op"] != "custom_json":
            continue
        d = o["data"]
        used = AU.ACTIVE if d.get("required_auths") else (AU.POSTING if d.get("required_posting_auths") else None)
        if used is None:
            continue
        if AU.is_overprivileged(op_class, used):
            over.append({"index": o["index"], "id": d.get("id"), "timestamp": o.get("timestamp"),
                         "used": used, "needed": need})
        else:
            correct += 1
    total = len(over) + correct
    return {
        "opClass": op_class,
        "authorityNeeded": need,
        "totalCustomJson": total,
        "correctlyScoped": correct,
        "overprivileged": len(over),
        "overprivilegedPct": round(len(over) / total * 100, 1) if total else 0.0,
        "byProtocol": dict(Counter(x["id"] for x in over)),
        "examples": over[:5],
        "verdict": ("all correctly scoped" if not over and total else
                    "%d of %d use more authority than needed" % (len(over), total) if total else
                    "no custom_json operations supplied"),
    }


def protocols_already_using_posting(ops: Sequence[Dict[str, Any]]) -> List[str]:
    """Proof that posting authority is already working in this account."""
    ids = set()
    for o in ops:
        if o["op"] == "custom_json" and o["data"].get("required_posting_auths"):
            ids.add(o["data"].get("id") or "<none>")
    return sorted(ids)


# --------------------------------------------------------------------------
# Packing headroom
# --------------------------------------------------------------------------

def packing_headroom(ops: Sequence[Dict[str, Any]], anchor_id: str,
                     max_json_bytes: int = 8192) -> Dict[str, Any]:
    """How much of the custom_json budget the anchors actually use."""
    sizes: List[int] = []
    counts: List[Any] = []
    for o in ops:
        if o["op"] != "custom_json" or o["data"].get("id") != anchor_id:
            continue
        j = o["data"].get("json") or ""
        sizes.append(len(j.encode()))
        try:
            parsed = json.loads(j)
            if isinstance(parsed, dict) and "count" in parsed:
                counts.append(parsed["count"])
        except json.JSONDecodeError:
            pass
    if not sizes:
        return {"anchorId": anchor_id, "samples": 0, "verdict": "no matching anchors"}
    avg = sum(sizes) / len(sizes)
    return {
        "anchorId": anchor_id,
        "samples": len(sizes),
        "minJsonBytes": min(sizes),
        "maxJsonBytes": max(sizes),
        "avgJsonBytes": round(avg, 1),
        "budgetBytes": max_json_bytes,
        "budgetUsedPct": round(avg / max_json_bytes * 100, 2),
        "headroomX": round(max_json_bytes / avg, 1) if avg else None,
        "observedCountField": dict(Counter(str(c) for c in counts)) if counts else None,
        "verdict": ("batching schema present but unused"
                    if counts and all(str(c) == "1" for c in counts) else
                    "no batching field observed" if not counts else "batching in use"),
    }


# --------------------------------------------------------------------------
# Per-protocol authority classification
# --------------------------------------------------------------------------

VALUE_MOVING_IDS = {"ssc-mainnet-hive"}


def classify_protocol(custom_json_id: Optional[str]) -> str:
    """Hive-Engine sidechain calls move tokens and legitimately need ACTIVE.

    Everything else observed in this account publishes data. Classifying them all
    as attestations would be wrong and would make the audit untrustworthy, so the
    value-moving set is explicit and small.
    """
    if custom_json_id in VALUE_MOVING_IDS:
        return AU.VALUE_MOVING
    return AU.ATTESTATION


def audit_authority_by_protocol(ops: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """Authority audit that respects what each protocol actually does."""
    rows: Dict[str, Dict[str, Any]] = {}
    for o in ops:
        if o["op"] != "custom_json":
            continue
        d = o["data"]
        pid = d.get("id") or "<none>"
        cls = classify_protocol(pid)
        need = AU.authority_for(cls)
        used = (AU.ACTIVE if d.get("required_auths")
                else AU.POSTING if d.get("required_posting_auths") else None)
        if used is None:
            continue
        r = rows.setdefault(pid, {"opClass": cls, "authorityNeeded": need, "total": 0,
                                  "correct": 0, "overprivileged": 0, "authorities": Counter()})
        r["total"] += 1
        r["authorities"][used] += 1
        if AU.is_overprivileged(cls, used):
            r["overprivileged"] += 1
        else:
            r["correct"] += 1
    att = [r for r in rows.values() if r["opClass"] == AU.ATTESTATION]
    val = [r for r in rows.values() if r["opClass"] == AU.VALUE_MOVING]
    att_total = sum(r["total"] for r in att)
    att_over = sum(r["overprivileged"] for r in att)
    return {
        "byProtocol": {k: {**v, "authorities": dict(v["authorities"])} for k, v in rows.items()},
        "attestationOps": att_total,
        "attestationOverprivileged": att_over,
        "attestationOverprivilegedPct": round(att_over / att_total * 100, 1) if att_total else 0.0,
        "valueMovingOps": sum(r["total"] for r in val),
        "valueMovingCorrectlyScoped": sum(r["correct"] for r in val),
        "verdict": ("%d of %d attestation operations use ACTIVE when POSTING suffices; "
                    "%d value-moving operations correctly use ACTIVE"
                    % (att_over, att_total, sum(r["total"] for r in val))),
    }


def duplicate_seal_audit(ops: Sequence[Dict[str, Any]], anchor_ids: Sequence[str]) -> Dict[str, Any]:
    """Find seals broadcast more than once with the same root and seq.

    Re-broadcasting an identical seal burns RC and creates two on-chain records
    for one logical commitment. The in-memory batcher already prevents this with
    an idempotency key; this checks whether the on-chain protocol does too.
    """
    seen: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for o in ops:
        if o["op"] != "custom_json" or (o["data"].get("id") not in anchor_ids):
            continue
        try:
            parsed = json.loads(o["data"].get("json") or "")
        except json.JSONDecodeError:
            continue
        if not isinstance(parsed, dict):
            continue
        key = "%s|%s|%s|%s" % (o["data"].get("id"), parsed.get("net") or parsed.get("protocol"),
                               parsed.get("seq", parsed.get("height")), parsed.get("root", parsed.get("stateRoot")))
        seen[key].append(o)
    dupes = {k: v for k, v in seen.items() if len(v) > 1}
    wasted = sum(len(v) - 1 for v in dupes.values())
    return {
        "distinctSeals": len(seen),
        "duplicatedSeals": len(dupes),
        "redundantBroadcasts": wasted,
        "details": [{"key": k, "times": len(v),
                     "first": v[0].get("timestamp"), "last": v[-1].get("timestamp")}
                    for k, v in sorted(dupes.items(), key=lambda kv: -len(kv[1]))[:10]],
        "verdict": ("no duplicates" if not dupes else
                    "%d seals broadcast more than once - %d redundant on-chain records"
                    % (len(dupes), wasted)),
    }


def conflicting_height_audit(ops: Sequence[Dict[str, Any]], anchor_ids: Sequence[str],
                             height_fields: Sequence[str] = ("height", "seq"),
                             root_fields: Sequence[str] = ("stateRoot", "root", "digest")) -> Dict[str, Any]:
    """Find heights that carry MORE THAN ONE DISTINCT ROOT.

    Not the same as duplicate_seal_audit, which finds the same seal broadcast
    repeatedly. That is waste. This finds two different states claiming one height,
    which is an integrity break: "what was the state at height N?" has two public
    answers and no way to choose between them.

    Measured on 115 real HIVE anchors read 2026-09-10:

        height 1764  root d7220b5e... 18:27:21 block 109770502 trx 0825c6b3...
        height 1764  root 84ae0a0a... 18:27:51 block 109770512 trx 9029171e...

    Thirty seconds apart, different blocks, different transactions, different
    digests, different `at`. Not a re-broadcast - two states, one height. Heights
    1668 (3.3 min apart) and 1476 (5.3 h apart, straddling a counter reset) show
    the same. The counter also reset 4488 -> 12 and NO payload carries an epoch
    field, so every height below 4488 is ambiguous.
    """
    by_height: Dict[Any, List[Dict[str, Any]]] = {}
    ordered: List[Dict[str, Any]] = []
    for o in ops:
        if o["op"] != "custom_json" or (o["data"].get("id") not in anchor_ids):
            continue
        try:
            parsed = json.loads(o["data"].get("json") or "")
        except json.JSONDecodeError:
            continue
        if not isinstance(parsed, dict):
            continue
        height = next((parsed[f] for f in height_fields if f in parsed), None)
        root = next((parsed[f] for f in root_fields if f in parsed), None)
        if height is None or root is None:
            continue
        rec = {"height": height, "root": root, "index": o.get("index"),
               "timestamp": o.get("timestamp"), "block": o.get("block"),
               "trx": o.get("trx_id"), "id": o["data"].get("id"),
               "epoch": parsed.get("epoch", parsed.get("instance", parsed.get("net")))}
        by_height.setdefault(height, []).append(rec)
        ordered.append(rec)
    conflicts = []
    for height, recs in by_height.items():
        roots = {r["root"] for r in recs}
        if len(roots) > 1:
            same_epoch = len({r["epoch"] for r in recs}) == 1
            conflicts.append({"height": height, "distinctRoots": len(roots),
                              "records": sorted(recs, key=lambda r: r["timestamp"] or ""),
                              "roots": sorted(roots), "sameEpoch": same_epoch,
                              "verdict": ("TWO STATES AT ONE HEIGHT - not explainable by an epoch change"
                                          if same_epoch else
                                          "ambiguous across an epoch boundary - the payload carries "
                                          "no epoch field to disambiguate")})
    conflicts.sort(key=lambda c: c["height"] if isinstance(c["height"], int) else 0)
    resets = []
    for i in range(1, len(ordered)):
        a, b = ordered[i - 1], ordered[i]
        if isinstance(a["height"], int) and isinstance(b["height"], int) and b["height"] < a["height"]:
            resets.append({"afterIndex": a["index"], "at": a["timestamp"], "fromHeight": a["height"],
                           "toIndex": b["index"], "toAt": b["timestamp"], "toHeight": b["height"],
                           "hasEpochField": b["epoch"] is not None})
    has_epoch = any(r["epoch"] is not None for r in ordered)
    return {"anchorsExamined": len(ordered), "distinctHeights": len(by_height),
            "conflictingHeights": len(conflicts), "conflicts": conflicts, "resets": resets,
            "anyEpochFieldPresent": has_epoch,
            "verdict": ("clean - every height carries exactly one root"
                        if not conflicts and not resets else
                        "%d height(s) carry more than one root; %d counter reset(s); epoch field %s"
                        % (len(conflicts), len(resets), "present" if has_epoch else "ABSENT")),
            "severity": ("none" if not conflicts and not resets else
                         "critical" if any(c["sameEpoch"] for c in conflicts) else
                         "high" if conflicts else "medium")}
