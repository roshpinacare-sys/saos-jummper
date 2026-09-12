"""Memo-lock reconciliation - what a lock written in a memo actually locks.

Four transfers in account headcorner history (500 entries read, 2026-09-03 to
2026-09-11) carry a lock protocol entirely in the memo field. All four are
self-transfers:

    #49621  2026-09-04T19:20:21  0.001 HIVE  saos:xlock:PHIVE:0.001
    #49625  2026-09-04T22:23:48  0.002 HIVE  saos:xlock:PHIVE:0.002:rt66
    #49626  2026-09-04T22:37:51  0.001 HIVE  saos:xunlock:PHIVE:0.001:rt66:7bdec0aa...
    #49697  2026-09-07T11:49:39  0.050 HIVE  saos:xlock:PHIVE:0.050

A self-transfer is economically a no-op: HIVE transfers carry no fee and sender
equals receiver, so the balance does not change. Nothing is held, escrowed or
time-locked. The word xlock records an intention, not a custody change.

Nothing validates an unlock. Any account can write saos:xunlock:PHIVE:999:anyref
into a memo and it is recorded with exactly as much authority as the real one.
That is an attestation protocol, which is legitimate - as long as nobody calls it
a lock.

This module reconciles the ledger and reports each defect as a distinct named
finding, because a single verdict of does-not-balance is not actionable. It never
signs and never broadcasts. Verified against the four real operations: 8 findings,
4 critical, 3 high; and against a balanced two-party protocol: RECONCILED with 0.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, List, Optional, Sequence

LOCK = "xlock"
UNLOCK = "xunlock"
PREFIX = "saos"
GRAPHENE_TXID = re.compile(r"^[0-9a-f]{40}$")


class XLockError(ValueError):
    pass


@dataclass(frozen=True)
class MemoOp:
    index: int
    timestamp: str
    sender: str
    receiver: str
    amount: str
    asset: str
    token: str
    action: str
    quantity: Optional[Decimal]
    ref_id: Optional[str]
    cited_txid: Optional[str]
    field_count: int
    trx_id: str
    block: Optional[int] = None

    @property
    def is_self_transfer(self) -> bool:
        return self.sender == self.receiver

    def as_dict(self) -> Dict[str, Any]:
        return {"index": self.index, "timestamp": self.timestamp,
                "sender": self.sender, "receiver": self.receiver,
                "amount": self.amount, "asset": self.asset, "token": self.token,
                "action": self.action,
                "quantity": None if self.quantity is None else str(self.quantity),
                "refId": self.ref_id, "citedTxid": self.cited_txid,
                "fieldCount": self.field_count, "trxId": self.trx_id,
                "block": self.block, "isSelfTransfer": self.is_self_transfer}


def parse_memo(memo: str) -> Optional[Dict[str, Any]]:
    """Parse a saos:xlock / saos:xunlock memo. Returns None if it is not one."""
    if not memo or not isinstance(memo, str):
        return None
    parts = memo.split(":")
    if len(parts) < 4 or parts[0] != PREFIX or parts[1] not in (LOCK, UNLOCK):
        return None
    out: Dict[str, Any] = {"token": parts[2], "fieldCount": len(parts),
                           "refId": None, "citedTxid": None, "action": parts[1]}
    try:
        out["quantity"] = Decimal(parts[3])
    except InvalidOperation:
        out["quantity"] = None
    if len(parts) >= 5 and parts[4]:
        out["refId"] = parts[4]
    if len(parts) >= 6 and parts[5]:
        out["citedTxid"] = parts[5]
    return out


def parse_transfer(index: int, tx: Dict[str, Any]) -> Optional[MemoOp]:
    """Build a MemoOp from one account_history transfer entry."""
    op = tx.get("op")
    if not (isinstance(op, list) and op and op[0] == "transfer"):
        return None
    d = op[1] if len(op) > 1 and isinstance(op[1], dict) else {}
    parsed = parse_memo(d.get("memo", ""))
    if parsed is None:
        return None
    amount = str(d.get("amount", "")).split()
    return MemoOp(index=index, timestamp=str(tx.get("timestamp", "")),
                  sender=str(d.get("from", "")), receiver=str(d.get("to", "")),
                  amount=amount[0] if amount else "",
                  asset=amount[1] if len(amount) > 1 else "",
                  token=parsed["token"], action=parsed["action"],
                  quantity=parsed["quantity"], ref_id=parsed["refId"],
                  cited_txid=parsed["citedTxid"], field_count=parsed["fieldCount"],
                  trx_id=str(tx.get("trx_id", "")), block=tx.get("block"))


def parse_history(history: Sequence[Any]) -> List[MemoOp]:
    out: List[MemoOp] = []
    for row in history or []:
        if not isinstance(row, (list, tuple)) or len(row) < 2:
            continue
        m = parse_transfer(row[0], row[1] if isinstance(row[1], dict) else {})
        if m is not None:
            out.append(m)
    return out


def reconcile(ops: Sequence[MemoOp]) -> Dict[str, Any]:
    """Reconcile locks against unlocks, reporting every defect separately."""
    locks = [o for o in ops if o.action == LOCK]
    unlocks = [o for o in ops if o.action == UNLOCK]
    findings: List[Dict[str, Any]] = []

    def add(kind: str, severity: str, detail: str, **extra: Any) -> None:
        rec: Dict[str, Any] = {"kind": kind, "severity": severity, "detail": detail}
        rec.update(extra)
        findings.append(rec)

    for o in ops:
        if o.is_self_transfer:
            add("self-transfer", "critical",
                "sender equals receiver, so the balance does not change and nothing "
                "is held; a HIVE transfer carries no fee. The memo records an "
                "intention, not a custody change",
                index=o.index, amount=o.amount, asset=o.asset)

    # Compared WITHIN each action type, not across both. An unlock legitimately
    # carries one more field than a lock (the cited txid), so a 5-field lock beside
    # a 6-field unlock is the normal shape and must not be reported as drift. The
    # first version compared across the whole ledger and flagged every well-formed
    # protocol that had both kinds of message.
    for action in (LOCK, UNLOCK):
        group = [o for o in ops if o.action == action]
        shapes = sorted({o.field_count for o in group})
        if len(shapes) > 1:
            add("inconsistent-format", "high",
                "%s memos carry differing field counts (%s); a positional parser "
                "cannot rely on any field index" % (action, shapes),
                action=action, fieldCounts=shapes, indices=[o.index for o in group])

    orphan = [o for o in locks if not o.ref_id]
    if orphan:
        add("lock-without-reference", "high",
            "%d lock(s) carry no reference id, so no unlock could ever cite them"
            % len(orphan),
            indices=[o.index for o in orphan], amounts=[o.amount for o in orphan])

    lock_refs = {o.ref_id for o in locks if o.ref_id}
    lock_txids = {o.trx_id for o in locks if o.trx_id}
    for o in unlocks:
        if o.ref_id and o.ref_id not in lock_refs:
            add("unlock-unknown-ref", "high",
                "unlock #%d cites reference %r which no lock in this history uses"
                % (o.index, o.ref_id), index=o.index, refId=o.ref_id)
        cited = o.cited_txid
        if cited and cited not in lock_txids:
            # Reported as UNRESOLVED, not as foreign or unfollowable. The producer
            # roundtrip.cjs cites st.s4.txid - the BURN on the other chain - because
            # the protocol unlocks against the burn that proves the wrapped asset was
            # destroyed, not against the lock that created it. Calling that "foreign"
            # was a false positive: this module has no model of a multi-chain
            # roundtrip, so it can only say the citation does not resolve within the
            # history it was given. See docs/XLOCK-AUDIT-CORRECTION.md.
            add("unlock-citation-unresolved", "medium",
                "unlock #%d cites txid %s which does not resolve to any lock in the "
                "supplied history. This module has no model of the protocol, so it "
                "cannot say whether the citation points at a burn on another chain "
                "(which is what roundtrip.cjs does) or at nothing. The memo names no "
                "chain, so a reader cannot resolve it either"
                % (o.index, cited[:16]),
                index=o.index, citedTxid=cited,
                isGrapheneFormat=bool(GRAPHENE_TXID.match(cited)),
                resolvesWithinHistory=False)

    by_ref: Dict[str, Dict[str, Decimal]] = {}
    for o in list(locks) + list(unlocks):
        if o.ref_id and o.quantity is not None:
            slot = by_ref.setdefault(o.ref_id, {"locked": Decimal(0), "unlocked": Decimal(0)})
            slot["locked" if o.action == LOCK else "unlocked"] += o.quantity
    for ref in sorted(by_ref):
        tot = by_ref[ref]
        if tot["unlocked"] != tot["locked"]:
            add("amount-mismatch", "high",
                "reference %r locked %s but unlocked %s"
                % (ref, tot["locked"], tot["unlocked"]),
                refId=ref, locked=str(tot["locked"]), unlocked=str(tot["unlocked"]),
                delta=str(tot["locked"] - tot["unlocked"]))

    for o in ops:
        if o.quantity is None:
            add("unparseable-quantity", "high",
                "operation #%d memo quantity is not a number" % o.index, index=o.index)
        elif o.amount:
            try:
                if Decimal(o.amount) != o.quantity:
                    add("memo-amount-mismatch", "high",
                        "operation #%d transferred %s %s but the memo claims %s"
                        % (o.index, o.amount, o.asset, o.quantity),
                        index=o.index, transferred=o.amount, claimed=str(o.quantity))
            except InvalidOperation:
                pass

    crit = [f for f in findings if f["severity"] == "critical"]
    high = [f for f in findings if f["severity"] == "high"]
    kinds = sorted({f["kind"] for f in findings})
    return {"locks": len(locks), "unlocks": len(unlocks), "operations": len(ops),
            "findings": findings, "findingCount": len(findings),
            "critical": len(crit), "high": len(high), "references": sorted(by_ref),
            "balances": {k: {"locked": str(v["locked"]), "unlocked": str(v["unlocked"])}
                         for k, v in by_ref.items()},
            "enforcement": ("none - a memo is an attestation; any account can write an "
                            "unlock and nothing validates it"),
            "custody": ("unchanged - every operation is a self-transfer"
                        if ops and all(o.is_self_transfer for o in ops) else "changed"),
            "verdict": ("RECONCILED" if not findings else
                        "%d finding(s): %s" % (len(findings), ", ".join(kinds)))}
