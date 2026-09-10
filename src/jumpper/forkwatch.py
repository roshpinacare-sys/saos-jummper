"""Fork watch - detecting contradictory state commitments in a public anchor stream.

WHAT WAS FOUND ON HIVE MAINNET
------------------------------
153 `saos-dex.anchor.v1` operations by account `headcorner`, read from
condenser_api.get_account_history on 2026-09-10, spanning 2026-09-07T14:42:57 to
2026-09-10T12:37:12.

**Eight heights carry more than one distinct stateRoot.** Two of them are 30
seconds apart:

    height 1764   #49833 2026-09-09T18:27:21  root d7220b5e9ecc953e7e8ddf0b...
                  #49834 2026-09-09T18:27:51  root 84ae0a0a08ef2f44becc99e4...

    height 1668   #49824 2026-09-09T18:19:18  root 74b29867195898f6691ce331...
                  #49825 2026-09-09T18:22:36  root e375e0f5d7fe98c69ea720d0...

    height 552    THREE anchors, THREE distinct roots, 09-07T21:57 / 22:02 / 22:04
    height 12     09-07T22:53 and 09-09T22:10 - two roots
    heights 1224, 1392, 1416, 1476 - two roots each

A verifier asking "what was the state at height 1764?" gets two contradictory
answers, both signed by the same account, both permanent, 30 seconds apart.

THE CAUSE
---------
The height counter is per-process, not global. Ten non-increasing steps appear in
the sequence:

    1416 -> 552              2026-09-07T21:57
    552  -> 552 -> 552       three anchors, same height, three roots
    552  -> 12               2026-09-07T22:53
    2088 -> 444              2026-09-08T02:47
    14304 -> 4920            2026-09-08T21:21   <- four minutes after the key rotation
    6276 -> 876              2026-09-09T17:36
    4488 -> 12               2026-09-09T22:10   <- reset to 12 again

The pulse chain restarts and its counter starts over near 12. Each restart
re-publishes low heights with fresh roots, colliding with heights already
committed under different roots.

Median positive step is 12 - the chain seals every 12 blocks, as designed. The
counter is correct WITHIN a process lifetime. It is simply not a global identifier,
and it is published to a permanent public ledger as though it were.

WHY THIS IS THE WORST FINDING IN THE ESTATE
-------------------------------------------
`roshpina/kernel/transparency-log/` is 93,118 characters of anti-fork machinery:
inclusion proofs, consistency proofs whose docstring names the split-view attack
explicitly, witnesses with liveness and gossip, cross-log consistency, and
federation anchors. None of it touches a public chain.

Meanwhile the component that DOES publish to a public chain forked eight times in
four days. The two halves of the system are aimed at each other's exact problem and
have never met.

THE FIX
-------
Namespace the height. Add an epoch or instance identifier to the payload so that
height is only meaningful within an epoch:

    {"protocol":"saos-dex/v1","action":"chain-seal","epoch":<process-or-day id>,
     "height":1764,"stateRoot":...}

Then (epoch, height) is unique even across restarts, and a restart is visible as a
new epoch rather than as a contradiction. Cost: about 12 bytes in a payload that
currently uses 3.04% of its 8,192-byte budget.

This module detects the condition rather than assuming it away. It is deliberately
usable against any anchor stream, not just this one.
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


class ForkWatchError(ValueError):
    pass


@dataclass(frozen=True)
class Anchor:
    index: Any
    timestamp: str
    height: Optional[int]
    root: Optional[str]
    epoch: Optional[str] = None
    authority: Optional[str] = None
    payload_bytes: int = 0


@dataclass(frozen=True)
class Fork:
    height: Optional[int]
    epoch: Optional[str]
    roots: Tuple[str, ...]
    records: Tuple[Dict[str, Any], ...]
    span_seconds: Optional[int]

    @property
    def severity(self) -> str:
        """A short span is worse: nothing legitimate re-derives a root in 30s."""
        if self.span_seconds is None:
            return "unknown"
        if self.span_seconds <= 300:
            return "critical"
        if self.span_seconds <= 86400:
            return "high"
        return "medium"

    def as_dict(self) -> Dict[str, Any]:
        return {"height": self.height, "epoch": self.epoch, "distinctRoots": list(self.roots),
                "count": len(self.records), "spanSeconds": self.span_seconds,
                "severity": self.severity,
                "records": [{"index": r.get("index"), "timestamp": r.get("timestamp"),
                             "root": (r.get("root") or "")[:16] + "..."} for r in self.records]}


def _ts(s: str) -> Optional[float]:
    import time as _t
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ"):
        try:
            return _t.mktime(_t.strptime(s, fmt)) - _t.timezone
        except (ValueError, TypeError):
            continue
    return None


def parse_history(history: Sequence[Any], anchor_id: str) -> List[Anchor]:
    """Extract anchors from a condenser account_history result."""
    out: List[Anchor] = []
    for row in history or []:
        if not isinstance(row, (list, tuple)) or len(row) < 2:
            continue
        idx, tx = row[0], row[1]
        if not isinstance(tx, dict):
            continue
        op = tx.get("op")
        if not (isinstance(op, list) and op and op[0] == "custom_json"):
            continue
        d = op[1] if len(op) > 1 and isinstance(op[1], dict) else {}
        if d.get("id") != anchor_id:
            continue
        try:
            j = json.loads(d.get("json") or "{}")
        except json.JSONDecodeError:
            continue
        if not isinstance(j, dict):
            continue
        out.append(Anchor(
            index=idx, timestamp=tx.get("timestamp") or "",
            height=j.get("height"), root=j.get("stateRoot") or j.get("root"),
            epoch=(str(j["epoch"]) if j.get("epoch") is not None else None),
            authority=("posting" if d.get("required_posting_auths")
                       else "active" if d.get("required_auths") else None),
            payload_bytes=len((d.get("json") or "").encode("utf-8"))))
    return out


def detect_forks(anchors: Sequence[Anchor]) -> List[Fork]:
    """Same (epoch, height) carrying more than one distinct root."""
    groups: Dict[Tuple[Optional[str], Any], List[Anchor]] = defaultdict(list)
    for a in anchors:
        if a.height is None or not a.root:
            continue
        groups[(a.epoch, a.height)].append(a)
    out: List[Fork] = []
    for (epoch, height), g in groups.items():
        roots = tuple(sorted({x.root for x in g}))
        if len(roots) < 2:
            continue
        times = [t for t in (_ts(x.timestamp) for x in g) if t is not None]
        span = int(max(times) - min(times)) if len(times) >= 2 else None
        out.append(Fork(height=height, epoch=epoch, roots=roots,
                        records=tuple({"index": x.index, "timestamp": x.timestamp,
                                       "root": x.root} for x in g),
                        span_seconds=span))
    out.sort(key=lambda f: (f.span_seconds is None, f.span_seconds if f.span_seconds is not None else 0))
    return out


def detect_resets(anchors: Sequence[Anchor]) -> List[Dict[str, Any]]:
    """Non-increasing height steps within one epoch - the signature of a restart."""
    out: List[Dict[str, Any]] = []
    prev: Optional[Anchor] = None
    for a in anchors:
        if a.height is None:
            continue
        if prev is not None and prev.epoch == a.epoch and a.height <= prev.height:
            out.append({"index": a.index, "timestamp": a.timestamp,
                        "from": prev.height, "to": a.height,
                        "kind": "repeat" if a.height == prev.height else "reset"})
        prev = a
    return out


def audit(anchors: Sequence[Anchor], budget_bytes: int = 8192) -> Dict[str, Any]:
    """Full report on an anchor stream."""
    if not anchors:
        raise ForkWatchError("no anchors supplied; nothing to audit")
    forks = detect_forks(anchors)
    resets = detect_resets(anchors)
    heights = [a.height for a in anchors if a.height is not None]
    epochs = sorted({a.epoch for a in anchors if a.epoch is not None})
    sizes = [a.payload_bytes for a in anchors if a.payload_bytes]
    auths = defaultdict(int)
    for a in anchors:
        auths[a.authority or "unknown"] += 1
    crit = [f for f in forks if f.severity == "critical"]
    return {
        "anchors": len(anchors),
        "distinctHeights": len(set(heights)),
        "heightsWithMultipleRoots": len({(f.epoch, f.height) for f in forks}),
        "forks": [f.as_dict() for f in forks],
        "criticalForks": len(crit),
        "resets": resets,
        "resetCount": len([r for r in resets if r["kind"] == "reset"]),
        "repeatCount": len([r for r in resets if r["kind"] == "repeat"]),
        "epochs": epochs,
        "epochNamespaced": bool(epochs),
        "authorityCounts": dict(auths),
        "avgPayloadBytes": round(sum(sizes) / len(sizes), 1) if sizes else None,
        "budgetUsedPct": round((sum(sizes) / len(sizes)) / budget_bytes * 100, 2) if sizes else None,
        "verdict": ("FORKED - %d height(s) carry contradictory roots, %d within 5 minutes"
                    % (len({(f.epoch, f.height) for f in forks}), len(crit)) if forks else
                    "no contradictions found"),
    }
