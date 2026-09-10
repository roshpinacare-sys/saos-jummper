"""Height uniqueness - the guard that would have prevented the public forks.

WHAT IS ON THE CHAIN, INDEPENDENTLY RE-DERIVED
---------------------------------------------
162 `saos-dex.anchor.v1` operations by `headcorner`, read from
condenser_api.get_account_history (500 entries) on 2026-09-10, spanning
2026-09-03T02:58:06 to 2026-09-10T18:03:06 via api.openhive.network.

    distinct heights                 153
    heights carrying >1 distinct root   8
    height sequence resets              6
    height sequence repeats             4
    epoch or namespace field            NONE, in any payload
    authority mix                       active 123, posting 39

The two tightest collisions:

    height 1764   #49833 2026-09-09T18:27:21  root d7220b5e9ecc953e7e8d...
                  #49834 2026-09-09T18:27:51  root 84ae0a0a08ef2f44becc...
                  30 seconds apart, both signed, both permanent

    height 1668   #49824 18:19:18 root 74b29867195898f6691c...
                  #49825 18:22:36 root e375e0f5d7fe98c69ea7...
                  198 seconds apart

    height 552    THREE anchors, THREE distinct roots, seven minutes

A verifier asking what the state was at height 1764 gets two contradictory
answers, thirty seconds apart, both signed by the same key, both permanent, and
the ledger supports both. Anyone can cite whichever suits them.

WHY IT HAPPENS
--------------
The height counter is per-process. The pulse chain restarts and the counter
begins again near 12, re-publishing low heights with fresh roots that collide
with heights already committed under different roots. Six resets in seven days.

This is not a bug in the anchor layer. The anchor layer did its job perfectly: it
published faithfully, at zero fee, permanently. The bug is that nothing checked
whether the commitment contradicted one already on chain BEFORE publishing.

THE TWO FIXES, BOTH SMALL
-------------------------
1. Add an epoch. A namespace per process incarnation makes (epoch, height) unique
   even when the counter restarts at 12. One field in the payload.

2. Check before publishing. A root that contradicts an already-anchored root at
   the same key must refuse, not overwrite. That is what HeightLedger does.

Note the interaction with budget.py: the repeat guard there blocks IDENTICAL
operations. This is the opposite failure - DIFFERENT payloads at the SAME key.
Neither guard alone catches both.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

ALLOW = "allow"
REFUSE = "refuse"
REPUBLISH = "republish-idempotent"


class HeightGuardError(ValueError):
    pass


@dataclass(frozen=True)
class Commitment:
    epoch: str
    height: int
    root: str
    timestamp: str
    block: Optional[int] = None
    tx_id: Optional[str] = None

    @property
    def key(self) -> Tuple[str, int]:
        return (self.epoch, self.height)


@dataclass
class HeightLedger:
    """What has already been committed, keyed by (epoch, height).

    A height with no epoch is filed under the empty string, which is itself a
    finding: it means the stream cannot distinguish one process incarnation from
    another, and that is exactly what produced the eight public forks."""

    entries: Dict[Tuple[str, int], List[Commitment]] = field(default_factory=dict)

    def add(self, c: Commitment) -> None:
        if not isinstance(c.height, int) or isinstance(c.height, bool):
            raise HeightGuardError("height must be an integer")
        if not c.root or len(c.root) != 64:
            raise HeightGuardError("root must be a 64-char hex digest")
        self.entries.setdefault(c.key, []).append(c)

    def check(self, epoch: Optional[str], height: int, root: str) -> Dict[str, Any]:
        """May this commitment be published?

        Three outcomes, and the distinction matters:
          allow               nothing at this key yet
          republish-idempotent  same root already there - safe, no contradiction
          refuse              a DIFFERENT root already there - publishing would
                              create a public contradiction that cannot be undone"""
        ep = epoch or ""
        if not isinstance(height, int) or isinstance(height, bool):
            raise HeightGuardError("height must be an integer")
        if not root or len(root) != 64:
            raise HeightGuardError("root must be a 64-char hex digest")
        prior = self.entries.get((ep, height), [])
        if not prior:
            missing_epoch = ep == ""
            return {"decision": ALLOW, "epoch": ep, "height": height, "root": root,
                    "priorCount": 0, "missingEpoch": missing_epoch,
                    "reason": ("no prior commitment at this key" if not missing_epoch else
                               "no prior commitment, but no epoch was supplied - a restart "
                               "will collide with this height")}
        same = [p for p in prior if p.root == root]
        diff = [p for p in prior if p.root != root]
        if diff:
            return {"decision": REFUSE, "epoch": ep, "height": height, "root": root,
                    "priorCount": len(prior), "conflictingCount": len(diff),
                    "conflicts": [{"root": p.root, "timestamp": p.timestamp,
                                   "block": p.block, "txId": p.tx_id} for p in diff],
                    "missingEpoch": ep == "",
                    "reason": ("a different root is already committed at (%r, %s); "
                               % (ep, height) +
                               "publishing would create a permanent public contradiction")}
        return {"decision": REPUBLISH, "epoch": ep, "height": height, "root": root,
                "priorCount": len(prior), "conflictingCount": 0, "missingEpoch": ep == "",
                "reason": "the same root is already committed; republishing is harmless"}

    def forks(self) -> List[Dict[str, Any]]:
        """Every key carrying more than one distinct root."""
        out = []
        for (ep, h), cs in sorted(self.entries.items(), key=lambda kv: (kv[0][0], kv[0][1])):
            roots = {c.root for c in cs}
            if len(roots) > 1:
                ordered = sorted(cs, key=lambda c: c.timestamp or "")
                out.append({"epoch": ep, "height": h, "anchors": len(cs),
                            "distinctRoots": len(roots), "roots": sorted(roots),
                            "firstAt": ordered[0].timestamp, "lastAt": ordered[-1].timestamp,
                            "records": [{"root": c.root, "timestamp": c.timestamp,
                                         "block": c.block, "txId": c.tx_id} for c in ordered]})
        return out

    def resets(self, ordered: Sequence[Commitment]) -> List[Dict[str, Any]]:
        """Non-increasing steps in a time-ordered stream, scoped per epoch."""
        out = []
        last: Dict[str, int] = {}
        for c in ordered:
            prev = last.get(c.epoch)
            if prev is not None and c.height < prev:
                out.append({"epoch": c.epoch, "from": prev, "to": c.height,
                            "at": c.timestamp, "drop": prev - c.height})
            elif prev is not None and c.height == prev:
                out.append({"epoch": c.epoch, "from": prev, "to": c.height,
                            "at": c.timestamp, "drop": 0, "repeat": True})
            last[c.epoch] = c.height
        return out


def audit(stream: Sequence[Commitment]) -> Dict[str, Any]:
    """Full verdict over an anchor stream."""
    if not stream:
        raise HeightGuardError("empty stream; nothing to audit")
    led = HeightLedger()
    for c in stream:
        led.add(c)
    ordered = sorted(stream, key=lambda c: c.timestamp or "")
    fk = led.forks()
    rs = led.resets(ordered)
    hard = len([x for x in rs if not x.get("repeat")])
    no_epoch = all((c.epoch or "") == "" for c in stream)
    verdict = ("CLEAN - no height carries contradictory roots" if not fk else
               "FORKED - %d height(s) carry contradictory roots" % len(fk))
    epochs = sorted({(c.epoch or "") for c in stream})
    return {"verdict": verdict, "anchors": len(stream),
            "distinctKeys": len(led.entries), "forks": len(fk),
            "forkDetails": fk, "resets": hard,
            "repeats": len([x for x in rs if x.get("repeat")]),
            "resetDetails": rs,
            "epochPresent": not no_epoch,
            "epochs": epochs,
            "epochAdvice": (None if not no_epoch else
                             "no payload carries an epoch field; a process restart will "
                             "re-publish low heights and collide with committed roots")}


def remediation_report(stream: Sequence[Commitment], log_id: str = "saos-dex.anchor.v1",
                       chain: str = "hive") -> Dict[str, Any]:
    """A machine-readable correction record for heights that already forked.

    The eight forked heights on HIVE mainnet are permanent. They cannot be
    retracted, and no amount of new code removes them. What CAN be done is publish
    a record so precise that a verifier who encounters one knows it is ambiguous
    rather than silently picking whichever root they found first.

    DELIBERATELY NOT DONE: declaring a canonical root. The chain cannot support
    that judgement. Two signed commitments at the same height are both real; which
    one the state machine actually produced is a fact about the operator's process,
    not about the ledger. Picking the earliest would be a convention dressed as a
    finding, and a verifier who trusted it would be trusting us rather than the
    chain. So every forked height is reported as AMBIGUOUS with all of its roots,
    and the operator must publish which one is authoritative if any is.
    """
    if not stream:
        raise HeightGuardError("empty stream; nothing to remediate")
    led = HeightLedger()
    for c in stream:
        led.add(c)
    fk = led.forks()
    ordered = sorted(stream, key=lambda c: c.timestamp or "")
    rs = led.resets(ordered)
    heights = [c.height for c in ordered]
    entries = []
    for f in fk:
        recs = f["records"]
        entries.append({
            "height": f["height"],
            "epoch": f["epoch"] or None,
            "status": "AMBIGUOUS",
            "canonicalRoot": None,
            "distinctRoots": f["distinctRoots"],
            "anchorCount": f["anchors"],
            "firstCommittedAt": f["firstAt"],
            "lastCommittedAt": f["lastAt"],
            "windowSeconds": _span_seconds(f["firstAt"], f["lastAt"]),
            "records": recs,
            "resolution": ("the chain cannot decide which root is authoritative; "
                           "the operator must publish that, or every verifier will "
                           "pick a different one"),
        })
    entries.sort(key=lambda e: (-(e["windowSeconds"] if e["windowSeconds"] is not None else 10**9),
                                e["height"]))
    return {
        "logId": log_id, "chain": chain,
        "generatedFrom": "%d anchors over %d distinct heights" % (len(stream), len({c.key for c in stream})),
        "heightRange": [min(heights), max(heights)] if heights else None,
        "forkedHeights": len(fk),
        "epochPresent": any((c.epoch or "") != "" for c in stream),
        "counterResets": len([x for x in rs if not x.get("repeat")]),
        "counterRepeats": len([x for x in rs if x.get("repeat")]),
        "entries": entries,
        "remedy": [
            "add an epoch field to the payload so (epoch, height) is unique across "
            "process incarnations - one field, and it prevents every future fork",
            "run HeightLedger.check() before broadcasting; it refuses a root that "
            "contradicts one already committed at the same key",
            "publish which root is authoritative for each forked height, or state "
            "plainly that none is",
            "do not delete or rewrite these records - they are permanent and a "
            "correction that hides the original is worse than the original",
        ],
    }


def _span_seconds(a: Optional[str], b: Optional[str]) -> Optional[int]:
    """Seconds between two ISO-8601 timestamps, or None if either is unusable."""
    if not a or not b:
        return None
    try:
        ta = time.strptime(a, "%Y-%m-%dT%H:%M:%S")
        tb = time.strptime(b, "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return None
    return int(time.mktime(tb) - time.mktime(ta))
