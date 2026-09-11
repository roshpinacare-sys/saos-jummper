"""Epoch lifecycle - the piece that stops forks instead of reporting them.

heightguard.HeightLedger answers 'may this commitment be published?' and refuses
when a different root already sits at the same (epoch, height). Correct and
necessary - but after the fact: by the time it can refuse, the height has already
collided.

Nothing in the estate assigns epochs. relay.ts (58,025 chars), relay-sol.ts
(12,981), relay-eth.ts (12,899) and chain.ts (64,434) were all searched: the word
'epoch' appears ZERO times in all four. The anchor payload is still

    { protocol: "saos-dex/v1", action: "chain-seal", at: job.at,
      height: job.info.toHeight, stateRoot: job.info.stateRoot, digest: ... }

and job.info.toHeight comes from a counter that starts again on every process
incarnation. Measured on the real stream: 6 counter resets, 4 repeats, 10
non-increasing steps, 8 heights carrying two or three contradictory roots -
height 1764 with two roots thirty seconds apart, height 552 with three in seven
minutes.

This module assigns an epoch BEFORE the broadcast, bumping it whenever the counter
fails to increase, so (epoch, height) is unique across process incarnations by
construction rather than by detection.

WHY BUMP ON NON-INCREASING RATHER THAN ON RESTART
-------------------------------------------------
A restart is not observable from inside the payload builder, and a process can
restart without the counter resetting if it reloads state. A non-increasing height
IS observable, and it is the only condition under which a collision can occur.
Bumping on it is sufficient and minimal: a monotonic stream never bumps.

It is also conservative in the right direction. Bumping unnecessarily costs one
extra epoch and creates no contradiction. Not bumping when it was necessary
creates a permanent public fork. The asymmetry is not close.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from .heightguard import Commitment, HeightLedger

CONTINUE = "continue"
BUMPED = "bumped"
FIRST = "first"
PUBLISHABLE = ("allow", "republish-idempotent")


class EpochError(ValueError):
    pass


@dataclass
class EpochTracker:
    """Assigns epochs so (epoch, height) never collides across incarnations.

    State is three values: the epoch index, the highest height seen in it, and
    whether anything has been seen at all. Small enough to persist in one line and
    reload on start - which is what makes it survive a restart, the thing the bare
    counter does not do."""

    log_id: str = "saos-dex.anchor.v1"
    epoch_format: str = "e%d"
    _epoch_index: int = 0
    _last_height: Optional[int] = None
    _bumps: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def epoch(self) -> str:
        return self.epoch_format % self._epoch_index

    @property
    def bumps(self) -> List[Dict[str, Any]]:
        return list(self._bumps)

    def state(self) -> Dict[str, Any]:
        """Persistable. Reload with from_state() on start."""
        return {"logId": self.log_id, "epochIndex": self._epoch_index,
                "epoch": self.epoch, "lastHeight": self._last_height,
                "bumpCount": len(self._bumps)}

    @classmethod
    def from_state(cls, st: Dict[str, Any]) -> "EpochTracker":
        if not isinstance(st, dict):
            raise EpochError("state must be an object")
        t = cls(log_id=st.get("logId") or "saos-dex.anchor.v1")
        idx = st.get("epochIndex")
        if idx is not None:
            if not isinstance(idx, int) or isinstance(idx, bool) or idx < 0:
                raise EpochError("epochIndex must be a non-negative integer")
            t._epoch_index = idx
        lh = st.get("lastHeight")
        if lh is not None:
            if not isinstance(lh, int) or isinstance(lh, bool) or lh < 0:
                raise EpochError("lastHeight must be a non-negative integer")
            t._last_height = lh
        return t

    def assign(self, height: int) -> Dict[str, Any]:
        """Return the epoch this height belongs to, bumping first if it must.

        Every return path carries an 'epoch' key, so the caller puts it straight
        into the payload without deciding between epochBefore and epochAfter."""
        if not isinstance(height, int) or isinstance(height, bool):
            raise EpochError("height must be an integer")
        if height < 0:
            raise EpochError("height cannot be negative")
        if self._last_height is None:
            self._last_height = height
            return {"epoch": self.epoch, "action": FIRST, "height": height,
                    "previousHeight": None, "epochIndex": self._epoch_index,
                    "reason": "first height in this epoch"}
        if height > self._last_height:
            prev = self._last_height
            self._last_height = height
            return {"epoch": self.epoch, "action": CONTINUE, "height": height,
                    "previousHeight": prev, "epochIndex": self._epoch_index,
                    "reason": "monotonic; no bump needed"}
        prev = self._last_height
        rec = {"epochBefore": self.epoch, "previousHeight": prev, "height": height,
               "reason": ("height repeated" if height == prev else "height went backwards")}
        self._epoch_index += 1
        self._last_height = height
        rec["epochAfter"] = self.epoch
        rec["action"] = BUMPED
        self._bumps.append(rec)
        rec["epoch"] = self.epoch
        rec["epochIndex"] = self._epoch_index
        return dict(rec)


def assign_stream(heights: Sequence[int], log_id: str = "saos-dex.anchor.v1") -> Dict[str, Any]:
    """Run a whole height sequence through the tracker and report the epochs.

    The test is the real sequence that produced the eight forks: with the tracker
    every (epoch, height) pair is unique, so two different roots can never land on
    the same key again."""
    t = EpochTracker(log_id=log_id)
    out: List[Dict[str, Any]] = [t.assign(h) for h in heights]
    pairs = [(r["epoch"], r["height"]) for r in out]
    return {"assignments": out, "epochs": sorted({p[0] for p in pairs}),
            "bumpCount": len(t.bumps), "uniquePairs": len(set(pairs)),
            "totalPairs": len(pairs), "collisions": len(pairs) - len(set(pairs)),
            "state": t.state()}


def guard_before_broadcast(tracker: EpochTracker, ledger: HeightLedger,
                           height: int, root: str,
                           timestamp: Optional[str] = None) -> Dict[str, Any]:
    """The complete pre-broadcast gate: assign an epoch, then ask the ledger.

    Order matters. The epoch must exist before check() is called, otherwise check()
    files the commitment under the empty epoch and the collision it is meant to
    prevent is already recorded."""
    a = tracker.assign(height)
    verdict = ledger.check(a["epoch"], height, root)
    decision = verdict.get("decision")
    publish = decision in PUBLISHABLE
    if publish:
        # Commitment has no log_id field and requires a timestamp string; passing
        # None would raise inside the function whose whole job is to decide whether
        # a broadcast is safe.
        ledger.add(Commitment(epoch=a["epoch"], height=height, root=root,
                              timestamp=timestamp or ""))
    return {"epoch": a["epoch"], "epochAction": a["action"], "height": height,
            "root": root, "ledger": verdict, "publish": publish,
            "decision": decision, "reason": verdict.get("reason")}
