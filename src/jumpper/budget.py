"""Budget and repeat guards - the control that would have stopped the leak.

WHY THIS MODULE EXISTS
----------------------
A live defect was measured on HIVE mainnet on 2026-09-08: eleven identical calls
to Hive-Engine hive.convert with quantity 9.632, spread over 31 hours, every one
of them doomed (the account holds no SWAP.HIVE), every one of them landing on
chain and consuming RC. At the measured aggregate cost of 157.7M RC per operation
that is roughly 1.73e9 RC - about a third of one day's entire regeneration budget
- spent on an operation that can never succeed. It was still running when read.

Nothing stopped it, because nothing was counting. Per-operation checks pass: each
individual call is small, well-formed and authorised. The damage is in the
REPETITION and the CUMULATIVE total, and no control in the estate looked at
either.

roshpina/kernel/policy/spend-budget-guard.ts already states this precisely for
fiat and API spend:

    "Per-action value thresholds stop ONE big action. They do NOT stop a runaway
     agent making thousands of individually-small actions whose SUM is enormous -
     the exact pattern behind the surprise five-figure bills people get from a
     loop gone wrong or a mispriced call."

That kernel is fail-closed throughout, and so is this module. The rules:

    - a guard that cannot determine the answer DENIES. It never allows by default.
    - missing budget data, malformed input, unknown chain, expired window, and any
      internal error all resolve to deny with a stated reason.
    - a denial carries the exact overage or the exact repeat count, so the caller
      can act on it instead of guessing.

Nothing here signs, broadcasts, or reads a key. It answers one question before an
operation happens: is this allowed to proceed?
"""

from __future__ import annotations

import hashlib
import json
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, Iterable, List, Optional, Sequence, Tuple

ALLOW = "allow"
DENY = "deny"


class BudgetError(ValueError):
    pass


# --------------------------------------------------------------------------
# Verdicts
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Verdict:
    decision: str
    guard: str
    reason: str
    detail: Dict[str, Any] = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        return self.decision == ALLOW

    def as_dict(self) -> Dict[str, Any]:
        return {"decision": self.decision, "guard": self.guard,
                "reason": self.reason, "detail": dict(self.detail)}


def deny(guard: str, reason: str, **detail: Any) -> Verdict:
    return Verdict(DENY, guard, reason, detail)


def allow(guard: str, reason: str, **detail: Any) -> Verdict:
    return Verdict(ALLOW, guard, reason, detail)


# --------------------------------------------------------------------------
# Rolling cumulative budget
# --------------------------------------------------------------------------

@dataclass
class RollingBudget:
    """Tenant/chain-scoped rolling-window cumulative spend cap.

    Answers BEFORE the operation: does this pending spend fit the remaining
    budget? If not, deny with the exact overage.

    Fail-closed on every ambiguous input. A budget with no limit configured
    denies, because an unconfigured cap is not the same as an infinite one.
    """

    limit: int
    window_seconds: int
    unit: str = "rc"
    scope: str = "default"
    _events: Deque[Tuple[int, int]] = field(default_factory=deque)

    def __post_init__(self) -> None:
        if not isinstance(self.limit, int) or self.limit <= 0:
            raise BudgetError("limit must be a positive integer; an unconfigured cap denies")
        if not isinstance(self.window_seconds, int) or self.window_seconds <= 0:
            raise BudgetError("window_seconds must be a positive integer")
        if not self.unit:
            raise BudgetError("unit required")

    def _prune(self, now: int) -> None:
        cutoff = now - self.window_seconds
        while self._events and self._events[0][0] < cutoff:
            self._events.popleft()

    def spent(self, now: Optional[int] = None) -> int:
        now = int(time.time()) if now is None else int(now)
        self._prune(now)
        return sum(a for _, a in self._events)

    def remaining(self, now: Optional[int] = None) -> int:
        return max(0, self.limit - self.spent(now))

    def check(self, amount: int, now: Optional[int] = None) -> Verdict:
        """Does `amount` fit? Never records - use commit() after the op succeeds."""
        now = int(time.time()) if now is None else int(now)
        if not isinstance(amount, int):
            return deny("budget", "amount must be an integer", scope=self.scope, unit=self.unit)
        if amount < 0:
            return deny("budget", "amount cannot be negative", scope=self.scope, amount=amount)
        if amount == 0:
            return deny("budget", "a zero-cost claim is a bug, not a free operation",
                        scope=self.scope, unit=self.unit)
        try:
            self._prune(now)
            used = sum(a for _, a in self._events)
        except Exception as exc:                                   # fail closed
            return deny("budget", "internal error while computing spend: %s" % type(exc).__name__,
                        scope=self.scope)
        if used + amount > self.limit:
            return deny("budget", "cumulative cap exceeded",
                        scope=self.scope, unit=self.unit, limit=self.limit,
                        spentInWindow=used, requested=amount,
                        overage=used + amount - self.limit,
                        remaining=max(0, self.limit - used),
                        windowSeconds=self.window_seconds)
        return allow("budget", "fits remaining budget",
                     scope=self.scope, unit=self.unit, requested=amount,
                     spentInWindow=used, remainingAfter=self.limit - used - amount)

    def commit(self, amount: int, now: Optional[int] = None) -> None:
        """Record a spend that actually happened. Call only after success."""
        now = int(time.time()) if now is None else int(now)
        if not isinstance(amount, int) or amount < 0:
            raise BudgetError("commit requires a non-negative integer amount")
        self._events.append((now, amount))
        self._prune(now)

    def state(self, now: Optional[int] = None) -> Dict[str, Any]:
        now = int(time.time()) if now is None else int(now)
        used = self.spent(now)
        return {"scope": self.scope, "unit": self.unit, "limit": self.limit,
                "windowSeconds": self.window_seconds, "spentInWindow": used,
                "remaining": max(0, self.limit - used),
                "eventCount": len(self._events),
                "utilisationPct": round(used / self.limit * 100, 2) if self.limit else None}


# --------------------------------------------------------------------------
# Repeat guard - the control the convert loop needed
# --------------------------------------------------------------------------

def fingerprint(op: Any) -> str:
    """Stable identity of an operation, independent of dict ordering."""
    blob = json.dumps(op, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


@dataclass
class RepeatGuard:
    """Blocks the same operation from being broadcast more than `max_repeats`
    times inside `window_seconds`.

    This is the control that was missing when hive.convert quantity 9.632 was
    broadcast eleven times over 31 hours against a balance that never moved.
    Each call was individually valid. The eleventh was not a decision, it was a
    loop, and nothing in the path could tell the difference.

    Fail-closed: an operation whose fingerprint cannot be computed is denied.
    """

    max_repeats: int = 1
    window_seconds: int = 86400
    _seen: Dict[str, List[int]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.max_repeats < 1:
            raise BudgetError("max_repeats must be >= 1")
        if self.window_seconds <= 0:
            raise BudgetError("window_seconds must be positive")

    def _prune(self, key: str, now: int) -> List[int]:
        cutoff = now - self.window_seconds
        kept = [t for t in self._seen.get(key, []) if t >= cutoff]
        self._seen[key] = kept
        return kept

    def check(self, op: Any, now: Optional[int] = None) -> Verdict:
        now = int(time.time()) if now is None else int(now)
        try:
            fp = fingerprint(op)
        except (TypeError, ValueError) as exc:
            return deny("repeat", "cannot fingerprint operation: %s" % type(exc).__name__)
        seen = self._prune(fp, now)
        if len(seen) >= self.max_repeats:
            return deny("repeat", "identical operation already broadcast %d time(s) in window"
                        % len(seen),
                        fingerprint=fp[:16], priorCount=len(seen),
                        maxRepeats=self.max_repeats,
                        firstAt=min(seen) if seen else None,
                        lastAt=max(seen) if seen else None,
                        windowSeconds=self.window_seconds,
                        hint="a repeating identical operation is a loop, not a decision")
        return allow("repeat", "not a repeat", fingerprint=fp[:16], priorCount=len(seen))

    def commit(self, op: Any, now: Optional[int] = None) -> str:
        now = int(time.time()) if now is None else int(now)
        fp = fingerprint(op)
        self._prune(fp, now)
        self._seen.setdefault(fp, []).append(now)
        return fp

    def counts(self, now: Optional[int] = None) -> Dict[str, int]:
        now = int(time.time()) if now is None else int(now)
        return {k[:16]: len(self._prune(k, now)) for k in list(self._seen)}


# --------------------------------------------------------------------------
# Composed gate
# --------------------------------------------------------------------------

@dataclass
class AnchorGate:
    """Every pre-broadcast check, in order, AND-composed.

    Mirrors roshpina GuardEvaluator semantics: ALL guards must allow; any deny
    denies; a guard that raises is treated as a deny, never as a pass.
    """

    budget: Optional[RollingBudget] = None
    repeat: Optional[RepeatGuard] = None
    require_mainnet: bool = True

    def evaluate(self, op: Any, cost: int, network: Optional[str] = None,
                 now: Optional[int] = None) -> Verdict:
        now = int(time.time()) if now is None else int(now)
        checks: List[Verdict] = []

        if self.require_mainnet:
            n = (network or "").lower()
            if not n:
                checks.append(deny("network", "no network declared; refusing to assume mainnet"))
            elif any(t in n for t in ("devnet", "testnet", "sepolia", "goerli", "holesky",
                                      "shasta", "nile")):
                checks.append(deny("network", "non-mainnet endpoint", network=network))
            elif "mainnet" not in n:
                checks.append(deny("network", "network not recognisably mainnet; fail closed",
                                   network=network))
            else:
                checks.append(allow("network", "mainnet", network=network))

        controls = 0
        for guard, arg in ((self.repeat, op), (self.budget, cost)):
            if guard is None:
                continue
            controls += 1
            try:
                checks.append(guard.check(arg, now))
            except Exception as exc:
                name = type(guard).__name__
                checks.append(deny(name, "guard raised %s; fail closed" % type(exc).__name__))

        # require_mainnet is a routing check, not a spend or repeat control. An
        # anchor with neither is an unguarded value-bearing action and denies.
        if controls == 0:
            return deny("gate", "no budget or repeat guard configured; "
                                "an unguarded value-bearing action denies",
                        checks=[c.as_dict() for c in checks])

        denies = [c for c in checks if not c.allowed]
        if denies:
            first = denies[0]
            # Preserve the denying guard's own detail (overage, priorCount, hint).
            # A denial without the number the caller needs is not actionable.
            merged = dict(first.detail)
            merged["deniedBy"] = [c.guard for c in denies]
            merged["checks"] = [c.as_dict() for c in checks]
            return Verdict(DENY, first.guard, first.reason, merged)
        return Verdict(ALLOW, "gate", "all guards allowed",
                       {"checks": [c.as_dict() for c in checks]})

    def commit(self, op: Any, cost: int, now: Optional[int] = None) -> None:
        """Record only after the broadcast actually succeeded."""
        now = int(time.time()) if now is None else int(now)
        if self.repeat is not None:
            self.repeat.commit(op, now)
        if self.budget is not None:
            self.budget.commit(cost, now)
