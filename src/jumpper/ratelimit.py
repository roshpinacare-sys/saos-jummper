"""Rate limit - the same discipline as budget.py, applied to an HTTP quota.

WHY THIS EXISTS
---------------
193 recorded GateRun rows were read from Saosmartwallet/db/custom.db. 101 did not
reach done. Of the 36 recorded errors, 17 - almost half - are one string:

    API request failed with status 429: {"error":"Too many requests, pleas...

100 of the 193 runs have origin=schedule, so this is automated traffic on a fixed
cadence meeting a limit that is not modelled anywhere. The runs die rather than
waiting.

budget.py already solves this shape of problem for Resource Credits: measure the
resource, project how it regenerates, and refuse a plan that would exceed it
rather than discovering the refusal from the network. This is that module, for a
request quota.

WHAT IT DOES
------------
    RateBudget      a sliding or fixed window quota with a known refill rate
    next_available  when the next request may be sent
    plan            whether n requests fit now, or when they will
    backoff         a Retry-After-aware delay with jitter and a cap
    concurrency     how many may be in flight at once

It never sleeps and never sends. It answers when it would be safe to, so the
caller can decide - and an unknown limit is a refusal, not an assumption.

FAIL-CLOSED, AND WHY THAT DIRECTION
-------------------------------------
An unknown or zero limit refuses rather than allowing everything. Guessing
generously is what produced 17 dead runs; guessing strictly costs a delay. The
asymmetry is not close."""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence

ALLOW = "allow"
DELAY = "delay"
REFUSE = "refuse"


class RateLimitError(ValueError):
    pass


@dataclass(frozen=True)
class RateBudget:
    """A quota that refills at a known rate.

    limit      requests allowed per window
    window_s   window length in seconds
    available  requests currently available, if known; None means unknown
    as_of      the timestamp the reading was taken, in seconds
    max_inflight  concurrency cap; 1 serialises, which is the safe default for a
                 limit that is enforced per connection rather than per account"""

    limit: int
    window_s: float
    available: Optional[float] = None
    as_of: float = 0.0
    max_inflight: int = 1

    def __post_init__(self) -> None:
        if not isinstance(self.limit, int) or isinstance(self.limit, bool):
            raise RateLimitError("limit must be an integer")
        if self.limit < 0:
            raise RateLimitError("limit cannot be negative")
        if self.window_s <= 0:
            raise RateLimitError("window_s must be positive")
        if self.available is not None:
            if not isinstance(self.available, (int, float)) or isinstance(self.available, bool):
                raise RateLimitError("available must be a number or None")
            if self.available < 0:
                raise RateLimitError("available cannot be negative")
        if not isinstance(self.max_inflight, int) or self.max_inflight < 1:
            raise RateLimitError("max_inflight must be an integer >= 1")

    @property
    def refill_per_second(self) -> float:
        return self.limit / self.window_s

    def projected(self, now: float) -> float:
        """Available now, projected forward from the reading - not the snapshot.

        This is the bug budget.py was written to fix on the RC side: a stored
        snapshot compared against a constant under-reported what was actually
        available by 52.6x and declared a chain blocked while it worked."""
        if self.limit == 0:
            return 0.0
        if self.available is None:
            # No reading, so no projection is possible. Returning the full limit here
            # would be optimistic in exactly the direction that produced 17 dead runs:
            # a caller would send and discover the real balance from a 429. The value
            # is still returned so a caller that must proceed can, but plan() marks the
            # result as resting on an assumption rather than a measurement.
            return float(self.limit)
        elapsed = max(0.0, now - self.as_of)
        return min(float(self.limit), self.available + self.refill_per_second * elapsed)

    def next_available(self, now: float) -> float:
        """Seconds until at least one request may be sent."""
        avail = self.projected(now)
        if avail >= 1.0:
            return 0.0
        if self.limit == 0:
            raise RateLimitError("a limit of zero never refills; no wait makes it "
                                 "available, so refuse rather than delay forever")
        return (1.0 - avail) / self.refill_per_second

    def plan(self, n: int, now: float) -> Dict[str, Any]:
        """Whether n requests fit now, or when they will.

    Returns allow, delay-with-a-wait, or refuse. A delay is only returned when the
    wait is finite and bounded by the window; beyond that it is a refusal."""
        if not isinstance(n, int) or isinstance(n, bool) or n < 0:
            raise RateLimitError("n must be a non-negative integer")
        if n == 0:
            return {"decision": ALLOW, "waitSeconds": 0.0, "reason": "nothing to send"}
        avail = self.projected(now)
        if self.limit == 0:
            return {"decision": REFUSE, "waitSeconds": None,
                    "reason": "the limit is zero and never refills"}
        assumed = self.available is None
        if avail >= n:
            return {"decision": ALLOW, "waitSeconds": 0.0, "available": avail,
                    "availabilityAssumed": assumed,
                    "reason": ("%d of %d available" % (n, int(avail)) if not assumed else
                               "%d of %d assumed available - no reading was supplied, so "
                               "this rests on the limit being unused, not on a measurement"
                               % (n, int(avail)))}
        need = n - avail
        wait = need / self.refill_per_second
        if wait > self.window_s:
            return {"decision": REFUSE, "waitSeconds": wait, "available": avail,
                    "availabilityAssumed": assumed,
                    "reason": "waiting %.1f s exceeds the %.1f s window; split the "
                              "batch rather than stalling" % (wait, self.window_s)}
        return {"decision": DELAY, "waitSeconds": wait, "available": avail,
                "availabilityAssumed": assumed,
                "reason": "%d available, %d requested; ready in %.1f s"
                        % (int(avail), n, wait)}


def backoff(attempt: int, retry_after: Optional[float] = None,
            base_s: float = 1.0, cap_s: float = 60.0,
            jitter: float = 0.25, rng: Optional[Any] = None) -> Dict[str, Any]:
    """A Retry-After-aware delay.

    A server that says when to come back is obeyed; one that does not gets
    exponential growth with jitter. Jitter matters because every scheduled run in
    the fleet fires on the same cadence, so identical backoffs make them all retry
    at the same instant and hit the same limit again."""
    if not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 0:
        raise RateLimitError("attempt must be a non-negative integer")
    if base_s <= 0 or cap_s <= 0:
        raise RateLimitError("base_s and cap_s must be positive")
    if cap_s < base_s:
        raise RateLimitError("cap_s cannot be below base_s")
    if not (0.0 <= jitter <= 1.0):
        raise RateLimitError("jitter must be between 0 and 1")
    if retry_after is not None:
        if not isinstance(retry_after, (int, float)) or isinstance(retry_after, bool):
            raise RateLimitError("retry_after must be a number or None")
        if retry_after < 0:
            raise RateLimitError("retry_after cannot be negative")
        return {"waitSeconds": float(retry_after), "source": "retry-after",
                "attempt": attempt, "capped": False}
    exp = min(cap_s, base_s * (2.0 ** attempt))
    r = rng if rng is not None else random
    delta = exp * jitter * (r.random() * 2.0 - 1.0)
    wait = max(0.0, min(cap_s, exp + delta))
    return {"waitSeconds": wait, "source": "exponential", "attempt": attempt,
            "uncapped": exp, "capped": exp >= cap_s}


def parse_retry_after(headers: Any) -> Optional[float]:
    """Extract Retry-After from a header mapping. None when absent or unparseable.

    An unparseable value is None rather than zero: treating a malformed header as
    no delay would retry immediately and hit the same limit."""
    if not isinstance(headers, dict):
        return None
    for k, v in headers.items():
        if isinstance(k, str) and k.lower() == "retry-after":
            try:
                f = float(str(v).strip())
            except (TypeError, ValueError):
                return None
            return f if f >= 0 else None
    return None


def schedule(n: int, budget: RateBudget, now: float,
             max_wait_s: Optional[float] = None) -> Dict[str, Any]:
    """Split n requests across the window instead of stalling on one big wait.

    The fleet failure was 100 scheduled runs meeting a limit at once. Sending them
    as one batch and waiting is the wrong shape; sending them in slices that each
    fit the quota is the right one, and this says how many slices and how far apart."""
    if not isinstance(n, int) or isinstance(n, bool) or n < 0:
        raise RateLimitError("n must be a non-negative integer")
    if n == 0:
        return {"slices": [], "sliceCount": 0, "totalWaitSeconds": 0.0}
    if budget.limit == 0:
        raise RateLimitError("a limit of zero can never be scheduled")
    per = max(1, int(budget.limit))
    slices: List[Dict[str, Any]] = []
    remaining = n
    t = float(now)
    first = True
    while remaining > 0:
        take = min(per, remaining)
        p = budget.plan(take, t)
        if p["decision"] == REFUSE:
            if not first:
                break
            return {"slices": [], "sliceCount": 0, "refused": True,
                    "reason": p["reason"]}
        wait = float(p.get("waitSeconds") or 0.0)
        if max_wait_s is not None and wait > max_wait_s:
            return {"slices": slices, "sliceCount": len(slices), "truncated": True,
                    "remaining": remaining,
                    "reason": "the next slice would wait %.1f s, over the %.1f s cap"
                              % (wait, max_wait_s)}
        slices.append({"at": t + wait, "count": take, "waitSeconds": wait})
        t = t + wait + (budget.window_s if not first or wait > 0 else 0.0)
        remaining -= take
        first = False
    total = (slices[-1]["at"] - now) if slices else 0.0
    return {"slices": slices, "sliceCount": len(slices),
            "scheduled": n - remaining, "remaining": remaining,
            "totalWaitSeconds": total,
            "verdict": ("%d request(s) in %d slice(s), last at +%.1f s"
                        % (n - remaining, len(slices), total))}
