"""Batch accumulation and sealing.

A batch seals on whichever condition hits first:
    max_leaves  (default 1000)
    max_age     (default 300 seconds)

Heights are monotonic and unique; one root maps to exactly one height. This
in-memory store enforces the same invariants the production store must.

Concurrency: the production pattern is a transactional append behind a write
mutex with retry on unique-constraint and lock-contention errors, plus an
idempotency key so a repeated submission returns the existing root rather than
forking. That pattern is already proven at 8/8 concurrent seals with contiguous
heights in the audited estate and ports directly. The lock below is the
single-process equivalent.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from . import merkle
from .claim import Claim


class BatchError(RuntimeError):
    pass


@dataclass
class SealedBatch:
    height: int
    root: str
    leaf_count: int
    sealed_at: float
    seal_reason: str = ""
    leaf_hashes: List[str] = field(default_factory=list)
    proofs: Dict[str, list] = field(default_factory=dict)


class Batcher:
    def __init__(self, max_leaves: int = 1000, max_age: float = 300.0):
        if max_leaves < 1:
            raise BatchError("max_leaves must be >= 1")
        if max_age <= 0:
            raise BatchError("max_age must be > 0")
        self.max_leaves = max_leaves
        self.max_age = max_age
        self._lock = threading.Lock()
        self._open: List[Claim] = []
        self._opened_at: Optional[float] = None
        self._height = 0
        self.sealed: List[SealedBatch] = []
        self._roots: Dict[str, int] = {}

    @property
    def height(self) -> int:
        return self._height

    @property
    def open_count(self) -> int:
        with self._lock:
            return len(self._open)

    def open_age(self, now: Optional[float] = None) -> float:
        with self._lock:
            if self._opened_at is None:
                return 0.0
            return (now or time.time()) - self._opened_at

    def add(self, claim: Claim, now: Optional[float] = None) -> Optional[SealedBatch]:
        now = time.time() if now is None else now
        with self._lock:
            if not self._open:
                self._opened_at = now
            self._open.append(claim)
            if len(self._open) >= self.max_leaves:
                return self._seal_locked(now, "max_leaves")
            return None

    def seal_if_due(self, now: Optional[float] = None) -> Optional[SealedBatch]:
        now = time.time() if now is None else now
        with self._lock:
            if not self._open or self._opened_at is None:
                return None
            if (now - self._opened_at) >= self.max_age:
                return self._seal_locked(now, "max_age")
            return None

    def force_seal(self, now: Optional[float] = None) -> Optional[SealedBatch]:
        now = time.time() if now is None else now
        with self._lock:
            if not self._open:
                return None
            return self._seal_locked(now, "forced")

    def _seal_locked(self, now: float, reason: str) -> SealedBatch:
        leaves = [c.leaf_hash for c in self._open]
        rt = merkle.root(leaves)
        if rt in self._roots:
            return self.sealed[self._roots[rt] - 1]
        self._height += 1
        proofs = {lh: merkle.proof(leaves, i) for i, lh in enumerate(leaves)}
        sb = SealedBatch(height=self._height, root=rt, leaf_count=len(leaves),
                         sealed_at=now, seal_reason=reason, leaf_hashes=leaves, proofs=proofs)
        self.sealed.append(sb)
        self._roots[rt] = self._height
        self._open = []
        self._opened_at = None
        return sb

    def assert_consistent(self) -> None:
        heights = [b.height for b in self.sealed]
        if heights != list(range(1, len(heights) + 1)):
            raise BatchError("heights not contiguous from 1: %r" % (heights[:20],))
        seen = set()
        for b in self.sealed:
            if b.root in seen:
                raise BatchError("duplicate root at height %d" % b.height)
            seen.add(b.root)
            if merkle.root(b.leaf_hashes) != b.root:
                raise BatchError("root mismatch at height %d" % b.height)
            for lh in b.leaf_hashes:
                if not merkle.verify(lh, b.proofs[lh], b.root):
                    raise BatchError("proof failed at height %d" % b.height)
