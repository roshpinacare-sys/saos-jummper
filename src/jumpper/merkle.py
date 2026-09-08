"""Merkle tree with inclusion proofs.

Port of the verified-correct merkle.ts from the audited estate:
  - SHA-256 throughout
  - odd node DUPLICATED (tree[n-1] = tree[n-1]), not self-hashed
  - proofs carry an explicit direction, so verification needs no index arithmetic
  - verify() is standalone: root + path only, no tree, no network, no trust

The odd-node rule matters. Duplicating rather than self-hashing avoids the
classic ambiguity and matches the reference implementation already in production.
"""

from __future__ import annotations

import hashlib
from typing import Dict, List, Sequence

HEXLEN = 64


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_pair(left: str, right: str) -> str:
    if len(left) != HEXLEN or len(right) != HEXLEN:
        raise ValueError("hash_pair expects two 64-char hex digests")
    return sha256_hex(bytes.fromhex(left) + bytes.fromhex(right))


def build(leaves: Sequence[str]) -> List[List[str]]:
    """Full tree. levels[0] = leaves, levels[-1] = [root]."""
    if not leaves:
        raise ValueError("cannot build a Merkle tree from zero leaves")
    for leaf in leaves:
        if len(leaf) != HEXLEN:
            raise ValueError("leaf must be 64-char hex, got %d chars" % len(leaf))
    levels: List[List[str]] = [list(leaves)]
    current = list(leaves)
    while len(current) > 1:
        nxt: List[str] = []
        for i in range(0, len(current) - 1, 2):
            nxt.append(hash_pair(current[i], current[i + 1]))
        if len(current) % 2 == 1:
            nxt.append(current[-1])
        levels.append(nxt)
        current = nxt
    return levels


def root(leaves: Sequence[str]) -> str:
    return build(leaves)[-1][0]


def proof(leaves: Sequence[str], index: int) -> List[Dict[str, str]]:
    """Inclusion proof for leaves[index]. Each step is {sibling, dir}."""
    if not 0 <= index < len(leaves):
        raise IndexError("index %d out of range for %d leaves" % (index, len(leaves)))
    levels = build(leaves)
    path: List[Dict[str, str]] = []
    idx = index
    for level in levels[:-1]:
        if idx % 2 == 0:
            if idx + 1 < len(level):
                path.append({"sibling": level[idx + 1], "dir": "right"})
        else:
            path.append({"sibling": level[idx - 1], "dir": "left"})
        idx //= 2
    return path


def verify(leaf: str, path: Sequence[Dict[str, str]], expected_root: str) -> bool:
    """Standalone verification. Needs no tree, no network, no trust in us."""
    if len(leaf) != HEXLEN or len(expected_root) != HEXLEN:
        return False
    current = leaf
    try:
        for step in path:
            sibling = step["sibling"]
            direction = step["dir"]
            if len(sibling) != HEXLEN or direction not in ("left", "right"):
                return False
            current = (
                hash_pair(sibling, current)
                if direction == "left"
                else hash_pair(current, sibling)
            )
    except (KeyError, TypeError, ValueError):
        return False
    return current == expected_root
