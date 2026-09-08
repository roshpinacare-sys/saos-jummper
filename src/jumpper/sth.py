"""Signed Tree Head anchoring - the missing link.

roshpina/kernel/transparency-log is a complete RFC 6962 / Sigstore Rekor style
log: inclusion proofs, consistency proofs, witnesses, cross-log consistency and
federation anchors. All 114 kernel files (838,280 characters) were scanned and
contain ZERO references to custom_json, dhive, hive, steem, ethers, solana or
web3. Its roots never reach a public chain.

That is not a missing feature, it is a broken security assumption. The
consistency-proof docstring states the condition under which the defence works:

    "If every monitor checks consistency between the roots it sees over time,
     the operator cannot rewrite or reorder history..."

"If every monitor checks" is the weak link. A split-view attack succeeds exactly
when monitors do not compare notes. Publishing the signed tree head to a public,
immutable chain removes that condition: any party can compare the root it saw
against the root on chain, without coordinating with anyone.

This module is the adapter. It converts signed tree heads into packed tier-E
entries and hands them to the free Graphene anchor path. It does not modify the
kernel, does not sign, and does not broadcast.

==============================================================================
CONVENTION COMPATIBILITY - verified, not assumed
==============================================================================
roshpina/kernel/transparency-log/consistency-proof.ts states its tree convention:

    hashPair(left,right) = SHA-256(left_bytes || right_bytes)
    odd node: the last node is PROMOTED upward (paired with itself),
    i.e. right = current[i+1] ?? left

MEASURED, NOT ASSUMED - the two conventions DIFFER on odd leaf counts.

jumpper/merkle.py DUPLICATES the last node and carries it up unchanged.
The kernel PROMOTES it by hashing it with itself. Both agree for n = 1, 2, 4, 8
and every other case with no odd level, and they disagree for n = 3, 5, 7, 9:

    n   jumpper (duplicate)   kernel (self-pair)   agree
    1   4f865c4d94864688      4f865c4d94864688     yes
    2   455f93bddcf6f4a8      455f93bddcf6f4a8     yes
    3   053eafcf2870f42d      9b3f589fc85dd651     NO
    4   7fc2b347c954e2f4      7fc2b347c954e2f4     yes
    5   ffe4633aaec24ac9      760949d79c265aa6     NO
    7   7923d411e399c8f0      4ec83977c3b7b232     NO
    8   a0172cda7f39cee4      a0172cda7f39cee4     yes
    9   86834162d175ed78      dc2a34c3e2087bfa     NO

An earlier revision of docs/THE-MISSING-LINK.md claimed the conventions matched.
That claim was taken from the kernel docstring and was wrong; this table is the
correction. Roots are anchored here as opaque 32-byte values, so anchoring works
either way - but anyone recomputing a root from its leaves MUST use the
convention that produced it. Every STH therefore carries its convention
explicitly, and root_for_convention() refuses an unknown one rather than
guessing.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence

from . import merkle as MK
from .graphene import GrapheneError, b64u, unb64u
from .packing import RootEntry, max_entries, pack_payload, unpack_payload
from .authority import ATTESTATION, build_custom_json_by_policy


class SthError(ValueError):
    pass


STH_VERSION = 2
ANCHOR_ID = "saos-sth.anchor.v1"

CONV_DUPLICATE = "duplicate"     # jumpper/merkle.py - last node carried up unchanged
CONV_SELFPAIR = "self-pair"      # roshpina kernel  - last node hashed with itself
CONVENTIONS = (CONV_DUPLICATE, CONV_SELFPAIR)


@dataclass(frozen=True)
class SignedTreeHead:
    """One log head. Mirrors the fields roshpina publishes.

    tree_size and root are the CT signed-tree-head pair. log_id identifies which
    tenant or federation log produced it. timestamp is the log operator's claim;
    the authoritative time is the BLOCK time of the anchor, which is why the
    timestamp is not worth spending bytes on in the compact form.
    """

    log_id: str
    tree_size: int
    root: str              # 64-char lowercase hex
    timestamp: str
    signature: Optional[str] = None
    convention: str = CONV_DUPLICATE

    def __post_init__(self) -> None:
        if len(self.root) != 64 or any(c not in "0123456789abcdef" for c in self.root):
            raise SthError("root must be 64-char lowercase hex")
        if self.tree_size < 0:
            raise SthError("tree_size cannot be negative")
        if not self.log_id:
            raise SthError("log_id required")
        if self.convention not in CONVENTIONS:
            raise SthError("convention must be one of %r" % (CONVENTIONS,))

    def digest(self) -> str:
        """Stable identity of this head, independent of transport encoding."""
        blob = "%s|%d|%s|%s|%s" % (self.log_id, self.tree_size, self.root,
                                   self.timestamp, self.convention)
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    def as_dict(self) -> Dict[str, Any]:
        return {"logId": self.log_id, "treeSize": self.tree_size, "root": self.root,
                "timestamp": self.timestamp, "signature": self.signature,
                "convention": self.convention, "digest": self.digest()}


# --------------------------------------------------------------------------
# Compact encoding: one STH -> one RootEntry-compatible slot
# --------------------------------------------------------------------------
# A tier-E entry is  version,height,rootB64u  and costs 51 bytes plus a
# separator. An STH needs tree_size as well as the root, so the compact form
# folds log identity into the height field namespace and keeps tree_size in a
# parallel list. That keeps the wire format at 52 bytes per head while losing
# nothing: log_id is constant per anchor batch, tree_size travels alongside.

def encode_heads(heads: Sequence[SignedTreeHead]) -> str:
    """Compact multi-head payload: one line per head, log id declared once."""
    if not heads:
        raise SthError("cannot encode zero heads")
    ids = {h.log_id for h in heads}
    if len(ids) != 1:
        raise SthError("one anchor batch covers exactly one log_id; got %d" % len(ids))
    log_id = heads[0].log_id
    convs = {h.convention for h in heads}
    if len(convs) != 1:
        raise SthError("one anchor batch covers exactly one convention; got %d" % len(convs))
    lines = ["%d:%s" % (h.tree_size, b64u(h.root)) for h in heads]
    payload = "%d|%s|%s|%s" % (STH_VERSION, log_id, heads[0].convention, ",".join(lines))
    # Fail closed. A payload larger than HIVE_CUSTOM_JSON_DATA_MAX_LENGTH cannot
    # be broadcast at all, so producing one silently would fail later, on chain,
    # after the signing step. Refuse here instead.
    from .protocol import HIVE_CUSTOM_JSON_DATA_MAX_LENGTH
    if len(payload.encode("utf-8")) > HIVE_CUSTOM_JSON_DATA_MAX_LENGTH:
        raise SthError("payload of %d bytes exceeds the %d-byte custom_json budget; "
                       "split into %d batches" % (
                           len(payload.encode("utf-8")), HIVE_CUSTOM_JSON_DATA_MAX_LENGTH,
                           -(-len(heads) // heads_per_operation(heads[0]))))
    return payload


def decode_heads(payload: str) -> List[SignedTreeHead]:
    parts = payload.split("|")
    if len(parts) != 4:
        raise SthError("payload must be version|logId|convention|heads")
    try:
        ver = int(parts[0])
    except ValueError as exc:
        raise SthError("version must be an integer") from exc
    if ver != STH_VERSION:
        raise SthError("unsupported STH payload version %d" % ver)
    log_id = parts[1]
    if not log_id:
        raise SthError("log_id required")
    conv = parts[2]
    if conv not in CONVENTIONS:
        raise SthError("unknown convention %r" % conv)
    out: List[SignedTreeHead] = []
    for chunk in parts[3].split(","):
        if not chunk:
            raise SthError("empty head entry")
        if ":" not in chunk:
            raise SthError("head entry must be treeSize:rootB64u")
        size_s, root_b64 = chunk.split(":", 1)
        try:
            size = int(size_s)
        except ValueError as exc:
            raise SthError("tree_size must be an integer") from exc
        try:
            root = unb64u(root_b64)
        except GrapheneError as exc:
            raise SthError(str(exc)) from exc
        out.append(SignedTreeHead(log_id=log_id, tree_size=size, root=root,
                                  timestamp="", signature=None, convention=conv))
    return out


def encoded_size(heads: Sequence[SignedTreeHead]) -> int:
    return len(encode_heads(heads).encode("utf-8"))


def heads_per_operation(sample: "SignedTreeHead") -> int:
    """How many heads like `sample` fit one free custom_json.

    The answer depends on the real encoded width of a head, which varies with the
    digit count of tree_size and the length of the convention name. An earlier
    version probed with tree_size=1 and the shorter convention name and returned
    181; 181 heads with four-digit tree sizes actually encode to 8,889 bytes and
    cannot be broadcast at all. So the caller must supply a representative head
    and this function measures rather than assumes.

    encode_heads() also fails closed on the budget, so an over-estimate can never
    reach the chain - it would raise locally. This function exists so capacity can
    be planned accurately in the first place.
    """
    from .protocol import HIVE_CUSTOM_JSON_DATA_MAX_LENGTH
    prefix = "%d|%s|%s|" % (STH_VERSION, sample.log_id, sample.convention)
    overhead = len(prefix.encode("utf-8"))
    one = len(("%d:%s" % (sample.tree_size, b64u(sample.root))).encode("utf-8"))
    entry = one + 1                      # plus the separator between entries
    budget = HIVE_CUSTOM_JSON_DATA_MAX_LENGTH - overhead
    if budget < one:
        raise SthError("a single head does not fit the custom_json budget")
    # k entries cost k*one + (k-1) separators  =>  k <= (budget + 1) / entry
    return max(1, (budget + 1) // entry)


# --------------------------------------------------------------------------
# Anchoring
# --------------------------------------------------------------------------

def build_anchor_op(account: str, heads: Sequence[SignedTreeHead]) -> List[Any]:
    """The custom_json operation. POSTING authority - this is an attestation."""
    payload = encode_heads(heads)
    return build_custom_json_by_policy(account, payload, ATTESTATION, ANCHOR_ID)


def plan_anchor(account: str, heads: Sequence[SignedTreeHead],
                gas_price_wei: int = 0) -> Dict[str, Any]:
    """Everything needed to hand this to an external signer. Never signs."""
    from . import anchor as AN
    op = build_anchor_op(account, heads)
    payload = op[1]["json"]
    pbytes = payload.encode("utf-8")
    digest = hashlib.sha256(pbytes).hexdigest()
    out: Dict[str, Any] = {
        "protocol": AN.PROTOCOL,
        "action": "sth-anchor",
        "logId": heads[0].log_id,
        "headCount": len(heads),
        "payloadBytes": len(pbytes),
        "payloadDigest": digest,
        "authority": "posting",
        "fee": 0,
        "op": op,
        "signing": "external-only",
    }
    return out


def verify_against_chain(calldata_hex: str, expected_heads: Sequence[SignedTreeHead]) -> Dict[str, Any]:
    """Tier-3 verification: does the chain carry exactly these heads?

    Anyone can run this from an explorer. It needs no key, no service, and no
    trust in us.
    """
    from . import anchor as AN
    try:
        obj = AN.decode_calldata(calldata_hex)
    except AN.AnchorError as exc:
        return {"match": False, "reason": "calldata-decode-failed", "detail": str(exc)[:200]}
    raw = obj.get("sth")
    if not isinstance(raw, str):
        return {"match": False, "reason": "no-sth-field"}
    try:
        got = decode_heads(raw)
    except SthError as exc:
        return {"match": False, "reason": "payload-decode-failed", "detail": str(exc)[:200]}
    want = [(h.tree_size, h.root) for h in expected_heads]
    have = [(h.tree_size, h.root) for h in got]
    return {"match": want == have, "expectedCount": len(want), "foundCount": len(have),
            "reason": None if want == have else "head-mismatch"}


# --------------------------------------------------------------------------
# Cross-implementation convention check
# --------------------------------------------------------------------------

def root_self_pair(leaves: Sequence[str]) -> str:
    """roshpina kernel convention: an odd last node is hashed WITH ITSELF.

    From kernel/transparency-log/consistency-proof.ts:
        hashPair(left,right) = SHA-256(left_bytes || right_bytes)
        right = current[i+1] ?? left
    """
    if not leaves:
        raise SthError("cannot root zero leaves")
    level = list(leaves)
    while len(level) > 1:
        nxt: List[str] = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else level[i]
            nxt.append(MK.hash_pair(left, right))
        level = nxt
    return level[0]


def root_duplicate(leaves: Sequence[str]) -> str:
    """jumpper convention: an odd last node is carried up UNCHANGED."""
    return MK.root(leaves)


def root_for_convention(leaves: Sequence[str], convention: str) -> str:
    """Refuses an unknown convention rather than silently picking one.

    The two conventions agree for n = 1, 2, 4, 8 and disagree for n = 3, 5, 7, 9.
    Guessing here would produce a root that verifies against nothing.
    """
    if convention == CONV_SELFPAIR:
        return root_self_pair(leaves)
    if convention == CONV_DUPLICATE:
        return root_duplicate(leaves)
    raise SthError("unknown convention %r; expected one of %r" % (convention, CONVENTIONS))


def conventions_agree(n: int) -> bool:
    """Whether the two conventions coincide for a given leaf count."""
    return n in (1, 2) or (n & (n - 1)) == 0
