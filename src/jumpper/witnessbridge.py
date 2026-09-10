"""Witness bridge - publishing roshpina's signed tree heads to a free public ledger.

THE TWO HALVES ALREADY EXIST
----------------------------
roshpina/kernel/transparency-log/witness.ts (9,964 chars, revision v387) implements
the Certificate-Transparency witness model. Its own header states the property:

    Consistency proofs (v379) make a split-view DETECTABLE by any monitor that
    compares the roots it sees over time. Witnessing makes split-view IMPOSSIBLE TO
    HIDE: independent third parties observe the log's signed tree head and CO-SIGN
    it. To fork the log the operator would have to get a QUORUM of independent
    witnesses to sign the fork. A receipt holder then checks not just "the operator
    signed this root" but "K independent witnesses also signed this exact root."

The exact shapes, read from source:

    WITNESS_STATEMENT_VERSION = "tfa-witness-v1"
    interface TreeHeadObservation { logId, root, treeSize, observedAt, witnessId }
    interface WitnessStatement { version, logId, root (64-hex SHA-256), treeSize,
                                 observedAt (ISO-8601), witnessId, algorithm,
                                 signature (base64 over the canonical payload) }
    witnessSigningPayload(obs) = canonicalJson({ version, logId, root, treeSize,
                                                 observedAt, witnessId })
    interface WitnessQuorumResult { reached, distinctWitnesses, threshold, witnessIds[] }
    SplitViewError code "SPLIT_VIEW" - a witness signing a DIFFERENT root for the
    same (logId, treeSize)

THE GAP
-------
The witness model makes a fork require witness collusion. But the statements live
wherever the collector put them. A receipt holder can only check "K independent
witnesses signed this exact root" if they can OBTAIN those statements - and the
only party that reliably has them is the operator being checked. The property is
real but not self-serve: it depends on the operator handing over the evidence that
constrains them. Nothing in the kernel publishes them - 838,280 characters contain
zero references to any blockchain.

THE BRIDGE
----------
Publish the quorum commitment to a free public ledger. graphene.py and packing.py
already do this at zero fee: 8,192 bytes per custom_json, POSTING authority,
verified against 21 real anchors on HIVE mainnet.

Per log head the commitment is:

    logId : treeSize : rootB64u : witnessCount : witnessSetDigestB64u

The root binds WHAT was witnessed; the count and set digest bind WHO witnessed it,
so a party holding the statements can prove the anchored set is the one that
signed, and a party holding nothing can still see that a quorum existed. The
signatures are too large to anchor (88+ bytes base64 each) and need not be: they
verify off-chain against the anchored root and set digest.

WHAT THIS MODULE NEVER DOES
---------------------------
It does not sign, broadcast, or read a key. It does NOT verify witness signatures -
that needs each witness's public key, which the kernel holds. Every result carries
signaturesVerified: false rather than implying a check that did not happen.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Sequence, Tuple

from .graphene import b64u, unb64u
from .authority import ATTESTATION, build_custom_json_by_policy

WITNESS_STATEMENT_VERSION = "tfa-witness-v1"
BRIDGE_ANCHOR_ID = "saos-witness-quorum.v1"
BRIDGE_VERSION = 1
ISO8601 = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$")
CUSTOM_JSON_BUDGET = 8192


class WitnessBridgeError(ValueError):
    pass


class SplitViewError(ValueError):
    """Two witnesses signed different roots for the same (logId, treeSize)."""


@dataclass(frozen=True)
class Statement:
    log_id: str
    root: str
    tree_size: int
    observed_at: str
    witness_id: str
    algorithm: str
    signature: str
    version: str = WITNESS_STATEMENT_VERSION

    @property
    def key(self) -> Tuple[str, int]:
        return (self.log_id, self.tree_size)

    def as_dict(self) -> Dict[str, Any]:
        return {"version": self.version, "logId": self.log_id, "root": self.root,
                "treeSize": self.tree_size, "observedAt": self.observed_at,
                "witnessId": self.witness_id, "algorithm": self.algorithm,
                "signature": self.signature}


def signing_payload(s: Statement) -> str:
    """Byte-compatible with witnessSigningPayload in the kernel.

    canonicalJson sorts keys, so only the field set and values matter. Reproducing
    it exactly is what lets a kernel-issued signature be re-verified against an
    anchored root.
    """
    return json.dumps({"version": s.version, "logId": s.log_id, "root": s.root,
                       "treeSize": s.tree_size, "observedAt": s.observed_at,
                       "witnessId": s.witness_id},
                      sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def parse_statement(raw: Dict[str, Any]) -> Statement:
    """Validate against the kernel interface. Malformed is an error, never a default."""
    if not isinstance(raw, dict):
        raise WitnessBridgeError("statement must be an object")
    for f in ("version", "logId", "root", "treeSize", "observedAt", "witnessId",
              "algorithm", "signature"):
        if f not in raw:
            raise WitnessBridgeError("statement is missing required field %r" % f)
    if raw["version"] != WITNESS_STATEMENT_VERSION:
        raise WitnessBridgeError("unsupported statement version %r" % raw["version"])
    root = raw["root"]
    if not isinstance(root, str) or len(root) != 64 or any(c not in "0123456789abcdef" for c in root):
        raise WitnessBridgeError("root must be 64-char lowercase hex")
    ts = raw["treeSize"]
    if not isinstance(ts, int) or isinstance(ts, bool) or ts < 0:
        raise WitnessBridgeError("treeSize must be a non-negative integer")
    if not isinstance(raw["observedAt"], str) or not ISO8601.match(raw["observedAt"]):
        raise WitnessBridgeError("observedAt must be ISO-8601")
    if not raw["logId"] or not raw["witnessId"]:
        raise WitnessBridgeError("logId and witnessId are required")
    return Statement(log_id=raw["logId"], root=root, tree_size=ts,
                     observed_at=raw["observedAt"], witness_id=raw["witnessId"],
                     algorithm=raw["algorithm"], signature=raw["signature"])


def detect_split_view(statements: Sequence[Statement]) -> List[Dict[str, Any]]:
    """Every (logId, treeSize) carrying more than one distinct root."""
    groups: Dict[Tuple[str, int], Dict[str, List[str]]] = {}
    for s in statements:
        groups.setdefault(s.key, {}).setdefault(s.root, []).append(s.witness_id)
    out = []
    for (log_id, size), by_root in groups.items():
        if len(by_root) > 1:
            out.append({"logId": log_id, "treeSize": size,
                        "distinctRoots": sorted(by_root),
                        "witnessesByRoot": {r: sorted(w) for r, w in sorted(by_root.items())}})
    return out


def quorum(statements: Sequence[Statement], log_id: str, tree_size: int,
           threshold: int) -> Dict[str, Any]:
    """Mirror of collectWitnessQuorum: distinct witnesses on one root.

    This counts DISTINCT WITNESS IDS. It does NOT verify signatures - that needs
    each witness's public key, which the kernel holds and this module does not.
    signaturesVerified is therefore always false, and a caller that has not
    verified signatures is counting claims, not witnesses.
    """
    if threshold < 1:
        raise WitnessBridgeError("threshold must be >= 1")
    matching = [s for s in statements if s.log_id == log_id and s.tree_size == tree_size]
    conflicts = detect_split_view(matching)
    if conflicts:
        raise SplitViewError("split view on (%s, %d): %d distinct roots"
                             % (log_id, tree_size, len(conflicts[0]["distinctRoots"])))
    if not matching:
        return {"reached": False, "distinctWitnesses": 0, "threshold": threshold,
                "witnessIds": [], "root": None, "signaturesVerified": False}
    ids = sorted({s.witness_id for s in matching})
    return {"reached": len(ids) >= threshold, "distinctWitnesses": len(ids),
            "threshold": threshold, "witnessIds": ids, "root": matching[0].root,
            "signaturesVerified": False}


def witness_set_digest(witness_ids: Sequence[str]) -> str:
    """Binds WHICH witnesses signed, so an anchored count cannot be inflated later."""
    blob = json.dumps(sorted(set(witness_ids)), separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class QuorumCommitment:
    log_id: str
    tree_size: int
    root: str
    witness_count: int
    witness_set_digest: str

    def encode(self) -> str:
        return "%s:%d:%s:%d:%s" % (self.log_id, self.tree_size, b64u(self.root),
                                   self.witness_count, b64u(self.witness_set_digest))

    @property
    def encoded_bytes(self) -> int:
        return len(self.encode().encode("utf-8"))


def commitment_from_quorum(log_id: str, tree_size: int, q: Dict[str, Any]) -> QuorumCommitment:
    if not q.get("root"):
        raise WitnessBridgeError("quorum has no root; nothing to commit")
    return QuorumCommitment(log_id=log_id, tree_size=tree_size, root=q["root"],
                            witness_count=q["distinctWitnesses"],
                            witness_set_digest=witness_set_digest(q["witnessIds"]))


def decode_commitment(s: str) -> QuorumCommitment:
    parts = s.split(":")
    if len(parts) != 5:
        raise WitnessBridgeError("commitment must be logId:treeSize:rootB64u:count:setDigestB64u")
    try:
        size = int(parts[1]); count = int(parts[3])
    except ValueError as exc:
        raise WitnessBridgeError("treeSize and witnessCount must be integers") from exc
    try:
        root = unb64u(parts[2]); digest = unb64u(parts[4])
    except Exception as exc:
        raise WitnessBridgeError("malformed base64url field: %s" % exc) from exc
    if len(root) != 64 or len(digest) != 64:
        raise WitnessBridgeError("root and set digest must each decode to 32 bytes")
    return QuorumCommitment(log_id=parts[0], tree_size=size, root=root,
                            witness_count=count, witness_set_digest=digest)


def pack_commitments(commitments: Sequence[QuorumCommitment], sep: str = ";") -> str:
    if not commitments:
        raise WitnessBridgeError("cannot pack zero commitments")
    payload = "%d|%s" % (BRIDGE_VERSION, sep.join(c.encode() for c in commitments))
    n = len(payload.encode("utf-8"))
    if n > CUSTOM_JSON_BUDGET:
        raise WitnessBridgeError("payload of %d bytes exceeds the %d-byte custom_json "
                                 "budget; split it" % (n, CUSTOM_JSON_BUDGET))
    return payload


def unpack_commitments(payload: str, sep: str = ";") -> List[QuorumCommitment]:
    parts = payload.split("|")
    if len(parts) != 2:
        raise WitnessBridgeError("payload must be version|commitments")
    try:
        ver = int(parts[0])
    except ValueError as exc:
        raise WitnessBridgeError("version must be an integer") from exc
    if ver != BRIDGE_VERSION:
        raise WitnessBridgeError("unsupported bridge payload version %d" % ver)
    if not parts[1]:
        raise WitnessBridgeError("empty commitment list")
    return [decode_commitment(c) for c in parts[1].split(sep)]


def max_commitments_that_fit(commitments: Sequence[QuorumCommitment],
                             budget: int = CUSTOM_JSON_BUDGET) -> int:
    """Largest prefix of commitments whose packed payload fits the budget.

    Measured on the real encodings, never extrapolated from one sample. An earlier
    version did extrapolate and returned 80 for a list whose real encodings ran
    8,231 bytes - log ids and tree sizes grow in digit width along the list, so a
    single sample under-counts. pack_commitments caught it and refused, which is
    the fail-closed behaviour working, but a capacity function that over-promises
    makes callers build payloads that cannot be sent.
    """
    if not commitments:
        raise WitnessBridgeError("cannot size an empty list")
    lo, hi, best = 0, len(commitments), 0
    while lo <= hi:
        mid = (lo + hi) // 2
        if mid == 0:
            best = 0; lo = mid + 1; continue
        try:
            pack_commitments(list(commitments[:mid]))
            best = mid; lo = mid + 1
        except WitnessBridgeError:
            hi = mid - 1
    return best


def split_into_operations(commitments: Sequence[QuorumCommitment],
                          budget: int = CUSTOM_JSON_BUDGET) -> List[List[QuorumCommitment]]:
    """Chunk a list so every chunk packs into one free custom_json.

    Raises if a single commitment does not fit alone - that is a design error, not
    something to work around by silently dropping it.
    """
    if not commitments:
        raise WitnessBridgeError("cannot split an empty list")
    overhead = len(("%d|" % BRIDGE_VERSION).encode())
    for c in commitments:
        if c.encoded_bytes + overhead > budget:
            raise WitnessBridgeError("commitment for log %r does not fit the budget alone" % c.log_id)
    out: List[List[QuorumCommitment]] = []
    rest = list(commitments)
    while rest:
        n = max_commitments_that_fit(rest, budget)
        if n < 1:
            raise WitnessBridgeError("cannot fit one commitment; unreachable by construction")
        out.append(rest[:n]); rest = rest[n:]
    return out


def commitments_per_operation(sample: QuorumCommitment) -> int:
    """PLANNER ESTIMATE ONLY - use max_commitments_that_fit for a real payload.

    Assumes every commitment encodes to the sample's width. Encodings vary with the
    digit width of logId and treeSize, so this can over-promise. pack_commitments
    fails closed regardless; this exists only for capacity planning.
    """
    overhead = len(("%d|" % BRIDGE_VERSION).encode())
    per = sample.encoded_bytes + 1
    budget = CUSTOM_JSON_BUDGET - overhead
    if budget < sample.encoded_bytes:
        raise WitnessBridgeError("a single commitment does not fit the budget")
    return max(1, (budget + 1) // per)


def build_anchor_op(account: str, commitments: Sequence[QuorumCommitment]) -> List[Any]:
    """The zero-fee custom_json. POSTING authority - this is an attestation."""
    return build_custom_json_by_policy(account, pack_commitments(commitments),
                                       ATTESTATION, BRIDGE_ANCHOR_ID)


def plan(account: str, commitments: Sequence[QuorumCommitment]) -> Dict[str, Any]:
    """Everything needed to hand this to an external signer. Signs nothing."""
    op = build_anchor_op(account, commitments)
    payload = op[1]["json"]
    n = len(payload.encode("utf-8"))
    return {"account": account, "anchorId": BRIDGE_ANCHOR_ID, "authority": "posting",
            "fee": 0, "commitments": len(commitments), "payloadBytes": n,
            "budgetBytes": CUSTOM_JSON_BUDGET,
            "budgetUsedPct": round(n / CUSTOM_JSON_BUDGET * 100, 2),
            "commitmentsPerOperation": max_commitments_that_fit(list(commitments)),
            "plannerEstimatePerOperation": commitments_per_operation(commitments[0]),
            "signing": "external-only", "broadcast": "never-performed-here",
            "signaturesVerified": False,
            "note": "witness signatures are NOT verified here; that needs their public keys"}
