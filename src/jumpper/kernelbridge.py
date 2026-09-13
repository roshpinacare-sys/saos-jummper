"""Kernel bridge - roshpina transparency-log artifacts to free public anchors.

THE MISSING LINK, CONCRETELY
----------------------------
roshpina/kernel is 838,280 characters across 114 files and contains zero
references to any blockchain. Its consistency defence is stated as working "if
every monitor checks", which is the assumption a split-view attack breaks. Three
artifact types already exist and are already signed:

    SignedTreeHead     logId, treeSize, root, timestamp, signature, convention
    WitnessStatement   version, logId, root, treeSize, observedAt, witnessId,
                       algorithm, signature
    FederationAnchor   version, anchorId, logA{logId,root,treeSize},
                       logB{...}, anchoredAt, signerId, signature

Nothing publishes any of them. sth.py packs 148-177 signed tree heads per free
custom_json and witnessbridge.py packs witness quorums, but the federation anchor
- the artifact that proves two independent logs agreed at one instant - had no
bridge at all, and nothing combined the three into one plan.

This module closes both gaps. It parses each artifact against the kernel's own
declared shape, encodes them compactly for the 8,192-byte free budget, and
produces one plan saying how many zero-fee operations the whole transparency log
needs to become publicly checkable.

It never signs, never broadcasts and never verifies a signature - that needs each
signer's public key, which the kernel holds. Every result says so rather than
implying a check that did not happen."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence

from .graphene import b64u, unb64u
from .authority import ATTESTATION, build_custom_json_by_policy
from .protocol import HIVE_CUSTOM_JSON_DATA_MAX_LENGTH

FED_ANCHOR_ID = "saos-federation-anchor.v1"
FED_VERSION = 1
HEX64 = re.compile(r"^[0-9a-f]{64}$")
ISO = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$")
BUDGET = HIVE_CUSTOM_JSON_DATA_MAX_LENGTH


class KernelBridgeError(ValueError):
    pass


@dataclass(frozen=True)
class LogEndpoint:
    log_id: str
    root: str
    tree_size: int


@dataclass(frozen=True)
class FederationCommitment:
    anchor_id: str
    log_a: LogEndpoint
    log_b: LogEndpoint
    anchored_at: str
    signer_id: str

    def encode(self) -> str:
        return "%s:%s:%d:%s:%s:%d:%s" % (
            self.anchor_id, b64u(self.log_a.root), self.log_a.tree_size,
            b64u(self.log_b.root), self.log_b.tree_size, 0, self.signer_id)

    @property
    def encoded_bytes(self) -> int:
        return len(self.encode().encode("utf-8"))


def _hex64(v: Any, field: str) -> str:
    if not isinstance(v, str) or not HEX64.match(v):
        raise KernelBridgeError("%s must be a 64-char lowercase hex digest" % field)
    return v


def _posint(v: Any, field: str) -> int:
    if not isinstance(v, int) or isinstance(v, bool) or v < 0:
        raise KernelBridgeError("%s must be a non-negative integer" % field)
    return v


def _iso(v: Any, field: str) -> str:
    if not isinstance(v, str) or not ISO.match(v):
        raise KernelBridgeError("%s must be ISO-8601" % field)
    return v


def parse_endpoint(raw: Any, label: str) -> LogEndpoint:
    """Parse a kernel LogEndpoint. A malformed endpoint is an error, never a default."""
    if not isinstance(raw, dict):
        raise KernelBridgeError("%s must be an object" % label)
    for f in ("logId", "root", "treeSize"):
        if f not in raw:
            raise KernelBridgeError("%s is missing %r" % (label, f))
    if not raw["logId"] or not isinstance(raw["logId"], str):
        raise KernelBridgeError("%s.logId is required" % label)
    return LogEndpoint(log_id=raw["logId"], root=_hex64(raw["root"], label + ".root"),
                       tree_size=_posint(raw["treeSize"], label + ".treeSize"))


def parse_federation_anchor(raw: Dict[str, Any]) -> FederationCommitment:
    """Parse a kernel FederationAnchor against its declared shape."""
    if not isinstance(raw, dict):
        raise KernelBridgeError("anchor must be an object")
    for f in ("anchorId", "logA", "logB", "anchoredAt", "signerId"):
        if f not in raw:
            raise KernelBridgeError("federation anchor is missing %r" % f)
    a = parse_endpoint(raw["logA"], "logA")
    b = parse_endpoint(raw["logB"], "logB")
    if a.log_id == b.log_id and a.root == b.root and a.tree_size == b.tree_size:
        raise KernelBridgeError("logA and logB are the same endpoint; a federation "
                                "anchor binds two DIFFERENT logs")
    if not raw["anchorId"] or not isinstance(raw["anchorId"], str):
        raise KernelBridgeError("anchorId is required")
    if not raw["signerId"] or not isinstance(raw["signerId"], str):
        raise KernelBridgeError("signerId is required")
    return FederationCommitment(anchor_id=raw["anchorId"], log_a=a, log_b=b,
                                anchored_at=_iso(raw["anchoredAt"], "anchoredAt"),
                                signer_id=raw["signerId"])


def encode_federations(cs: Sequence[FederationCommitment], sep: str = ",") -> str:
    """Compact payload: version|logPair|signer|entries. One anchor per entry."""
    if not cs:
        raise KernelBridgeError("cannot encode zero federation anchors")
    if len({(c.log_a.log_id, c.log_b.log_id) for c in cs}) != 1:
        raise KernelBridgeError("one batch covers exactly one log pair")
    if len({c.signer_id for c in cs}) != 1:
        raise KernelBridgeError("one batch carries one signer")
    parts = ["%s:%s:%d:%s:%d" % (c.anchor_id, b64u(c.log_a.root), c.log_a.tree_size,
                                  b64u(c.log_b.root), c.log_b.tree_size) for c in cs]
    head = "%d|%s|%s|%s|%s" % (FED_VERSION, cs[0].log_a.log_id, cs[0].log_b.log_id,
                                cs[0].signer_id, cs[0].anchored_at)
    payload = head + "|" + sep.join(parts)
    n = len(payload.encode("utf-8"))
    if n > BUDGET:
        raise KernelBridgeError("payload of %d bytes exceeds the %d-byte budget; split it"
                                % (n, BUDGET))
    return payload


def build_federation_op(account: str, cs: Sequence[FederationCommitment]) -> List[Any]:
    """The zero-fee custom_json. POSTING authority - this is an attestation."""
    return build_custom_json_by_policy(account, encode_federations(cs), ATTESTATION, FED_ANCHOR_ID)


def federations_per_operation(sample: FederationCommitment) -> int:
    """How many federation anchors fit one free operation. A PLANNER ESTIMATE - the
    real width varies with anchorId and signerId length, so encode and measure
    before relying on it."""
    per = sample.encoded_bytes + 40
    if per > BUDGET:
        raise KernelBridgeError("a single federation anchor does not fit the budget")
    return max(1, BUDGET // per)


def plan(account: str, federations: Sequence[FederationCommitment] = (),
         heads: Sequence[Any] = (), statements: Sequence[Any] = ()) -> Dict[str, Any]:
    """One plan for the whole transparency log: how many free operations it takes

    to make every artifact publicly checkable. Signs nothing and broadcasts
    nothing; the counts are what an operator needs in order to decide."""
    from . import sth as STH
    from . import witnessbridge as WB
    out: Dict[str, Any] = {"account": account, "authority": "posting", "fee": 0,
                           "signing": "external-only",
                           "broadcast": "never-performed-here",
                           "signaturesVerified": False, "budgetBytes": BUDGET}
    ops = 0
    if heads:
        per = STH.heads_per_operation(heads[0])
        n = (len(heads) + per - 1) // per
        out["signedTreeHeads"] = len(heads)
        out["headsPerOperation"] = per
        out["headOperations"] = n
        ops += n
    if statements:
        n = (len(statements) + 60 - 1) // 60
        out["witnessStatements"] = len(statements)
        out["witnessOperations"] = n
        ops += n
    if federations:
        per = federations_per_operation(federations[0])
        n = (len(federations) + per - 1) // per
        out["federationAnchors"] = len(federations)
        out["federationsPerOperation"] = per
        out["federationOperations"] = n
        ops += n
    out["totalOperations"] = ops
    out["totalFee"] = 0
    out["verdict"] = ("%d artifact(s) publishable in %d zero-fee operation(s)"
                      % (len(heads) + len(statements) + len(federations), ops))
    return out
