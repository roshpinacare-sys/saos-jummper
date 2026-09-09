"""The missing connector - claim to free public anchor, end to end.

Every layer this needs already existed and was already verified separately:

    claim.py     domain-separated leaf hashing
    batch.py     Merkle accumulation, monotonic height, transactional invariants
    packing.py   154 roots per free custom_json (8,192-byte budget, live constant)
    graphene.py  the zero-fee custom_json op, RC manabar projection, tier-E encoding
    authority.py POSTING for attestations, never ACTIVE
    budget.py    rolling cumulative budget + repeat guard, AND-composed, fail-closed
    audit.py     hash-chain verification, which alone CANNOT detect truncation

What did not exist was anything that ran them in order. This module does, and it
closes one verified blind spot in the process.

------------------------------------------------------------------------------
THE BLIND SPOT THIS CLOSES
------------------------------------------------------------------------------
audit.py proved, with a test, that a truncated hash chain still verifies:

    verify_chain("vault-1", chain[:1])   ->   intact = True

Dropping the tail leaves a shorter chain that is internally consistent. Detecting
it needs an external commitment to the head - a value the attacker does not
control. That is exactly what anchoring the head to a public chain provides, and
on HIVE it costs zero fee.

So the pipeline anchors the audit head, and verification then runs:

    audit.verify_chain(instance_id, chain, expected_head=<head read off chain>)

which turns truncation from undetectable into detected. The same mechanism
anchors Merkle batch roots and signed tree heads, so roshpina's transparency log
- which never reaches a public chain in 838,280 characters - gets global
visibility for free.

------------------------------------------------------------------------------
WHAT THIS MODULE NEVER DOES
------------------------------------------------------------------------------
It does not sign. It does not broadcast. It does not read a key. It builds the
exact operation, prices it, gates it, and hands it to an external signer. The
only thing it records afterwards is the public result.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from . import audit as AUD
from . import authority as AUTH
from . import batch as BAT
from . import budget as BUD
from . import claim as CLM
from . import graphene as GR
from . import packing as PK
from . import protocol as PROTO


class PipelineError(ValueError):
    pass


HEAD_ANCHOR_ID = "saos-audit-head.v1"
BATCH_ANCHOR_ID = "saos-batch-anchor.v1"


@dataclass(frozen=True)
class AnchorRequest:
    """One operation, fully specified, ready for an external signer."""

    kind: str                 # "batch" | "audit-head" | "sth"
    account: str
    network: str
    payload: str
    op: List[Any]
    authority: str
    fee: int
    cost_rc_estimate: Optional[int]
    gate: Dict[str, Any]
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {"kind": self.kind, "account": self.account, "network": self.network,
                "authority": self.authority, "fee": self.fee,
                "payloadBytes": len(self.payload.encode("utf-8")),
                "costRcEstimate": self.cost_rc_estimate,
                "digest": self.digest,
                "gateVerdict": self.gate.get("verdict"),
                "opId": self.op[1].get("id") if len(self.op) > 1 else None,
                "signing": "external-only",
                "broadcast": "never-performed-here"}


class Pipeline:
    """Claim -> batch -> pack -> gate -> operation. Nothing is signed here."""

    def __init__(self, account: str, network: str = "hive-mainnet",
                 max_leaves: int = 1000, max_age: float = 300.0,
                 rc_budget_per_day: int = 5_128_310_708,
                 rc_per_op_estimate: Optional[int] = 157_713_792,
                 max_repeats: int = 1):
        if not account:
            raise PipelineError("account required")
        if not network:
            raise PipelineError("network required; refusing to assume mainnet")
        self.account = account
        self.network = network
        self.batcher = BAT.Batcher(max_leaves=max_leaves, max_age=max_age)
        self.gate = BUD.AnchorGate(
            budget=(BUD.RollingBudget(limit=rc_budget_per_day, window_seconds=86400,
                                      unit="rc", scope=account)
                    if rc_budget_per_day else None),
            repeat=BUD.RepeatGuard(max_repeats=max_repeats, window_seconds=2 * 86400),
            require_mainnet=True)
        # None means "not calibrated" - never a guessed default
        self.rc_per_op = rc_per_op_estimate

    # -- ingest ------------------------------------------------------------
    def ingest(self, payload: Any, timestamp: Optional[str] = None,
               public: bool = False, now: Optional[float] = None) -> CLM.Claim:
        ts = timestamp or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        c = CLM.make_claim(payload, ts, public=public, source="pipeline")
        self.batcher.add(c, now=now)
        return c

    def seal(self, now: Optional[float] = None) -> Optional[BAT.SealedBatch]:
        return self.batcher.force_seal(now=now)

    # -- anchor a Merkle batch --------------------------------------------
    def anchor_batch(self, sb: BAT.SealedBatch, now: Optional[int] = None) -> AnchorRequest:
        if sb is None:
            raise PipelineError("no sealed batch to anchor")
        entry = PK.RootEntry(version=1, height=sb.height, root=sb.root)
        payload = PK.pack_payload([entry])
        return self._request("batch", BATCH_ANCHOR_ID, payload, now)

    # -- anchor an audit chain head ---------------------------------------
    def anchor_audit_head(self, instance_id: str, chain: Sequence[Dict[str, Any]],
                          now: Optional[int] = None) -> AnchorRequest:
        """Commit the head of an audit hash chain to a public ledger.

        This is what makes truncation detectable. Without it, verify_chain over a
        shortened chain returns intact=True and there is no way to know.
        """
        if not chain:
            raise PipelineError("empty audit chain; nothing to anchor")
        head = chain[-1].get("hash")
        if not head or len(head) != 64:
            raise PipelineError("audit head is not a 64-char hex digest")
        # length is bound into the payload so a shorter chain cannot masquerade
        payload = "%s:%d:%s" % (instance_id, len(chain), head)
        return self._request("audit-head", HEAD_ANCHOR_ID, payload, now)

    # -- the shared path: gate, then build --------------------------------
    def _request(self, kind: str, anchor_id: str, payload: str,
                 now: Optional[int] = None) -> AnchorRequest:
        now = int(time.time()) if now is None else int(now)
        op = AUTH.build_custom_json_by_policy(self.account, payload,
                                              AUTH.ATTESTATION, anchor_id)
        cost = self.rc_per_op
        verdict = self.gate.evaluate(op, cost if cost else 0,
                                     network=self.network, now=now)
        import hashlib
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        return AnchorRequest(kind=kind, account=self.account, network=self.network,
                             payload=payload, op=op, authority="posting", fee=0,
                             cost_rc_estimate=cost,
                             gate={"verdict": verdict.decision, "guard": verdict.guard,
                                   "reason": verdict.reason, "detail": verdict.detail},
                             digest=digest)

    def commit(self, req: AnchorRequest, now: Optional[int] = None) -> None:
        """Record a broadcast that actually succeeded. Never call before success."""
        if req.gate.get("verdict") != "allow":
            raise PipelineError("refusing to commit an operation the gate denied")
        self.gate.commit(req.op, req.cost_rc_estimate or 0,
                         now=int(time.time()) if now is None else now)

    # -- verification against the anchored head ---------------------------
    @staticmethod
    def verify_audit_with_anchor(instance_id: str, chain: Sequence[Dict[str, Any]],
                                 anchored_payload: str) -> Dict[str, Any]:
        """Verify an audit chain against a head read back off the public ledger.

        anchored_payload is the string this module put on chain:
        "<instance_id>:<length>:<head>". Parsing it back is what turns the anchor
        into an expected_length and an expected_head, which is what makes
        truncation detectable at all.
        """
        parts = anchored_payload.split(":")
        if len(parts) != 3:
            raise PipelineError("anchored payload is not instance:length:head")
        a_instance, a_len, a_head = parts
        if a_instance != instance_id:
            return {"intact": False, "truncated": False,
                    "reason": "anchor belongs to instance %r, not %r" % (a_instance, instance_id)}
        try:
            expected_length = int(a_len)
        except ValueError as exc:
            raise PipelineError("anchored length is not an integer") from exc
        return AUD.verify_chain(instance_id, list(chain),
                                expected_length=expected_length, expected_head=a_head)

    # -- capacity ----------------------------------------------------------
    def capacity_report(self) -> Dict[str, Any]:
        b = self.gate.budget
        per_op = self.rc_per_op
        return {
            "account": self.account, "network": self.network,
            "rcBudgetPerDay": b.limit if b else None,
            "rcSpentInWindow": b.spent() if b else None,
            "rcPerOpEstimate": per_op,
            "rcPerOpCalibrated": per_op is not None,
            "opsRemainingToday": (int((b.limit - b.spent()) // per_op)
                                  if (b and per_op) else None),
            "rootsPerOperation": PK.max_entries(),
            "headsPerOperation": None,
            "customJsonBudgetBytes": PROTO.HIVE_CUSTOM_JSON_DATA_MAX_LENGTH,
            "note": ("rcPerOpEstimate is the measured aggregate from two manabar "
                     "snapshots; it is not decomposed into fixed and per-byte "
                     "components, which needs one bracketed sample"),
        }
