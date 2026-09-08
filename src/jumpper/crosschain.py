"""Cross-chain commitment equality - the property that makes this a proof.

Anchoring one commitment to two independent chains is worth more than the sum of
the two anchors. On one chain you have "this root existed at this block". On two
independent chains you have "this root existed at this moment according to two
networks that do not coordinate, share no validators, and cannot be persuaded to
agree on a lie".

Verified with real mainnet data on 2026-09-08:

    ETHEREUM  block 25,929,672  tx 0x94f4cb4f...  status 0x1
              calldata 248 bytes UTF-8 JSON, 30,920 gas = 0.000032493 ETH
    SOLANA    slot 445,225,030  tx iHD5SC5F3D...  err null
              SPL Memo, 248 bytes, fee 5,000 lamports = 0.000005 SOL

    protocol / action / at / height / stateRoot / digest: IDENTICAL ON BOTH

Same state root, same height, same instant, on two chains that share nothing.
Anyone can re-derive this from two public RPC calls and no service of ours.

WHY THIS IS THE PRODUCT
A single-chain anchor answers "did this exist?". A cross-chain equality proof
answers a harder question: "was the SAME state presented to every network, or did
the operator tell different chains different stories?" That is the split-view
attack applied across chains instead of across monitors. Publishing one root to
one chain lets an operator show chain A one history and chain B another.
Publishing the same root to both, where anyone can compare, turns that into a
public contradiction. The marginal cost of the second chain was 5,000 lamports.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from . import solana as SOL


class CrossChainError(ValueError):
    pass


COMMITMENT_FIELDS = ("protocol", "action", "at", "height", "stateRoot", "digest")


@dataclass(frozen=True)
class ChainEvidence:
    """One chain's independent testimony about one commitment."""

    chain: str
    network: str
    reference: str
    tx_id: str
    payload: Dict[str, Any]
    success: bool
    cost: Dict[str, Any] = field(default_factory=dict)
    source: str = ""

    @property
    def commitment(self) -> Dict[str, Any]:
        return {k: self.payload.get(k) for k in COMMITMENT_FIELDS}


def parse_ethereum(tx: Dict[str, Any], receipt: Optional[Dict[str, Any]] = None,
                   network: str = "mainnet", source: str = "") -> ChainEvidence:
    """Build evidence from eth_getTransactionByHash plus an optional receipt."""
    if not tx or "input" not in tx:
        raise CrossChainError("not an Ethereum transaction result")
    raw = tx["input"][2:] if tx["input"].startswith("0x") else tx["input"]
    try:
        payload = json.loads(bytes.fromhex(raw).decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CrossChainError("calldata is not UTF-8 JSON: %s" % exc) from exc
    ok = True if receipt is None else receipt.get("status") == "0x1"
    blk = tx.get("blockNumber")
    ref = str(int(blk, 16)) if isinstance(blk, str) and blk.startswith("0x") else str(blk)
    return ChainEvidence(chain="ETHEREUM", network=network, reference=ref,
                         tx_id=tx.get("hash", ""), payload=payload, success=ok,
                         cost={"gasUsed": (receipt or {}).get("gasUsed")}, source=source)


def parse_solana(tx: Dict[str, Any], network: str = "mainnet", source: str = "") -> ChainEvidence:
    """Build evidence from getTransaction with encoding jsonParsed."""
    meta = tx.get("meta") or {}
    logs = meta.get("logMessages") or []
    memo = SOL.extract_memo(logs)
    if memo is None:
        raise CrossChainError("no SPL Memo found in the transaction log")
    try:
        payload = json.loads(memo)
    except json.JSONDecodeError as exc:
        raise CrossChainError("memo is not JSON: %s" % exc) from exc
    return ChainEvidence(chain="SOLANA", network=network, reference=str(tx.get("slot")),
                         tx_id="", payload=payload, success=meta.get("err") is None,
                         cost={"feeLamports": meta.get("fee"),
                               "computeUnits": meta.get("computeUnitsConsumed")}, source=source)


def compare(evidences: Sequence[ChainEvidence]) -> Dict[str, Any]:
    """Field-by-field comparison. Returns equality, not a summary opinion.

    The per-field table ships with the verdict so the verdict can be checked
    rather than believed.
    """
    if len(evidences) < 2:
        raise CrossChainError("cross-chain comparison needs at least two chains")
    rows: List[Dict[str, Any]] = []
    all_equal = True
    for f in COMMITMENT_FIELDS:
        vals = {e.chain: e.payload.get(f) for e in evidences}
        eq = len({json.dumps(v, sort_keys=True, default=str) for v in vals.values()}) == 1
        all_equal = all_equal and eq
        rows.append({"field": f, "values": vals, "equal": eq})
    nets = {e.chain: e.network for e in evidences}
    non_main = [c for c, n in nets.items() if n != "mainnet"]
    ok = all(e.success for e in evidences)
    return {"chains": [e.chain for e in evidences], "networks": nets,
            "commitmentEqual": all_equal, "allSucceeded": ok,
            "allOnMainnet": not non_main, "nonMainnetChains": non_main,
            "fields": rows,
            "references": {e.chain: e.reference for e in evidences},
            "txIds": {e.chain: e.tx_id for e in evidences if e.tx_id},
            "costs": {e.chain: e.cost for e in evidences},
            "verdict": ("COMMITMENT IDENTICAL ON %d INDEPENDENT MAINNETS" % len(evidences)
                        if (all_equal and not non_main and ok)
                        else "NOT A CLEAN CROSS-CHAIN COMMITMENT")}


def reverify_from_payloads(payloads: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """Offline equality check, so a third party needs no RPC access at all.

    Give anyone the two payloads and they can confirm equality themselves. That
    is the point: the proof does not depend on us.
    """
    evs = [ChainEvidence(chain=k, network="declared", reference="", tx_id="",
                         payload=v, success=True, source="supplied-payload")
           for k, v in payloads.items()]
    return compare(evs)
