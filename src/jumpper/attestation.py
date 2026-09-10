"""Attestation integrity - a claim must be derived from the state it describes.

THE DEFECT THIS EXISTS FOR
--------------------------
Seven value_lock records are signed on HIVE mainnet with POSTING authority and say,
permanently and non-repudiably:

    {"lockedSaos":0.166,"depthBefore":106.868,
     "note":"LP locked permanently - fees keep flowing",
     "srcTxid":"4f83ae2a4754b2f7b07b242fac0c39a74bed1a5e"}

The operator's own committed state file (saos-dex/state/pool.json) says:

    "lpLocked": false, "lockedAt": null,
    "tvlMicroUsd": 0, "feesGeneratedMicroUsd": 0

Live Hive-Engine balances say: SAOS 0.19776475, SWAP.HIVE 0.00000000.

So a permanent public attestation of locked liquidity with flowing fees was
published while the state it describes said not locked, no fees, zero TVL - and the
balances cannot fund a pool 540x larger than everything the account holds.

The attestation is not forged. It is correctly signed and correctly published. The
failure is that nobody compared it to anything before signing it. The note is a
hardcoded string; the amounts have no relation to a checked condition.

THE RULE
--------
An attestation field must be DERIVED from the state it describes, and a claim the
state contradicts must refuse to publish:

  - 'locked' requires lpLocked true AND lockedAt non-null
  - 'fees flowing' requires feesGenerated > 0
  - a depth or amount claim requires a balance that can fund it
  - a srcTxid must name the chain it resolves on, or it is not a pointer
  - a field in the claim but absent from the state is a refusal, not a pass

This module never signs and never broadcasts. It answers one question before the
signature happens: does the state support this claim?"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence

ALLOW = "allow"
REFUSE = "refuse"

CLAIM_WORDS = {
    "locked":      ("lpLocked", "lockedAt"),
    "permanently": ("lpLocked", "lockedAt"),
    "fees":        ("feesGeneratedMicroUsd",),
    "flowing":     ("feesGeneratedMicroUsd",),
    "funded":      ("tvlMicroUsd",),
    "backed":      ("tvlMicroUsd",),
    "verified":    ("verified",),
    "final":       ("finalized",),
    "settled":     ("settled",),
}

EVM_TXID = re.compile(r"^0x[0-9a-fA-F]{64}$")
# 40 hex chars is 20 bytes, which is the GRAPHENE transaction id format used by
# HIVE, STEEM and BitShares - verified against two real ones read this session:
#   92654439d97f4cd30a70a5ced46b2bd93488b722   HIVE account_update
#   a80805a0ef2853dcb5f0379b7e1b62b981cbe3dd   STEEM anchor
# An Ethereum txid is 32 bytes / 64 hex, and ethereum-rpc.publicnode.com rejects a
# 40-char value outright with -32602 "hex string has length ...". An earlier
# version of this module called 40 hex "Ethereum-format", which is wrong, and the
# mistake was repeated in docs/ONCHAIN-ROAST.md. Both are corrected.
GRAPHENE_TXID = re.compile(r"^[0-9a-fA-F]{40}$")
BARE_TXID = GRAPHENE_TXID


class AttestationError(ValueError):
    pass


@dataclass(frozen=True)
class Contradiction:
    claim: str
    asserted: Any
    state_says: Any
    field_name: str
    severity: str
    detail: str

    def as_dict(self) -> Dict[str, Any]:
        return {"claim": self.claim, "asserted": self.asserted,
                "stateSays": self.state_says, "field": self.field_name,
                "severity": self.severity, "detail": self.detail}


def _num(v: Any) -> Optional[float]:
    if v is None or isinstance(v, bool):
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def check_note_against_state(note: str, state: Dict[str, Any]) -> List[Contradiction]:
    """Every state-asserting word in a free-text note must be backed by the state.

    A note is the part of an attestation nobody validates, because it reads like
    prose. It is also the part a third party believes."""
    out: List[Contradiction] = []
    low = (note or "").lower()
    for word, fields in CLAIM_WORDS.items():
        if word not in low:
            continue
        for f in fields:
            if f not in state:
                out.append(Contradiction(word, note[:120], None, f, "high",
                    "the note asserts %r but the state has no field %r to support it"
                    % (word, f)))
                continue
            v = state[f]
            if v in (False, None, 0, "0", "", "null"):
                out.append(Contradiction(word, note[:120], v, f, "critical",
                    "the note asserts %r but %s is %r" % (word, f, v)))
            elif isinstance(v, (int, float)) and not isinstance(v, bool) and v <= 0:
                out.append(Contradiction(word, note[:120], v, f, "critical",
                    "the note asserts %r but %s is %s" % (word, f, v)))
    return out


def check_amount_against_balance(claimed: Any, balance: Any, label: str) -> List[Contradiction]:
    """A claimed amount must be fundable by the balance that backs it."""
    c = _num(claimed); b = _num(balance)
    if c is None:
        return [Contradiction(label, claimed, balance, label, "high",
            "claimed amount is not a number; nothing to verify against")]
    if b is None:
        return [Contradiction(label, claimed, balance, label, "high",
            "no balance available to verify the claim against; refusing rather "
            "than assuming it is funded")]
    if c > b:
        return [Contradiction(label, c, b, label, "critical",
            "claims %s but only %s is held - the claim exceeds everything "
            "available by %.8g" % (c, b, c - b))]
    return []


def check_txid_pointer(txid: Any, chain: Optional[str] = None) -> List[Contradiction]:
    """A pointer that does not name its chain cannot be followed."""
    out: List[Contradiction] = []
    if txid in (None, ""):
        return out
    t = str(txid)
    if BARE_TXID.match(t):
        out.append(Contradiction("srcTxid", t, chain, "srcTxid", "high",
            "40-hex is the GRAPHENE transaction id format (HIVE, STEEM, BitShares), "
            "not Ethereum - whose txids are 64 hex and which rejects a 40-char "
            "value outright with -32602. The length is right for those chains, so "
            "the ambiguity is between two Graphene networks, and a pointer without "
            "a network cannot be resolved"))
    elif not EVM_TXID.match(t):
        out.append(Contradiction("srcTxid", t, chain, "srcTxid", "medium",
            "unrecognised transaction id format"))
    if not chain:
        out.append(Contradiction("srcTxid.chain", None, None, "chain", "high",
            "no chain recorded for the transaction pointer"))
    return out


def check_claim_fields_present(claim: Dict[str, Any], state: Dict[str, Any],
                              required_from_state: Sequence[str]) -> List[Contradiction]:
    """Every claimed field meant to come from state must exist there."""
    out: List[Contradiction] = []
    for f in required_from_state:
        if f not in state:
            out.append(Contradiction(f, claim.get(f), None, f, "high",
                "the claim carries %r but the state has no such field, so it "
                "cannot have been derived from it" % f))
    return out


_SEVERITY_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}


def dedupe(found: Sequence["Contradiction"]) -> List["Contradiction"]:
    """Collapse repeated findings on the same field, keeping the most severe.

    A field can fail two independent checks - an amount over balance AND a field
    absent from state - and reporting both separately inflates the count and buries
    the verdict in noise. Details are merged so nothing is lost and the worst
    severity wins."""
    best: Dict[str, Contradiction] = {}
    order: List[str] = []
    for c in found:
        k = c.field_name
        if k not in best:
            best[k] = c; order.append(k); continue
        cur = best[k]
        worse, better = (cur, c) if _SEVERITY_RANK.get(c.severity, 0) > _SEVERITY_RANK.get(cur.severity, 0) else (c, cur)
        best[k] = Contradiction(better.claim, better.asserted, better.state_says,
                                better.field_name, better.severity,
                                better.detail + " | also: " + worse.detail)
    return [best[k] for k in order]


COUNTER_FIELDS = ("seq", "height", "version", "count", "index", "n")


def numeric_claim_fields(claim: Dict[str, Any]) -> List[str]:
    """Every numeric claim field that is not a counter.

    A counter (seq, height, version) is an identifier, not an amount, and comparing
    it against a balance is meaningless. Everything else numeric is an assertion
    about quantity and must be fundable by the balance that backs it.
    """
    out = []
    for k, v in claim.items():
        if k in COUNTER_FIELDS:
            continue
        if isinstance(v, bool):
            continue
        if isinstance(v, (int, float)):
            out.append(k)
        elif isinstance(v, str):
            try:
                float(v)
            except ValueError:
                continue
            out.append(k)
    return out


def attest(claim: Dict[str, Any], state: Dict[str, Any],
           balance: Optional[Any] = None,
           amount_field: Optional[str] = None,
           balance_field: str = "depthSaos",
           chain: Optional[str] = None) -> Dict[str, Any]:
    """Decide whether this claim may be published. Refuses rather than warns.

    Returns a verdict listing every contradiction, so a caller can act on the
    specific reason instead of seeing a bare no."""
    if not isinstance(claim, dict) or not claim:
        raise AttestationError("claim must be a non-empty object")
    if not isinstance(state, dict):
        raise AttestationError("state must be an object; refusing to attest "
                               "against nothing")
    found: List[Contradiction] = []
    note = claim.get("note") or ""
    if note:
        found += check_note_against_state(note, state)
    # Check EVERY numeric claim field, not one. An earlier version took a single
    # amount_field and defaulted it to lockedSaos, so depthBefore: 106.868 against a
    # balance of 0.19776475 was never examined at all. Checking one number in a
    # claim that asserts several is not verification.
    amt_balance = balance if balance is not None else state.get(balance_field)
    fields = [amount_field] if amount_field else numeric_claim_fields(claim)
    for af in fields:
        if af in claim:
            found += check_amount_against_balance(claim.get(af), amt_balance, af)
    if claim.get("srcTxid") is not None:
        found += check_txid_pointer(claim.get("srcTxid"), chain)
    derived = [k for k in claim
               if k not in ("protocol", "action", "account", "seq", "note", "srcTxid")]
    found += check_claim_fields_present(claim, state, derived)
    found = dedupe(found)
    critical = [c for c in found if c.severity == "critical"]
    high = [c for c in found if c.severity == "high"]
    decision = REFUSE if (critical or high) else ALLOW
    return {
        "decision": decision,
        "contradictions": [c.as_dict() for c in found],
        "critical": len(critical), "high": len(high),
        "medium": len([c for c in found if c.severity == "medium"]),
        "reason": ("state supports the claim" if decision == ALLOW else
                   "REFUSED - the state contradicts the claim: "
                   + "; ".join(c.detail for c in (critical + high))[:400]),
        "note": ("a permanent public attestation that the operator own state "
                 "refutes is not a trust layer; it is a record someone will "
                 "believe forever"),
    }
