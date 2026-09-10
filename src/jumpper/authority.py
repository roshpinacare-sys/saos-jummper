# hardening:allow-file H-11 reason=builds BOTH authority variants by policy; the active branch must be able to emit required_auths
"""Authority least-privilege policy for Graphene custom_json.

The finding
-----------
Every live anchor read from HIVE mainnet on 2026-09-08 was signed with the
ACTIVE authority:

    custom_json {
      required_auths:         ["headcorner"]     <- ACTIVE key
      required_posting_auths: []
      id: "saos-dex.anchor.v1"
      json: {...}
    }

verified across 21 real anchors, blocks 109708562 to 109734678.

A custom_json that only publishes a Merkle root is a DATA ATTESTATION. It moves
no value, changes no ownership, creates no market order. It needs no more
authority than POSTING.

On Graphene the authorities are strictly ordered:

    posting  - vote, follow, comment, custom_json with posting auth
    active   - everything posting can do, PLUS transfer, power up/down,
               market orders, account updates, key changes
    owner    - everything, PLUS changing the active and posting keys

So signing a data anchor with ACTIVE means the signing process holds a key that
can move every asset in the account. For an operation that only needs to publish
bytes, that is a large exposure purchased for nothing.

Cost of switching to posting: zero. custom_json with required_posting_auths
consumes the same resource classes - execution time plus history bytes - as one
with required_auths. The payload is the same size. RC does not care which
authority signed.

Benefit: if the anchor signer is ever compromised, the attacker can post and
vote. They cannot drain the account.

This module makes the choice explicit and testable rather than incidental. A
policy test fails if any attestation-class operation is built with ACTIVE
authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

POSTING = "posting"
ACTIVE = "active"
OWNER = "owner"

AUTHORITY_RANK = {POSTING: 0, ACTIVE: 1, OWNER: 2}

ATTESTATION = "attestation"
VALUE_MOVING = "value-moving"
ADMINISTRATIVE = "administrative"


class AuthorityError(ValueError):
    pass


@dataclass(frozen=True)
class AuthorityPolicy:
    """Least privilege required for a class of operation."""

    op_class: str
    required_authority: str
    reason: str
    examples: List[str]


POLICIES: List[AuthorityPolicy] = [
    AuthorityPolicy(
        op_class=ATTESTATION,
        required_authority=POSTING,
        reason="publishes bytes only; moves no value and changes no ownership",
        examples=["merkle root anchor", "proof of existence", "timestamp commitment",
                  "audit log entry", "commit-reveal commit and reveal",
                  "credential issue and revoke", "heartbeat", "name claim",
                  "cross-chain relay message", "licence key record"],
    ),
    AuthorityPolicy(
        op_class=VALUE_MOVING,
        required_authority=ACTIVE,
        reason="moves assets or creates obligations; genuinely needs active",
        examples=["transfer", "transfer_to_vesting (power up)", "withdraw_vesting",
                  "limit_order_create", "escrow_transfer", "account_update"],
    ),
    AuthorityPolicy(
        op_class=ADMINISTRATIVE,
        required_authority=OWNER,
        reason="changes who controls the account; must never be automated",
        examples=["changing active key", "changing posting key", "account recovery"],
    ),
]


def policy_for(op_class: str) -> AuthorityPolicy:
    for p in POLICIES:
        if p.op_class == op_class:
            return p
    raise AuthorityError("unknown op_class: %r" % op_class)


def authority_for(op_class: str) -> str:
    return policy_for(op_class).required_authority


def is_overprivileged(op_class: str, used_authority: str) -> bool:
    """True when the operation was signed with more authority than it needs."""
    need = AUTHORITY_RANK[authority_for(op_class)]
    used = AUTHORITY_RANK.get(used_authority)
    if used is None:
        raise AuthorityError("unknown authority: %r" % used_authority)
    return used > need


def blast_radius(authority: str) -> Dict[str, Any]:
    """What an attacker gets if the signing process for this authority is compromised."""
    if authority == POSTING:
        return {"canMoveFunds": False, "canChangeKeys": False,
                "canPublishData": True, "canVoteAndSocial": True,
                "severity": "low", "summary": "can post and vote; cannot drain the account"}
    if authority == ACTIVE:
        return {"canMoveFunds": True, "canChangeKeys": False,
                "canPublishData": True, "canVoteAndSocial": True,
                "severity": "critical",
                "summary": "can transfer every asset, power down, and place market orders"}
    if authority == OWNER:
        return {"canMoveFunds": True, "canChangeKeys": True,
                "canPublishData": True, "canVoteAndSocial": True,
                "severity": "total-loss",
                "summary": "can replace active and posting keys - permanent takeover"}
    raise AuthorityError("unknown authority: %r" % authority)


def build_custom_json_by_policy(account: str, payload: str, op_class: str = ATTESTATION,
                                anchor_id: str = "saos-jumpper.anchor.v1") -> List[Any]:
    """Build the op with the least authority the class requires.

    Attestation -> required_posting_auths. Never required_auths.
    """
    auth = authority_for(op_class)
    if not account:
        raise AuthorityError("account required")
    if not payload:
        raise AuthorityError("payload required")
    if auth == POSTING:
        return ["custom_json", {"required_auths": [], "required_posting_auths": [account],
                                "id": anchor_id, "json": payload}]
    if auth == ACTIVE:
        return ["custom_json", {"required_auths": [account], "required_posting_auths": [],
                                "id": anchor_id, "json": payload}]
    raise AuthorityError("owner authority must never be used for automated broadcasting")


def audit_live_anchors(anchors: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Classify real anchors read from the chain by the authority they used."""
    used_active = 0
    used_posting = 0
    for a in anchors:
        ra = a.get("required_auths") or []
        rp = a.get("required_posting_auths") or []
        if ra:
            used_active += 1
        elif rp:
            used_posting += 1
    total = used_active + used_posting
    return {"total": total, "signedWithActive": used_active, "signedWithPosting": used_posting,
            "overprivilegedForAttestation": used_active,
            "overprivilegedPct": round(used_active / total * 100, 1) if total else 0.0,
            "verdict": ("all attestations use ACTIVE - migrate to POSTING"
                        if total and used_active == total else
                        "mixed" if used_active and used_posting else
                        "all attestations use POSTING - correct" if total else "no anchors supplied")}
