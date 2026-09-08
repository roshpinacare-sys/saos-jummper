"""Claim ingestion and leaf hashing.

The leaf hash commits to a payload without necessarily revealing it: when
public=False only the hash is retained and the payload is returned to the
submitter and discarded. Commit without disclosure.

Domain separation is mandatory. The prefix stops a leaf hash from being reused
as a batch root, an anchor digest, or a claim under another protocol version.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any, Optional

from .canonical import canonical, canonical_bytes

DOMAIN = "saos-jumpper/claim/v1"
SEP = b"\x1f"
ISO8601 = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)


class ClaimError(ValueError):
    pass


@dataclass(frozen=True)
class Claim:
    claim_id: str
    leaf_hash: str
    canonical_payload: str
    timestamp: str
    public: bool
    source: Optional[str] = None
    schema: Optional[str] = None
    payload_size: int = 0

    def disclosure(self) -> dict:
        """What a submitter keeps when the claim is private."""
        return {"claimId": self.claim_id, "leafHash": self.leaf_hash,
                "canonicalPayload": self.canonical_payload,
                "timestamp": self.timestamp, "schema": self.schema}


def leaf_hash(payload: Any, timestamp: str) -> str:
    if not ISO8601.match(timestamp):
        raise ClaimError("timestamp must be ISO-8601, got %r" % (timestamp,))
    return hashlib.sha256(
        DOMAIN.encode("utf-8") + SEP + canonical_bytes(payload) + SEP + timestamp.encode("utf-8")
    ).hexdigest()


def make_claim(payload: Any, timestamp: str, public: bool = False,
               source: Optional[str] = None, schema: Optional[str] = None) -> Claim:
    canon = canonical(payload)
    lh = leaf_hash(payload, timestamp)
    return Claim(claim_id=lh[:16], leaf_hash=lh,
                 canonical_payload=canon if public else "",
                 timestamp=timestamp, public=public, source=source,
                 schema=schema, payload_size=len(canon.encode("utf-8")))
