"""Graphene free-anchor layer: STEEM / HIVE / BLURT custom_json.

This is the PRIMARY anchor path. It costs ZERO fee.

Verified against HIVE mainnet on 2026-09-08 (independent, read-only):

    account   headcorner
    op        custom_json, id "saos-dex.anchor.v1"
    authority required_auths = ["headcorner"]  (ACTIVE key)
    fee       none - the operation has no fee field
    anchors   21 found in the last 100 account-history entries
    blocks    109,708,562 .. 109,734,678
    window    2026-09-07T14:42:57 .. 2026-09-08T12:31:57
    payload   247-250 bytes, mean 248.8
    examples  trx 48982c950f5532fb879c26d52d7c79be9df38dd1  block 109732622
              trx 0c66e2c59e65cc4bcb753cb7768b1fc991547ea4  block 109733604
              trx 0eafff4632773d90d4c1f788036a4257c885ea96  block 109734678

------------------------------------------------------------------------------
THE MANABAR BUG THIS MODULE EXISTS TO PREVENT
------------------------------------------------------------------------------
rc_api.find_rc_accounts returns rc_manabar.current_mana AS OF last_update_time.
It is a SNAPSHOT, not the current balance. Reading it raw under-reports
available RC by however long the snapshot is stale.

Observed live:

    stored current_mana   =     1,392,041   (last_update_time 1788870714)
    wall clock            =     1788871925  (1,211 seconds later)
    max_rc                = 25,641,553,538
    regen rate            = max_rc / 432000 = 59,355 RC/sec
    EFFECTIVE mana        =    73,271,489   (52.6x the stored value)

An anchor gate comparing the raw snapshot against a constant therefore reports
"blocked" while the account actually holds tens of millions of RC. That is a
stale-read bug, not a resource shortage, and it costs nothing to fix.

Correct projection:

    effective = min(max_rc, current_mana + (max_rc / REGEN_SECONDS) * elapsed)

REGEN_SECONDS = 432,000 (5 days) for the HIVE RC manabar.

------------------------------------------------------------------------------
PAYLOAD COMPACTION
------------------------------------------------------------------------------
RC consumption scales with transaction bytes, so shrinking the JSON multiplies
free throughput. Measured against the live 250-byte payload:

    A. as broadcast today                    250 B   baseline
    D. JSON, root hex -> base64url            67 B   -73.2%
    E. bare CSV, no JSON braces               51 B   -79.6%

Two fields in the legacy payload are not merely redundant, they are wrong:

  digest  sha256 of the payload. Recomputable by anyone. Paying RC to store a
          value the reader can derive is pure waste.
  at      our own ISO clock. The BLOCK timestamp is the authoritative time and
          is what makes an anchor meaningful. Broadcasting our own clock is
          weaker AND costs bytes.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

ANCHOR_ID = "saos-jumpper.anchor.v1"

HIVE_REGEN_SECONDS = 5 * 24 * 3600
STEEM_REGEN_SECONDS = 7 * 24 * 3600


class GrapheneError(ValueError):
    pass


@dataclass(frozen=True)
class RcState:
    account: str
    stored_mana: int
    last_update_time: int
    max_rc: int
    now: int

    @property
    def regen_per_second(self) -> float:
        return self.max_rc / HIVE_REGEN_SECONDS

    @property
    def elapsed(self) -> int:
        return max(0, self.now - self.last_update_time)

    @property
    def effective_mana(self) -> float:
        """The number that actually matters. Projection-corrected."""
        return min(float(self.max_rc), self.stored_mana + self.regen_per_second * self.elapsed)

    @property
    def effective_pct(self) -> float:
        return self.effective_mana / self.max_rc * 100.0 if self.max_rc else 0.0

    @property
    def regen_per_day(self) -> float:
        return self.regen_per_second * 86400

    @property
    def stale_underreport_factor(self) -> float:
        if self.stored_mana <= 0:
            return float("inf")
        return self.effective_mana / self.stored_mana

    def as_dict(self) -> Dict[str, Any]:
        return {"account": self.account, "storedMana": self.stored_mana,
                "lastUpdateTime": self.last_update_time, "maxRc": self.max_rc,
                "now": self.now, "elapsedSeconds": self.elapsed,
                "regenPerSecond": round(self.regen_per_second, 2),
                "regenPerDay": round(self.regen_per_day, 0),
                "effectiveMana": round(self.effective_mana, 0),
                "effectivePct": round(self.effective_pct, 4),
                "staleUnderreportFactor": (round(self.stale_underreport_factor, 3)
                                           if self.stored_mana > 0 else None)}


def rc_state(account: str, stored_mana: int, last_update_time: int, max_rc: int, now: int) -> RcState:
    if max_rc <= 0:
        raise GrapheneError("max_rc must be positive")
    if stored_mana < 0:
        raise GrapheneError("stored_mana cannot be negative")
    return RcState(account=account, stored_mana=stored_mana,
                   last_update_time=last_update_time, max_rc=max_rc, now=now)


def rc_state_from_api(account: str, api_rc_account: Dict[str, Any], now: int) -> RcState:
    try:
        bar = api_rc_account["rc_manabar"]
        return rc_state(account, int(bar["current_mana"]), int(bar["last_update_time"]),
                        int(api_rc_account["max_rc"]), now)
    except (KeyError, TypeError, ValueError) as exc:
        raise GrapheneError("malformed rc_api response: %s" % exc) from exc


def can_afford(state: RcState, cost_rc: float, floor_rc: float = 0.0) -> bool:
    """Gate on EFFECTIVE mana. Never on the stale snapshot."""
    return state.effective_mana - cost_rc >= floor_rc


def max_affordable_anchors(state: RcState, cost_rc: float) -> int:
    if cost_rc <= 0:
        raise GrapheneError("cost_rc must be positive")
    return int(state.effective_mana // cost_rc)


def b64u(hexstr: str) -> str:
    """64-char lowercase hex -> 43-char url-safe base64, unpadded."""
    if len(hexstr) != 64 or any(c not in "0123456789abcdef" for c in hexstr):
        raise GrapheneError("expected 64-char lowercase hex")
    return base64.urlsafe_b64encode(bytes.fromhex(hexstr)).decode().rstrip("=")


def unb64u(s: str) -> str:
    try:
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)).hex()
    except Exception as exc:
        raise GrapheneError("invalid base64url: %s" % exc) from exc


@dataclass(frozen=True)
class CompactAnchor:
    version: int
    height: int
    root: str

    def payload_e(self) -> str:
        """Tier E: bare CSV. Smallest. ~51 bytes for a real root."""
        return "%d,%d,%s" % (self.version, self.height, b64u(self.root))

    def payload_d(self) -> str:
        """Tier D: JSON with base64url root."""
        return json.dumps({"v": self.version, "h": self.height, "r": b64u(self.root)},
                          separators=(",", ":"))

    def payload_legacy(self, at: str, digest: str, protocol: str = "saos-dex/v1") -> str:
        """Byte-compatible with what is on HIVE mainnet today. Migration only."""
        return json.dumps({"protocol": protocol, "action": "chain-seal", "at": at,
                           "height": self.height, "stateRoot": self.root, "digest": digest},
                          separators=(",", ":"))

    def sizes(self) -> Dict[str, int]:
        return {"E_csv": len(self.payload_e().encode()),
                "D_json_b64": len(self.payload_d().encode())}


def parse_payload_e(s: str) -> CompactAnchor:
    parts = s.split(",")
    if len(parts) != 3:
        raise GrapheneError("tier-E payload must be 'version,height,rootB64u'")
    try:
        v, h = int(parts[0]), int(parts[1])
    except ValueError as exc:
        raise GrapheneError("version and height must be integers") from exc
    return CompactAnchor(version=v, height=h, root=unb64u(parts[2]))


def build_custom_json(account: str, payload: str, anchor_id: str = ANCHOR_ID,
                      posting: bool = False) -> List[Any]:
    """Exact op shape verified on HIVE mainnet. Zero fee.

    posting=False uses required_auths (ACTIVE authority), matching the live
    anchors. posting=True is for non-authoritative signals only.
    """
    if not account:
        raise GrapheneError("account required")
    if not payload:
        raise GrapheneError("payload required")
    if posting:
        return ["custom_json", {"required_auths": [], "required_posting_auths": [account],
                                "id": anchor_id, "json": payload}]
    return ["custom_json", {"required_auths": [account], "required_posting_auths": [],
                            "id": anchor_id, "json": payload}]


def build_transaction_skeleton(op: List[Any], ref_block_num: int, ref_block_prefix: int,
                               expiration: str, extensions: Optional[List[Any]] = None,
                               signatures: Optional[List[str]] = None) -> Dict[str, Any]:
    """Unsigned tx skeleton. Signing is ALWAYS external - never here."""
    return {"ref_block_num": ref_block_num & 0xFFFF,
            "ref_block_prefix": ref_block_prefix,
            "expiration": expiration,
            "extensions": extensions or [],
            "operations": [op],
            "signatures": signatures or []}


HIVE_NODES = ["https://api.openhive.network", "https://api.deathwing.me",
              "https://api.hive.blog", "https://api.developer.witnesses.lol"]
STEEM_NODES = ["https://api.steemit.com", "https://api.justyy.com", "https://steem.61bts.com"]
