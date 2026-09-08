"""Multi-root packing: commit many batches in ONE free operation.

The finding
-----------
A HIVE custom_json may carry 8,192 bytes (HIVE_CUSTOM_JSON_DATA_MAX_LENGTH,
fetched live from mainnet). The live anchors carry 250 bytes - 3.1% of the
budget. Meanwhile the custom_json wrapper itself

    {"required_auths":["<account>"],"required_posting_auths":[],
     "id":"saos-dex.anchor.v1","json":""}

costs ~101 bytes and is paid ONCE PER OPERATION. Broadcasting one root per
operation therefore spends two thirds of every operation's bytes on wrapper.

Measured at 51 bytes per tier-E root entry:

    K roots | packed  | unpacked (K separate ops) | saving | ratio
          1 |    152 B |                    152 B  |   0.0% |  1.00x
         10 |    616 B |                  1,520 B  |  59.5% |  2.47x
         50 |  2,656 B |                  7,600 B  |  65.1% |  2.86x
        100 |  5,206 B |                 15,200 B  |  65.7% |  2.92x
        157 |  8,148 B |                 23,864 B  |  65.9% |  2.93x

157 roots is the maximum that fits one operation. Packing therefore gives a
~2.93x byte reduction ON TOP of the ~4.9x tier-E compaction, for a combined
~12x reduction in bytes per anchored batch versus what is on chain today.

Why this is not only a byte saving
-----------------------------------
RC consumption has a per-operation fixed component (resource_execution_time) and
a byte-proportional component (resource_history_bytes). Packing K roots into one
operation pays the fixed component ONCE instead of K times. The size of that win
depends on the fixed/variable split, which is UNMEASURED - see freeops.
RcCalibration. The byte-proportional win above is exact and needs no calibration.

A third win is structural and certain: account history grows by ONE entry
instead of K. Their pulse chain seals every 12 blocks = every 36 s = 2,400 seals
per day. Anchoring every seal one-per-op would add 2,400 permanent history
entries daily. Packed at 157 roots, it adds 16.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence

from . import protocol as PROTO
from .graphene import GrapheneError, b64u, unb64u

WRAPPER_BYTES = 101          # measured: the custom_json envelope, empty json
TIER_E_ENTRY_BYTES = 52      # measured: "v,height,<43-char b64u root>" + separator


class PackingError(ValueError):
    pass


@dataclass(frozen=True)
class RootEntry:
    version: int
    height: int
    root: str            # 64-char lowercase hex

    def encode(self) -> str:
        return "%d,%d,%s" % (self.version, self.height, b64u(self.root))

    @property
    def encoded_bytes(self) -> int:
        return len(self.encode().encode())


def decode_entry(s: str) -> RootEntry:
    parts = s.split(",")
    if len(parts) != 3:
        raise PackingError("entry must be version,height,rootB64u")
    try:
        v, h = int(parts[0]), int(parts[1])
    except ValueError as exc:
        raise PackingError("version and height must be integers") from exc
    try:
        return RootEntry(version=v, height=h, root=unb64u(parts[2]))
    except GrapheneError as exc:
        raise PackingError(str(exc)) from exc


def pack_payload(entries: Sequence[RootEntry], sep: str = ";") -> str:
    """Many roots, one json field. Exact round-trip with unpack_payload."""
    if not entries:
        raise PackingError("cannot pack zero entries")
    return sep.join(e.encode() for e in entries)


def unpack_payload(payload: str, sep: str = ";") -> List[RootEntry]:
    if not payload:
        raise PackingError("empty payload")
    return [decode_entry(p) for p in payload.split(sep)]


def max_entries(entry_bytes: int = TIER_E_ENTRY_BYTES, sep_bytes: int = 1) -> int:
    """Largest K whose packed payload still fits one custom_json."""
    per = entry_bytes + sep_bytes
    if per < 1:
        raise PackingError("per-entry bytes must be >= 1")
    k = (PROTO.HIVE_CUSTOM_JSON_DATA_MAX_LENGTH + sep_bytes) // per
    return max(1, k)


@dataclass(frozen=True)
class PackingPlan:
    k: int
    packed_json_bytes: int
    unpacked_bytes: int
    byte_saving_pct: float
    byte_ratio: float
    bytes_per_anchor: float
    fits_custom_json: bool

    def as_dict(self) -> Dict[str, Any]:
        return {"rootsPerOperation": self.k, "packedJsonBytes": self.packed_json_bytes,
                "unpackedBytes": self.unpacked_bytes,
                "byteSavingPct": round(self.byte_saving_pct, 2),
                "byteRatio": round(self.byte_ratio, 3),
                "bytesPerAnchor": round(self.bytes_per_anchor, 2),
                "fitsCustomJson": self.fits_custom_json}


def plan(k: Optional[int] = None, account: str = "headcorner",
         anchor_id: str = "saos-dex.anchor.v1",
         entry_bytes: int = TIER_E_ENTRY_BYTES) -> PackingPlan:
    """Exact byte accounting for packing k roots into one operation."""
    k = k if k is not None else max_entries(entry_bytes)
    if k < 1:
        raise PackingError("k must be >= 1")
    wrapper = ('{"required_auths":["%s"],"required_posting_auths":[],'
               '"id":"%s","json":""}' % (account, anchor_id))
    wrap_bytes = len(wrapper.encode())
    packed_json = k * entry_bytes + (k - 1)
    packed_op = wrap_bytes + packed_json
    unpacked = k * (wrap_bytes + entry_bytes)
    return PackingPlan(
        k=k, packed_json_bytes=packed_json, unpacked_bytes=unpacked,
        byte_saving_pct=(1 - packed_op / unpacked) * 100 if unpacked else 0.0,
        byte_ratio=unpacked / packed_op if packed_op else 0.0,
        bytes_per_anchor=packed_op / k,
        fits_custom_json=packed_json <= PROTO.HIVE_CUSTOM_JSON_DATA_MAX_LENGTH,
    )


def operations_per_day_for_seals(seals_per_day: float, k: Optional[int] = None) -> float:
    """How many free operations are needed to anchor every seal."""
    k = k if k is not None else max_entries()
    if k < 1:
        raise PackingError("k must be >= 1")
    return seals_per_day / k
