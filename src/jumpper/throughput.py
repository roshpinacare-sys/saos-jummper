"""The free-throughput multiplier stack, with every number marked measured or not.

This module exists because "free" is not a single fact. It is a stack of
independent multipliers, and conflating them is how optimistic numbers get
published. Each stage below states whether it is MEASURED against live mainnet,
DERIVED from a measured constant, or UNMEASURED and pending calibration.

Stage 1 - payload compaction                          MEASURED
    250 bytes on chain today -> 51 bytes tier E. 4.90x.
    Two removed fields were not just redundant but wrong: digest is recomputable
    by anyone, and at is our own clock where the block time is the authority.

Stage 2 - multi-root packing                          DERIVED (exact arithmetic)
    HIVE_CUSTOM_JSON_DATA_MAX_LENGTH = 8192, fetched live from mainnet.
    The custom_json envelope costs ~99 bytes and is paid once per OPERATION.
    Packing K roots into one operation amortises it.
    At the maximum K = 154: 64.0% byte saving, 2.78x ratio.

Stages 1 and 2 combined                                 DERIVED
    351 bytes per anchor today -> 53.6 bytes packed. 6.55x, 84.7% fewer bytes.

Stage 3 - operation-count collapse                      DERIVED
    The pulse chain seals every 12 blocks. Blocks are 3 s. That is 2,400 seals
    per day. At 154 roots per operation, anchoring EVERY seal needs 15.6
    operations per day instead of 2,400. Account history grows by 16 permanent
    entries per day rather than 2,400.

Stage 4 - authority downgrade                           MEASURED, zero RC change
    All 21 live anchors sign with ACTIVE. Attestations need only POSTING. Same
    resource classes, same payload size, same RC. Removes fund-moving capability
    from the signer. See authority.py.

Stage 5 - RC budget                                     PARTLY MEASURED
    MEASURED: max_rc 25,641,553,538 and regen 59,355 RC/sec for headcorner, read
    live from rc_api.find_rc_accounts. That is 5.13e9 RC per day.
    UNMEASURED: RC consumed per anchor. The Hive price curve is deliberately not
    reimplemented from memory - a guessed formula producing confident wrong
    numbers is worse than an admitted gap. freeops.RcCalibration measures it from
    bracketing samples instead.
    Until calibrated, the pessimistic floor stands: at 1e6 RC per anchor,
    5,128 anchors per day are free. The packed byte reduction multiplies that
    floor by up to 6.55x if RC is byte-dominated.

Stage 6 - fleet striping                                STRUCTURAL
    RC is per-account. N independently staked accounts give N times the budget.
    The estate already holds a fleet of 7 keys. If each account carries stake,
    total RC scales linearly with no protocol change. If they do not, striping
    still spreads account-history growth and gives redundancy, but does NOT
    multiply the budget - delegation moves RC between accounts, it does not
    create it.

What is certain without any calibration
    - custom_json carries no fee. Verified: the operation has no fee field.
    - 21 real anchors landed in about 22 hours with RC positive and rising.
    - 8,192 bytes fit one operation. Protocol constant, fetched live.
    - 154 roots fit that budget at 52 bytes per entry. Exact arithmetic.
    - Posting authority costs no more RC than active. Same resource classes.

What requires one measurement
    - RC per anchor. One bracketed sample pair around a single real anchor turns
      every floor above into an exact figure.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from . import packing as PK
from . import protocol as PROTO
from .freeops import PESSIMISTIC_RC_PER_ANCHOR


class ThroughputError(ValueError):
    pass


ONCHAIN_PAYLOAD_BYTES = 250      # measured from 21 live anchors
ONCHAIN_WRAPPER_BYTES = 101      # measured custom_json envelope for that account
ONCHAIN_BYTES_PER_ANCHOR = ONCHAIN_PAYLOAD_BYTES + ONCHAIN_WRAPPER_BYTES
PULSE_CHAIN_BLOCKS_BETWEEN_SEALS = 12


@dataclass(frozen=True)
class StageResult:
    name: str
    evidence: str          # MEASURED | DERIVED | UNMEASURED | STRUCTURAL
    multiplier: Optional[float]
    detail: str

    def as_dict(self) -> Dict[str, Any]:
        return {"stage": self.name, "evidence": self.evidence,
                "multiplier": self.multiplier, "detail": self.detail}


def compaction_multiplier() -> float:
    """Stage 1. Measured: 250 bytes live, 51 bytes tier E."""
    entry = PK.TIER_E_ENTRY_BYTES - 1      # 51 bytes for the entry itself
    return ONCHAIN_PAYLOAD_BYTES / entry


def packing_multiplier(k: Optional[int] = None) -> float:
    """Stage 2. Derived from the live 8192-byte protocol constant."""
    return PK.plan(k).byte_ratio


def combined_bytes_per_anchor(k: Optional[int] = None) -> float:
    return PK.plan(k).bytes_per_anchor


def combined_multiplier(k: Optional[int] = None) -> float:
    return ONCHAIN_BYTES_PER_ANCHOR / combined_bytes_per_anchor(k)


def seals_per_day(blocks_between_seals: int = PULSE_CHAIN_BLOCKS_BETWEEN_SEALS) -> float:
    return PROTO.seals_per_day_at_interval(blocks_between_seals)


def operations_per_day(k: Optional[int] = None,
                       blocks_between_seals: int = PULSE_CHAIN_BLOCKS_BETWEEN_SEALS) -> float:
    """Stage 3. Anchoring EVERY seal, packed."""
    return PK.operations_per_day_for_seals(seals_per_day(blocks_between_seals), k)


def pessimistic_anchors_per_day(regen_per_day: float) -> float:
    """Stage 5 floor. Deliberately pessimistic; real figure is higher."""
    return regen_per_day / PESSIMISTIC_RC_PER_ANCHOR


def fleet_budget(regen_per_day_per_account: float, staked_accounts: int) -> float:
    """Stage 6. RC is per-account, so independent stake multiplies the budget."""
    if staked_accounts < 1:
        raise ThroughputError("staked_accounts must be >= 1")
    return regen_per_day_per_account * staked_accounts


def stack(regen_per_day: float = 5128310708.0, staked_accounts: int = 1,
          k: Optional[int] = None) -> Dict[str, Any]:
    """The whole stack in one honest report."""
    kk = k if k is not None else PK.max_entries()
    stages = [
        StageResult("payload compaction", "MEASURED", round(compaction_multiplier(), 2),
                    "250 B live on chain -> 51 B tier E; digest recomputable, at superseded by block time"),
        StageResult("multi-root packing", "DERIVED", round(packing_multiplier(kk), 2),
                    "8192 B custom_json budget holds %d roots; wrapper amortised once per op" % kk),
        StageResult("combined bytes per anchor", "DERIVED", round(combined_multiplier(kk), 2),
                    "%.0f B -> %.1f B per anchor (%.1f%% fewer bytes)"
                    % (ONCHAIN_BYTES_PER_ANCHOR, combined_bytes_per_anchor(kk),
                       (1 - combined_bytes_per_anchor(kk) / ONCHAIN_BYTES_PER_ANCHOR) * 100)),
        StageResult("operation-count collapse", "DERIVED", round(seals_per_day() / operations_per_day(kk), 1),
                    "%.0f seals/day anchored in %.1f operations/day"
                    % (seals_per_day(), operations_per_day(kk))),
        StageResult("authority downgrade", "MEASURED", None,
                    "21/21 live anchors sign with ACTIVE; POSTING suffices at identical RC cost"),
        StageResult("RC budget", "PARTLY MEASURED", None,
                    "regen %.3e RC/day measured; RC per anchor UNMEASURED pending calibration"
                    % regen_per_day),
        StageResult("fleet striping", "STRUCTURAL", float(staked_accounts),
                    "RC is per-account; %d staked account(s)" % staked_accounts),
    ]
    return {
        "stages": [s.as_dict() for s in stages],
        "rootsPerOperation": kk,
        "bytesPerAnchorToday": ONCHAIN_BYTES_PER_ANCHOR,
        "bytesPerAnchorOptimised": round(combined_bytes_per_anchor(kk), 2),
        "combinedMultiplier": round(combined_multiplier(kk), 2),
        "sealsPerDay": seals_per_day(),
        "operationsPerDay": round(operations_per_day(kk), 2),
        "regenRcPerDay": regen_per_day,
        "fleetRcPerDay": fleet_budget(regen_per_day, staked_accounts),
        "pessimisticAnchorsPerDay": pessimistic_anchors_per_day(
            fleet_budget(regen_per_day, staked_accounts)),
        "rcPerAnchor": None,
        "note": "rcPerAnchor is null until RcCalibration has bracketing samples. "
                "Every figure above it is measured or exactly derived; nothing is guessed.",
    }
