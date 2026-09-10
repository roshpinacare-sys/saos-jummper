"""Live HIVE protocol constants - fetched from mainnet, not remembered.

Read from api.openhive.network via condenser_api.get_config on 2026-09-08.
These numbers bound what is possible for free. They are protocol constants, so
they only change with a hard fork - which is exactly why a test should fail
loudly if they ever drift.

The single most important one:

    HIVE_CUSTOM_JSON_DATA_MAX_LENGTH = 8192

One free custom_json operation may carry 8,192 bytes of arbitrary JSON. Our live
anchors carry 250. That is 3.1% of the available budget, and it is the reason a
single operation can commit ~157 Merkle roots instead of one.
"""

from __future__ import annotations

from typing import Any, Dict

# --- fetched live from mainnet 2026-09-08 -----------------------------------
HIVE_CUSTOM_JSON_DATA_MAX_LENGTH = 8192
HIVE_MAX_TRANSACTION_SIZE = 65536
HIVE_MAX_BLOCK_SIZE = 65536
HIVE_BLOCK_INTERVAL = 3
HIVE_BLOCKS_PER_DAY = 28800
HIVE_RC_TARGET_BUDGET_PER_BLOCK = 37679442792
HIVE_RC_AVERAGE_BLOCK_MANA = 3229666525
HIVE_RC_ACCOUNT_SUBSIDY_TRIPLE_WINDOW = 432000      # 5 days - confirms the regen model
HIVE_RC_MAX_MANA = 2147483647
HIVE_CREATE_ACCOUNT_MIN_DELEGATION_RATIO = 20
HIVE_CREATE_ACCOUNT_DELEGATION_RATIO = 57

RAW_SNAPSHOT: Dict[str, Any] = {
    "source": "api.openhive.network condenser_api.get_config",
    "fetched": "2026-09-08",
    "HIVE_CUSTOM_JSON_DATA_MAX_LENGTH": HIVE_CUSTOM_JSON_DATA_MAX_LENGTH,
    "HIVE_MAX_TRANSACTION_SIZE": HIVE_MAX_TRANSACTION_SIZE,
    "HIVE_MAX_BLOCK_SIZE": HIVE_MAX_BLOCK_SIZE,
    "HIVE_BLOCK_INTERVAL": HIVE_BLOCK_INTERVAL,
    "HIVE_RC_TARGET_BUDGET_PER_BLOCK": HIVE_RC_TARGET_BUDGET_PER_BLOCK,
    "HIVE_RC_AVERAGE_BLOCK_MANA": HIVE_RC_AVERAGE_BLOCK_MANA,
    "HIVE_RC_ACCOUNT_SUBSIDY_TRIPLE_WINDOW": HIVE_RC_ACCOUNT_SUBSIDY_TRIPLE_WINDOW,
}

NETWORK_RC_PER_DAY = HIVE_RC_TARGET_BUDGET_PER_BLOCK * HIVE_BLOCKS_PER_DAY
REGEN_SECONDS = HIVE_RC_ACCOUNT_SUBSIDY_TRIPLE_WINDOW     # 432000 s = 5 days


class ProtocolError(ValueError):
    pass


def roots_per_operation(entry_bytes_including_separator: int) -> int:
    """How many Merkle-root entries fit in ONE free custom_json.

    entry_bytes_including_separator must include the separator, because K entries
    carry K-1 separators and the budget is consumed by both. For tier E that is
    51 bytes of entry plus 1 byte of separator = 52, giving 8192 // 53 = 154
    when the trailing separator is accounted for exactly as packing.max_entries
    does. Callers should prefer packing.max_entries(), which is the authority.
    """
    if entry_bytes_including_separator < 1:
        raise ProtocolError("entry_bytes must be >= 1")
    return HIVE_CUSTOM_JSON_DATA_MAX_LENGTH // entry_bytes_including_separator


def operations_per_transaction(operation_bytes: int) -> int:
    """How many such operations fit in one transaction (64 KiB)."""
    if operation_bytes < 1:
        raise ProtocolError("operation_bytes must be >= 1")
    return HIVE_MAX_TRANSACTION_SIZE // operation_bytes


def seconds_per_day() -> int:
    return 86400


def seals_per_day_at_interval(blocks_between_seals: int) -> float:
    """Their pulse chain seals every N blocks; blocks are 3 s apart."""
    if blocks_between_seals < 1:
        raise ProtocolError("blocks_between_seals must be >= 1")
    return HIVE_BLOCKS_PER_DAY / blocks_between_seals
