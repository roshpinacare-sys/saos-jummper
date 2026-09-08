"""Ethereum mainnet anchor: calldata construction and exact gas costing.

Method: self-transfer, 0 ETH value, commitment carried in calldata.

Why self-transfer rather than a contract:
  - no deployment, no contract risk, no upgrade path to break
  - no counterparty, no approval, no allowance
  - calldata is permanent in block history (EIP-4844 blobs expire; calldata does not)
  - verifiable by anyone from any public explorer, with zero trust in us

This module builds and prices the payload. It NEVER signs and NEVER broadcasts.
Signing happens outside the system; JUMPPER records only the public result.

------------------------------------------------------------------------------
GAS MODEL - validated against real mainnet, not assumed
------------------------------------------------------------------------------
Two rules apply and the transaction pays the MAXIMUM of them:

  EIP-2028 (Istanbul)  calldataGas = 16 * nonzero + 4 * zero
  EIP-7623 (Prague)    tokens      = zero + 4 * nonzero
                       floorGas    = 10 * tokens
                       gasUsed     = max(21000 + calldataGas, 21000 + floorGas)

For ASCII-JSON payloads (all bytes non-zero) the EIP-7623 floor always binds:
effective cost is 40 gas per byte, not 16. A naive EIP-2028-only model
underestimates by 150 percent (24,968 predicted vs 30,920 actual).

VALIDATION against a real Ethereum mainnet transaction:
    txid      0x94f4cb4fc0c50d742a583576b2cb1d14fa55dd99437510bf252a6ccba3e37813
    block     25,929,672   status 0x1   to == from (EOA self-transfer)
    calldata  248 bytes, 248 non-zero, 0 zero
    tokens    0 + 4*248                   = 992
    floorGas  10 * 992                    = 9,920
    eip2028   16 * 248                    = 3,968
    model     max(21000+3968, 21000+9920) = 30,920
    actual    gasUsed                     = 30,920      EXACT MATCH
    model     30920 * 1050884809 wei      = 0.000032493 ETH  EXACT MATCH

That exact match is why this module can be trusted to price the product.

------------------------------------------------------------------------------
THE ECONOMIC CONSEQUENCE (measured, see docs/ECONOMICS.md)
------------------------------------------------------------------------------
A Merkle root is 64 hex chars regardless of leaf count, so calldata does NOT
grow with batch size. Measured: leafCount 1 -> 1,000,000 costs only +240 gas
(+0.85%). Adding the full 5-chain witness costs +2,560 gas (+9.0%).
Per-claim cost therefore falls almost exactly as 1/batchSize. That is the
entire business model.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, Optional

PROTOCOL = "saos-jumpper/v1"
ACTION = "batch-anchor"
BASE_GAS = 21000
GAS_NONZERO = 16
GAS_ZERO = 4
FLOOR_TOKEN_MULTIPLIER = 4
FLOOR_COST_PER_TOKEN = 10


class AnchorError(ValueError):
    pass


def calldata_tokens(payload: bytes) -> int:
    """EIP-7623 token count: 1 per zero byte, 4 per non-zero byte."""
    nonzero = sum(1 for b in payload if b != 0)
    return (len(payload) - nonzero) + FLOOR_TOKEN_MULTIPLIER * nonzero


def calldata_gas_eip2028(payload: bytes) -> int:
    nonzero = sum(1 for b in payload if b != 0)
    return nonzero * GAS_NONZERO + (len(payload) - nonzero) * GAS_ZERO


def calldata_gas_floor(payload: bytes) -> int:
    return FLOOR_COST_PER_TOKEN * calldata_tokens(payload)


def calldata_gas(payload: bytes) -> int:
    """Effective calldata gas: whichever rule binds."""
    return max(calldata_gas_eip2028(payload), calldata_gas_floor(payload))


def total_gas(payload: bytes) -> int:
    return BASE_GAS + calldata_gas(payload)


@dataclass(frozen=True)
class AnchorCost:
    payload_bytes: int
    nonzero_bytes: int
    zero_bytes: int
    tokens: int
    gas_eip2028: int
    gas_floor: int
    binding_rule: str
    calldata_gas: int
    total_gas: int
    gas_price_wei: int
    cost_wei: int
    cost_eth: float

    def as_dict(self) -> Dict[str, Any]:
        return {"payloadBytes": self.payload_bytes, "nonzeroBytes": self.nonzero_bytes,
                "zeroBytes": self.zero_bytes, "tokens": self.tokens,
                "gasEip2028": self.gas_eip2028, "gasFloor": self.gas_floor,
                "bindingRule": self.binding_rule, "calldataGas": self.calldata_gas,
                "totalGas": self.total_gas, "gasPriceWei": self.gas_price_wei,
                "costWei": self.cost_wei, "costEth": self.cost_eth}


def estimate_cost(payload: bytes, gas_price_wei: int) -> AnchorCost:
    if gas_price_wei < 0:
        raise AnchorError("gas_price_wei must be non-negative")
    nz = sum(1 for b in payload if b != 0)
    g2028 = calldata_gas_eip2028(payload)
    gfloor = calldata_gas_floor(payload)
    cg = max(g2028, gfloor)
    tg = BASE_GAS + cg
    cw = tg * gas_price_wei
    return AnchorCost(payload_bytes=len(payload), nonzero_bytes=nz,
                      zero_bytes=len(payload) - nz, tokens=calldata_tokens(payload),
                      gas_eip2028=g2028, gas_floor=gfloor,
                      binding_rule="EIP-7623-floor" if gfloor >= g2028 else "EIP-2028",
                      calldata_gas=cg, total_gas=tg, gas_price_wei=gas_price_wei,
                      cost_wei=cw, cost_eth=cw / 1e18)


def build_payload(height: int, root: str, leaf_count: int, at: str,
                  witness: Optional[Dict[str, Any]] = None) -> str:
    """Exact calldata string: compact UTF-8 JSON, insertion-ordered."""
    if not isinstance(height, int) or isinstance(height, bool) or height < 1:
        raise AnchorError("height must be an int >= 1")
    if not isinstance(leaf_count, int) or isinstance(leaf_count, bool) or leaf_count < 1:
        raise AnchorError("leaf_count must be an int >= 1")
    if len(root) != 64 or any(c not in "0123456789abcdef" for c in root):
        raise AnchorError("root must be 64-char lowercase hex")
    obj: Dict[str, Any] = {"protocol": PROTOCOL, "action": ACTION, "height": height,
                           "root": root, "leafCount": leaf_count, "at": at}
    if witness:
        obj["witness"] = witness
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


def payload_bytes(payload: str) -> bytes:
    return payload.encode("utf-8")


def to_calldata_hex(payload: str) -> str:
    """0x-prefixed calldata exactly as it appears on chain."""
    return "0x" + payload_bytes(payload).hex()


def decode_calldata(hexdata: str) -> Dict[str, Any]:
    """Decode calldata from a public explorer or RPC. Zero trust in us."""
    h = hexdata[2:] if hexdata.startswith("0x") else hexdata
    if len(h) % 2 != 0:
        raise AnchorError("calldata hex has odd length")
    try:
        raw = bytes.fromhex(h)
    except ValueError as exc:
        raise AnchorError("calldata is not valid hex: %s" % exc) from exc
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AnchorError("calldata is not valid UTF-8: %s" % exc) from exc
    try:
        obj = json.loads(text)
    except json.JSONDecodeError as exc:
        raise AnchorError("calldata is not valid JSON: %s" % exc) from exc
    if not isinstance(obj, dict):
        raise AnchorError("calldata JSON must be an object")
    return obj


def verify_anchor_matches(calldata_hex: str, height: int, root: str, leaf_count: int) -> bool:
    """Tier-3 check anyone can run: does the chain say what we claim?"""
    try:
        obj = decode_calldata(calldata_hex)
    except AnchorError:
        return False
    return (obj.get("protocol") == PROTOCOL and obj.get("action") == ACTION
            and obj.get("height") == height and obj.get("root") == root
            and obj.get("leafCount") == leaf_count)
