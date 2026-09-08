# hardening:allow-file ALL reason=this module documents the defective verifier flag and the devnet default it exists to prevent
"""Solana memo anchoring - measured against mainnet, not estimated.

VERIFIED on Solana mainnet via solana-rpc.publicnode.com, 2026-09-08:

    signature  iHD5SC5F3Dq6VeJqq1mQs8Bju5RSs9yBGmVCRVnSa21r33MYVNq7evfFzzs4FT7mJ7TKSdnXRd9ocgsb1h5kgGq
    slot       445,225,030      blockTime 1788834653      err null (success)
    fee        5,000 lamports = 0.000005 SOL
    compute    102,351 of 200,000 units
    program    MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr   (official SPL Memo)
    signer     9knfnFMLmhUNjKRDbR1BmVnVkq4BRczyYjJ7BqiZSgiL
    memo       248 bytes of UTF-8 JSON, recorded verbatim in the program log

The memo text is recoverable by ANYONE from the transaction log with no indexer,
no service and no trust in us.

WHAT THIS SETTLES
The ledger recorded solana anchored=27, verified=0, which read as 27 failures.
It is not. This anchor is on MAINNET and it succeeded. The zero is caused
entirely by the verifier calling getSignatureStatuses with
searchTransactionHistory: false, which cannot see anything older than the node
cache. One boolean. See rule H-13.

The separate risk that relay-sol.ts defaults to api.devnet.solana.com when
SOL_RPC_URL is unset (rule H-12) did NOT materialise for this anchor - it is
provably mainnet. The risk is still real for any run with the variable unset, so
it still needs the fail-closed fix.

COST, MEASURED - for an identical 248-byte commitment:

    Solana memo        5,000 lamports   0.000005000 SOL   ~$0.00075 at $150
    Ethereum calldata  30,920 gas       0.000032493 ETH   ~$0.08123 at $2500
    Ethereum is 108x more expensive for the same bytes on a public chain.

Runway is a balance question, not a budget question. At the observed balance of
23,981,117 lamports the account can still fund 4,796 more memo anchors.

SIZE LIMIT - stated honestly. A Solana transaction is capped at 1,232 bytes. A
single-signer memo transaction carries a 64-byte signature plus message overhead.
The widely quoted SPL Memo ceiling is 566 bytes. NEITHER figure is verified here
by construction - only the 248-byte memo above is proven to have landed. Treat 248
as measured and anything larger as needing a test broadcast first. This matters
because the HIVE custom_json budget of 8,192 bytes is proven and holds 154 roots;
Solana memo cannot hold that many, so the two are not interchangeable for packing.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

MEMO_PROGRAM_ID = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"

MEASURED_FEE_LAMPORTS = 5000
MEASURED_COMPUTE_UNITS = 102351
MEASURED_COMPUTE_BUDGET = 200000
MEASURED_MEMO_BYTES = 248
MEASURED_SLOT = 445225030
MEASURED_SIGNATURE = "iHD5SC5F3Dq6VeJqq1mQs8Bju5RSs9yBGmVCRVnSa21r33MYVNq7evfFzzs4FT7mJ7TKSdnXRd9ocgsb1h5kgGq"
MEASURED_SIGNER = "9knfnFMLmhUNjKRDbR1BmVnVkq4BRczyYjJ7BqiZSgiL"

TX_SIZE_LIMIT = 1232
REPORTED_MEMO_CEILING = 566
CONSERVATIVE_MEMO_BUDGET = 512


class SolanaError(ValueError):
    pass


@dataclass(frozen=True)
class MemoCost:
    fee_lamports: int
    fee_sol: float
    memo_bytes: int
    compute_units: int
    usd_at_price: Optional[float]
    cost_usd: Optional[float]

    def as_dict(self) -> Dict[str, Any]:
        return {"feeLamports": self.fee_lamports, "feeSol": self.fee_sol,
                "memoBytes": self.memo_bytes, "computeUnits": self.compute_units,
                "solPriceUsd": self.usd_at_price, "costUsd": self.cost_usd}


def memo_cost(memo_bytes: int, sol_price_usd: Optional[float] = None) -> MemoCost:
    """The fee is flat per signature, not per byte - measured, not assumed."""
    if memo_bytes < 0:
        raise SolanaError("memo_bytes cannot be negative")
    if memo_bytes > CONSERVATIVE_MEMO_BUDGET:
        raise SolanaError("memo of %d bytes exceeds the %d-byte planning budget; only "
                          "%d bytes is proven to have landed on mainnet"
                          % (memo_bytes, CONSERVATIVE_MEMO_BUDGET, MEASURED_MEMO_BYTES))
    sol = MEASURED_FEE_LAMPORTS / 1e9
    return MemoCost(fee_lamports=MEASURED_FEE_LAMPORTS, fee_sol=sol, memo_bytes=memo_bytes,
                    compute_units=MEASURED_COMPUTE_UNITS, usd_at_price=sol_price_usd,
                    cost_usd=(sol * sol_price_usd) if sol_price_usd else None)


def runway(balance_lamports: int) -> Dict[str, Any]:
    """How many more anchors the account can fund. Pure arithmetic on the flat fee."""
    if balance_lamports < 0:
        raise SolanaError("balance cannot be negative")
    return {"balanceLamports": balance_lamports, "balanceSol": balance_lamports / 1e9,
            "feeLamports": MEASURED_FEE_LAMPORTS,
            "anchorsRemaining": balance_lamports // MEASURED_FEE_LAMPORTS}


def extract_memo(log_messages) -> Optional[str]:
    """Pull the memo text back out of a transaction log.

    This is the tier-3 verification path: anyone can fetch the transaction from a
    public RPC and recover exactly what was committed, with no help from us.
    """
    marker = "Program log: Memo (len "
    for line in log_messages or []:
        if not isinstance(line, str) or marker not in line:
            continue
        tail = line.split(marker, 1)[1]
        if "): " not in tail:
            continue
        declared, payload = tail.split("): ", 1)
        try:
            n = int(declared)
        except ValueError:
            continue
        body = payload.strip()
        if body.startswith('"') and body.endswith('"'):
            body = body[1:-1]
        body = body.replace('\\\"', '"')
        if len(body.encode("utf-8")) != n:
            continue
        return body
    return None


def memo_matches(log_messages, expected_payload: str) -> bool:
    got = extract_memo(log_messages)
    return got is not None and got == expected_payload


def verify_transaction(tx: Dict[str, Any], expected_payload: str) -> Dict[str, Any]:
    """Full verification from a raw getTransaction result."""
    meta = tx.get("meta") or {}
    logs = meta.get("logMessages") or []
    memo = extract_memo(logs)
    return {"success": meta.get("err") is None, "err": meta.get("err"),
            "slot": tx.get("slot"), "blockTime": tx.get("blockTime"),
            "feeLamports": meta.get("fee"), "memoFound": memo is not None,
            "memoMatches": memo == expected_payload,
            "signedByExpectedSigner": any("Signed by " + MEASURED_SIGNER in (l or "") for l in logs),
            "usedOfficialMemoProgram": any(MEMO_PROGRAM_ID in (l or "") for l in logs),
            "verified": bool(meta.get("err") is None and memo == expected_payload
                             and any(MEMO_PROGRAM_ID in (l or "") for l in logs))}


def is_mainnet_endpoint(url: str) -> Optional[bool]:
    """Refuse to guess. True/False when unambiguous, else None.

    Rule H-12 exists because relay-sol.ts silently defaults to devnet. A caller
    that gets None back must fail closed rather than assume mainnet.
    """
    u = (url or "").lower()
    if "devnet" in u or "testnet" in u:
        return False
    if "mainnet" in u:
        return True
    return None
