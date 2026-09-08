"""Multi-chain temporal witness.

At anchor time we read the head reference from five independent chains. Five
clocks testify to the same moment. If Ethereum reorgs, four witnesses remain.
If our server clock drifts, the chains do not.

All endpoints are keyless and public. Every probe is read-only. Nothing here
signs, broadcasts, or mutates any chain.

Honest degradation is mandatory: an unreachable chain is reported as
unreachable with its error class. A witness value is NEVER invented. The audited
estate lost trust precisely because counters were incremented optimistically
instead of being derived from verification results.

Only hostnames are logged, never full URLs - some public endpoints embed keys in
query strings.
"""

from __future__ import annotations

import time
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None

TIMEOUT = 2.5

CHAINS: List[str] = ["STEEM", "HIVE", "TRON", "ETHEREUM", "SOLANA"]


def _host(url: str) -> str:
    try:
        return urlparse(url).hostname or "unknown"
    except Exception:
        return "unknown"


def _post(url: str, payload: Dict[str, Any], timeout: float = TIMEOUT) -> Any:
    if requests is None:
        raise RuntimeError("requests not available")
    r = requests.post(url, json=payload, headers={"Content-Type": "application/json"},
                      timeout=timeout)
    r.raise_for_status()
    body = r.json()
    if isinstance(body, dict) and body.get("error"):
        raise RuntimeError(str(body["error"])[:120])
    return body


def probe_steem() -> Dict[str, Any]:
    url = "https://api.steemit.com"
    res = _post(url, {"jsonrpc": "2.0", "id": 1,
                      "method": "condenser_api.get_dynamic_global_properties", "params": []})
    props = res["result"] if isinstance(res, dict) else res[0]["result"]
    return {"endpoint": _host(url), "headRef": int(props["head_block_number"]), "kind": "head_block_number"}


def probe_hive() -> Dict[str, Any]:
    url = "https://api.hive.blog"
    res = _post(url, {"jsonrpc": "2.0", "id": 1,
                      "method": "condenser_api.get_dynamic_global_properties", "params": []})
    props = res["result"]
    return {"endpoint": _host(url), "headRef": int(props["head_block_number"]), "kind": "head_block_number"}


def probe_tron() -> Dict[str, Any]:
    url = "https://api.trongrid.io"
    r = requests.post(url + "/wallet/getnowblock", json={}, timeout=TIMEOUT)
    r.raise_for_status()
    blk = r.json()
    return {"endpoint": _host(url), "headRef": int(blk["block_header"]["raw_data"]["number"]), "kind": "block_number"}


def probe_ethereum() -> Dict[str, Any]:
    url = "https://ethereum-rpc.publicnode.com"
    res = _post(url, {"jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber", "params": []})
    return {"endpoint": _host(url), "headRef": int(res["result"], 16), "kind": "blockNumber"}


def probe_solana() -> Dict[str, Any]:
    url = "https://api.mainnet-beta.solana.com"
    res = _post(url, {"jsonrpc": "2.0", "id": 1, "method": "getSlot", "params": []})
    return {"endpoint": _host(url), "headRef": int(res["result"]), "kind": "slot"}


PROBES: Dict[str, Callable[[], Dict[str, Any]]] = {
    "STEEM": probe_steem, "HIVE": probe_hive, "TRON": probe_tron,
    "ETHEREUM": probe_ethereum, "SOLANA": probe_solana,
}


def capture(chains: Optional[List[str]] = None) -> Dict[str, Dict[str, Any]]:
    """Capture head refs. Never raises; unreachable chains are reported honestly."""
    out: Dict[str, Dict[str, Any]] = {}
    for chain in chains or CHAINS:
        fn = PROBES.get(chain)
        started = time.time()
        if fn is None:
            out[chain] = {"reachable": False, "error": "unknown-chain", "ms": 0}
            continue
        try:
            data = fn()
            data.update({"reachable": True, "chain": chain,
                         "capturedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                         "ms": round((time.time() - started) * 1000, 1)})
            out[chain] = data
        except Exception as exc:
            out[chain] = {"chain": chain, "reachable": False,
                          "error": type(exc).__name__, "detail": str(exc)[:120],
                          "capturedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                          "ms": round((time.time() - started) * 1000, 1)}
    return out


def compact_witness(captured: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """Minimal form embedded in calldata. Keeps bytes (and therefore gas) low."""
    out: Dict[str, Any] = {}
    for chain, data in captured.items():
        if data.get("reachable"):
            out[chain.lower()] = data["headRef"]
        else:
            out[chain.lower()] = None
    return out


def summary(captured: Dict[str, Dict[str, Any]]) -> Dict[str, int]:
    reachable = sum(1 for d in captured.values() if d.get("reachable"))
    return {"reachable": reachable, "unreachable": len(captured) - reachable, "total": len(captured)}
