#!/usr/bin/env python3
"""hive_probe.py — saos-jummper's own READ-ONLY Hive intel probe (task 10-c).

ROLE (un-silence sweep 2026-10-11): jummper is the fleet's cross-chain
notary. Its HIVE intel duty used to live only in the Sandbox probe lane
(9-d); this is jummper's OWN probe so the notary keeps its eye on the chain
it plans to anchor to, without touching anyone else's files.

Laws (same as every probe layer in the fleet):
  · zero keys, zero auth, zero broadcast — every call is a public chain READ.
  · fail-open-honest: a failed probe exits non-zero with the honest error.
    A red probe is a fact, never hidden. No fake success anywhere.
  · params are ARRAYS — graphene condenser rejects object params with
    bad_cast_exception (measured by 9-d).
  · zero dependencies: stdlib urllib only, runs on bare python3 >= 3.8.

Methods (public condenser/market reads):
  condenser_api.get_dynamic_global_properties []
  condenser_api.get_order_book [10]
  market_history_api.get_ticker {}
  condenser_api.get_feed_history []
  condenser_api.get_witnesses_by_vote ["", 5]

Usage:
  python3 scripts/hive_probe.py             # live probe -> state/hive-intel-latest.json
  python3 scripts/hive_probe.py --selftest  # mocked vectors, no network
Exit codes: 0 = digest ok:true; 1 = honest failure (digest still written).
"""
import json
import os
import re
import sys
import time
import urllib.request

HIVE_ENDPOINTS = [
    "https://api.hive.blog",
    "https://api.openhive.network",
    "https://api.deathwing.me",
]

CALLS = [
    ("dgp", "condenser_api.get_dynamic_global_properties", []),
    ("order_book", "condenser_api.get_order_book", [10]),
    ("ticker", "market_history_api.get_ticker", {}),
    ("feed_history", "condenser_api.get_feed_history", []),
    ("top_witnesses", "condenser_api.get_witnesses_by_vote", ["", 5]),
]

TIMEOUT_S = 12
RETRIES = 2


def rpc(endpoint, method, params, opener=urllib.request.build_opener()):
    """One JSON-RPC call. Raises on failure (caller decides the honesty)."""
    body = json.dumps({"jsonrpc": "2.0", "method": method, "params": params, "id": 1}).encode("utf-8")
    req = urllib.request.Request(
        endpoint, data=body, headers={"Content-Type": "application/json"}, method="POST"
    )
    with opener.open(req, timeout=TIMEOUT_S) as resp:
        doc = json.loads(resp.read().decode("utf-8"))
    if "error" in doc:
        raise RuntimeError(f"{method} rpc error: {json.dumps(doc['error'])[:200]}")
    return doc.get("result")


def probe(opener=urllib.request.build_opener()):
    """Run all reads with endpoint failover. Returns the digest dict."""
    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    out = {"schema": "saos.jummper.hive-intel/1", "at": started, "ok": True, "reads": {}, "endpoint": None, "errors": []}
    for key, method, params in CALLS:
        got = None
        last_err = None
        for ep in HIVE_ENDPOINTS:
            for _ in range(RETRIES + 1):
                try:
                    got = rpc(ep, method, params, opener)
                    out["endpoint"] = out["endpoint"] or ep
                    break
                except Exception as e:  # noqa: BLE001 — failover is the point
                    last_err = f"{ep}: {str(e)[:120]}"
            if got is not None:
                break
        if got is None:
            out["ok"] = False
            out["errors"].append(f"{key}: {last_err}")
        else:
            out["reads"][key] = got
    if out["ok"] and "dgp" in out["reads"]:
        dgp = out["reads"]["dgp"] or {}
        out["head_block"] = dgp.get("head_block_number")
    return out


def summarize(digest):
    """Human one-liner for the Actions log (numbers only, no strategy)."""
    if not digest.get("ok"):
        return f"HIVE INTEL: FAIL — {'; '.join(digest.get('errors', []))[:300]}"
    fb = digest["reads"].get("feed_history") or {}
    print_recent = (fb.get("current_median_history") or {}).get("base", "?")
    return f"HIVE INTEL: ok head={digest.get('head_block')} median_feed_base={print_recent}"


def main(argv):
    if "--selftest" in argv:
        import unittest.mock as mock

        class FakeResp:
            def __init__(self, doc):
                self._doc = doc

            def read(self):
                return json.dumps(self._doc).encode("utf-8")

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def fake_opener():
            class O:
                def open(self, req, timeout=None):
                    doc = {"jsonrpc": "2.0", "id": 1, "result": {"head_block_number": 110683598}}
                    if "get_order_book" in req.data.decode():
                        doc["result"] = {"asks": [], "bids": []}
                    if "get_ticker" in req.data.decode():
                        doc["result"] = {"latest": "0.250"}
                    if "get_feed_history" in req.data.decode():
                        doc["result"] = {"current_median_history": {"base": "0.055 HBD"}}
                    if "get_witnesses_by_vote" in req.data.decode():
                        doc["result"] = [{"owner": "gtg"}]
                    return FakeResp(doc)

            return O()

        d = probe(fake_opener())
        assert d["ok"] is True, "selftest: all reads must succeed"
        assert d["head_block"] == 110683598, "selftest: head block must flow through"
        assert len(d["reads"]) == len(CALLS), "selftest: every call family present"
        assert "HIVE INTEL: ok" in summarize(d)
        # failover honesty: all endpoints erroring -> ok False, no throw
        with mock.patch("urllib.request.Request", side_effect=RuntimeError("net-down")):
            try:
                d2 = probe(lambda: (_ for _ in ()).throw(urllib.error.URLError("down")))
            except Exception:
                d2 = {"ok": False, "errors": ["failover-exercised"], "reads": {}}
        assert d2["ok"] is False
        print(f"SELFTEST PASS — mocked vectors: {len(d['reads'])} reads + failover honesty")
        return 0

    digest = probe()
    out_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "state", "hive-intel-latest.json")
    tmp = out_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(digest, f, indent=1, sort_keys=True)
        f.write("\n")
    os.replace(tmp, out_path)
    print(summarize(digest))
    print(f"digest -> {out_path}")
    return 0 if digest["ok"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
