#!/usr/bin/env python3
"""truthrail_anchor.py — saos-jummper's TruthRail notary lane (T-58 revival).

ROLE (FLEET-GRAPH edge saos-jummper -> TruthRail): the fleet's receipts
channel (TruthRail receipts/*.json, public, keyless) now gets a MERKLE ANCHOR:
one deterministic root over the latest receipts, with inclusion proofs, so
anyone — human or agent — can prove a receipt is part of the anchored batch
WITHOUT trusting the notary. The anchor lives at
state/truthrail-anchor-latest.json and is verified independently by the
fleet SDK (@saos/fleet-sdk verifyAnchor — recomputes the root, checks every
proof, spot-checks one receipt's bytes).

Laws (same as every probe/anchor layer in the fleet):
  · zero keys, zero auth, zero broadcast — every call is a public READ.
  · fail-open-honest: a failed anchor still commits its digest (a red anchor
    is a fact, never hidden). No fake success anywhere.
  · odd-node DUPLICATED merkle rule — the exact port already in production
    (src/jumpper/merkle.py) and in the fleet SDK; both must agree forever.
  · zero dependencies: stdlib urllib/hashlib only, bare python3 >= 3.8.

External chain anchors (Ethereum/Solana): adapters exist (src/jumpper/
crosschain.py, solana.py) but are KEY-GATED by the owner — recorded in the
anchor as `external: pending-owner-keys`. This lane does not fake one.

Usage:
  python3 scripts/truthrail_anchor.py             # live anchor -> state/
  python3 scripts/truthrail_anchor.py --selftest  # mocked vectors, no network
Exit codes: 0 = anchor ok:true; 1 = honest failure (digest still written).
"""
import hashlib
import json
import os
import sys
import time
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from jumpper import merkle  # the production port — never re-implement here

OWNER = "roshpinacare-sys"
RECEIPTS_API = f"https://api.github.com/repos/{OWNER}/TruthRail/contents/receipts"
RECEIPT_RAW = f"https://raw.githubusercontent.com/{OWNER}/TruthRail/main/receipts/"
MAX_RECEIPTS = 16
TIMEOUT_S = 15
OUT = os.path.join(os.path.dirname(__file__), "..", "state", "truthrail-anchor-latest.json")


def _get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "saos-jummper-notary/1 (keyless)"})
    with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:
        return resp.read()


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fetch_latest_receipts(limit=MAX_RECEIPTS):
    """Public, keyless listing + fetch of the fleet's receipt channel."""
    listing = json.loads(_get(RECEIPTS_API).decode("utf-8"))
    if not isinstance(listing, list) or not listing:
        raise RuntimeError(f"receipts listing empty or malformed ({len(listing) if isinstance(listing, list) else 'not a list'})")
    names = [x["name"] for x in listing if isinstance(x, dict) and x.get("name", "").endswith(".json")]
    picked = names[-limit:]
    out = []
    for name in picked:
        raw = _get(RECEIPT_RAW + urllib.request.quote(name))
        out.append({"path": name, "sha256": _sha256_hex(raw)})
    return out


def _build_anchor(leaves_meta, source):
    hashes = [m["sha256"] for m in leaves_meta]
    root = merkle.root(hashes)
    proofs = []
    for i in range(min(2, len(hashes))):
        proofs.append({"path": leaves_meta[i]["path"], "leaf": hashes[i], "proof": merkle.proof(hashes, i)})
    return {
        "schema": "saos.jummper.truthrail-anchor/1",
        "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "ok": True,
        "source": source,
        "root": root,
        "count": len(hashes),
        "leaves": leaves_meta,
        "proofs": proofs,
        "merkleRule": "sha256, odd-node duplicated (src/jumpper/merkle.py; fleet SDK port agrees)",
        "verifyWith": f"@saos/fleet-sdk verifyAnchor — Sdk repo sdk/index.js (keyless, recomputes root + proofs + bytes spot-check)",
        "external": "pending-owner-keys — crosschain.py/solana.py adapters ready; no key exists in this lane (by design)",
    }


def _write(anchor):
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(anchor, f, ensure_ascii=False, indent=2)
        f.write("\n")


def live():
    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    try:
        leaves = _fetch_latest_receipts()
        anchor = _build_anchor(leaves, f"TruthRail receipts/ on public main ({OWNER})")
        _write(anchor)
        print(f"ANCHOR OK root={anchor['root'][:16]}… receipts={anchor['count']} proofs={len(anchor['proofs'])}")
        return 0
    except Exception as e:  # noqa: BLE001 — fail-open-honest: red anchor is a fact
        _write({
            "schema": "saos.jummper.truthrail-anchor/1", "at": started, "ok": False,
            "source": f"TruthRail receipts/ on public main ({OWNER})",
            "error": str(e)[:300],
            "external": "pending-owner-keys — crosschain.py/solana.py adapters ready; no key exists in this lane (by design)",
        })
        print(f"ANCHOR RED (digest still written, honest): {e}", file=sys.stderr)
        return 1


def selftest():
    """Mocked receipts — deterministic root + proofs + tamper detection, no network."""
    base = os.path.join(os.path.dirname(__file__), "..", "state")
    try:
        fake = [{"path": f"receipt-{i}.json", "sha256": hashlib.sha256(f"mock-receipt-{i}".encode()).hexdigest()} for i in range(5)]
        anchor = _build_anchor(fake, "selftest (mocked, no network)")
        # invariants
        assert anchor["ok"] and len(anchor["leaves"]) == 5 and len(anchor["proofs"]) == 2
        recomputed = merkle.root([m["sha256"] for m in anchor["leaves"]])
        assert recomputed == anchor["root"], "root not reproducible"
        for p in anchor["proofs"]:
            assert merkle.verify(p["leaf"], p["proof"], anchor["root"]), f"proof for {p['path']} does not verify"
        # tamper: flip one leaf -> verification must fail
        bad = fake[0]["sha256"][:-1] + ("0" if fake[0]["sha256"][-1] != "0" else "1")
        assert not merkle.verify(bad, merkle.proof([m["sha256"] for m in fake], 0), anchor["root"]), "tampered leaf verified (IMPOSSIBLE)"
        # parity with the fleet SDK's independent recompute is checked by the SDK selftest
        print(f"SELFTEST OK root={anchor['root'][:16]}… (5 mocked receipts, 2 proofs, tamper detected)")
        return 0
    except AssertionError as e:
        print(f"SELFTEST FAIL: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(selftest() if "--selftest" in sys.argv else live())
