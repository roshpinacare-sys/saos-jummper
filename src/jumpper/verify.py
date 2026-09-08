"""Standalone verifier - tier 1: zero trust, zero network.

    python -m jumpper.verify --leaf <64hex> --proof proof.json --root <64hex>
    python -m jumpper.verify --calldata <0xhex> --height H --root <64hex> --leaf-count N

Exit 0 match, 1 mismatch, 2 bad input. Must work with no network access and no
dependency on any JUMPPER service. If it needs us, it is not a verifier.
"""

from __future__ import annotations

import argparse
import json
import sys

from . import anchor, merkle


def verify_inclusion(leaf: str, path, expected_root: str) -> bool:
    return merkle.verify(leaf, path, expected_root)


def verify_onchain(calldata_hex: str, height: int, root: str, leaf_count: int) -> bool:
    return anchor.verify_anchor_matches(calldata_hex, height, root, leaf_count)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="jumpper.verify", description="Standalone JUMPPER verifier")
    p.add_argument("--leaf"); p.add_argument("--proof"); p.add_argument("--root")
    p.add_argument("--calldata"); p.add_argument("--height", type=int); p.add_argument("--leaf-count", type=int)
    a = p.parse_args(argv)
    try:
        if a.calldata:
            if a.height is None or a.root is None or a.leaf_count is None:
                print("calldata mode needs --height --root --leaf-count", file=sys.stderr); return 2
            ok = verify_onchain(a.calldata, a.height, a.root, a.leaf_count)
            print(json.dumps({"mode": "onchain", "match": ok})); return 0 if ok else 1
        if a.leaf and a.proof and a.root:
            with open(a.proof) as fh: path = json.load(fh)
            ok = verify_inclusion(a.leaf, path, a.root)
            print(json.dumps({"mode": "inclusion", "match": ok})); return 0 if ok else 1
        print("provide --calldata mode or --leaf/--proof/--root mode", file=sys.stderr); return 2
    except (anchor.AnchorError, json.JSONDecodeError, OSError, ValueError) as exc:
        print(json.dumps({"error": type(exc).__name__, "detail": str(exc)[:200]}), file=sys.stderr); return 2


if __name__ == "__main__":
    raise SystemExit(main())
