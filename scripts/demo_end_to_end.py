#!/usr/bin/env python3
"""End-to-end demonstration of the full JUMPPER pipeline.

Runs the whole chain locally and, where the sandbox allows, performs a REAL
read-only witness capture against public chain endpoints. Nothing is signed.
Nothing is broadcast. No keys are read.

    python scripts/demo_end_to_end.py
"""

import hashlib, json, sys, time

import os as _os
_HERE = _os.path.dirname(_os.path.abspath(__file__))
_ROOT = _os.path.dirname(_HERE)
for _cand in (_os.path.join(_ROOT, "src"), _ROOT):
    if _os.path.isdir(_os.path.join(_cand, "jumpper")):
        sys.path.insert(0, _cand)
        break

from jumpper import anchor as AN
from jumpper import batch as BA
from jumpper import claim as CL
from jumpper import merkle as MK
from jumpper import witness as WI


def main() -> int:
    print("=" * 74)
    print("SAOS JUMPPER - end-to-end pipeline demonstration")
    print("=" * 74)

    # L0 INGEST
    b = BA.Batcher(max_leaves=5, max_age=300)
    base = time.time()
    claims = []
    for i in range(5):
        c = CL.make_claim(
            {"agent": "demo", "seq": i, "statement": "state at step %d" % i},
            time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(base + i)),
            public=(i == 0),
            source="demo",
        )
        claims.append(c)
        s = b.add(c, now=base + i)
    print("\n[L0 INGEST]  5 claims hashed, 1 public / 4 private (commit without disclosure)")
    print("             leafHash[0] =", claims[0].leaf_hash)

    # L1 BATCH
    sealed = b.sealed[-1] if b.sealed else b.force_seal(now=base + 10)
    print("\n[L1 BATCH]   height=%d leaves=%d reason=%s" % (sealed.height, sealed.leaf_count, sealed.seal_reason))
    print("             root =", sealed.root)
    b.assert_consistent()
    print("             invariants: heights contiguous, roots unique, all proofs valid")

    # L3 WITNESS (real, read-only, keyless)
    print("\n[L3 WITNESS] capturing head refs from public chain endpoints (read-only)...")
    cap = WI.capture()
    for chain in WI.CHAINS:
        d = cap[chain]
        if d.get("reachable"):
            print("             %-9s OK   headRef=%-12s %-20s %sms" % (chain, d["headRef"], d["kind"], d["ms"]))
        else:
            print("             %-9s FAIL %s (honest degradation - value NOT invented)" % (chain, d.get("error")))
    print("             summary:", WI.summary(cap))
    w = WI.compact_witness(cap)

    # L2 ANCHOR (built and priced, never signed, never broadcast)
    at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    payload = AN.build_payload(sealed.height, sealed.root, sealed.leaf_count, at, w)
    hexdata = AN.to_calldata_hex(payload)
    cost = AN.estimate_cost(AN.payload_bytes(payload), 10 ** 9)
    print("\n[L2 ANCHOR]  payload %d bytes -> calldata %d hex chars" % (len(payload.encode()), len(hexdata) - 2))
    print("             binding rule : %s (tokens=%d, eip2028=%d, floor=%d)"
          % (cost.binding_rule, cost.tokens, cost.gas_eip2028, cost.gas_floor))
    print("             total gas    : %s" % format(cost.total_gas, ","))
    print("             cost @1gwei  : %.9f ETH" % cost.cost_eth)
    print("             per claim    : %.3e ETH" % (cost.cost_eth / sealed.leaf_count))
    print("             NOT SIGNED. NOT BROADCAST. External signer only.")

    # L4 VERIFY - tier 1 (self) and tier 3 (on-chain shape)
    print("\n[L4 VERIFY]")
    leaf0 = claims[0].leaf_hash
    ok1 = MK.verify(leaf0, sealed.proofs[leaf0], sealed.root)
    print("             tier1 self-verify inclusion : %s (no network, no trust in us)" % ok1)
    ok3 = AN.verify_anchor_matches(hexdata, sealed.height, sealed.root, sealed.leaf_count)
    print("             tier3 on-chain shape match  : %s (anyone can run this from an explorer)" % ok3)
    bad = AN.verify_anchor_matches(hexdata, sealed.height + 1, sealed.root, sealed.leaf_count)
    print("             tamper rejected             : %s" % (not bad))

    print("\n" + "=" * 74)
    allgreen = ok1 and ok3 and not bad
    print("RESULT: %s" % ("PIPELINE GREEN" if allgreen else "PIPELINE FAILED"))
    print("=" * 74)
    print("\ncalldata that WOULD be sent (public, permanent, verifiable):")
    print(payload)
    return 0 if allgreen else 1


if __name__ == "__main__":
    raise SystemExit(main())
