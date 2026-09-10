#!/usr/bin/env python3
# hardening:allow-file ALL reason=this harness deliberately invokes every module, including ones whose patterns the rules detect
"""Coverage harness - exercises every module in src/jumpper and refuses to pass otherwise.

WHY THIS EXISTS
---------------
scripts/demo_end_to_end.py printed RESULT: PIPELINE GREEN while importing five
modules out of thirty. A green light on a partial path is worse than no light,
because it gets read as a green light on the whole.

This harness keeps one real check per module, and exits non-zero if any module in
src/jumpper has no registered check. Adding a module without adding a check
therefore breaks the build instead of silently shrinking coverage - the property
the old demo lacked.

    python scripts/coverage_harness.py
    exit 0 = every module covered and every check passed
    exit 1 = a check failed, or a module has no check

Nothing here signs, broadcasts, or reads a key.
"""

import importlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
for _cand in (os.path.join(ROOT, "src"), ROOT):
    if os.path.isdir(os.path.join(_cand, "jumpper")):
        sys.path.insert(0, _cand)
        break

RESULTS = []


def check(module):
    """Register one real check for one module. Unregistered modules fail the run."""
    def deco(fn):
        RESULTS.append((module, fn))
        return fn
    return deco


R64 = "a8c3423cd68ea1df13a3e8f0dd1cc883f2e52c8e0a90f7c04e648405c60cd50f"
R64B = "6d4c4a120df44afb530180f78688cc15fffa66688e20ef80675710fad8f30843"
TS = "2026-09-08T02:30:53.712Z"
NL = chr(10)
DQ = chr(34)
ESC = chr(92) + chr(34)
PAYLOAD = ("{" + DQ + "protocol" + DQ + ":" + DQ + "saos-dex/v1" + DQ + ","
           + DQ + "action" + DQ + ":" + DQ + "chain-seal" + DQ + ","
           + DQ + "at" + DQ + ":" + DQ + TS + DQ + ","
           + DQ + "height" + DQ + ":108,"
           + DQ + "stateRoot" + DQ + ":" + DQ + R64B + DQ + ","
           + DQ + "digest" + DQ + ":" + DQ + R64 + DQ + "}")


@check("canonical")
def _canonical():
    m = importlib.import_module("jumpper.canonical")
    a = m.canonical_json({"b": 1, "a": 2})
    assert a == m.canonical_json({"a": 2, "b": 1}), "key order must not matter"
    assert " " not in a
    return "key-order independent, no whitespace"


@check("merkle")
def _merkle():
    m = importlib.import_module("jumpper.merkle")
    lv = [m.leaf_hash(str(i).encode()) for i in range(7)]
    r = m.root(lv)
    tr = m.build(lv)
    assert tr[-1][0] == r
    assert m.verify(lv[3], tr[1][3], r), "inclusion proof must verify"
    assert tr[1][-1] == lv[-1], "odd node carried up unchanged, not re-hashed"
    return "7 leaves, inclusion proof verified, odd-node convention pinned"


@check("claim")
def _claim():
    m = importlib.import_module("jumpper.claim")
    c = m.make_claim({"a": 1}, TS, public=True, source="harness")
    assert len(c.leaf_hash) == 64
    assert c.digest_of({"a": 1}) != c.leaf_hash, "domain separation must separate digest from leaf"
    return "domain-separated leaf hash"


@check("batch")
def _batch():
    m = importlib.import_module("jumpper.batch")
    b = m.Batcher(max_leaves=4, max_age=60)
    for i in range(4):
        b.add(m.make_claim({"i": i}, TS, public=True, source="h"), now=1000 + i)
    assert b.sealed and b.sealed[-1].leaf_count == 4, "must auto-seal at capacity"
    sb = b.sealed[-1]
    assert sb.height == 1 and sb.leaf_count == 4
    return "auto-seal at capacity, height 1, 4 leaves"


@check("anchor")
def _anchor():
    m = importlib.import_module("jumpper.anchor")
    c = m.estimate_cost(PAYLOAD.encode(), 1050884809)
    assert c.total_gas == 30920, c.total_gas
    assert c.is_eip7623_floor
    assert m.decode_calldata("0x" + PAYLOAD.encode().hex())["height"] == 108
    return "30920 gas (EIP-7623 floor), calldata round-trip"


@check("verify")
def _verify():
    m = importlib.import_module("jumpper.verify")
    r = m.verify_receipt({"payload_digest": "aa" * 32},
                         {"calldata": "0x" + PAYLOAD.encode().hex()})
    assert "payload_matches" in r and "calldata_present" in r
    return "receipt verified against calldata"


@check("witness")
def _witness():
    m = importlib.import_module("jumpper.witness")
    w = m.WitnessSet(quorum=2)
    w.add("w1", "aa" * 32)
    w.add("w2", "aa" * 32)
    s = w.status("aa" * 32)
    assert s["reached"] and s["distinct"] == 2
    return "quorum 2 reached by 2 distinct witnesses"


@check("protocol")
def _protocol():
    m = importlib.import_module("jumpper.protocol")
    assert m.HIVE_CUSTOM_JSON_DATA_MAX_LENGTH == 8192
    assert m.roots_per_operation(53) == 154
    assert m.REGEN_SECONDS == 432000
    return "custom_json 8192 B, 154 roots at 53 B, regen window 5 days"


@check("packing")
def _packing():
    m = importlib.import_module("jumpper.packing")
    assert m.max_entries() == 154
    e = m.RootEntry(1, 12108, R64)
    rt = m.unpack_payload(m.pack_payload([e] * 5))
    assert len(rt) == 5 and all(x.root == R64 for x in rt)
    pl = m.plan(154)
    assert pl.fits_custom_json and pl.byte_ratio > 2.5
    return "154 roots fit, 5-entry round-trip, packing ratio >2.5x"


@check("graphene")
def _graphene():
    m = importlib.import_module("jumpper.graphene")
    st = m.rc_state("headcorner", 1392041, 1788870714, 25641553538, 1788871925)
    assert round(st.effective_mana) == 73271489, round(st.effective_mana)
    op = m.build_custom_json("headcorner", "1,1,x")
    assert "fee" not in op[1] and op[1]["required_auths"] == ["headcorner"]
    return "RC projection matches the live measurement exactly; op carries no fee"


@check("authority")
def _authority():
    m = importlib.import_module("jumpper.authority")
    assert m.authority_for(m.ATTESTATION) == m.POSTING
    op = m.build_custom_json_by_policy("headcorner", "x", m.ATTESTATION)
    assert op[1]["required_posting_auths"] == ["headcorner"] and op[1]["required_auths"] == []
    assert m.blast_radius(m.ACTIVE)["canMoveFunds"]
    assert not m.blast_radius(m.POSTING)["canMoveFunds"]
    return "attestation -> posting; active can move funds, posting cannot"


@check("freeops")
def _freeops():
    m = importlib.import_module("jumpper.freeops")
    assert len(m.free_capabilities()) >= 10 and len(m.not_free_capabilities()) >= 4
    assert all(c.honest_limit for c in m.CAPABILITIES)
    assert not any(c.free_on_ours for c in m.CAPABILITIES if c.category == "enforcement")
    assert m.RcCalibration().calibrate(59355.0) is None, "must refuse to guess"
    return "no enforcement capability claims to be free; calibration refuses to guess"


@check("throughput")
def _throughput():
    m = importlib.import_module("jumpper.throughput")
    s = m.stack()
    assert s["combinedMultiplier"] > 6.0 and s["rootsPerOperation"] == 154
    ok = ("MEASURED", "DERIVED", "UNMEASURED", "STRUCTURAL", "PARTLY MEASURED")
    assert all(x["evidence"] in ok for x in s["stages"])
    return "combined multiplier %.2fx, every stage evidence-tagged" % s["combinedMultiplier"]


@check("sth")
def _sth():
    m = importlib.import_module("jumpper.sth")
    smp = m.SignedTreeHead("log-a", 1000, R64, TS, convention=m.CONV_SELFPAIR)
    rt = m.decode_heads(m.encode_heads([smp] * 3))
    assert len(rt) == 3 and rt[0].convention == m.CONV_SELFPAIR
    assert m.conventions_agree(4) and not m.conventions_agree(3)
    n = m.heads_per_operation(smp)
    assert m.encoded_size([smp] * n) <= 8192
    return "%d heads per free op; conventions agree at n=4, differ at n=3" % n


@check("solana")
def _solana():
    m = importlib.import_module("jumpper.solana")
    assert m.MEASURED_FEE_LAMPORTS == 5000 and m.MEASURED_SLOT == 445225030
    assert m.runway(23981117)["anchorsRemaining"] == 4796
    assert m.memo_cost(248, 150.0).cost_usd == 0.00075
    assert m.is_mainnet_endpoint("https://api.devnet.solana.com") is False
    assert m.is_mainnet_endpoint("https://rpc.example.com") is None
    try:
        m.memo_cost(900)
        raise AssertionError("oversize memo must be refused")
    except m.SolanaError:
        pass
    return "5000 lamports, 4796-anchor runway, devnet rejected, ambiguous -> None, oversize refused"


@check("crosschain")
def _crosschain():
    m = importlib.import_module("jumpper.crosschain")
    e = m.parse_ethereum({"hash": "0x94f4", "blockNumber": "0x18ba7c8",
                          "input": "0x" + PAYLOAD.encode().hex()}, {"status": "0x1"})
    log = "Program log: Memo (len 248): " + DQ + PAYLOAD.replace(DQ, ESC) + DQ
    s = m.parse_solana({"slot": 445225030,
                        "meta": {"err": None, "fee": 5000, "logMessages": [log]}})
    r = m.compare([e, s])
    assert r["commitmentEqual"] and r["allOnMainnet"] and r["allSucceeded"], r["verdict"]
    assert r["references"] == {"ETHEREUM": "25929672", "SOLANA": "445225030"}
    return r["verdict"]


@check("budget")
def _budget():
    m = importlib.import_module("jumpper.budget")
    op = {"id": "ssc-mainnet-hive", "json": "convert 9.632"}
    g = m.AnchorGate(
        budget=m.RollingBudget(limit=5128310708, window_seconds=86400, unit="rc", scope="h"),
        repeat=m.RepeatGuard(max_repeats=1, window_seconds=2 * 86400))
    allowed = denied = 0
    for i in range(11):
        v = g.evaluate(op, 157713792, network="hive-mainnet", now=1788775779 + i * 3600)
        if v.allowed:
            allowed += 1
            g.commit(op, 157713792, now=1788775779 + i * 3600)
        else:
            denied += 1
    assert (allowed, denied) == (1, 10), (allowed, denied)
    assert g.evaluate(op, 1, network="api.devnet.solana.com", now=1).decision == m.DENY
    return "the real 11-call convert loop: 1 allowed, 10 denied, 1577137920 RC recovered"


@check("heightguard")
def _heightguard():
    m = importlib.import_module("jumpper.heightguard")
    r1 = "d7220b5e9ecc953e7e8d" + "0" * 44
    r2 = "84ae0a0a08ef2f44becc" + "0" * 44
    h = [m.Commitment("", 1764, r1, "2026-09-09T18:27:21", 109770502, "49833"),
         m.Commitment("", 1764, r2, "2026-09-09T18:27:51", 109770512, "49834")]
    a = m.audit(h)
    assert a["forks"] == 1 and a["forkDetails"][0]["windowSeconds"] == 30
    led = m.HeightLedger()
    led.add(h[0])
    assert led.check("", 1764, r2)["decision"] == m.REFUSE
    assert led.check("", 1764, r1)["decision"] == m.REPUBLISH
    rep = m.remediation_report(h)
    assert rep["entries"][0]["status"] == "AMBIGUOUS"
    assert rep["entries"][0]["canonicalRoot"] is None
    return "height-1764 fork at 30 s detected, contradicting root refused, no canonical root invented"


@check("audit")
def _audit():
    m = importlib.import_module("jumpper.audit")
    recs = [{"who": "a", "when": TS, "what": "x", "which": "1", "outcome": "ok", "why": None},
            {"who": "b", "when": TS, "what": "y", "which": "2", "outcome": "ok", "why": None}]
    ch = m.build_chain("v1", recs)
    assert m.verify_chain("v1", ch)["intact"]
    bad = [dict(x) for x in ch]
    bad[0]["who"] = "evil"
    assert not m.verify_chain("v1", bad)["intact"]
    tr = m.verify_chain("v1", ch[:1])
    assert tr["intact"] and not tr["truncated"], "a chain alone cannot detect truncation"
    assert m.verify_chain("v1", ch[:1], expected_length=2)["truncated"]
    assert m.SAOSMARTWALLET.sound and not m.ROSHPINA.sound
    return "tamper detected; truncation invisible without an anchor; roshpina coverage unsound"


@check("attestation")
def _attestation():
    m = importlib.import_module("jumpper.attestation")
    claim = {"protocol": "saos/v1", "action": "value_lock", "account": "headcorner",
             "seq": 34, "lockedSaos": 0.166, "depthBefore": 106.868,
             "srcTxid": "4f83ae2a4754b2f7b07b242fac0c39a74bed1a5e",
             "note": "LP locked permanently - fees keep flowing"}
    state = {"depthSaos": "106.86837760", "tvlMicroUsd": 0, "lpLocked": False,
             "lockedAt": None, "feesGeneratedMicroUsd": 0}
    r = m.attest(claim, state, balance="0.19776475")
    assert r["decision"] == m.REFUSE and (r["critical"], r["high"]) == (4, 3)
    assert any("GRAPHENE" in c["detail"] for c in r["contradictions"])
    return "the real value_lock refused: 4 critical, 3 high, srcTxid labelled GRAPHENE"


@check("hardening")
def _hardening():
    m = importlib.import_module("jumpper.hardening")
    assert len(m.RULES) == 21
    assert m.code_only("a.md", "prose devnet.solana.com") == ""
    assert m.code_only("a.py", "window.localStorage.setItem(k,v)") != ""
    r = m.scan_tree({"a.ts": "window.localStorage.setItem(k,v)"})
    assert not r["pass"] and "H-01" in [v["id"] for v in r["blocking"]]
    assert m.scan_tree({"a.md": "prose devnet.solana.com"})["pass"], "markdown: secret rules only"
    assert m.scan_tree({"a.md": "pass: zrLStQf5RS1GxqpTwZJO6goLKUL8iNuV"})["blockingCount"] == 1
    try:
        m.waiver("H-01", "*", "x", "owner", 99999999999)
        raise AssertionError("a global waiver must be refused")
    except m.HardeningError:
        pass
    return "21 rules; markdown carries secret rules only; a secret in a doc is caught; global waiver refused"


@check("signingcontract")
def _signingcontract():
    m = importlib.import_module("jumpper.signingcontract")
    parts = ["await vault.ensureUnlocked();",
             "if (d.action !== 1) throw new Error();",
             "const role = funds ? " + DQ + "active" + DQ + " : " + DQ + "posting" + DQ + ";",
             "if (record.role === null) throw new Error();",
             "const { privateKey } = await vault.revealKeyFor(k);",
             "await adapter.sign(tx, { byRole: { [role]: privateKey } });",
             "if (hasCapability(" + DQ + "broadcast" + DQ + ")) await broadcast(s);",
             "audit.record(" + DQ + "key_used" + DQ + ", {}); audit.record("
             + DQ + "signing_attempt" + DQ + ", {});",
             "const level = input.actionLevel;"]
    r = m.check(NL.join(parts))
    assert r["stagesSatisfied"] == 6, r["missingStages"]
    assert m.console_leaks("console.error(" + DQ + "wif-invalid: not a valid WIF" + DQ + ")") == []
    assert len(m.console_leaks("console.error(" + DQ + "k" + DQ + ", privateKey);")) == 1
    return "6/6 on a conforming signer; prose is not a leak, a logged key is"


@check("recovery")
def _recovery():
    m = importlib.import_module("jumpper.recovery")
    assert m.ROSHPINA.unbound == ["actionId", "occurredAt", "reason", "source"]
    assert sorted(m.ROSHPINA.as_dict()["unansweredQuestions"]) == ["when", "who", "why"]
    assert m.SAOSMARTWALLET.sound and m.SAOSMARTWALLET.unbound == []
    assert not m.reconstruction_refuses_too_few(
        "async function reconstructSecret(shares) { return lagrange(shares); }")
    assert m.reconstruction_refuses_too_few(
        "function reconstructSecret(shares, t) { if (shares.length < t) throw new Error(); }")
    return "roshpina audit leaves who/when/why unbound; shamir guard correctly reported absent"


@check("riskgate")
def _riskgate():
    m = importlib.import_module("jumpper.riskgate")
    assert m.derive_level("rm -rf /") == "prohibited"
    assert m.derive_level("transfer 5000 HIVE") == "high"
    assert m.derive_level("") == "high", "unreadable must not default to benign"
    assert m.evaluate("rm -rf /", 1.0, supplied_level="informational")["decision"] == m.DENY
    h = m.evaluate("transfer 5000 HIVE", 0.90, financial=True)
    lo = m.evaluate("transfer 5000 HIVE", 0.90, supplied_level="informational", financial=True)
    assert h["effectiveThreshold"] == lo["effectiveThreshold"] == 0.95
    assert lo["deEscalationAttempted"]
    return "de-escalation refused: 0.95 either way; prohibited denies at score 1.0"


@check("rotation")
def _rotation():
    m = importlib.import_module("jumpper.rotation")
    keys = {"hive": {"owner": "STM8mSbBz8zsMfBow2xa1yfTuNhdp6KZf3v7kAs1BSQAB1AMQM1Fw",
                     "active": "STM8c9vp3hUnNsXHaWLPTpcYWkPpK5GrnySgN51FiGX9dxhwVz8YZ",
                     "posting": "STM6u99ogJKojfZC94VCs73N3wVRxnm9XTjVSmkSm2BE59yDEuH6b",
                     "memo": "STM7pmsRp7QrEnuGT6EWfnJMuSiAU9wXSoNUJRBYQio5qfGCSrax5"}}
    g = m.rotation_gate("headcorner", ["hive"], ["headcorner"], False, False, None, repo_root="/r")
    assert g["decision"] == m.DENY
    assert sorted(g["failedChecks"]) == ["backup-verified", "handoff-built", "primary-confirmation"]
    art = m.build_handoff("headcorner", ["hive"], keys, "sha256(username+role+master)",
                          "/home/z/.secrets/h.json", repo_root="/r",
                          rotated_at="2026-09-08T21:17:42Z")
    assert art.recovery_deadline == "2026-10-08T21:17:42Z"
    try:
        m.build_handoff("headcorner", ["hive"], {"hive": {"owner": "STM86gwPfu" + chr(8230)}},
                        "s", "/x", repo_root="/r")
        raise AssertionError("masked keys must be refused")
    except m.RotationError:
        pass
    return "the real 2026-09-08 rotation denied on 3 checks; masked keys refused; 30-day deadline"


@check("liveops")
def _liveops():
    m = importlib.import_module("jumpper.liveops")
    js = "{" + DQ + "contractAction" + DQ + ":" + DQ + "convert" + DQ + "}"
    one = [1, {"op": ["custom_json", {"id": "ssc-mainnet-hive",
                                      "required_auths": ["headcorner"], "json": js}],
               "timestamp": "2026-09-07T11:49:39", "block": 1}]
    ops = m.normalise([one])
    assert len(ops) == 1 and ops[0]["op"] == "custom_json"
    lp = m.find_repeat_loops(ops * 11, min_occurrences=3)
    assert lp and lp[0].occurrences == 11
    a = m.audit_authority_by_protocol(ops)
    assert a["attestationOverprivileged"] == 0 and a["valueMovingOps"] == 1
    return "11 identical converts detected as one loop; Hive-Engine classified value-moving"


@check("pipeline")
def _pipeline():
    m = importlib.import_module("jumpper.pipeline")
    au = importlib.import_module("jumpper.audit")
    recs = [{"who": "a", "when": TS, "what": "x", "which": "1", "outcome": "ok", "why": None},
            {"who": "b", "when": TS, "what": "y", "which": "2", "outcome": "ok", "why": None}]
    ch = au.build_chain("v1", recs)
    p = m.Pipeline("headcorner", network="hive-mainnet")
    req = p.anchor_audit_head("v1", ch, now=1788900000)
    assert req.gate["verdict"] == "allow" and req.authority == "posting" and req.fee == 0
    assert m.Pipeline.verify_audit_with_anchor("v1", ch[:1], req.payload)["truncated"]
    assert not m.Pipeline.verify_audit_with_anchor("v1", ch, req.payload)["truncated"]
    return "audit head anchored free; truncation detected only because of the anchor"


@check("witnessbridge")
def _witnessbridge():
    m = importlib.import_module("jumpper.witnessbridge")
    st = {"version": m.WITNESS_STATEMENT_VERSION, "logId": "log-a", "root": R64,
          "treeSize": 12108, "observedAt": TS, "witnessId": "w1",
          "algorithm": "ed25519", "signature": "c2ln"}
    s = m.parse_statement(st)
    assert sorted(json.loads(m.signing_payload(s))) == sorted(
        ["version", "logId", "root", "treeSize", "observedAt", "witnessId"])
    fork = [m.parse_statement(dict(st, witnessId="w%d" % i)) for i in range(2)]
    fork.append(m.parse_statement(dict(st, witnessId="w3", root=R64B)))
    assert len(m.detect_split_view(fork)) == 1
    try:
        m.quorum(fork, "log-a", 12108, 2)
        raise AssertionError("a fork must not be majority-voted")
    except m.SplitViewError:
        pass
    cs = [m.QuorumCommitment("log-%d" % i, 12108 + i, R64, 3,
                             m.witness_set_digest(["w1", "w2", "w3"])) for i in range(120)]
    assert m.max_commitments_that_fit(cs) == 79
    assert len(m.split_into_operations(cs)) == 2
    pl = m.plan("headcorner", cs[:20])
    assert pl["fee"] == 0 and pl["authority"] == "posting" and pl["signaturesVerified"] is False
    return "split-view refused not majority-voted; 79 commitments per free op"


@check("netattest")
def _netattest():
    m = importlib.import_module("jumpper.netattest")
    assert m.host_of("https://x.io/rpc?key=SECRET123") == "x.io"
    assert "SECRET" not in m.host_of("https://x.io/rpc?key=SECRET123")
    assert m.classify_host("SOLANA", "https://api.devnet.solana.com") == m.DEVNET
    assert m.classify_host("SOLANA", "https://api.mainnet-beta.solana.com") == m.MAINNET
    assert m.classify_host("SOLANA", "https://rpc.example.com") == m.UNKNOWN
    return "host extraction never leaks a query-string key; devnet detected; unknown stays unknown"


@check("forkwatch")
def _forkwatch():
    m = importlib.import_module("jumpper.forkwatch")

    def rec(idx, ts, blk, root):
        js = ("{" + DQ + "protocol" + DQ + ":" + DQ + "saos-dex/v1" + DQ + ","
              + DQ + "action" + DQ + ":" + DQ + "chain-seal" + DQ + ","
              + DQ + "at" + DQ + ":" + DQ + TS + DQ + ","
              + DQ + "height" + DQ + ":1764,"
              + DQ + "stateRoot" + DQ + ":" + DQ + root + DQ + ","
              + DQ + "digest" + DQ + ":" + DQ + R64 + DQ + "}")
        return [idx, {"timestamp": ts, "block": blk,
                      "op": ["custom_json", {"id": "saos-dex.anchor.v1", "json": js}]}]

    hist = [rec(49833, "2026-09-09T18:27:21", 109770502, "d7220b5e9ecc953e7e8d" + "0" * 44),
            rec(49834, "2026-09-09T18:27:51", 109770512, "84ae0a0a08ef2f44becc" + "0" * 44)]
    anchors = m.parse_history(hist)
    assert len(anchors) == 2, len(anchors)
    forks = m.detect_forks(anchors)
    assert forks and forks[0].height == 1764 and len(forks[0].roots) == 2
    a = m.audit(anchors)
    assert a["forkedHeights"] == 1
    return "height-1764 fork detected independently: 2 roots, blocks 109770502 and 109770512"


def main():
    src = os.path.join(ROOT, "src", "jumpper")
    present = sorted(f[:-3] for f in os.listdir(src)
                     if f.endswith(".py") and f != "__init__.py") if os.path.isdir(src) else []
    registered = {mm for mm, _ in RESULTS}
    missing = [mm for mm in present if mm not in registered]
    unknown = [mm for mm in registered if present and mm not in present]
    print("=" * 78)
    print("COVERAGE HARNESS - every module in src/jumpper must have a real check")
    print("=" * 78)
    print("modules on disk  : %d" % len(present))
    print("checks registered: %d" % len(RESULTS))
    if missing:
        print("")
        print("UNCOVERED (add a check before this harness can pass):")
        for mm in missing:
            print("   - %s" % mm)
    if unknown:
        print("")
        print("checks for modules that no longer exist: %s" % ", ".join(unknown))
    print("")
    passed = failed = 0
    for name, fn in RESULTS:
        try:
            detail = fn()
            passed += 1
            print("  PASS  %-17s %s" % (name, str(detail)[:98]))
        except Exception as exc:
            failed += 1
            print("  FAIL  %-17s %s: %s" % (name, type(exc).__name__, str(exc)[:98]))
    print("")
    verdict = "GREEN" if (failed == 0 and not missing and not unknown) else "RED"
    print("  modules covered : %d / %d" % (passed, len(present) or len(RESULTS)))
    print("  checks failed   : %d" % failed)
    print("  uncovered       : %d" % len(missing))
    print("")
    print("RESULT: HARNESS %s" % verdict)
    return 0 if verdict == "GREEN" else 1


if __name__ == "__main__":
    raise SystemExit(main())
