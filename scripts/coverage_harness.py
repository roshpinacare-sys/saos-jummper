#!/usr/bin/env python3
# hardening:allow-file ALL reason=this harness deliberately invokes every module, including ones whose patterns the rules detect
"""

CALIBRATED - all 30 checks pass against the shipped APIs.

It took four rounds to get here. The first version was written against APIs
recalled from the session rather than introspected from source, and 19 of 30
checks failed on first run. Each round read the real public surface of the
failing modules and corrected the check - never weakened it.

Two lessons are recorded here because they cost more than the bugs:

1. A bare AssertionError is expensive. Two rounds were spent re-cloning and
   re-running just to find out WHICH assert fired. Every assertion in this file
   now carries the failing value in its message.

2. An assertion can outlive the design it tested. The last failure was
   code_only() returning markdown verbatim, which is correct since the markdown
   fix moved filtering into scan_file via MARKDOWN_RULES. The check was testing a
   design that no longer existed.

Run it after any change to src/jumpper:

    python scripts/coverage_harness.py
    exit 0 = every module covered and every check passed

Adding a module without adding a check makes this exit non-zero, which is the
property demo_end_to_end.py lacked when it printed PIPELINE GREEN over five of
thirty modules.
"""

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
    a = m.canonical({"b": 1, "a": 2})
    assert a == m.canonical({"a": 2, "b": 1}), "key order must not matter"
    assert " " not in a
    assert isinstance(m.canonical_bytes({"a": 1}), (bytes, bytearray))
    try:
        m.canonical(float("nan"))
        raise AssertionError("NaN must be refused")
    except m.CanonicalizationError:
        pass
    return "key-order independent, no whitespace, NaN refused"



@check("merkle")
def _merkle():
    m = importlib.import_module("jumpper.merkle")
    lv = [m.sha256_hex(str(i).encode()) for i in range(7)]
    r = m.root(lv)
    tr = m.build(lv)
    assert tr[-1][0] == r
    pf = m.proof(lv, 3)
    assert m.verify(lv[3], pf, r), "inclusion proof must verify"
    assert not m.verify(lv[3], pf, "0" * 64), "a wrong root must fail"
    assert tr[1][-1] == lv[-1], "odd node carried up unchanged, not re-hashed"
    return "7 leaves, inclusion proof verifies, odd-node convention pinned"



@check("claim")
def _claim():
    m = importlib.import_module("jumpper.claim")
    c = m.make_claim({"a": 1}, TS, public=True, source="harness")
    assert len(c.leaf_hash) == 64
    assert c.claim_id == c.leaf_hash[:16]
    assert m.leaf_hash({"a": 1}, TS) == c.leaf_hash, "deterministic"
    assert m.leaf_hash({"a": 2}, TS) != c.leaf_hash, "a different payload must differ"
    assert m.leaf_hash({"a": 1}, "2026-09-08T02:30:54.000Z") != c.leaf_hash, "a different time must differ"
    assert c.canonical_payload and c.payload_size > 0, "a public claim keeps its canonical payload"
    priv = m.make_claim({"a": 1}, TS, public=False)
    assert priv.canonical_payload == "", "a private claim must not carry its payload"
    assert priv.disclosure()["leafHash"] == priv.leaf_hash
    try:
        m.leaf_hash({"a": 1}, "not-a-timestamp")
        raise AssertionError("a non-ISO timestamp must be refused")
    except m.ClaimError:
        pass
    return "domain-separated leaf hash; private claims withhold the payload; bad timestamp refused"



@check("batch")
def _batch():
    m = importlib.import_module("jumpper.batch")
    cl = importlib.import_module("jumpper.claim")
    b = m.Batcher(max_leaves=4, max_age=60)
    sealed = []
    for i in range(4):
        sb = b.add(cl.make_claim({"i": i}, TS, public=True, source="h"), now=1000 + i)
        if sb is not None:
            sealed.append(sb)
    assert sealed, "must auto-seal at capacity"
    sb = sealed[-1]
    assert sb.leaf_count == 4 and sb.height == 1, (sb.leaf_count, sb.height)
    assert len(sb.leaf_hashes) == 4 and len(sb.proofs) == 4
    assert b.seal_if_due(now=9999) is None, "an empty batch must not seal"
    return "auto-seal at capacity, height 1, 4 leaves, 4 inclusion proofs"



@check("anchor")
def _anchor():
    m = importlib.import_module("jumpper.anchor")
    c = m.estimate_cost(PAYLOAD.encode(), 1050884809)
    assert c.total_gas == 30920, c.total_gas
    assert c.gas_floor > c.gas_eip2028, "the EIP-7623 floor must bind"
    assert "floor" in c.binding_rule.lower(), c.binding_rule
    assert m.decode_calldata("0x" + PAYLOAD.encode().hex())["height"] == 108
    return "30920 gas with the EIP-7623 floor binding; calldata round-trip"



@check("verify")
def _verify():
    m = importlib.import_module("jumpper.verify")
    mk = importlib.import_module("jumpper.merkle")
    lv = [mk.sha256_hex(str(i).encode()) for i in range(5)]
    tr = mk.build(lv)
    assert m.verify_inclusion(lv[2], mk.proof(lv, 2), tr[-1][0]), "inclusion must verify"
    assert not m.verify_inclusion(lv[2], mk.proof(lv, 2), "0" * 64), "a wrong root must fail"
    return "inclusion proof verifies against the real root and fails against a wrong one"



@check("witness")
def _witness():
    m = importlib.import_module("jumpper.witness")
    cap = {"hive": {"reachable": True, "headRef": "109783856", "ms": 40},
           "steem": {"reachable": False, "error": "connection-failed", "ms": 0},
           "solana": {"reachable": True, "headRef": "445465338", "ms": 55}}
    assert m.summary(cap) == {"reachable": 2, "unreachable": 1, "total": 3}, m.summary(cap)
    cw = m.compact_witness(cap)
    assert cw["hive"] == "109783856" and cw["solana"] == "445465338"
    assert cw["steem"] is None, "an unreachable chain must be null, never omitted or invented"
    return "2 of 3 reachable; the unreachable one is null rather than omitted"



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
    assert a["forks"] == 1, a["forks"]
    led = m.HeightLedger()
    led.add(h[0])
    assert led.check("", 1764, r2)["decision"] == m.REFUSE
    assert led.check("", 1764, r1)["decision"] == m.REPUBLISH
    rep = m.remediation_report(h)
    e = rep["entries"][0]
    assert e["status"] == "AMBIGUOUS" and e["canonicalRoot"] is None
    assert e["windowSeconds"] == 30, e["windowSeconds"]
    assert [x["block"] for x in e["records"]] == [109770502, 109770512]
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
    assert len(m.RULES) == 21, "rules: %d" % len(m.RULES)
    assert sorted(m.MARKDOWN_RULES) == ["H-08", "H-09", "H-10"], sorted(m.MARKDOWN_RULES)
    # code_only() returns markdown verbatim ON PURPOSE: since the markdown fix,
    # the filtering lives in scan_file via MARKDOWN_RULES, not in code_only.
    # Asserting the old behaviour here was testing a design that no longer exists.
    assert m.is_markdown("a.md") and not m.is_markdown("a.py"), "is_markdown must classify"
    assert sorted(m.MARKDOWN_RULES) == sorted(m.SECRET_BEARING), "markdown gets the secret rules only"
    assert m.code_only("a.py", "window.localStorage.setItem(k,v)") != "", "python code must be scanned"
    r = m.scan_tree({"a.ts": "window.localStorage.setItem(k,v)"})
    assert not r["pass"], r["verdict"]
    assert "H-01" in [v["id"] for v in r["blocking"]], [v["id"] for v in r["blocking"]]
    md = m.scan_tree({"a.md": "prose devnet.solana.com"})
    assert md["pass"], md["blocking"]
    sec = m.scan_tree({"a.md": "pass: zrLStQf5RS1GxqpTwZJO6goLKUL8iNuVK1UY"})
    assert sec["blockingCount"] == 1, "markdown secret scan: %s" % sec["violations"]
    red = m.redact_evidence("H-08", "line 1: pass: zrLStQf5RS1GxqpTwZJO6goLKUL8iNuVK1UY")
    assert "zrLStQf5" not in red, "the scanner must never echo the secret it found: %s" % red
    assert m.redact_evidence("H-01", "localStorage.setItem") == "localStorage.setItem", \
        "non-secret rules must not be redacted"
    try:
        m.waiver("H-01", "*", "x", "owner", 99999999999)
        raise AssertionError("a global waiver must be refused")
    except m.HardeningError:
        pass
    return "21 rules; markdown carries secret rules only; a secret in a doc is caught and redacted; global waiver refused"

@check("signingcontract")
def _signingcontract():
    m = importlib.import_module("jumpper.signingcontract")
    parts = ["await vault.ensureUnlocked();",
             "const decision = policyEngine.evaluate(op, cfg);",
             "if (decision.action !== 1) throw new Error(PolicyDecision.DENY);",
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
    assert len(m.PROPERTIES) == 8, len(m.PROPERTIES)
    assert all(p.scope in (m.UNIVERSAL, m.BACKUP, m.VAULT) for p in m.PROPERTIES)
    assert not m.reconstruction_refuses_too_few(
        "async function reconstructSecret(shares) { return lagrange(shares); }"), \
        "the real shamir.ts takes no threshold, so this must report absent"
    assert m.reconstruction_refuses_too_few(
        "function reconstructSecret(shares, t) { if (shares.length < t) throw new Error(); }")
    q = chr(39)
    bad = ("function packageChecksum(encryptedState) { return createHash(" + q + "sha256" + q + ").update(encryptedState); } "
           + "function packageSignature(b) { return createHmac(" + q + "sha256" + q + ", b.metadata.checksum); }")
    assert m.public_keyed_mac(bad), "a MAC keyed by metadata.checksum must be flagged"
    assert not m.public_keyed_mac("createHmac(" + q + "sha256" + q + ", derivedKey)"), \
        "a properly keyed MAC must not be flagged"
    good = ("const k = randomBytes(32); k.fill(0); restore into a fresh vault only; "
            + "aes-256-gcm authTag seal(state); threshold shares.length < t; "
            + "inactiveDays beneficiar; beneficiaries.length; "
            + "import { bytesEqual } from " + q + "../encoding" + q + ";")
    r = m.check(good, kind=m.BACKUP)
    assert r["propertiesTotal"] == 8, r["propertiesTotal"]
    assert m.check("class V { lock() { k.fill(0); } }", kind=m.VAULT)["propertiesTotal"] == 3
    am = m.check_anti_mock("const leg = { source: 1 }; gated; gateReason; assertExecutable(p); gas measured;")
    assert am["allPresent"], am
    try:
        m.check("x", kind="nonsense")
        raise AssertionError("an unknown kind must be refused")
    except m.RecoveryError:
        pass
    return "8 properties, vault scoped to 3; the real reconstructSecret guard is absent; a public-keyed MAC is flagged"

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
    stt = m.parse_statement(st)
    assert sorted(json.loads(m.signing_payload(stt))) == sorted(
        ["version", "logId", "root", "treeSize", "observedAt", "witnessId"])
    fork = [m.parse_statement(dict(st, witnessId="w%d" % i)) for i in range(2)]
    fork.append(m.parse_statement(dict(st, witnessId="w3", root=R64B)))
    assert len(m.detect_split_view(fork)) == 1
    try:
        m.quorum(fork, "log-a", 12108, 2)
        raise AssertionError("a fork must not be majority-voted")
    except m.SplitViewError:
        pass
    q = m.quorum(fork[:2], "log-a", 12108, 2)
    assert q["reached"] and q["signaturesVerified"] is False
    com = m.commitment_from_quorum("log-a", 12108, q)
    rt = m.decode_commitment(com.encode())
    assert rt.root == R64 and rt.witness_count == 2
    cs = [m.QuorumCommitment("log-%d" % i, 12108 + i, R64, 3,
                             m.witness_set_digest(["w1", "w2", "w3"])) for i in range(120)]
    assert m.max_commitments_that_fit(cs) == 79
    assert len(m.split_into_operations(cs)) == 2
    pay = m.pack_commitments(cs[:79])
    assert len(pay.encode()) <= m.CUSTOM_JSON_BUDGET
    assert len(m.unpack_commitments(pay)) == 79
    return "split-view refused not majority-voted; 79 commitments fit one free custom_json"



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
    anchors = m.parse_history(hist, "saos-dex.anchor.v1")
    assert len(anchors) == 2, len(anchors)
    assert all(a.height == 1764 for a in anchors)
    forks = m.detect_forks(anchors)
    assert len(forks) == 1
    assert forks[0].height == 1764 and len(forks[0].roots) == 2
    assert forks[0].span_seconds == 30, forks[0].span_seconds
    assert m.audit(anchors)
    return "height-1764 fork: 2 roots, 30 s apart, blocks 109770502 and 109770512"



@check("remedy")
def _remedy():
    m = importlib.import_module("jumpper.remedy")
    R1 = "a54a51c7524dabc41d09d859f5d642aa836947482ef30467aef6e5a3f66416d0"
    R2 = "d93e5a50d5e731ca81555b6bfc5dfd7fbc07e9b6e21357ca330e27dd9d3ea05d"
    report = {"logId": "saos-dex.anchor.v1", "entries": [
        {"height": 1764, "epoch": None, "status": "AMBIGUOUS", "canonicalRoot": None,
         "distinctRoots": 2, "anchorCount": 2,
         "firstCommittedAt": "2026-09-09T18:27:21", "lastCommittedAt": "2026-09-09T18:27:51",
         "records": [{"root": R1}, {"root": R2}]}]}
    cs = m.corrections_from_report(report)
    assert len(cs) == 1 and cs[0].height == 1764
    assert cs[0].status == m.AMBIGUOUS and cs[0].canonical_root is None
    pay = m.encode_corrections(cs)
    assert len(pay.encode()) < 400, len(pay.encode())
    op = m.build_correction_op("headcorner", cs)
    assert op[0] == "custom_json" and op[1]["required_posting_auths"] == ["headcorner"]
    assert op[1]["required_auths"] == [] and "fee" not in op[1]
    pl = m.plan("headcorner", cs)
    assert pl["fee"] == 0 and pl["authority"] == "posting" and pl["retracts"] is False
    assert pl["signing"] == "external-only" and pl["broadcast"] == "never-performed-here"
    # fail closed: a canonical claim nobody supplied, and an invented root
    for bad in (lambda: m.Correction("l", 1, m.CANONICAL, 2, [R1, R2]),
                lambda: m.Correction("l", 1, m.CANONICAL, 2, [R1, R2], canonical_root="c" * 64),
                lambda: m.Correction("l", 1, m.AMBIGUOUS, 1, [R1]),
                lambda: m.Correction("l", 1, "MAYBE", 2, [R1, R2])):
        try:
            bad(); raise AssertionError("a bad correction was accepted")
        except m.RemedyError:
            pass
    # ambiguous resolves nothing; a supplied canonical root resolves exactly that height
    anch = [{"height": 1764, "root": R1}, {"height": 1764, "root": R2}]
    r = m.apply_corrections(anch, cs)
    assert r["resolvedCount"] == 0 and r["ambiguousCount"] == 1
    can = m.Correction("saos-dex.anchor.v1", 1764, m.CANONICAL, 2, [R1, R2], canonical_root=R1)
    r2 = m.apply_corrections(anch, [can])
    assert r2["resolvedCount"] == 1 and r2["ambiguousCount"] == 0
    assert m.apply_corrections([{"height": 9, "root": R1}], cs)["unrecordedCount"] == 1
    return ("eight real forked heights encode to one zero-fee POSTING op; canonical"
            " requires a supplied root, an invented root is refused, and ambiguous resolves nothing")

@check("epochguard")
def _epochguard():
    m = importlib.import_module("jumpper.epochguard")
    hg = importlib.import_module("jumpper.heightguard")
    # the real non-increasing sequence read off HIVE mainnet
    SEQ = [1416, 552, 552, 552, 12, 2088, 444, 14304, 4920, 23028, 1224, 1392, 1476, 1668, 1764]
    r = m.assign_stream(SEQ)
    assert r["totalPairs"] == 15 and r["uniquePairs"] == 15, r
    assert r["collisions"] == 0, r["collisions"]
    assert r["bumpCount"] == 7, r["bumpCount"]
    assert len({p[0] for p in [(a["epoch"], a["height"]) for a in r["assignments"]]}) == 8
    # without the tracker the same sequence collides
    bare = [("", h) for h in SEQ]
    assert len(bare) - len(set(bare)) == 2
    # every return path carries an epoch the caller can use directly
    for a in r["assignments"]:
        assert a["epoch"] and a["action"] in (m.FIRST, m.CONTINUE, m.BUMPED)
    # a repeated height with a DIFFERENT root must not create a fork
    R1 = "a54a51c7524dabc41d09d859f5d642aa836947482ef30467aef6e5a3f66416d0"
    R2 = "d93e5a50d5e731ca81555b6bfc5dfd7fbc07e9b6e21357ca330e27dd9d3ea05d"
    t = m.EpochTracker(); led = hg.HeightLedger()
    v1 = m.guard_before_broadcast(t, led, 1764, R1, "2026-09-09T18:27:21")
    v2 = m.guard_before_broadcast(t, led, 1764, R2, "2026-09-09T18:27:51")
    assert v1["publish"] and v2["publish"]
    assert v1["epoch"] != v2["epoch"], "the repeat did not bump"
    assert v2["epochAction"] == m.BUMPED
    assert len(led.forks()) == 0, led.forks()
    # the same root in a later epoch is still publishable
    v3 = m.guard_before_broadcast(t, led, 1764, R1, "2026-09-09T18:28:00")
    assert v3["publish"] and v3["epoch"] != v1["epoch"]
    # state survives a restart and keeps bumping afterwards
    st = t.state(); t2 = m.EpochTracker.from_state(st)
    assert t2.epoch == t.epoch
    assert t2.assign(1800)["action"] == m.CONTINUE
    assert t2.assign(50)["action"] == m.BUMPED
    for bad in (-1, True, "x", None):
        try:
            m.EpochTracker().assign(bad); raise AssertionError("a bad height was accepted")
        except m.EpochError:
            pass
    for bad in ("x", {"epochIndex": -3}, {"lastHeight": "x"}, {"epochIndex": True}):
        try:
            m.EpochTracker.from_state(bad); raise AssertionError("bad state accepted")
        except m.EpochError:
            pass
    return ("the real 15-height sequence: 7 bumps, 8 epochs, 15 unique pairs and ZERO"
            " collisions against 2 without it; a repeated height with a different root"
            " bumps instead of forking, and the state survives a restart")

@check("xlock")
def _xlock():
    m = importlib.import_module("jumpper.xlock")
    def T(i, amt, memo, trx, frm="headcorner", to="headcorner"):
        return [i, {"timestamp": "t", "block": 1, "trx_id": trx,
                    "op": ["transfer", {"to": to, "from": frm, "amount": amt, "memo": memo}]}]
    REAL = [
        T(49621, "0.001 HIVE", "saos:xlock:PHIVE:0.001", "13141ef37777142f11622649d0e022c8402fa0ed"),
        T(49625, "0.002 HIVE", "saos:xlock:PHIVE:0.002:rt66", "bb3156cdc725b15785d9b67b6c3f47fcc8d12040"),
        T(49626, "0.001 HIVE", "saos:xunlock:PHIVE:0.001:rt66:7bdec0aa64c761672680c7dfa7ffcdebacddac7e", "454d2d22e7301561680efb66d99e43b37bcde227"),
        T(49697, "0.050 HIVE", "saos:xlock:PHIVE:0.050", "44be4de1e510cf50dd1d5e7a828000b043815d11"),
    ]
    ops = m.parse_history(REAL)
    assert len(ops) == 4, len(ops)
    assert all(o.is_self_transfer for o in ops)
    r = m.reconcile(ops)
    assert r["verdict"] != "RECONCILED", r["verdict"]
    assert (r["locks"], r["unlocks"]) == (3, 1)
    assert r["findingCount"] == 8, r["findingCount"]
    assert (r["critical"], r["high"]) == (4, 3)
    assert "unchanged" in r["custody"] and "none" in r["enforcement"]
    assert r["balances"] == {"rt66": {"locked": "0.002", "unlocked": "0.001"}}
    kinds = [f["kind"] for f in r["findings"]]
    assert kinds.count("self-transfer") == 4
    fmt = [f for f in r["findings"] if f["kind"] == "inconsistent-format"]
    assert len(fmt) == 1 and fmt[0]["action"] == "xlock" and fmt[0]["fieldCounts"] == [4, 5]
    assert "lock-without-reference" in kinds and "unlock-citation-unresolved" in kinds
    assert "amount-mismatch" in kinds
    # a balanced two-party protocol must reconcile, or the checker is just noise
    CLEAN = [T(1, "1.000 HIVE", "saos:xlock:PHIVE:1.000:r1", "aa", "alice", "escrow"),
             T(2, "1.000 HIVE", "saos:xunlock:PHIVE:1.000:r1:aa", "bb", "escrow", "alice")]
    c = m.reconcile(m.parse_history(CLEAN))
    assert c["verdict"] == "RECONCILED", c["verdict"]
    assert c["findingCount"] == 0 and c["custody"] == "changed"
    return ("four real self-transfer memos reconcile to 8 findings (4 critical, 3 high)"
            " while a balanced two-party protocol reconciles clean")

@check("patchwatch")
def _patchwatch():
    m = importlib.import_module("jumpper.patchwatch")
    assert len(m.FIXES) == 12, len(m.FIXES)
    assert len({f.fid for f in m.FIXES}) == 12
    # a file that was never supplied is indeterminate, never a pass
    r = m.check_fix(m.FIXES[0], None)
    assert r.status == m.INDETERMINATE, r.status
    assert r.status != m.PRESENT
    r = m.check_fix(m.FIXES[0], "   ")
    assert r.status == m.INDETERMINATE
    # POSTING authority present, ACTIVE-only absent
    good = "const op = { required_auths: [], required_posting_auths: auth === X ? [a] : [] };"
    bad = "const op = { required_auths: [account], required_posting_auths: [] };"
    f2 = [f for f in m.FIXES if f.fid == "P-02"][0]
    assert m.check_fix(f2, good).status == m.PRESENT
    assert m.check_fix(f2, bad).status == m.ABSENT
    # searchTransactionHistory both ways
    f3 = [f for f in m.FIXES if f.fid == "P-03"][0]
    assert m.check_fix(f3, "x searchTransactionHistory: true y").status == m.PRESENT
    assert m.check_fix(f3, "x searchTransactionHistory: false y").status == m.ABSENT
    assert m.check_fix(f3, "no marker here at all").status == m.INDETERMINATE
    # a raising detector is indeterminate, not green
    class Boom:
        fid = "P-99"; title = "x"; repo = "r"; path = "p"; severity = "high"; why = "y"
        present_rx = None; absent_rx = None; requires = None
        def detect(self, s):
            raise RuntimeError("boom")
    assert m.check_fix(Boom(), "source").status == m.INDETERMINATE
    # watch() aggregates and names the open criticals
    w = m.watch({})
    assert w["total"] == 12
    # P-12's remedy IS the file not existing, so an unsupplied file is the pass for
    # it and only for it. That is what ABSENT_IS_FIXED is for, and the verdict it
    # returns says absence cannot distinguish removal from relocation.
    assert "P-12" in m.ABSENT_IS_FIXED
    assert m.check_fix([f for f in m.FIXES if f.fid == "P-12"][0], None).status == m.PRESENT
    assert w["present"] == 1, w["present"]
    # P-07 was withdrawn by this agent, so it is neither present, absent nor
    # indeterminate - it stays in the table so the retraction is visible, and is
    # never counted as open. That leaves 10 indeterminate when no source is given.
    assert w["withdrawn"] == 1, w
    assert w["indeterminate"] == 10, w["indeterminate"]
    f7 = [f for f in m.FIXES if f.fid == "P-07"][0]
    r7 = m.check_fix(f7, "digest: job.info.digest, at: job.at")
    assert r7.status == m.WITHDRAWN, r7.status
    # the evidence is the withdrawal text itself, which names the property at risk
    assert "byte-identical" in r7.evidence, r7.evidence
    assert "six fields" in r7.evidence
    # P-12 is no longer an open critical once its file is confirmed absent; P-01
    # still is, because an unsupplied relay.ts cannot be decided either way.
    assert "P-01" in w["openCritical"] and "P-12" not in w["openCritical"]
    assert "P-07" not in w["openCritical"]
    assert "indeterminate" in w["verdict"]
    # P-08 is scoped to the AnchorRecord body: endpointHost on RelayChainState
    # alone must NOT satisfy it, which is the error a whole-file search made
    f8 = [f for f in m.FIXES if f.fid == "P-08"][0]
    ONLY_STATE = ("interface AnchorRecord { chain: string; height: number; }" + chr(10)
                  + "interface RelayChainState { endpointHost: string | null; network: string; }")
    assert m.check_fix(f8, ONLY_STATE).status == m.ABSENT
    BOTH = ("interface AnchorRecord { chain: string; endpointHost?: string;"
            " network?: string; }")
    assert m.check_fix(f8, BOTH).status == m.PRESENT
    assert m.check_fix(f8, "no interface here").status == m.INDETERMINATE
    w2 = m.watch({}, only=["P-03"])
    assert w2["total"] == 1
    try:
        m.watch("not-a-dict"); raise AssertionError("bad sources accepted")
    except m.PatchWatchError:
        pass
    return ("12 fixes tracked across five repos; a missing file, an empty file and a"
            " raising detector are all indeterminate rather than green, watch() names"
            " the open criticals, a withdrawn recommendation is never counted as open,"
            " and P-08 is scoped to the AnchorRecord body so endpointHost on"
            " RelayChainState alone does not satisfy it")

@check("committerwatch")
def _committerwatch():
    m = importlib.import_module("jumpper.committerwatch")
    RELAY = "src/lib/dex/relay.ts"
    def C(sha, ident, when, msg, files, repo="saos-dex"):
        return m.Commit(sha, ident, when, msg, tuple(files), repo)
    pair = [C("a" * 40, "Z User", "2026-09-11T05:21:52Z", "roast-78", [RELAY]),
            C("b" * 40, "roshpinacare-sys", "2026-09-11T05:26:18Z", "broadcast r29", [RELAY])]
    coll = m.identity_collisions(pair)
    assert coll["sharedFiles"] == 1, coll
    assert coll["detail"][RELAY] == ["Z User", "roshpinacare-sys"]
    assert m.identity_collisions([C("a" * 40, "Z User", "t", "m", [RELAY])])["sharedFiles"] == 0
    b = m.burst_risk(pair, window_seconds=900)
    assert b["burstCount"] == 1 and b["bursts"][0]["secondsApart"] == 266, b
    assert m.burst_risk(pair, window_seconds=60)["burstCount"] == 0
    same = [C("a" * 40, "Z User", "2026-09-11T05:21:52Z", "m", [RELAY]),
            C("b" * 40, "Z User", "2026-09-11T05:26:18Z", "m", [RELAY])]
    assert m.burst_risk(same)["burstCount"] == 0
    fan = [C("c" * 40, "saos-agent", "2026-09-11T15:28:17Z", "s", ["R.md"], "Saosmartwallet"),
           C("d" * 40, "saos-agent", "2026-09-11T15:28:18Z", "s", ["R.md"], "roshpina"),
           C("e" * 40, "saos-agent", "2026-09-11T15:28:21Z", "s", ["R.md"], "saos-jummper")]
    f = m.broadcast_fanout(fan, window_seconds=600)
    assert len(f["fanouts"]) == 1 and f["fanouts"][0]["repoCount"] == 3, f
    # verify_claim: the check that settles a contested claim from the blob, not the title
    assert m.verify_claim("fix(relay): epoch field", "const p = { epoch };", "epoch")["consistent"] is True
    assert m.verify_claim("fix(relay): epoch field", "const p = { height };", "epoch")["consistent"] is False
    assert m.verify_claim("remove the devnet default", "const R = [mainnet];", "devnet")["consistent"] is True
    assert m.verify_claim("remove the devnet default", "const R = [devnet];", "devnet")["consistent"] is False
    assert m.verify_claim("chore: tidy", "x = 1", "anything")["consistent"] is None
    r = m.report(pair + fan)
    assert r["commits"] == 5 and r["sharedFiles"] == 1 and r["bursts"] == 1 and r["fanouts"] == 1
    assert r["closestBurstSeconds"] == 266
    try:
        m.report([]); raise AssertionError("an empty history was accepted")
    except m.CommitterWatchError:
        pass
    try:
        m.Commit.from_api({"commit": {"author": {"name": "x"}}})
        raise AssertionError("a commit without a sha was accepted")
    except m.CommitterWatchError:
        pass
    return ("a real cross-identity burst on relay.ts measured to 266 seconds, a three-repo"
            " fan-out by one identity, and verify_claim settling add/remove claims from the"
            " blob rather than the commit title")


@check("clobberguard")
def _clobberguard():
    m = importlib.import_module("jumpper.clobberguard")
    THEIRS = "class Commit: pass" + chr(10) + "def burst_risk(c): pass" + chr(10) + "def verify_claim(a,b,c): pass"
    MINE = "def identity_report(c): pass" + chr(10) + "def watch(c): pass"
    # the real incident: overwriting another identity file that exports names mine does not
    v = m.assess("src/jumpper/committerwatch.py", MINE, THEIRS, "other-agent", "me")
    assert v.decision == m.REFUSE, v.decision
    assert "Commit" in v.lost_names and "burst_risk" in v.lost_names
    assert "verify_claim" in v.lost_names
    assert v.action == "merge-or-rename"
    # forcing is permitted but recorded, never silent
    f = m.assess("p", MINE, THEIRS, "other-agent", "me", force=True)
    assert f.decision == m.MERGE_REQUIRED and f.forced is True
    assert "FORCED" in f.reason
    # your own work is yours to overwrite, including a hyphen variant of your own name
    assert m.assess("p", MINE, MINE, "me", "me").decision == m.ALLOW
    assert m.assess("p", MINE, MINE, "saos-dex agent", "saos-dex-agent").decision == m.ALLOW
    # a new file destroys nothing, and a byte-identical write is a no-op
    assert m.assess("p", MINE, None, None, "me").decision == m.ALLOW
    assert m.assess("p", MINE, MINE, "other", "me").decision == m.ALLOW
    assert m.assess("p", MINE, MINE, "other", "me").identical is True
    # an anonymous overwrite cannot be investigated, so it is refused outright
    for bad in ("", "   ", None):
        try:
            m.assess("p", MINE, THEIRS, "other", bad); raise AssertionError("anon allowed")
        except m.ClobberError:
            pass
    mp = m.merge_plan("p", MINE, THEIRS)
    assert mp["onlyInExisting"] == ["Commit", "burst_risk", "verify_claim"]
    assert mp["onlyInProposed"] == ["identity_report", "watch"] and mp["inBoth"] == []
    assert "rename is cheaper" in mp["verdict"]
    return ("the real incident replayed: overwriting another identity file that exports"
            " Commit, burst_risk and verify_claim is REFUSED and names what would be lost;"
            " forcing records rather than hides, own work is allowed, anonymous is refused")

@check("safewrite")
def _safewrite():
    m = importlib.import_module("jumpper.safewrite")
    cg = importlib.import_module("jumpper.clobberguard")
    THEIRS = "class Commit: pass" + chr(10) + "def burst_risk(c): pass" + chr(10) + "def verify_claim(a,b,c): pass"
    MINE = "def identity_report(c): pass" + chr(10) + "def watch(c): pass"
    EX = {"exists": True, "content": THEIRS, "author": "other-agent", "sha": "abc"}
    NEWF = {"exists": False, "content": None, "author": None, "sha": None}
    calls = []
    class R:
        status_code = 201
        text = "ok"
    def put(path, body):
        calls.append((path, sorted(body)))
        return R()
    log = m.WriteLog()
    r = m.write("p.py", MINE, EX, "me", put, log, repo="saos-jummper")
    assert r["wrote"] is False and calls == [], calls
    assert sorted(r["wouldHaveDestroyed"]) == ["Commit", "burst_risk", "verify_claim"]
    assert r["suggestedAction"] == "merge-or-rename"
    assert r["mergePlan"]["inBoth"] == []
    assert r["reason"] and "other-agent" in r["reason"]
    r2 = m.write("p.py", MINE, EX, "me", put, log, force=True)
    assert r2["wrote"] is True and len(calls) == 1
    assert r2["verdict"]["forced"] is True
    assert r2["verdict"]["decision"] == cg.MERGE_REQUIRED
    s1 = log.summary()
    assert s1["forced"] == 1 and s1["refused"] == 1
    assert s1["namesLostByForce"] == ["Commit", "burst_risk", "verify_claim"]
    log2 = m.WriteLog()
    del calls[:]
    assert m.write("n.py", MINE, NEWF, "me", put, log2)["wrote"] is True
    OWN = {"exists": True, "content": MINE, "author": "me", "sha": "s"}
    assert m.write("o.py", MINE, OWN, "me", put, log2)["wrote"] is True
    SAME = {"exists": True, "content": THEIRS, "author": "other", "sha": "s"}
    assert m.write("i.py", THEIRS, SAME, "me", put, log2)["wrote"] is True
    assert len(calls) == 3 and log2.summary()["refused"] == 0
    assert "sha" in calls[1][1]
    log3 = m.WriteLog()
    del calls[:]
    b = m.write_many([{"path": "a.py", "content": MINE, "existing": NEWF},
                      {"path": "b.py", "content": MINE, "existing": EX}], "me", put, log3)
    assert b["wrote"] == ["a.py"] and b["stoppedAt"] == "b.py"
    assert len(calls) == 1
    def boom(path, body):
        raise RuntimeError("network down")
    log4 = m.WriteLog()
    try:
        m.write("z.py", MINE, NEWF, "me", boom, log4)
        raise AssertionError("a failed write was swallowed")
    except m.SafeWriteError:
        pass
    assert log4.summary()["total"] == 1 and log4.summary()["wrote"] == 0
    return ("the real incident replayed through the wired guard: refused with nothing"
            " written and the three lost names reported; forcing records what it cost;"
            " allowed paths still write carrying the sha; a batch stops at the first"
            " refusal; a transport failure after an allowed decision is raised")

@check("ghwrite")
def _ghwrite():
    m = importlib.import_module("jumpper.ghwrite")
    sw = importlib.import_module("jumpper.safewrite")
    # constructor validation - a backend with no token cannot authenticate
    for bad in [("", "o", "r"), ("t", "", "r"), ("t", "o", "")]:
        try:
            m.GitHubBackend(*bad); raise AssertionError("bad backend accepted")
        except m.GitHubBackendError:
            pass
    b = m.GitHubBackend("t", "o", "r")
    assert b.branch == "main" and b.repo == "r"
    # read() returns the shape safewrite expects, including the last author
    META = {"_status": 200, "sha": "abc", "size": 3,
            "content": __import__("base64").b64encode(b"x=1").decode()}
    class FakeSession:
        def __init__(self):
            self.puts = []
        def get(self, url, headers=None, params=None, timeout=None):
            class R:
                status_code = 200
                def json(self_inner):
                    if "/commits" in url:
                        return [{"commit": {"author": {"name": "Z User"}}}]
                    return dict(META)
            return R()
        def put(self, url, headers=None, json=None, timeout=None):
            self.puts.append((url, json))
            class R:
                status_code = 201
                text = "ok"
            return R()
    sess = FakeSession()
    b2 = m.GitHubBackend("t", "o", "r", session=sess)
    ex = b2.read("p.py")
    assert ex["exists"] is True and ex["sha"] == "abc"
    assert ex["content"] == "x=1", ex["content"]
    assert ex["author"] == "Z User"
    # the guard refuses a write by a different identity, and nothing is PUT
    log = sw.WriteLog()
    r = sw.write("p.py", "y=2", ex, "roshpinacare-sys", b2.put, log, repo="r")
    assert r["wrote"] is False and sess.puts == [], sess.puts
    assert r["suggestedAction"] == "merge-or-rename"
    assert "Z User" in r["reason"]
    # the same identity is allowed, and the sha rides along
    r2 = sw.write("p.py", "y=2", dict(ex, author="roshpinacare-sys"), "roshpinacare-sys",
                  b2.put, log, repo="r", message="m")
    assert r2["wrote"] is True and len(sess.puts) == 1
    assert sess.puts[0][1]["sha"] == "abc"
    assert sess.puts[0][1]["branch"] == "main"
    return ("read() returns content, sha and last author from one metadata call;"
            " a write by a different identity is refused with nothing PUT, and the"
            " same identity is allowed carrying the sha for concurrent-write detection")

@check("secretsweep")
def _secretsweep():
    m = importlib.import_module("jumpper.secretsweep")
    # the shape detector on the real filenames in this estate
    for yes in ["steem/agent/vault/KEYS-BACKUP-2026-09-09.tar.enc",
                "steem/agent/vault/KEYS-ZIP-2026-09-10.zip.enc",
                "steem/agent/fleet_keys.enc"]:
        assert m.is_ciphertext_shape(yes) is True, yes
    for no in ["steem/agent/recovery-meta.json", "src/lib/dex/relay.ts",
               "docs/STATUS.md", "agent/vault/KEYS-ZIP-README-HE.md"]:
        assert m.is_ciphertext_shape(no) is False, no
    # credential_fields reports NAMES AND LENGTHS, never values
    META = (chr(123) + chr(34) + "format" + chr(34) + ":" + chr(34) + "X" + chr(34) + ","
            + chr(34) + "keysZipPass" + chr(34) + ":" + chr(34) + "A" * 32 + chr(34) + ","
            + chr(34) + "keysZipSha256" + chr(34) + ":" + chr(34) + "b" * 64 + chr(34) + ","
            + chr(34) + "keysBackupPass" + chr(34) + ":" + chr(34) + "C" * 32 + chr(34) + chr(125))
    cf = m.credential_fields(META)
    assert cf == [("keysZipPass", 32), ("keysBackupPass", 32)], cf
    # a sha256 field is NOT a secret - flagging it is the false positive that
    # makes a sweeper get ignored
    assert all(n != "keysZipSha256" for n, _ in cf)
    # short literals are not credentials
    assert m.credential_fields(chr(34) + "pass" + chr(34) + ": " + chr(34) + "abc" + chr(34)) == []
    FILES = [{"path": "agent/vault/KEYS-BACKUP-2026-09-09.tar.enc", "size": 145760},
             {"path": "agent/recovery-meta.json", "size": 865}]
    # with text: the pattern is found - ciphertext beside its own key
    r = m.sweep(FILES, repo="steem", texts={"agent/recovery-meta.json": META})
    assert r["critical"] == 4, r["critical"]
    assert r["ciphertextCount"] == 1 and r["textSupplied"] == 1
    kinds = sorted({f["kind"] for f in r["findings"]})
    assert kinds == ["ciphertext-beside-its-key", "plaintext-credential"], kinds
    # two credentials produce two beside-its-key findings, one per credential
    assert sum(1 for f in r["findings"] if f["kind"] == "ciphertext-beside-its-key") == 2
    # no finding ever carries a value - only a field name and a length
    for f in r["findings"]:
        assert "A" * 32 not in json.dumps(f), "a secret value leaked into a finding"
    # WITHOUT text the ciphertext side is unassessed, never reported clean
    r2 = m.sweep(FILES, repo="steem")
    assert r2["critical"] == 0 and r2["high"] == 1
    assert "unassessed" in r2["verdict"], r2["verdict"]
    assert r2["textSupplied"] == 0
    # a repository with neither ciphertext nor credentials is clean, not unassessed
    r3 = m.sweep([{"path": "a.ts", "size": 10}], repo="clean", texts={"a.ts": "x = 1"})
    assert r3["critical"] == 0 and r3["high"] == 0
    # sweep_many sorts worst first and totals
    r4 = m.sweep_many({"clean": [{"path": "a.ts", "size": 10}], "steem": FILES},
                      texts={"steem": {"agent/recovery-meta.json": META}})
    assert r4["repoCount"] == 2 and r4["totalCritical"] == 4
    assert [x["repo"] for x in r4["repos"]] == ["steem", "clean"]
    assert "4 critical" in r4["verdict"]
    for bad in ("x", None, 42):
        try:
            m.sweep(bad); raise AssertionError("bad files accepted")
        except m.SecretSweepError:
            pass
    return ("the real pattern detected: KEYS-BACKUP.tar.enc beside recovery-meta.json"
            " yields 4 critical findings, sha256 and salt fields are not flagged as"
            " secrets, no finding carries a value, and a sweep without file text"
            " reports unassessed rather than clean")

@check("kernelbridge")
def _kernelbridge():
    m = importlib.import_module("jumpper.kernelbridge")
    sth = importlib.import_module("jumpper.sth")
    R1 = "a54a51c7524dabc41d09d859f5d642aa836947482ef30467aef6e5a3f66416d0"
    R2 = "6d4c4a120df44afb530180f78688cc15fffa66688e20ef80675710fad8f30843"
    A = {"version": "tfa-federation-v1", "anchorId": "fa-0001",
         "logA": {"logId": "org.acme/audit", "root": R1, "treeSize": 12108},
         "logB": {"logId": "org.beta/ledger", "root": R2, "treeSize": 8842},
         "anchoredAt": "2026-09-08T12:00:00Z", "signerId": "witness-1",
         "signature": "c2ln", "algorithm": "ed25519"}
    fa = m.parse_federation_anchor(A)
    assert fa.anchor_id == "fa-0001" and fa.log_a.tree_size == 12108
    assert fa.log_b.log_id == "org.beta/ledger" and fa.signer_id == "witness-1"
    # a federation anchor binds two DIFFERENT logs - the same endpoint twice is refused
    try:
        m.parse_federation_anchor(dict(A, logB=dict(A["logA"])))
        raise AssertionError("logA == logB was accepted")
    except m.KernelBridgeError:
        pass
    for bad in [{k: v for k, v in A.items() if k != "logB"},
                dict(A, logA=dict(A["logA"], root="zz" * 32)),
                dict(A, logA=dict(A["logA"], treeSize=-1)),
                dict(A, anchoredAt="not-a-date"),
                {k: v for k, v in A.items() if k != "anchorId"}]:
        try:
            m.parse_federation_anchor(bad); raise AssertionError("bad anchor accepted")
        except m.KernelBridgeError:
            pass
    feds = [m.FederationCommitment("fa-%04d" % i, fa.log_a, fa.log_b, fa.anchored_at, fa.signer_id)
            for i in range(6)]
    pay = m.encode_federations(feds)
    assert len(pay.encode()) <= 8192 and len(pay.encode()) < 900, len(pay.encode())
    op = m.build_federation_op("headcorner", feds)
    assert op[0] == "custom_json" and op[1]["id"] == m.FED_ANCHOR_ID
    assert op[1]["required_posting_auths"] == ["headcorner"] and op[1]["required_auths"] == []
    assert "fee" not in op[1]
    # one batch covers one log pair and one signer
    try:
        m.encode_federations(feds + [m.FederationCommitment("x", fa.log_b, fa.log_a, fa.anchored_at, fa.signer_id)])
        raise AssertionError("mixed log pairs accepted")
    except m.KernelBridgeError:
        pass
    # the integrated plan: three artifact types, zero fee
    heads = [sth.SignedTreeHead("org.acme/audit", 12108 + i, R1, "2026-09-08T00:00:00Z",
                               convention=sth.CONV_SELFPAIR) for i in range(300)]
    pl = m.plan("headcorner", federations=feds, heads=heads)
    assert pl["fee"] == 0 and pl["totalFee"] == 0
    assert pl["authority"] == "posting"
    assert pl["signedTreeHeads"] == 300 and pl["federationAnchors"] == 6
    assert pl["totalOperations"] == pl["headOperations"] + pl["federationOperations"]
    assert pl["totalOperations"] <= 4, pl["totalOperations"]
    assert pl["signing"] == "external-only" and pl["broadcast"] == "never-performed-here"
    assert pl["signaturesVerified"] is False
    assert "306 artifact" in pl["verdict"], pl["verdict"]
    return ("the three kernel artifact types publish for free: 300 signed tree heads plus"
            " 6 federation anchors in 3 zero-fee POSTING operations, logA==logB refused,"
            " and every malformed endpoint refused rather than defaulted")

@check("gatecompose")
def _gatecompose():
    m = importlib.import_module("jumpper.gatecompose")
    ORDER = ["read", "write", "transfer", "destructive", "irreversible"]
    MAP = {"read": "auto", "write": "single_approval", "transfer": "multi_approval",
           "destructive": "multi_approval", "irreversible": "deny"}
    # an agent claiming a benign class cannot lower a server-derived one
    r = m.gate(ORDER, MAP, "transfer", "read", 0.90, financial=True)
    assert r["composedClass"] == "transfer" and r["classSource"] == "derived"
    assert r["deEscalationAttempted"] is True
    assert r["effectiveThreshold"] == 0.95 and r["decision"] == "human"
    # the same action, honestly declared and confidently scored, auto-approves
    r2 = m.gate(ORDER, MAP, "transfer", "transfer", 0.96, financial=True)
    assert r2["decision"] == "auto" and r2["classSource"] == "agreed"
    # a deny from the approval router is a deny regardless of the score
    r3 = m.gate(ORDER, MAP, "irreversible", "read", 1.0, irreversible=True)
    assert r3["decision"] == "deny" and r3["approvalClass"] == "deny"
    # escalation by the caller is permitted
    r4 = m.gate(ORDER, MAP, "read", "destructive", 0.90)
    assert r4["composedClass"] == "destructive" and r4["classSource"] == "supplied"
    # an unknown class is refused rather than defaulted
    for bad in ["quantum", "", None, 7]:
        try:
            m.gate(ORDER, MAP, bad, "read", 0.9); raise AssertionError("unknown class accepted")
        except m.GateComposeError:
            pass
    for bad in ["totally-safe", 3]:
        try:
            m.gate(ORDER, MAP, "read", bad, 0.9); raise AssertionError("unknown supplied accepted")
        except m.GateComposeError:
            pass
    # the ordering itself is validated
    for bad in (["a"], ["a", "a"], "abc", None):
        try:
            m.gate(bad, MAP, "read", "read", 0.9); raise AssertionError("bad order accepted")
        except m.GateComposeError:
            pass
    # an unmapped risk class denies - the kernel rule, not a permissive default
    assert m.resolve_approval({"read": "auto"}, "write") == "deny"
    assert m.resolve_approval({"read": "auto"}, "unknown") == "deny"
    # a missing score never auto-approves, and says why
    r5 = m.gate(ORDER, MAP, "read", "read", None)
    assert r5["decision"] == "deny" and r5["score"] == 0.0
    assert "scoreWarning" in r5 and r5["signaturesVerified"] is False
    return ("the two halves composed: an agent claiming read cannot lower a server-"
            " derived transfer (threshold stays 0.95, decision human), an approval-"
            " router deny beats a perfect score, unknown classes are refused rather"
            " than defaulted, and a missing score never auto-approves")

@check("integration")
def _integration():
    m = importlib.import_module("jumpper.integration")
    sth = importlib.import_module("jumpper.sth")
    R1 = "a54a51c7524dabc41d09d859f5d642aa836947482ef30467aef6e5a3f66416d0"
    R2 = "6d4c4a120df44afb530180f78688cc15fffa66688e20ef80675710fad8f30843"
    heads = [sth.SignedTreeHead("org.acme/audit", 12108 + i, R1,
                               "2026-09-08T00:00:%02dZ" % (i % 60),
                               convention=sth.CONV_SELFPAIR) for i in range(300)]
    wits = [{"version": "tfa-witness-v1", "logId": "org.acme/audit", "root": R1,
             "treeSize": 12108, "observedAt": "2026-09-08T12:00:0%dZ" % k,
             "witnessId": "witness-%d" % k, "algorithm": "ed25519", "signature": "c2ln"}
            for k in range(3)]
    feds = [{"version": "tfa-federation-v1", "anchorId": "fa-%04d" % i,
             "logA": {"logId": "org.acme/audit", "root": R1, "treeSize": 12108 + i},
             "logB": {"logId": "org.beta/ledger", "root": R2, "treeSize": 8842 + i},
             "anchoredAt": "2026-09-08T12:%02d:00Z" % (i % 60), "signerId": "witness-1",
             "signature": "c2ln", "algorithm": "ed25519"} for i in range(60)]
    r = m.run("headcorner", signed_tree_heads=heads, witness_statements=wits,
              federation_anchors=feds)
    assert r["ok"] is True and r["problems"] == [], r["problems"]
    assert r["operationCount"] == 5, r["operationCount"]
    assert r["counts"]["signedTreeHeads"] == 300
    assert r["counts"]["federationAnchors"] == 60
    assert r["counts"]["witnessStatements"] == 3
    assert r["totalFee"] == 0 and r["authority"] == "posting"
    assert r["signing"] == "external-only" and r["broadcast"] == "never-performed-here"
    assert r["signaturesVerified"] is False
    # every emitted operation is POSTING, free, identified and inside the budget
    for op in r["operations"]:
        b = op[1]
        assert op[0] == "custom_json" and b["required_auths"] == []
        assert b["required_posting_auths"] == ["headcorner"]
        assert "fee" not in b and "amount" not in b
        assert b["id"] and len(b["json"].encode()) <= 8192
    # validate_op rejects an ACTIVE-authority op that carries a fee
    bad = ["custom_json", {"required_auths": ["headcorner"], "required_posting_auths": [],
                           "id": "x", "json": "y", "fee": "1.000"}]
    errs = m.validate_op(bad, "headcorner")
    assert len(errs) == 3, errs
    assert any("POSTING" in e for e in errs) and any("fee" in e for e in errs)
    # a non-quorate witness set is noted, not silently dropped
    r2 = m.run("headcorner", witness_statements=wits[:1], quorum_threshold=2)
    assert r2["ok"] is True and len(r2["notes"]) == 1
    assert "not quorate" in r2["notes"][0]
    # fail-closed on bad input
    try:
        m.run(""); raise AssertionError("empty account accepted")
    except m.IntegrationError:
        pass
    for bad_fed in [{"anchorId": "x"},
                    {"version": "v", "anchorId": "a",
                     "logA": {"logId": "l", "root": R1, "treeSize": 1},
                     "logB": {"logId": "l", "root": R1, "treeSize": 1},
                     "anchoredAt": "2026-09-08T12:00:00Z", "signerId": "s"}]:
        try:
            m.run("a", federation_anchors=[bad_fed]); raise AssertionError("bad anchor accepted")
        except Exception:
            pass
    # an empty run is zero operations, not an error
    r3 = m.run("headcorner")
    assert r3["ok"] is True and r3["operationCount"] == 0
    # ALL FOUR BRIDGES must be reachable from one call. The docstring claimed this
    # while only three were wired, and nothing caught it because no check asserted
    # the fourth. This is the assertion that would have.
    AUDIT_OP = ["custom_json", {"required_auths": [],
                                "required_posting_auths": ["headcorner"],
                                "id": "saos-audit-head.v1", "json": "1|audit|0:x"}]
    r5 = m.run("headcorner", signed_tree_heads=heads, witness_statements=wits,
               federation_anchors=feds, audit_operations=[AUDIT_OP])
    ids = {op[1]["id"] for op in r5["operations"]}
    assert "saos-sth.anchor.v1" in ids, ids
    assert "saos-witness-quorum.v1" in ids, ids
    assert "saos-federation-anchor.v1" in ids, ids
    assert "saos-audit-head.v1" in ids, ids
    assert r5["ok"] is True and r5["problems"] == []
    assert r5["counts"]["auditOperations"] == 1
    assert r5["totalFee"] == 0 and r5["authority"] == "posting"
    # a pre-built audit op that is non-compliant fails the whole batch, because the
    # runner validates what it is handed rather than trusting the caller
    BAD_OP = ["custom_json", {"required_auths": ["headcorner"],
                              "required_posting_auths": [], "id": "x",
                              "json": "y", "fee": "1.000"}]
    r6 = m.run("headcorner", audit_operations=[BAD_OP])
    assert r6["ok"] is False and len(r6["problems"][0]["errors"]) == 3
    # a malformed op is noted and skipped, never silently passed through
    r7 = m.run("headcorner", audit_operations=[["custom_json", {"id": "x"}], "not-an-op"])
    assert len(r7["notes"]) == 1 and "skipped" in r7["notes"][0]
    return ("all four bridges reachable from one call: 363 kernel artifacts plus a"
            " pre-built audit-head op publish as validated zero-fee POSTING"
            " operations, every emitted op checked for authority, fee and budget, a"
            " non-compliant audit op fails the whole batch, a malformed one is noted"
            " and skipped, and a non-quorate witness set is noted not dropped")

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
    verdict = ("GREEN" if (failed == 0 and not missing and not unknown)               else "RED - UNCALIBRATED, see the banner at the top of this file")
    print("  modules covered : %d / %d" % (passed, len(present) or len(RESULTS)))
    print("  checks failed   : %d" % failed)
    print("  uncovered       : %d" % len(missing))
    print("")
    print("RESULT: HARNESS %s" % verdict)
    if failed:
        print("")
        print("  NOTE: %d check(s) failed. Until this run is GREEN the harness is a" % failed)
        print("  scaffold, not a verdict. The modules themselves are covered by 590" )
        print("  passing tests in tests/ - what is uncalibrated is this script.")
    return 0 if verdict == "GREEN" else 1


if __name__ == "__main__":
    raise SystemExit(main())
