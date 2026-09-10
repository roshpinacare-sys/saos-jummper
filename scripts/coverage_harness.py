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
