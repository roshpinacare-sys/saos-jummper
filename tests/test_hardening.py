"""Hardening engine tested against the REAL defects read out of this estate.

Every fixture is a snippet taken from a file read directly from a repository
during the 2026-09-08 audit. If the engine does not catch these, it catches
nothing that matters. Values are truncated where a full secret would otherwise
be reproduced in a test file.
"""

FENCE = chr(96) * 3

import unittest

from jumpper import hardening as HD

NOW = 1788900000

SECURE_STORAGE = """
export function getBackend() {
  if (typeof window !== 'undefined' && window.__SAOS_SECURE_BACKEND__) cached = window.__SAOS_SECURE_BACKEND__;
  else cached = { async setItem(k,v){ window.localStorage.setItem(k,v); } };
}
"""

KEY_DERIVATION = """
export function deriveBip32FromMnemonic(_m, _p) {
  throw new Error('deriveBip32FromMnemonic is not implemented in key-derivation.ts');
}
function makeSalt(purpose) {
  const base = (typeof crypto!=='undefined'&&crypto.randomUUID)?crypto.randomUUID():Math.random().toString(36).slice(2)+Date.now().toString(36);
  return sha256('saos:salt:'+purpose+':'+base);
}
"""

VAULT_ORIG = "<<<<<<< HEAD\n export interface Vault {}\n=======\n export interface VaultKey { privateKeyRef: string }\n>>>>>>> incoming\n"
META_JSON = '{ "format":"SAOS-FLEET-VAULT-1","count":7,"pass": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" }'
RELAY_SOL = ("const SOL_RPCS = process.env.SOL_RPC_URL ? [process.env.SOL_RPC_URL] : ['https://api.devnet.solana.com'];\n"
             "await rpc('getSignatureStatuses',[[txid],{searchTransactionHistory:false}]);\n"
             "if (st && st.confirmationStatus === 'confirmed') verified += 1;\n")
RELAY_HIVE = ("if (mana.current_mana < 1000000) return {blocked:true};\n"
              "const op=['custom_json',{required_auths:['headcorner'],required_posting_auths:[],id:'saos-dex.anchor.v1',json:payload}];\n")
SCOPES = "admin:enterprise, admin:org, admin:ssh_signing_key, delete_repo, repo, workflow"
CLEAN = "import os,hashlib\ndef salt(p): return hashlib.sha256(p.encode()+os.urandom(32)).digest()\n"

FIXTURES = {
    "packages/core/src/vault/secure-storage.ts": SECURE_STORAGE,
    "packages/core/src/vault/key-derivation.ts": KEY_DERIVATION,
    "packages/core/src/vault/vault.ts.orig": VAULT_ORIG,
    "db/custom.db": "",
    "agent/keys/fleet_keys.meta.json": META_JSON,
    "src/lib/dex/relay-sol.ts": RELAY_SOL,
    "src/lib/dex/relay.ts": RELAY_HIVE,
    "docs/token-scopes.txt": SCOPES,
    "src/jumpper/clean.py": CLEAN,
}

EXPECTED = {
    "packages/core/src/vault/secure-storage.ts": {"H-01", "H-06"},
    "packages/core/src/vault/key-derivation.ts": {"H-02", "H-05"},
    "packages/core/src/vault/vault.ts.orig": {"H-03", "H-04"},
    "db/custom.db": {"H-07"},
    "agent/keys/fleet_keys.meta.json": {"H-08"},
    "src/lib/dex/relay-sol.ts": {"H-12", "H-13", "H-16"},
    "src/lib/dex/relay.ts": {"H-11", "H-15"},
    "docs/token-scopes.txt": {"H-17"},
    "src/jumpper/clean.py": set(),
}


def ids(path):
    return {v.rid for v in HD.scan_file(path, FIXTURES[path])}


class TestEveryRealDefectIsCaught(unittest.TestCase):
    def test_each_file_yields_exactly_the_expected_rules(self):
        for path, want in EXPECTED.items():
            self.assertEqual(ids(path), want, path)

    def test_total_counts_match_the_audit(self):
        r = HD.scan_tree(FIXTURES, now=NOW)
        self.assertEqual(r["filesScanned"], 9)
        self.assertEqual(r["blockingCount"], 10)
        self.assertEqual(r["reportingCount"], 4)
        self.assertEqual(r["bySeverity"]["critical"], 4)
        self.assertEqual(r["bySeverity"]["high"], 6)
        self.assertEqual(r["bySeverity"]["medium"], 4)
        self.assertEqual(r["verdict"], "BLOCKED")

    def test_clean_file_is_clean(self):
        self.assertEqual(ids("src/jumpper/clean.py"), set())

    def test_H09_private_key_pattern(self):
        bad = "const WIF = '5J" + "a" * 46 + "';"
        self.assertIn("H-09", {v.rid for v in HD.scan_file("src/k.ts", bad)})

    def test_H10_token_in_tree(self):
        bad = "TOKEN = 'ghp_" + "A" * 36 + "'"
        self.assertIn("H-10", {v.rid for v in HD.scan_file("scripts/push.sh", bad)})


class TestVerdictSemantics(unittest.TestCase):
    def test_blocking_rule_fails_the_build(self):
        r = HD.scan_tree({"src/vault/secure-storage.ts": SECURE_STORAGE}, now=NOW)
        self.assertFalse(r["pass"])
        self.assertEqual(r["verdict"], "BLOCKED")
        self.assertIn("H-01", [v["id"] for v in r["blocking"]])

    def test_reporting_rule_does_not_block(self):
        r = HD.scan_tree({"src/x.ts": "async f(){ state.verified += 1 }"}, now=NOW)
        self.assertTrue(r["pass"])
        self.assertGreater(r["reportingCount"], 0)

    def test_every_violation_carries_an_actionable_fix(self):
        r = HD.scan_tree(FIXTURES, now=NOW)
        for v in r["violations"]:
            self.assertTrue(v["fix"] and len(v["fix"]) > 20, v["id"])
            self.assertIn(v["severity"], (HD.CRITICAL, HD.HIGH, HD.MEDIUM, HD.LOW))

    def test_violations_carry_a_line_number_for_content_matches(self):
        r = HD.scan_tree(FIXTURES, now=NOW)
        for v in r["violations"]:
            if v["evidence"].startswith("line "):
                self.assertIsInstance(v["line"], int)
                self.assertGreaterEqual(v["line"], 1)


class TestWaivers(unittest.TestCase):
    def test_waiver_requires_expiry(self):
        with self.assertRaises(HD.HardeningError):
            HD.waiver("H-01", "src/vault/*.ts", "reason", "owner", 0, now=NOW)

    def test_waiver_requires_known_rule(self):
        with self.assertRaises(HD.HardeningError):
            HD.waiver("H-99", "src/*.ts", "reason", "owner", NOW + 3600, now=NOW)

    def test_waiver_must_be_scoped_not_global(self):
        for glob in ("*", "**"):
            with self.assertRaises(HD.HardeningError):
                HD.waiver("H-01", glob, "lazy", "owner", NOW + 3600, now=NOW)

    def test_valid_waiver_suppresses_its_rule_on_its_path(self):
        w = HD.waiver("H-01", "packages/core/src/vault/*.ts", "ticket SAOS-42", "owner", NOW + 7 * 86400, now=NOW)
        r = HD.scan_tree(FIXTURES, [w], now=NOW)
        self.assertNotIn("H-01", [v["id"] for v in r["violations"]])
        self.assertEqual(r["blockingCount"], 9)
        self.assertEqual(r["waivers"][0]["valid"], True)

    def test_expired_waiver_does_not_suppress(self):
        w = HD.Waiver("H-01", "packages/core/src/vault/*.ts", "old", "owner", NOW - 1)
        self.assertFalse(w.is_valid(NOW)[0])
        r = HD.scan_tree(FIXTURES, [w], now=NOW)
        self.assertIn("H-01", [v["id"] for v in r["violations"]])

    def test_waiver_is_scoped_to_its_glob(self):
        w = HD.waiver("H-01", "src/other/*.ts", "wrong path", "owner", NOW + 3600, now=NOW)
        r = HD.scan_tree(FIXTURES, [w], now=NOW)
        self.assertIn("H-01", [v["id"] for v in r["violations"]])

    def test_waiver_never_suppresses_a_different_rule(self):
        w = HD.waiver("H-01", "packages/core/src/vault/*.ts", "x", "owner", NOW + 3600, now=NOW)
        r = HD.scan_tree(FIXTURES, [w], now=NOW)
        self.assertIn("H-02", [v["id"] for v in r["violations"]])

    def test_every_waiver_is_listed_in_every_verdict(self):
        w = HD.waiver("H-01", "packages/core/src/vault/*.ts", "ticket SAOS-42", "owner", NOW + 3600, now=NOW)
        r = HD.scan_tree({"src/a.py": "x=1"}, [w], now=NOW)
        self.assertEqual(len(r["waivers"]), 1)
        self.assertEqual(r["waivers"][0]["rid"], "H-01")
        self.assertEqual(r["waivers"][0]["approvedBy"], "owner")
        self.assertIn("reason", r["waivers"][0])


class TestRuleRegistry(unittest.TestCase):
    def test_every_rule_documents_its_real_origin(self):
        for r in HD.RULES:
            self.assertTrue(len(r.origin) > 20, r.rid)
            self.assertTrue(len(r.why) > 20, r.rid)
            self.assertTrue(len(r.fix) > 20, r.rid)
            self.assertIn(r.severity, (HD.CRITICAL, HD.HIGH, HD.MEDIUM, HD.LOW))
            self.assertIn(r.action, (HD.BLOCK, HD.REPORT))

    def test_rule_ids_unique_and_ordered(self):
        got = [r.rid for r in HD.RULES]
        self.assertEqual(len(got), len(set(got)))
        self.assertEqual(got, sorted(got))

    def test_blocking_outnumbers_reporting(self):
        self.assertGreater(len(HD.rules_for(action=HD.BLOCK)), len(HD.rules_for(action=HD.REPORT)))

    def test_filters(self):
        self.assertTrue(all(r.severity == HD.CRITICAL for r in HD.rules_for(severity=HD.CRITICAL)))
        self.assertTrue(all(r.action == HD.BLOCK for r in HD.rules_for(action=HD.BLOCK)))



class TestEvidenceRedaction(unittest.TestCase):
    """A scanner that prints the secret it found turns one exposure into two."""

    SECRET = "zrLStQf5RS1GxqpTwZJO6goLKUL8iNuVK1UYtuVvraY"
    TOKENV = "ghp_" + "A" * 36
    WIF = "5J" + "a" * 46

    def test_password_value_is_never_in_evidence(self):
        v = HD.scan_file("agent/keys/fleet_keys.meta.json",
                         '{"pass": "%s"}' % self.SECRET)
        self.assertTrue(v)
        for x in v:
            self.assertNotIn(self.SECRET, x.evidence, x.rid)
            self.assertNotIn(self.SECRET, x.as_dict()["evidence"], x.rid)

    def test_token_value_is_never_in_evidence(self):
        v = HD.scan_file("scripts/push.sh", "T='%s'" % self.TOKENV)
        for x in v:
            self.assertNotIn(self.TOKENV, x.evidence, x.rid)

    def test_private_key_is_never_in_evidence(self):
        v = HD.scan_file("src/k.ts", "const WIF='%s';" % self.WIF)
        for x in v:
            self.assertNotIn(self.WIF, x.evidence, x.rid)

    def test_secret_still_reports_where_it_is(self):
        v = HD.scan_file("agent/keys/fleet_keys.meta.json", '{"pass": "%s"}' % self.SECRET)
        h08 = [x for x in v if x.rid == "H-08"]
        self.assertTrue(h08)
        self.assertIn("line 1", h08[0].evidence)
        self.assertIn("pass", h08[0].evidence)
        self.assertIn(HD.REDACTED, h08[0].evidence)

    def test_redaction_does_not_touch_non_secret_rules(self):
        v = HD.scan_file("src/a.ts", "window.localStorage.setItem(k,v)")
        h01 = [x for x in v if x.rid == "H-01"]
        self.assertTrue(h01)
        self.assertIn("localStorage", h01[0].evidence)

    def test_full_verdict_is_secret_free(self):
        import json as _json
        files = dict(FIXTURES)
        files["agent/keys/fleet_keys.meta.json"] = '{ "pass": "%s" }' % self.SECRET
        files["scripts/push.sh"] = "T='%s'" % self.TOKENV
        blob = _json.dumps(HD.scan_tree(files, now=NOW))
        self.assertNotIn(self.SECRET, blob)
        self.assertNotIn(self.TOKENV, blob)



class TestInlineAllowances(unittest.TestCase):
    """A policy engine must be runnable on its own source, and an allowance must
    never be silent."""

    DEFECT = "window.localStorage.setItem(k, v);"

    def test_line_allowance_on_another_line_does_not_suppress(self):
        self.assertIn("H-01", {x.rid for x in HD.scan_file("x.ts", "a = 1  # hardening:allow H-01\n" + self.DEFECT)})

    def test_line_allowance_on_the_defect_line_suppresses_it(self):
        self.assertEqual(HD.scan_file("x.ts", self.DEFECT + "  # hardening:allow H-01"), [])

    def test_file_allowance_suppresses_whole_file(self):
        src = "hardening:allow-file H-01 reason=documentation quotes the pattern\n" + self.DEFECT
        self.assertEqual(HD.scan_file("docs/x.md", src), [])

    def test_allowance_never_suppresses_a_different_rule(self):
        src = ("hardening:allow-file H-01 reason=x\nwindow.localStorage.setItem(k,v);\n"
               "throw new Error('foo is not implemented');\n")
        ids = {v.rid for v in HD.scan_file("x.ts", src)}
        self.assertNotIn("H-01", ids)
        self.assertIn("H-02", ids)

    def test_all_allowance_is_honoured_and_counted(self):
        src = "hardening:allow-file ALL reason=rule definitions quote their own patterns\n" + self.DEFECT
        used = []
        v = HD.scan_file("src/jumpper/hardening.py", src, collect_allowances=used)
        self.assertEqual(v, [])
        self.assertTrue(used)
        self.assertEqual(used[0]["rid"], "ALL")

    def test_allowances_are_always_listed_in_the_verdict(self):
        # Markdown prose is not scanned any more - only fenced code blocks are.
        # An allowance can only be recorded when it actually suppresses something,
        # so the fixture must put the defect where the scanner looks.
        src = ("hardening:allow-file H-01 reason=documentation\n\n"
               + FENCE + "\n" + self.DEFECT + "\n" + FENCE + "\n")
        r = HD.scan_tree({"docs/x.md": src})
        self.assertGreaterEqual(r["allowanceCount"], 1)
        self.assertEqual(r["allowancesUsed"][0]["rid"], "H-01")
        self.assertIn("documentation", r["allowancesUsed"][0]["reason"])
        self.assertTrue(r["pass"])

    def test_lowercase_ids_are_normalised(self):
        self.assertEqual(sorted(x.rid for x in HD.parse_allowances("x  # hardening:allow h-01, H-02")), ["H-01", "H-02"])

    def test_malformed_allowances_are_ignored_not_fatal(self):
        for bad in ("hardening:allow\n", "hardening:allow-file\n",
                    "hardening:allow-file H-01\n", "# hardening:allow H-99\n"):
            HD.scan_file("x.ts", bad + self.DEFECT)


if __name__ == "__main__":
    unittest.main(verbosity=2)
