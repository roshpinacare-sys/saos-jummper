# hardening:allow-file ALL reason=fixtures are the real on-chain attestation and the real state file it contradicts
"""Tests for attestation integrity against the real value_lock record signed on HIVE
mainnet and the real saos-dex/state/pool.json that contradicts it."""

import unittest

from jumpper import attestation as AT

CLAIM = {"protocol": "saos/v1", "action": "value_lock", "account": "headcorner", "seq": 34,
         "lockedSaos": 0.166, "depthBefore": 106.868,
         "srcTxid": "4f83ae2a4754b2f7b07b242fac0c39a74bed1a5e",
         "note": "LP locked permanently - fees keep flowing"}
STATE = {"depthSaos": "106.86837760", "tvlMicroUsd": 0, "lpLocked": False,
         "lockedAt": None, "feesGeneratedMicroUsd": 0}
BAL = "0.19776475"

def gc():
    c = dict(CLAIM); c["note"] = "LP pending"; c["lockedSaos"] = 0.1
    c["depthBefore"] = 0.15; c.pop("srcTxid"); return c

def gs():
    s = dict(STATE); s.update({"lpLocked": True, "lockedAt": "2026-09-08T00:00:00Z",
        "feesGeneratedMicroUsd": 1234, "tvlMicroUsd": 5000, "lockedSaos": 0.1,
        "depthBefore": 0.15}); return s

def bad():
    return AT.attest(CLAIM, STATE, balance=BAL)


class TestRealAttestationRefused(unittest.TestCase):
    def test_refused_with_measured_counts(self):
        r = bad()
        self.assertEqual(r["decision"], AT.REFUSE); self.assertEqual((r["critical"], r["high"]), (2, 6))

    def test_locked_contradicted(self):
        f = [(c["field"], c["severity"]) for c in bad()["contradictions"]]
        self.assertIn(("lpLocked", "critical"), f); self.assertIn(("lockedAt", "critical"), f)

    def test_fees_contradicted(self):
        self.assertIn("feesGeneratedMicroUsd", [c["field"] for c in bad()["contradictions"]])

    def test_depth_reported_once(self):
        db = [x for x in bad()["contradictions"] if x["field"] == "depthBefore"]
        self.assertEqual(len(db), 1); self.assertEqual(db[0]["severity"], "critical")
        self.assertIn("also", db[0]["detail"])

    def test_pointer_unresolvable(self):
        cs = bad()["contradictions"]
        self.assertTrue(any("Ethereum-format" in c["detail"] for c in cs))
        self.assertIn("chain", [c["field"] for c in cs])

    def test_reason_names_the_contradiction(self):
        r = bad()["reason"]
        self.assertIn("REFUSED", r); self.assertIn("lpLocked", r)

    def test_dedupe_collapses_fields(self):
        f = [c["field"] for c in bad()["contradictions"]]
        self.assertEqual(len(f), len(set(f)))


class TestDiscrimination(unittest.TestCase):
    def test_supported_claim_allowed(self):
        r = AT.attest(gc(), gs(), balance=BAL, chain="hive")
        self.assertEqual(r["decision"], AT.ALLOW, r["contradictions"]); self.assertEqual(r["contradictions"], [])

    def test_refuse_and_allow_on_same_shape(self):
        self.assertEqual(bad()["decision"], AT.REFUSE)
        self.assertEqual(AT.attest(gc(), gs(), balance=BAL, chain="hive")["decision"], AT.ALLOW)

    def test_weakest_field_wins(self):
        c = gc(); c["depthBefore"] = 106.868
        s = gs(); s["depthBefore"] = 106.868
        r = AT.attest(c, s, balance=BAL, chain="hive")
        self.assertEqual(r["decision"], AT.REFUSE)
        self.assertIn("depthBefore", [x["field"] for x in r["contradictions"]])


class TestNoteWords(unittest.TestCase):
    def test_each_word_needs_its_field(self):
        for w, f in (("locked","lpLocked"),("fees","feesGeneratedMicroUsd"),("funded","tvlMicroUsd"),("verified","verified")):
            c = AT.check_note_against_state("it is " + w, {}); self.assertTrue(c, w); self.assertEqual(c[0].field_name, f)

    def test_false_critical_missing_high(self):
        self.assertEqual(AT.check_note_against_state("locked", {"lpLocked": False})[0].severity, "critical")
        m = AT.check_note_against_state("locked", {})[0]; self.assertEqual(m.severity, "high"); self.assertIn("no field", m.detail)

    def test_backed_and_plain_prose_clean(self):
        self.assertEqual(AT.check_note_against_state("locked", {"lpLocked": True, "lockedAt": "x"}), [])
        self.assertEqual(AT.check_note_against_state("routine heartbeat", {"lpLocked": False}), [])


class TestAmountsPointers(unittest.TestCase):
    def test_amount_bounds(self):
        self.assertEqual(AT.check_amount_against_balance(0.166, BAL, "x"), [])
        self.assertEqual(AT.check_amount_against_balance(106.868, BAL, "d")[0].severity, "critical")

    def test_missing_balance_refuses(self):
        c = AT.check_amount_against_balance(1.0, None, "x"); self.assertTrue(c); self.assertIn("refusing", c[0].detail)

    def test_non_numeric_refuses(self):
        self.assertTrue(AT.check_amount_against_balance("lots", "1.0", "x"))

    def test_bare_hash_flagged(self):
        c = AT.check_txid_pointer("4f83ae2a4754b2f7b07b242fac0c39a74bed1a5e")
        self.assertEqual(len(c), 2); self.assertTrue(any(x.field_name == "chain" for x in c))

    def test_named_chain_clears_and_empty_clean(self):
        self.assertEqual(AT.check_txid_pointer("0x" + "a" * 64, chain="ethereum"), [])
        self.assertEqual(AT.check_txid_pointer(None), []); self.assertEqual(AT.check_txid_pointer(""), [])


class TestValidation(unittest.TestCase):
    def test_bad_inputs(self):
        with self.assertRaises(AT.AttestationError): AT.attest({}, {})
        with self.assertRaises(AT.AttestationError): AT.attest({"a": 1}, "x")
        with self.assertRaises(AT.AttestationError): AT.attest({"a": 1}, None)


if __name__ == "__main__":
    unittest.main(verbosity=2)
