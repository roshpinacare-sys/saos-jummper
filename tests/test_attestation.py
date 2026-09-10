# hardening:allow-file ALL reason=fixtures are the real on-chain attestation and the real state file it contradicts
"""Tests for attestation integrity.

Every fixture is real: CLAIM is the value_lock record signed on HIVE mainnet under
the custom_json id "saos", STATE is saos-dex/state/pool.json as committed, and BAL
is the live SAOS balance from accounts.hive-engine.com. The record says "LP locked
permanently - fees keep flowing" with lockedSaos 0.166 and depthBefore 106.868,
while the state says lpLocked false, lockedAt null, tvl 0 and fees 0, and the
account holds 0.19776475 SAOS in total with zero SWAP.HIVE.
"""

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


class TestTheRealAttestationIsRefused(unittest.TestCase):
    def test_refused_with_the_measured_counts(self):
        r = bad()
        self.assertEqual(r["decision"], AT.REFUSE)
        self.assertEqual((r["critical"], r["high"]), (4, 3))
        self.assertEqual(len(r["contradictions"]), 7)

    def test_locked_is_contradicted_by_lpLocked_false_and_lockedAt_null(self):
        f = [(c["field"], c["severity"]) for c in bad()["contradictions"]]
        self.assertIn(("lpLocked", "critical"), f)
        self.assertIn(("lockedAt", "critical"), f)

    def test_fees_flowing_is_contradicted_by_zero_fees(self):
        self.assertIn("feesGeneratedMicroUsd",
                      [c["field"] for c in bad()["contradictions"]])

    def test_the_depth_claim_is_reported_exactly_once(self):
        db = [x for x in bad()["contradictions"] if x["field"] == "depthBefore"]
        self.assertEqual(len(db), 1)
        self.assertEqual(db[0]["severity"], "critical")
        self.assertIn("exceeds", db[0]["detail"])

    def test_the_pointer_cannot_be_resolved(self):
        cs = bad()["contradictions"]
        # corrected: 40 hex is the GRAPHENE format, not Ethereum. The finding is
        # the missing chain name, which is what makes it unresolvable.
        self.assertTrue(any("GRAPHENE" in c["detail"] for c in cs))
        self.assertFalse(any("Ethereum-format" in c["detail"] for c in cs))
        self.assertIn("chain", [c["field"] for c in cs])

    def test_the_reason_names_the_contradiction_not_just_a_refusal(self):
        r = bad()["reason"]
        self.assertIn("REFUSED", r); self.assertIn("lpLocked", r)

    def test_dedupe_reports_each_field_once(self):
        f = [c["field"] for c in bad()["contradictions"]]
        self.assertEqual(len(f), len(set(f)))


class TestTheCheckerDiscriminates(unittest.TestCase):
    def test_a_claim_the_state_supports_is_allowed(self):
        r = AT.attest(gc(), gs(), balance=BAL, chain="hive")
        self.assertEqual(r["decision"], AT.ALLOW, r["contradictions"])
        self.assertEqual(r["contradictions"], [])

    def test_refuse_and_allow_on_the_same_input_shape(self):
        self.assertEqual(bad()["decision"], AT.REFUSE)
        self.assertEqual(AT.attest(gc(), gs(), balance=BAL, chain="hive")["decision"], AT.ALLOW)

    def test_a_claim_is_only_as_good_as_its_weakest_field(self):
        c = gc(); c["depthBefore"] = 106.868
        s = gs(); s["depthBefore"] = 106.868
        r = AT.attest(c, s, balance=BAL, chain="hive")
        self.assertEqual(r["decision"], AT.REFUSE)
        self.assertIn("depthBefore", [x["field"] for x in r["contradictions"]])


class TestNoteWords(unittest.TestCase):
    def test_every_asserting_word_needs_its_field(self):
        for w, f in (("locked","lpLocked"),("fees","feesGeneratedMicroUsd"),
                     ("funded","tvlMicroUsd"),("verified","verified")):
            c = AT.check_note_against_state("it is " + w, {})
            self.assertTrue(c, w); self.assertEqual(c[0].field_name, f)

    def test_a_false_field_is_critical_and_a_missing_one_is_high(self):
        self.assertEqual(AT.check_note_against_state("locked", {"lpLocked": False})[0].severity, "critical")
        m = AT.check_note_against_state("locked", {})[0]
        self.assertEqual(m.severity, "high"); self.assertIn("no field", m.detail)

    def test_backed_words_and_plain_prose_produce_nothing(self):
        self.assertEqual(AT.check_note_against_state("locked", {"lpLocked": True, "lockedAt": "x"}), [])
        self.assertEqual(AT.check_note_against_state("routine heartbeat", {"lpLocked": False}), [])


class TestAmountsAndPointers(unittest.TestCase):
    def test_within_balance_passes_and_over_balance_is_critical(self):
        self.assertEqual(AT.check_amount_against_balance(0.166, BAL, "x"), [])
        self.assertEqual(AT.check_amount_against_balance(106.868, BAL, "d")[0].severity, "critical")

    def test_a_missing_balance_refuses_rather_than_assuming_funded(self):
        c = AT.check_amount_against_balance(1.0, None, "x")
        self.assertTrue(c); self.assertIn("refusing", c[0].detail)

    def test_a_non_numeric_claim_refuses(self):
        self.assertTrue(AT.check_amount_against_balance("lots", "1.0", "x"))

    def test_a_bare_ethereum_hash_without_a_chain_is_flagged(self):
        c = AT.check_txid_pointer("4f83ae2a4754b2f7b07b242fac0c39a74bed1a5e")
        self.assertEqual(len(c), 2)
        self.assertTrue(any(x.field_name == "chain" for x in c))

    def test_a_named_chain_clears_it_and_an_empty_pointer_is_not_a_finding(self):
        self.assertEqual(AT.check_txid_pointer("0x" + "a" * 64, chain="ethereum"), [])
        self.assertEqual(AT.check_txid_pointer(None), [])
        self.assertEqual(AT.check_txid_pointer(""), [])


class TestInputValidation(unittest.TestCase):
    def test_empty_or_wrong_types_are_refused(self):
        with self.assertRaises(AT.AttestationError): AT.attest({}, {})
        with self.assertRaises(AT.AttestationError): AT.attest({"a": 1}, "not-a-dict")

    def test_attesting_against_nothing_is_an_error_not_an_allow(self):
        with self.assertRaises(AT.AttestationError): AT.attest({"a": 1}, None)


if __name__ == "__main__":
    unittest.main(verbosity=2)
