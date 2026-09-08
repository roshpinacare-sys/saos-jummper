"""Tests for the live-operations forensics detectors.

These run against a REAL fixture: 100 account-history entries read from HIVE
mainnet for account headcorner on 2026-09-08 (tests/fixtures/). The expected
values are what the chain actually contains, so a detector that starts lying
fails here rather than in production.
"""

import json
import os
import unittest

from jumpper import authority as AU
from jumpper import liveops as LO
from jumpper import protocol as PROTO

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURE = os.path.join(HERE, "fixtures", "hive_headcorner_history.json")


def load():
    if not os.path.exists(FIXTURE):
        raise unittest.SkipTest("live fixture not present")
    with open(FIXTURE) as fh:
        return json.load(fh)


class TestNormalisation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fx = load()
        cls.ops = LO.normalise(cls.fx["history"])

    def test_all_100_rows_normalise(self):
        self.assertEqual(len(self.ops), 100)

    def test_op_type_counts_match_chain(self):
        inv = LO.inventory(self.ops)
        self.assertEqual(inv["byOpType"]["custom_json"], 94)
        self.assertEqual(inv["byOpType"]["transfer"], 2)
        self.assertEqual(inv["byOpType"]["delegate_vesting_shares"], 1)
        self.assertEqual(inv["byOpType"]["fill_convert_request"], 1)

    def test_protocol_inventory_matches_chain(self):
        ids = LO.inventory(self.ops)["byCustomJsonId"]
        self.assertEqual(ids["ssc-mainnet-hive"], 32)
        self.assertEqual(ids["saos-dex.anchor.v1"], 23)
        self.assertEqual(ids["saos.attest.v1"], 20)
        self.assertEqual(ids["saos.weave.v1"], 11)
        self.assertEqual(ids["saos"], 5)
        self.assertEqual(ids["saos.id.v1"], 3)

    def test_rejects_malformed_rows(self):
        self.assertEqual(LO.normalise([]), [])
        self.assertEqual(LO.normalise([["x"], [1, "notadict"], [1, 2, 3]]), [])


class TestAuthorityAuditOnRealData(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ops = LO.normalise(load()["history"])
        cls.a = LO.audit_authority_by_protocol(cls.ops)

    def test_hive_engine_is_value_moving_and_correctly_active(self):
        r = self.a["byProtocol"]["ssc-mainnet-hive"]
        self.assertEqual(r["opClass"], AU.VALUE_MOVING)
        self.assertEqual(r["authorityNeeded"], AU.ACTIVE)
        self.assertEqual(r["overprivileged"], 0)
        self.assertEqual(r["total"], 32)

    def test_every_saos_attestation_protocol_is_overprivileged(self):
        for pid in ("saos-dex.anchor.v1", "saos.attest.v1", "saos.weave.v1", "saos.id.v1"):
            r = self.a["byProtocol"][pid]
            self.assertEqual(r["opClass"], AU.ATTESTATION, pid)
            self.assertEqual(r["authorityNeeded"], AU.POSTING, pid)
            self.assertEqual(r["overprivileged"], r["total"], pid)
            self.assertEqual(r["authorities"], {"active": r["total"]}, pid)

    def test_one_protocol_already_does_it_right(self):
        r = self.a["byProtocol"]["saos"]
        self.assertEqual(r["authorities"], {"posting": 5})
        self.assertEqual(r["correct"], 5)
        self.assertEqual(r["overprivileged"], 0)
        self.assertEqual(LO.protocols_already_using_posting(self.ops), ["saos"])

    def test_headline_numbers_match_the_chain(self):
        self.assertEqual(self.a["attestationOps"], 62)
        self.assertEqual(self.a["attestationOverprivileged"], 57)
        self.assertEqual(self.a["attestationOverprivilegedPct"], 91.9)
        self.assertEqual(self.a["valueMovingOps"], 32)

    def test_naive_audit_would_have_overclaimed(self):
        """The unclassified audit flags 89; the classified one flags 57.

        Counting ssc-mainnet-hive as overprivileged would be wrong - it moves
        tokens and genuinely needs ACTIVE. This test pins the difference so the
        honest number cannot silently drift back to the inflated one.
        """
        naive = LO.audit_authority(self.ops, AU.ATTESTATION)
        self.assertEqual(naive["overprivileged"], 89)
        self.assertEqual(self.a["attestationOverprivileged"], 57)
        self.assertLess(self.a["attestationOverprivileged"], naive["overprivileged"])


class TestRepeatLoopDetection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ops = LO.normalise(load()["history"])
        cls.loops = LO.find_repeat_loops(cls.ops, 3)

    def test_finds_the_convert_loop(self):
        conv = [f for f in self.loops if f.custom_json_id == "ssc-mainnet-hive"]
        self.assertEqual(len(conv), 1)
        self.assertEqual(conv[0].occurrences, 11)
        self.assertIn("9.632", conv[0].fingerprint)
        self.assertEqual(conv[0].first_timestamp, "2026-09-07T11:49:39")
        self.assertEqual(conv[0].last_timestamp, "2026-09-08T18:28:09")

    def test_finds_the_duplicate_weave_seal(self):
        w = [f for f in self.loops if f.custom_json_id == "saos.weave.v1"]
        self.assertEqual(sum(f.occurrences for f in w), 10)

    def test_rejects_bad_threshold(self):
        with self.assertRaises(LO.LiveOpsError):
            LO.find_repeat_loops(self.ops, 1)

    def test_waste_estimate_requires_a_measured_cost(self):
        with self.assertRaises(LO.LiveOpsError):
            LO.estimate_loop_waste(self.loops, 0)
        w = LO.estimate_loop_waste(self.loops, 157_713_792)
        self.assertEqual(w["redundantOps"], 18)   # 11 + 5 + 5 occurrences, minus 1 legitimate each
        self.assertIn("MEASURED", w["basis"])


class TestDuplicateSealAudit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ops = LO.normalise(load()["history"])
        cls.d = LO.duplicate_seal_audit(cls.ops, ["saos.weave.v1", "saos-dex.anchor.v1", "saos.attest.v1"])

    def test_finds_the_ten_times_seal(self):
        self.assertEqual(self.d["distinctSeals"], 45)
        self.assertEqual(self.d["duplicatedSeals"], 1)
        self.assertEqual(self.d["redundantBroadcasts"], 9)
        top = self.d["details"][0]
        self.assertEqual(top["times"], 10)
        self.assertIn("a62ba761", top["key"])
        self.assertIn("saos-net/0", top["key"])

    def test_anchors_are_not_duplicated(self):
        keys = [d["key"] for d in self.d["details"]]
        self.assertFalse(any("saos-dex.anchor.v1" in k for k in keys))


class TestPackingHeadroom(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ops = LO.normalise(load()["history"])

    def test_anchor_uses_3_percent_of_budget(self):
        h = LO.packing_headroom(self.ops, "saos-dex.anchor.v1")
        self.assertEqual(h["samples"], 23)
        self.assertAlmostEqual(h["avgJsonBytes"], 248.9, delta=0.5)
        self.assertLess(h["budgetUsedPct"], 4.0)
        self.assertGreater(h["headroomX"], 30)
        self.assertIsNone(h["observedCountField"])

    def test_weave_has_batching_schema_but_never_uses_it(self):
        h = LO.packing_headroom(self.ops, "saos.weave.v1")
        self.assertEqual(h["samples"], 11)
        self.assertEqual(h["minJsonBytes"], 218)
        self.assertEqual(h["maxJsonBytes"], 218)
        self.assertEqual(h["observedCountField"], {"1": 11})
        self.assertEqual(h["verdict"], "batching schema present but unused")
        self.assertLess(h["budgetUsedPct"], 3.0)

    def test_unknown_protocol_reports_no_samples(self):
        h = LO.packing_headroom(self.ops, "does-not-exist")
        self.assertEqual(h["samples"], 0)
        self.assertIn("no matching", h["verdict"])

    def test_budget_matches_live_protocol_constant(self):
        h = LO.packing_headroom(self.ops, "saos.weave.v1")
        self.assertEqual(h["budgetBytes"], PROTO.HIVE_CUSTOM_JSON_DATA_MAX_LENGTH)


class TestRcFixture(unittest.TestCase):
    def test_fixture_carries_real_rc_snapshot(self):
        fx = load()
        rc = fx["rc_account"]
        self.assertEqual(rc["account"], "headcorner")
        self.assertEqual(rc["max_rc"], 25641553538)
        self.assertEqual(rc["delegated_rc"], 0)
        self.assertEqual(rc["received_delegated_rc"], 0)
        self.assertGreater(rc["rc_manabar"]["current_mana"], 0)

    def test_fixture_records_unchanged_balance_across_convert_loop(self):
        fx = load()
        self.assertEqual(fx["account"]["balance"], "9.682 HIVE")


if __name__ == "__main__":
    unittest.main(verbosity=2)
