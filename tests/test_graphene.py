"""Tests for the free Graphene anchor layer and the capability matrix.

Fixtures are REAL values read from HIVE mainnet on 2026-09-08 via
api.openhive.network, read-only. Nothing here is invented.
"""

import json
import unittest

from jumpper import freeops as FO
from jumpper import graphene as GR

LIVE_ACCOUNT = "headcorner"
LIVE_STORED_MANA = 1392041
LIVE_LAST_UPDATE = 1788870714
LIVE_MAX_RC = 25641553538
LIVE_NOW = 1788871925
LIVE_EFFECTIVE = 73271489
LIVE_REGEN_PER_DAY = 5128310708
REGEN_PER_SEC = 59355.0
REAL_ROOT = "a8c3423cd68ea1df13a3e8f0dd1cc883f2e52c8e0a90f7c04e648405c60cd50f"
REAL_DIGEST = "9a4b6e9ac8c482f6891a4b977ed4a90e1431b04cef1277abe6efb62409fdb7d8"
REAL_HEIGHT = 12108
REAL_AT = "2026-09-08T12:31:53.662Z"
REAL_LEGACY_BYTES = 250
LEGACY_GATE_RC_MIN = 1000000
STALE_READ_THAT_BLOCKED_HIVE = 924265


class TestRcProjection(unittest.TestCase):
    def setUp(self):
        self.st = GR.rc_state(LIVE_ACCOUNT, LIVE_STORED_MANA, LIVE_LAST_UPDATE, LIVE_MAX_RC, LIVE_NOW)

    def test_matches_live_mainnet_measurement_exactly(self):
        self.assertEqual(round(self.st.effective_mana), LIVE_EFFECTIVE)

    def test_regen_rate_is_max_over_five_days(self):
        self.assertAlmostEqual(self.st.regen_per_second, LIVE_MAX_RC / 432000, delta=1)
        self.assertAlmostEqual(self.st.regen_per_day, LIVE_REGEN_PER_DAY, delta=2000)

    def test_elapsed_never_negative_under_clock_skew(self):
        st = GR.rc_state("a", 100, LIVE_NOW + 9999, LIVE_MAX_RC, LIVE_NOW)
        self.assertEqual(st.elapsed, 0)
        self.assertEqual(round(st.effective_mana), 100)

    def test_effective_never_exceeds_max(self):
        st = GR.rc_state("a", LIVE_MAX_RC, LIVE_NOW - 10**7, LIVE_MAX_RC, LIVE_NOW)
        self.assertLessEqual(st.effective_mana, LIVE_MAX_RC)

    def test_stale_snapshot_underreports_by_measured_factor(self):
        self.assertGreater(self.st.stale_underreport_factor, 50)
        self.assertLess(self.st.stale_underreport_factor, 55)

    def test_rejects_bad_input(self):
        with self.assertRaises(GR.GrapheneError): GR.rc_state("a", 1, 1, 0, 1)
        with self.assertRaises(GR.GrapheneError): GR.rc_state("a", -1, 1, 100, 1)


class TestTheStaleReadBug(unittest.TestCase):
    def test_raw_snapshot_gate_falsely_blocks(self):
        self.assertFalse(STALE_READ_THAT_BLOCKED_HIVE >= LEGACY_GATE_RC_MIN)

    def test_projection_correct_gate_passes(self):
        st = GR.rc_state(LIVE_ACCOUNT, LIVE_STORED_MANA, LIVE_LAST_UPDATE, LIVE_MAX_RC, LIVE_NOW)
        self.assertTrue(GR.can_afford(st, 5000))

    def test_gate_uses_effective_not_stored(self):
        st = GR.rc_state("a", 10, LIVE_NOW - 600, LIVE_MAX_RC, LIVE_NOW)
        self.assertLess(st.stored_mana, LEGACY_GATE_RC_MIN)
        self.assertTrue(GR.can_afford(st, LEGACY_GATE_RC_MIN))

    def test_max_affordable_derives_from_effective(self):
        st = GR.rc_state(LIVE_ACCOUNT, LIVE_STORED_MANA, LIVE_LAST_UPDATE, LIVE_MAX_RC, LIVE_NOW)
        self.assertEqual(GR.max_affordable_anchors(st, 5000), int(LIVE_EFFECTIVE // 5000))
        with self.assertRaises(GR.GrapheneError): GR.max_affordable_anchors(st, 0)


class TestRcApiParsing(unittest.TestCase):
    def test_parses_raw_api_shape(self):
        raw = {"account": LIVE_ACCOUNT,
               "rc_manabar": {"current_mana": LIVE_STORED_MANA, "last_update_time": LIVE_LAST_UPDATE},
               "max_rc": LIVE_MAX_RC, "delegated_rc": 0, "received_delegated_rc": 0}
        self.assertEqual(round(GR.rc_state_from_api(LIVE_ACCOUNT, raw, LIVE_NOW).effective_mana), LIVE_EFFECTIVE)

    def test_malformed_raises(self):
        with self.assertRaises(GR.GrapheneError): GR.rc_state_from_api("a", {"rc_manabar": {}}, LIVE_NOW)


class TestPayloadCompaction(unittest.TestCase):
    def setUp(self):
        self.ca = GR.CompactAnchor(version=1, height=REAL_HEIGHT, root=REAL_ROOT)
        self.legacy = self.ca.payload_legacy(REAL_AT, REAL_DIGEST)

    def test_legacy_size_matches_observed_mainnet(self):
        self.assertEqual(len(self.legacy.encode()), REAL_LEGACY_BYTES)

    def test_tier_e_is_substantially_smaller(self):
        e = len(self.ca.payload_e().encode())
        self.assertLessEqual(e, 52)
        self.assertGreater((REAL_LEGACY_BYTES - e) / REAL_LEGACY_BYTES, 0.79)

    def test_tier_d_smaller_than_legacy(self):
        self.assertLess(len(self.ca.payload_d().encode()), REAL_LEGACY_BYTES)

    def test_tier_e_roundtrip_exact(self):
        rt = GR.parse_payload_e(self.ca.payload_e())
        self.assertEqual((rt.version, rt.height, rt.root), (self.ca.version, self.ca.height, self.ca.root))

    def test_base64url_roundtrip_preserves_all_64_hex(self):
        self.assertEqual(GR.unb64u(GR.b64u(REAL_ROOT)), REAL_ROOT)

    def test_rejects_non_hex_root(self):
        with self.assertRaises(GR.GrapheneError): GR.b64u("ZZ" * 32)
        with self.assertRaises(GR.GrapheneError): GR.b64u(REAL_ROOT.upper())

    def test_parse_rejects_malformed(self):
        for bad in ("1,2", "x,y,z", "1,2,!!!notbase64!!!"):
            with self.assertRaises(GR.GrapheneError): GR.parse_payload_e(bad)


class TestOpShape(unittest.TestCase):
    def test_matches_verified_mainnet_form(self):
        op = GR.build_custom_json(LIVE_ACCOUNT, "1,12108,x")
        self.assertEqual(op[0], "custom_json")
        d = op[1]
        self.assertEqual(d["required_auths"], [LIVE_ACCOUNT])
        self.assertEqual(d["required_posting_auths"], [])
        self.assertEqual(set(d.keys()), {"required_auths", "required_posting_auths", "id", "json"})

    def test_carries_no_fee_field(self):
        blob = json.dumps(GR.build_custom_json(LIVE_ACCOUNT, "1,1,x")[1])
        self.assertNotIn("fee", blob)
        self.assertNotIn("amount", blob)

    def test_posting_authority_variant(self):
        op = GR.build_custom_json(LIVE_ACCOUNT, "1,1,x", posting=True)
        self.assertEqual(op[1]["required_auths"], [])
        self.assertEqual(op[1]["required_posting_auths"], [LIVE_ACCOUNT])

    def test_rejects_empty(self):
        with self.assertRaises(GR.GrapheneError): GR.build_custom_json("", "x")
        with self.assertRaises(GR.GrapheneError): GR.build_custom_json("a", "")

    def test_tx_skeleton_never_contains_a_key(self):
        tx = GR.build_transaction_skeleton(GR.build_custom_json("a", "1,1,x"), 1234, 5678, "2026-01-01T00:00:00")
        blob = json.dumps(tx).lower()
        for banned in ("private", "wif", "secret"):
            self.assertNotIn(banned, blob)
        self.assertEqual(tx["signatures"], [])
        self.assertEqual(tx["ref_block_num"], 1234)


class TestCapabilityMatrix(unittest.TestCase):
    def test_no_enforcement_capability_claims_free(self):
        for c in FO.CAPABILITIES:
            if c.category == "enforcement":
                self.assertFalse(c.free_on_ours, c.name)

    def test_every_entry_states_its_honest_limit(self):
        for c in FO.CAPABILITIES:
            self.assertTrue(c.honest_limit and len(c.honest_limit) > 20, c.name)

    def test_partition_is_complete(self):
        self.assertEqual(len(FO.free_capabilities()) + len(FO.not_free_capabilities()), len(FO.CAPABILITIES))
        self.assertGreaterEqual(len(FO.free_capabilities()), 10)
        self.assertGreaterEqual(len(FO.not_free_capabilities()), 4)

    def test_matrix_serializes(self):
        rows = FO.matrix_as_dicts()
        self.assertEqual(len(rows), len(FO.CAPABILITIES))
        self.assertTrue(all("honestLimit" in r for r in rows))
        json.dumps(rows)

    def test_pessimistic_floor_is_conservative(self):
        self.assertEqual(FO.pessimistic_anchors_per_day(LIVE_REGEN_PER_DAY),
                         LIVE_REGEN_PER_DAY / FO.PESSIMISTIC_RC_PER_ANCHOR)
        self.assertGreater(FO.pessimistic_anchors_per_day(LIVE_REGEN_PER_DAY), 5000)


class TestCalibrationRefusesToGuess(unittest.TestCase):
    def test_uncalibrated_without_samples(self):
        cal = FO.RcCalibration()
        self.assertIsNone(cal.calibrate(REGEN_PER_SEC))
        self.assertEqual(cal.calibration_quality, "uncalibrated-needs-bracketing-samples")
        self.assertIsNone(cal.anchors_per_day(LIVE_REGEN_PER_DAY))

    def test_reports_a_floor_instead_of_a_guess(self):
        rep = FO.RcCalibration().report(LIVE_REGEN_PER_DAY)
        self.assertIn("UNMEASURED", rep["note"])
        self.assertIn("5128", rep["note"])

    def test_calibrates_from_real_bracketing_samples(self):
        cal = FO.RcCalibration()
        cal.add_sample(1000, 10_000_000, "before-anchor")
        cal.add_sample(1060, 12_000_000, "after-anchor")
        cost = cal.calibrate(REGEN_PER_SEC)
        self.assertIsNotNone(cost)
        self.assertAlmostEqual(cost, (10_000_000 + REGEN_PER_SEC * 60) - 12_000_000, delta=1)
        self.assertTrue(cal.calibration_quality.startswith("calibrated-from-60"))
        self.assertIsNotNone(cal.anchors_per_day(LIVE_REGEN_PER_DAY))

    def test_rejects_gap_too_small(self):
        cal = FO.RcCalibration()
        cal.add_sample(1000, 10_000_000, "before-anchor")
        cal.add_sample(1001, 9_000_000, "after-anchor")
        self.assertIsNone(cal.calibrate(REGEN_PER_SEC))
        self.assertEqual(cal.calibration_quality, "uncalibrated-gap-too-small")

    def test_rejects_nonpositive_spend(self):
        cal = FO.RcCalibration()
        cal.add_sample(1000, 10_000_000, "before-anchor")
        cal.add_sample(1060, 100_000_000, "after-anchor")
        self.assertIsNone(cal.calibrate(REGEN_PER_SEC))
        self.assertEqual(cal.calibration_quality, "uncalibrated-nonpositive-spend")


if __name__ == "__main__":
    unittest.main(verbosity=2)
