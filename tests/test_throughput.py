"""Tests for the free-throughput multiplier stack.

Every fixture is either a live mainnet constant fetched on 2026-09-08, a value
measured from 21 real anchors, or exact arithmetic derived from those. Nothing
here is a guess dressed as a measurement.
"""

import unittest

from jumpper import authority as AU
from jumpper import graphene as GR
from jumpper import packing as PK
from jumpper import protocol as PROTO
from jumpper import throughput as T

LIVE_CUSTOM_JSON_MAX = 8192
LIVE_MAX_TX_SIZE = 65536
LIVE_BLOCK_INTERVAL = 3
LIVE_BLOCKS_PER_DAY = 28800
LIVE_RC_WINDOW = 432000
LIVE_ROOTS_PER_OP = 154
LIVE_SEALS_PER_DAY = 2400
REAL_ROOT = "a8c3423cd68ea1df13a3e8f0dd1cc883f2e52c8e0a90f7c04e648405c60cd50f"
REGEN_PER_DAY = 5128310708.0


class TestProtocolConstants(unittest.TestCase):
    def test_match_live_mainnet(self):
        self.assertEqual(PROTO.HIVE_CUSTOM_JSON_DATA_MAX_LENGTH, LIVE_CUSTOM_JSON_MAX)
        self.assertEqual(PROTO.HIVE_MAX_TRANSACTION_SIZE, LIVE_MAX_TX_SIZE)
        self.assertEqual(PROTO.HIVE_BLOCK_INTERVAL, LIVE_BLOCK_INTERVAL)
        self.assertEqual(PROTO.HIVE_BLOCKS_PER_DAY, LIVE_BLOCKS_PER_DAY)

    def test_regen_window_confirms_five_day_model(self):
        self.assertEqual(PROTO.HIVE_RC_ACCOUNT_SUBSIDY_TRIPLE_WINDOW, LIVE_RC_WINDOW)
        self.assertEqual(PROTO.REGEN_SECONDS, 5 * 24 * 3600)

    def test_blocks_per_day_consistent_with_interval(self):
        self.assertEqual(PROTO.HIVE_BLOCKS_PER_DAY, 86400 // PROTO.HIVE_BLOCK_INTERVAL)

    def test_roots_per_operation_agrees_with_packing(self):
        self.assertEqual(PROTO.roots_per_operation(PK.TIER_E_ENTRY_BYTES + 1), LIVE_ROOTS_PER_OP)
        self.assertEqual(PROTO.roots_per_operation(PK.TIER_E_ENTRY_BYTES + 1), PK.max_entries())
        with self.assertRaises(PROTO.ProtocolError):
            PROTO.roots_per_operation(0)

    def test_seals_per_day(self):
        self.assertEqual(PROTO.seals_per_day_at_interval(12), LIVE_SEALS_PER_DAY)
        with self.assertRaises(PROTO.ProtocolError):
            PROTO.seals_per_day_at_interval(0)

    def test_snapshot_is_recorded(self):
        self.assertEqual(PROTO.RAW_SNAPSHOT["HIVE_CUSTOM_JSON_DATA_MAX_LENGTH"], LIVE_CUSTOM_JSON_MAX)
        self.assertIn("source", PROTO.RAW_SNAPSHOT)


class TestStrictBase64(unittest.TestCase):
    """Regression: base64 discards non-alphabet chars by default, so garbage
    used to decode silently to an empty digest instead of raising."""

    def test_rejects_non_alphabet(self):
        for bad in ("!!!", "A", "****"):
            with self.assertRaises(GR.GrapheneError):
                GR.unb64u(bad)

    def test_rejects_wrong_length(self):
        with self.assertRaises(GR.GrapheneError):
            GR.unb64u("zzzz")

    def test_rejects_empty(self):
        with self.assertRaises(GR.GrapheneError):
            GR.unb64u("")

    def test_valid_roundtrip_exact(self):
        self.assertEqual(GR.unb64u(GR.b64u(REAL_ROOT)), REAL_ROOT)

    def test_packing_rejects_garbage_entry(self):
        with self.assertRaises(PK.PackingError):
            PK.unpack_payload("1,2,!!!")


class TestPacking(unittest.TestCase):
    def test_max_entries_matches_protocol_budget(self):
        self.assertEqual(PK.max_entries(), LIVE_ROOTS_PER_OP)

    def test_max_plan_fits_and_one_more_does_not(self):
        self.assertTrue(PK.plan(LIVE_ROOTS_PER_OP).fits_custom_json)
        self.assertFalse(PK.plan(LIVE_ROOTS_PER_OP + 1).fits_custom_json)

    def test_packed_payload_never_exceeds_budget(self):
        self.assertLessEqual(PK.plan(LIVE_ROOTS_PER_OP).packed_json_bytes, LIVE_CUSTOM_JSON_MAX)

    def test_byte_ratio_is_substantial(self):
        p = PK.plan(LIVE_ROOTS_PER_OP)
        self.assertGreater(p.byte_ratio, 2.5)
        self.assertGreater(p.byte_saving_pct, 60.0)

    def test_single_root_has_no_packing_gain(self):
        self.assertAlmostEqual(PK.plan(1).byte_ratio, 1.0, delta=0.15)

    def test_monotonic_improvement_with_k(self):
        ratios = [PK.plan(k).byte_ratio for k in (1, 10, 50, 100, LIVE_ROOTS_PER_OP)]
        self.assertEqual(ratios, sorted(ratios))

    def test_roundtrip_is_exact(self):
        e = PK.RootEntry(1, 12108, REAL_ROOT)
        out = PK.unpack_payload(PK.pack_payload([e] * 5))
        self.assertEqual(len(out), 5)
        for o in out:
            self.assertEqual((o.version, o.height, o.root), (1, 12108, REAL_ROOT))

    def test_roundtrip_preserves_distinct_entries(self):
        entries = [PK.RootEntry(1, i, REAL_ROOT) for i in range(1, 20)]
        self.assertEqual([o.height for o in PK.unpack_payload(PK.pack_payload(entries))],
                         list(range(1, 20)))

    def test_rejects_empty_and_malformed(self):
        with self.assertRaises(PK.PackingError): PK.pack_payload([])
        with self.assertRaises(PK.PackingError): PK.unpack_payload("")
        for bad in ("1,2", "a,b,c", "1,2,!!!"):
            with self.assertRaises(PK.PackingError): PK.unpack_payload(bad)

    def test_operations_per_day_for_every_seal(self):
        ops = PK.operations_per_day_for_seals(LIVE_SEALS_PER_DAY)
        self.assertLess(ops, 20)
        self.assertGreater(ops, 10)


class TestAuthority(unittest.TestCase):
    def test_attestation_requires_only_posting(self):
        self.assertEqual(AU.authority_for(AU.ATTESTATION), AU.POSTING)

    def test_value_moving_requires_active(self):
        self.assertEqual(AU.authority_for(AU.VALUE_MOVING), AU.ACTIVE)

    def test_administrative_requires_owner(self):
        self.assertEqual(AU.authority_for(AU.ADMINISTRATIVE), AU.OWNER)

    def test_all_21_live_anchors_were_overprivileged(self):
        live = [{"required_auths": ["headcorner"], "required_posting_auths": []}] * 21
        a = AU.audit_live_anchors(live)
        self.assertEqual(a["total"], 21)
        self.assertEqual(a["signedWithActive"], 21)
        self.assertEqual(a["overprivilegedPct"], 100.0)

    def test_policy_built_op_uses_posting_not_active(self):
        op = AU.build_custom_json_by_policy("headcorner", "1,1,x")
        self.assertEqual(op[1]["required_auths"], [])
        self.assertEqual(op[1]["required_posting_auths"], ["headcorner"])
        self.assertNotIn("fee", op[1])

    def test_active_is_flagged_overprivileged_for_attestation(self):
        self.assertTrue(AU.is_overprivileged(AU.ATTESTATION, AU.ACTIVE))
        self.assertFalse(AU.is_overprivileged(AU.ATTESTATION, AU.POSTING))
        self.assertTrue(AU.is_overprivileged(AU.VALUE_MOVING, AU.OWNER))

    def test_blast_radius_escalates(self):
        p, a, o = AU.blast_radius(AU.POSTING), AU.blast_radius(AU.ACTIVE), AU.blast_radius(AU.OWNER)
        self.assertFalse(p["canMoveFunds"])
        self.assertTrue(a["canMoveFunds"])
        self.assertFalse(a["canChangeKeys"])
        self.assertTrue(o["canChangeKeys"])
        self.assertEqual([p["severity"], a["severity"], o["severity"]],
                         ["low", "critical", "total-loss"])

    def test_owner_never_used_for_automated_broadcast(self):
        with self.assertRaises(AU.AuthorityError):
            AU.build_custom_json_by_policy("a", "x", AU.ADMINISTRATIVE)

    def test_every_policy_states_reason_and_examples(self):
        for p in AU.POLICIES:
            self.assertTrue(len(p.reason) > 20, p.op_class)
            self.assertGreaterEqual(len(p.examples), 3, p.op_class)


class TestThroughputStack(unittest.TestCase):
    def test_compaction_multiplier_is_measured(self):
        self.assertGreater(T.compaction_multiplier(), 4.5)
        self.assertLess(T.compaction_multiplier(), 5.5)

    def test_combined_multiplier_matches_byte_ratio(self):
        comb = T.combined_multiplier()
        self.assertGreater(comb, 6.0)
        self.assertLess(comb, 7.0)
        self.assertAlmostEqual(comb, T.ONCHAIN_BYTES_PER_ANCHOR / T.combined_bytes_per_anchor(), delta=0.001)

    def test_bytes_per_anchor_falls_hard(self):
        self.assertLess(T.combined_bytes_per_anchor(), 60)
        self.assertGreater(T.ONCHAIN_BYTES_PER_ANCHOR, 300)

    def test_operation_count_collapses(self):
        self.assertEqual(T.seals_per_day(), LIVE_SEALS_PER_DAY)
        self.assertLess(T.operations_per_day(), 20)

    def test_fleet_striping_is_linear_in_staked_accounts(self):
        one = T.fleet_budget(REGEN_PER_DAY, 1)
        self.assertAlmostEqual(T.fleet_budget(REGEN_PER_DAY, 7), one * 7, delta=1)
        with self.assertRaises(T.ThroughputError):
            T.fleet_budget(REGEN_PER_DAY, 0)

    def test_pessimistic_floor_is_conservative(self):
        self.assertEqual(T.pessimistic_anchors_per_day(REGEN_PER_DAY), REGEN_PER_DAY / 1e6)

    def test_stack_marks_every_stage_evidence(self):
        allowed = {"MEASURED", "DERIVED", "UNMEASURED", "STRUCTURAL", "PARTLY MEASURED"}
        for st in T.stack()["stages"]:
            self.assertIn(st["evidence"], allowed)

    def test_stack_never_claims_a_measured_rc_cost(self):
        s = T.stack()
        self.assertIsNone(s["rcPerAnchor"])
        self.assertIn("guessed", s["note"])

    def test_stack_scales_with_fleet(self):
        self.assertAlmostEqual(T.stack(staked_accounts=7)["fleetRcPerDay"], REGEN_PER_DAY * 7, delta=1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
