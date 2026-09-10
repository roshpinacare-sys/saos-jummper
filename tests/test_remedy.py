# hardening:allow-file ALL reason=fixtures are the real eight forked heights read from HIVE mainnet
"""Tests for the correction anchor, against the real forks.json: eight heights on
HIVE mainnet carrying contradictory roots, two of them 30 seconds apart."""

import json
import os
import unittest

from jumpper import remedy as RM

HERE = os.path.dirname(os.path.abspath(__file__))
FORKS = json.load(open(os.path.join(HERE, "fixtures_forks.json")))
R1 = "a54a51c7524dabc41d09d859f5d642aa836947482ef30467aef6e5a3f66416d0"
R2 = "d93e5a50d5e731ca81555b6bfc5dfd7fbc07e9b6e21357ca330e27dd9d3ea05d"

def cs():
    return RM.corrections_from_report(FORKS)

def anchors():
    return [{"height": c.height, "root": r} for c in cs() for r in c.roots]


class TestTheRealEight(unittest.TestCase):
    def test_all_eight_are_parsed(self):
        self.assertEqual(len(cs()), FORKS["forkedHeights"])

    def test_none_is_declared_canonical_because_nobody_decided(self):
        self.assertEqual({c.status for c in cs()}, {"AMBIGUOUS"})
        self.assertEqual(sum(1 for c in cs() if c.canonical_root), 0)

    def test_height_1764_the_thirty_second_collision_is_present(self):
        c = [x for x in cs() if x.height == 1764]
        self.assertEqual(len(c), 1); self.assertEqual(c[0].distinct_roots, 2)

    def test_height_552_carries_three_roots(self):
        c = [x for x in cs() if x.height == 552][0]
        self.assertEqual(c.distinct_roots, 3); self.assertEqual(len(c.roots), 3)

    def test_the_whole_record_fits_one_free_operation(self):
        pay = RM.encode_corrections(cs())
        n = len(pay.encode())
        self.assertLessEqual(n, 8192)
        self.assertLess(n, 1200)

    def test_plan_reports_it_fits_and_costs_nothing(self):
        pl = RM.plan("headcorner", cs())
        self.assertTrue(pl["fitsInOneOperation"]); self.assertEqual(pl["fee"], 0)
        self.assertEqual(pl["authority"], "posting"); self.assertEqual(pl["corrections"], 8)
        self.assertFalse(pl["retracts"])


class TestTheOperation(unittest.TestCase):
    def test_posting_authority_and_no_fee_field(self):
        op = RM.build_correction_op("headcorner", cs())
        self.assertEqual(op[0], "custom_json")
        self.assertEqual(op[1]["required_posting_auths"], ["headcorner"])
        self.assertEqual(op[1]["required_auths"], [])
        self.assertEqual(op[1]["id"], RM.CORRECTION_ANCHOR_ID)
        self.assertNotIn("fee", op[1])

    def test_plan_never_signs_or_broadcasts(self):
        pl = RM.plan("headcorner", cs())
        self.assertEqual(pl["signing"], "external-only")
        self.assertEqual(pl["broadcast"], "never-performed-here")


class TestFailClosed(unittest.TestCase):
    def test_canonical_without_a_root_is_refused(self):
        with self.assertRaises(RM.RemedyError):
            RM.Correction("l", 1, RM.CANONICAL, 2, [R1, R2])

    def test_an_invented_canonical_root_is_refused(self):
        with self.assertRaises(RM.RemedyError):
            RM.Correction("l", 1, RM.CANONICAL, 2, [R1, R2], canonical_root="c" * 64)

    def test_ambiguous_with_one_root_is_refused(self):
        with self.assertRaises(RM.RemedyError):
            RM.Correction("l", 1, RM.AMBIGUOUS, 1, [R1])

    def test_an_unknown_status_is_refused(self):
        with self.assertRaises(RM.RemedyError):
            RM.Correction("l", 1, "MAYBE", 2, [R1, R2])

    def test_a_malformed_root_is_refused(self):
        for bad in ("AB" * 32, "a" * 63, "z" * 64):
            with self.assertRaises(RM.RemedyError):
                RM.Correction("l", 1, RM.AMBIGUOUS, 2, [R1, bad])

    def test_a_negative_or_bool_height_is_refused(self):
        for bad in (-1, True):
            with self.assertRaises(RM.RemedyError):
                RM.Correction("l", bad, RM.AMBIGUOUS, 2, [R1, R2])

    def test_empty_and_mixed_batches_are_refused(self):
        with self.assertRaises(RM.RemedyError): RM.encode_corrections([])
        with self.assertRaises(RM.RemedyError):
            RM.encode_corrections([RM.Correction("a", 1, RM.AMBIGUOUS, 2, [R1, R2]),
                                   RM.Correction("b", 2, RM.AMBIGUOUS, 2, [R1, R2])])

    def test_an_oversize_batch_is_refused_not_truncated(self):
        many = [RM.Correction("l", i, RM.AMBIGUOUS, 2, [R1, R2]) for i in range(400)]
        with self.assertRaises(RM.RemedyError): RM.encode_corrections(many)

    def test_a_report_with_no_entries_is_refused(self):
        with self.assertRaises(RM.RemedyError): RM.corrections_from_report({"entries": []})
        with self.assertRaises(RM.RemedyError): RM.corrections_from_report("x")


class TestApplyCorrections(unittest.TestCase):
    def test_ambiguous_resolves_nothing_and_says_so(self):
        r = RM.apply_corrections(anchors(), cs())
        self.assertEqual(r["resolvedCount"], 0); self.assertEqual(r["ambiguousCount"], 8)
        self.assertIn("ambiguous", r["verdict"])

    def test_a_canonical_root_supplied_by_the_operator_resolves_that_height(self):
        real = cs()
        can = RM.Correction(real[0].log_id, real[0].height, RM.CANONICAL,
                            real[0].distinct_roots, list(real[0].roots),
                            canonical_root=real[0].roots[0])
        r = RM.apply_corrections(anchors(), [can] + real[1:])
        self.assertEqual(r["resolvedCount"], 1); self.assertEqual(r["ambiguousCount"], 7)

    def test_a_canonical_root_not_among_the_committed_ones_resolves_nothing(self):
        real = cs()
        can = RM.Correction(real[0].log_id, real[0].height, RM.CANONICAL,
                            real[0].distinct_roots, list(real[0].roots) + ["c" * 64],
                            canonical_root="c" * 64)
        r = RM.apply_corrections(anchors(), [can] + real[1:])
        self.assertEqual(r["resolvedCount"], 0)

    def test_heights_with_no_correction_record_are_reported_not_ignored(self):
        r = RM.apply_corrections([{"height": 999, "root": R1}], cs())
        self.assertEqual(r["unrecordedCount"], 1); self.assertEqual(r["unrecorded"], [999])


if __name__ == "__main__":
    unittest.main(verbosity=2)
