# hardening:allow-file ALL reason=fixtures reproduce the truncation blind spot the pipeline exists to close
"""Tests for the end-to-end anchor pipeline.

The centrepiece is a before-and-after: audit.verify_chain over a truncated chain
returns intact=True, and the same chain verified against an anchored head returns
truncated=True. That transition is the whole reason this module exists.
"""

import unittest

from jumpper import audit as AU
from jumpper import packing as PK
from jumpper import pipeline as PL

RECORDS = [
    {"who": "agent-a", "when": "2026-09-08T12:00:00Z", "what": "transfer",
     "which": "tx-1", "outcome": "denied", "why": "over budget"},
    {"who": "agent-b", "when": "2026-09-08T12:00:03Z", "what": "seal",
     "which": "b-7", "outcome": "success", "why": None},
    {"who": "agent-a", "when": "2026-09-08T12:00:09Z", "what": "anchor",
     "which": "h-42", "outcome": "success", "why": None},
]
NOW = 1788900000


def chain():
    return AU.build_chain("vault-1", RECORDS)


def pipe(**kw):
    return PL.Pipeline("headcorner", network="hive-mainnet", **kw)


def head_req(p=None, c=None):
    return (p or pipe()).anchor_audit_head("vault-1", c if c is not None else chain(), now=NOW)


class TestTheBlindSpotIsClosed(unittest.TestCase):
    def test_without_an_anchor_a_truncated_chain_verifies(self):
        self.assertTrue(AU.verify_chain("vault-1", chain()[:1])["intact"])

    def test_with_an_anchor_the_same_truncation_is_detected(self):
        req = head_req()
        r = PL.Pipeline.verify_audit_with_anchor("vault-1", chain()[:1], req.payload)
        self.assertTrue(r["truncated"])
        self.assertIn("does not match", r["reason"])

    def test_a_complete_chain_is_not_reported_as_truncated(self):
        req = head_req()
        r = PL.Pipeline.verify_audit_with_anchor("vault-1", chain(), req.payload)
        self.assertTrue(r["intact"])
        self.assertFalse(r["truncated"])
        self.assertIsNone(r["reason"])

    def test_an_anchor_from_another_instance_is_rejected(self):
        req = head_req()
        r = PL.Pipeline.verify_audit_with_anchor("vault-2", chain(), req.payload)
        self.assertFalse(r["intact"])
        self.assertIn("vault-1", r["reason"])

    def test_content_tampering_is_still_detected_through_the_anchor_path(self):
        req = head_req()
        bad = [dict(x) for x in chain()]
        bad[0]["who"] = "agent-evil"
        r = PL.Pipeline.verify_audit_with_anchor("vault-1", bad, req.payload)
        self.assertFalse(r["intact"])
        self.assertEqual(r["firstBadSeq"], 0)

    def test_the_length_is_bound_so_a_shorter_chain_cannot_masquerade(self):
        req = head_req()
        parts = req.payload.split(":")
        self.assertEqual(parts[0], "vault-1")
        self.assertEqual(parts[1], "3")
        self.assertEqual(len(parts[2]), 64)

    def test_a_malformed_anchored_payload_is_refused(self):
        for bad in ("", "vault-1", "vault-1:3", "vault-1:notanint:" + "a" * 64):
            with self.assertRaises(PL.PipelineError):
                PL.Pipeline.verify_audit_with_anchor("vault-1", chain(), bad)


class TestAuditHeadAnchor(unittest.TestCase):
    def test_uses_posting_authority_and_no_fee(self):
        req = head_req()
        self.assertEqual(req.authority, "posting")
        self.assertEqual(req.fee, 0)
        self.assertEqual(req.op[1]["required_auths"], [])
        self.assertEqual(req.op[1]["required_posting_auths"], ["headcorner"])
        self.assertNotIn("fee", req.op[1])

    def test_payload_fits_the_free_budget_with_room_for_many_heads(self):
        req = head_req()
        n = len(req.payload.encode())
        self.assertLess(n, 120)
        self.assertGreater(8192 // max(n, 1), 60)

    def test_empty_chain_is_refused(self):
        with self.assertRaises(PL.PipelineError):
            pipe().anchor_audit_head("vault-1", [], now=NOW)

    def test_a_bad_head_is_refused(self):
        with self.assertRaises(PL.PipelineError):
            pipe().anchor_audit_head("vault-1", [{"hash": "tooshort"}], now=NOW)

    def test_the_operation_is_never_signed_or_broadcast_here(self):
        req = head_req()
        d = req.as_dict()
        self.assertEqual(d["signing"], "external-only")
        self.assertEqual(d["broadcast"], "never-performed-here")
        self.assertEqual(req.op[1].get("signatures"), None)


class TestBatchAnchoring(unittest.TestCase):
    def test_ingest_seal_and_anchor_end_to_end(self):
        p = pipe(max_leaves=8)
        for i in range(4):
            p.ingest({"i": i}, timestamp="2026-09-08T12:00:0%dZ" % i, now=NOW + i)
        sb = p.seal(now=NOW + 10)
        self.assertIsNotNone(sb)
        self.assertEqual(sb.leaf_count, 4)
        req = p.anchor_batch(sb, now=NOW + 11)
        self.assertEqual(req.kind, "batch")
        self.assertEqual(req.gate["verdict"], "allow")
        self.assertEqual(req.op[1]["id"], "saos-batch-anchor.v1")
        entry = PK.unpack_payload(req.payload)[0]
        self.assertEqual(entry.root, sb.root)
        self.assertEqual(entry.height, sb.height)

    def test_anchoring_nothing_is_refused(self):
        with self.assertRaises(PL.PipelineError):
            pipe().anchor_batch(None, now=NOW)

    def test_every_sealed_leaf_still_verifies_against_the_anchored_root(self):
        from jumpper import merkle as MK
        p = pipe(max_leaves=9)
        claims = [p.ingest({"i": i}, timestamp="2026-09-08T12:00:0%dZ" % i, now=NOW + i)
                  for i in range(5)]
        sb = p.seal(now=NOW + 10)
        self.assertIsNotNone(sb)
        for c in claims:
            self.assertTrue(MK.verify(c.leaf_hash, sb.proofs[c.leaf_hash], sb.root))


class TestAutoSealOnCapacity(unittest.TestCase):
    def test_the_batcher_seals_itself_when_full_so_a_later_seal_is_none(self):
        p = pipe(max_leaves=4)
        sealed = []
        for i in range(4):
            before = len(p.batcher.sealed)
            p.ingest({"i": i}, timestamp="2026-09-08T12:00:0%dZ" % i, now=NOW + i)
            if len(p.batcher.sealed) > before:
                sealed.append(p.batcher.sealed[-1])
        self.assertEqual(len(sealed), 1)
        self.assertEqual(sealed[0].leaf_count, 4)
        self.assertIsNone(p.seal(now=NOW + 10))

    def test_an_auto_sealed_batch_still_anchors(self):
        p = pipe(max_leaves=3)
        for i in range(3):
            p.ingest({"i": i}, timestamp="2026-09-08T12:00:0%dZ" % i, now=NOW + i)
        sb = p.batcher.sealed[-1]
        req = p.anchor_batch(sb, now=NOW + 5)
        self.assertEqual(req.gate["verdict"], "allow")
        entry = PK.unpack_payload(req.payload)[0]
        self.assertEqual(entry.root, sb.root)
        self.assertEqual(entry.height, sb.height)


class TestGatingIsWiredIn(unittest.TestCase):
    def test_a_repeat_anchor_is_denied_after_commit(self):
        p = pipe()
        req = head_req(p)
        p.commit(req, now=NOW)
        second = p.anchor_audit_head("vault-1", chain(), now=NOW + 60)
        self.assertEqual(second.gate["verdict"], "deny")
        self.assertEqual(second.gate["guard"], "repeat")

    def test_committing_a_denied_operation_is_refused(self):
        p = pipe()
        req = head_req(p)
        p.commit(req, now=NOW)
        denied = p.anchor_audit_head("vault-1", chain(), now=NOW + 60)
        with self.assertRaises(PL.PipelineError):
            p.commit(denied, now=NOW + 61)

    def test_a_non_mainnet_network_is_denied(self):
        p = PL.Pipeline("headcorner", network="api.devnet.solana.com")
        self.assertEqual(head_req(p).gate["verdict"], "deny")

    def test_a_missing_network_is_refused_at_construction(self):
        for bad in ("", None):
            with self.assertRaises(PL.PipelineError):
                PL.Pipeline("headcorner", network=bad)

    def test_a_missing_account_is_refused(self):
        with self.assertRaises(PL.PipelineError):
            PL.Pipeline("", network="hive-mainnet")

    def test_exceeding_the_rc_budget_is_denied(self):
        p = pipe(rc_budget_per_day=1000, rc_per_op_estimate=900)
        first = head_req(p, )
        self.assertEqual(first.gate["verdict"], "allow")
        p.commit(first, now=NOW)
        second = p.anchor_audit_head("vault-1", chain(), now=NOW + 60)
        self.assertEqual(second.gate["verdict"], "deny")


class TestCapacityReport(unittest.TestCase):
    def test_reports_measured_values_and_admits_what_is_not_calibrated(self):
        rep = pipe().capacity_report()
        self.assertEqual(rep["rcBudgetPerDay"], 5_128_310_708)
        self.assertEqual(rep["rcPerOpEstimate"], 157_713_792)
        self.assertEqual(rep["rootsPerOperation"], 154)
        self.assertEqual(rep["customJsonBudgetBytes"], 8192)
        self.assertIn("not decomposed", rep["note"])

    def test_ops_remaining_is_derived_not_guessed(self):
        rep = pipe().capacity_report()
        self.assertEqual(rep["opsRemainingToday"],
                         int(5_128_310_708 // 157_713_792))

    def test_an_uncalibrated_cost_is_reported_as_none_not_zero(self):
        rep = pipe(rc_per_op_estimate=None).capacity_report()
        self.assertIsNone(rep["rcPerOpEstimate"])
        self.assertFalse(rep["rcPerOpCalibrated"])
        self.assertIsNone(rep["opsRemainingToday"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
