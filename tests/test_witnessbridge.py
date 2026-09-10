# hardening:allow-file ALL reason=fixtures reproduce the kernel WitnessStatement shape the bridge consumes
"""Tests for the witness bridge, written against the real interface in
roshpina/kernel/transparency-log/witness.ts (v387)."""

import json
import unittest

from jumpper import witnessbridge as WB

R1 = "a8c3423cd68ea1df13a3e8f0dd1cc883f2e52c8e0a90f7c04e648405c60cd50f"
R2 = "6d4c4a120df44afb530180f78688cc15fffa66688e20ef80675710fad8f30843"
VER = "tfa-witness-v1"
TS = "2026-09-08T21:17:42Z"

def st(log, root, size, wid):
    return WB.Statement(log_id=log, root=root, tree_size=size, observed_at=TS,
                        witness_id=wid, algorithm="ed25519", signature="c2ln")

def raw(log, root, size, wid):
    return {"version": VER, "logId": log, "root": root, "treeSize": size,
            "observedAt": TS, "witnessId": wid, "algorithm": "ed25519", "signature": "c2ln"}

def coms(n):
    return [WB.QuorumCommitment("log-%d" % i, 12108 + i, R1 if i % 2 else R2, 3,
                               WB.witness_set_digest(["w1", "w2", "w3"])) for i in range(n)]


class TestStatementParsing(unittest.TestCase):
    def test_a_valid_kernel_statement_parses(self):
        s = WB.parse_statement(raw("log-a", R1, 12108, "w1"))
        self.assertEqual((s.log_id, s.tree_size, s.witness_id), ("log-a", 12108, "w1"))

    def test_every_required_field_is_enforced(self):
        base = raw("log-a", R1, 12108, "w1")
        for f in list(base):
            bad = dict(base); del bad[f]
            with self.assertRaises(WB.WitnessBridgeError): WB.parse_statement(bad)

    def test_wrong_version_is_refused(self):
        bad = raw("log-a", R1, 12108, "w1"); bad["version"] = "tfa-witness-v2"
        with self.assertRaises(WB.WitnessBridgeError): WB.parse_statement(bad)

    def test_bad_root_is_refused(self):
        for bad in ("AB" * 32, "ab" * 31, "zz" * 32, ""):
            with self.assertRaises(WB.WitnessBridgeError): WB.parse_statement(raw("log-a", bad, 1, "w1"))

    def test_bad_tree_size_and_timestamp_are_refused(self):
        with self.assertRaises(WB.WitnessBridgeError): WB.parse_statement(raw("log-a", R1, -1, "w1"))
        with self.assertRaises(WB.WitnessBridgeError): WB.parse_statement(raw("log-a", R1, True, "w1"))
        r = raw("log-a", R1, 1, "w1"); r["observedAt"] = "not-a-date"
        with self.assertRaises(WB.WitnessBridgeError): WB.parse_statement(r)


class TestSigningPayloadIsKernelCompatible(unittest.TestCase):
    def test_it_carries_exactly_the_six_kernel_fields(self):
        p = json.loads(WB.signing_payload(st("log-a", R1, 12108, "w1")))
        self.assertEqual(sorted(p), sorted(["version","logId","root","treeSize","observedAt","witnessId"]))

    def test_it_excludes_algorithm_and_signature(self):
        p = WB.signing_payload(st("log-a", R1, 12108, "w1"))
        self.assertNotIn("algorithm", p); self.assertNotIn("signature", p)

    def test_it_is_deterministic_with_no_whitespace(self):
        a = WB.signing_payload(st("log-a", R1, 12108, "w1"))
        self.assertEqual(a, WB.signing_payload(st("log-a", R1, 12108, "w1")))
        self.assertNotIn(" ", a)


class TestSplitView(unittest.TestCase):
    def test_unanimous_witnesses_are_not_a_split_view(self):
        self.assertEqual(WB.detect_split_view([st("a", R1, 1, "w%d" % i) for i in range(3)]), [])

    def test_one_dissenter_is_a_split_view(self):
        c = WB.detect_split_view([st("a", R1, 1, "w1"), st("a", R1, 1, "w2"), st("a", R2, 1, "w3")])
        self.assertEqual(len(c), 1); self.assertEqual(len(c[0]["distinctRoots"]), 2)
        self.assertEqual(c[0]["witnessesByRoot"][R2], ["w3"])

    def test_different_tree_sizes_are_not_a_split_view(self):
        self.assertEqual(WB.detect_split_view([st("a", R1, 1, "w1"), st("a", R2, 2, "w2")]), [])

    def test_quorum_raises_on_a_fork_rather_than_picking_a_side(self):
        s = [st("a", R1, 1, "w1"), st("a", R1, 1, "w2"), st("a", R2, 1, "w3")]
        with self.assertRaises(WB.SplitViewError): WB.quorum(s, "a", 1, 2)


class TestQuorum(unittest.TestCase):
    def test_threshold_met_and_not_met(self):
        q = WB.quorum([st("a", R1, 7, "w%d" % i) for i in range(3)], "a", 7, 3)
        self.assertTrue(q["reached"]); self.assertEqual(q["distinctWitnesses"], 3); self.assertEqual(q["root"], R1)
        self.assertFalse(WB.quorum([st("a", R1, 7, "w1")], "a", 7, 3)["reached"])

    def test_duplicate_witness_ids_do_not_inflate_the_count(self):
        q = WB.quorum([st("a", R1, 7, "w1")] * 5, "a", 7, 3)
        self.assertEqual(q["distinctWitnesses"], 1); self.assertFalse(q["reached"])

    def test_it_never_claims_signatures_were_verified(self):
        self.assertFalse(WB.quorum([st("a", R1, 7, "w1")], "a", 7, 1)["signaturesVerified"])

    def test_no_statements_is_not_a_quorum(self):
        q = WB.quorum([], "a", 7, 1); self.assertFalse(q["reached"]); self.assertIsNone(q["root"])

    def test_threshold_must_be_positive(self):
        with self.assertRaises(WB.WitnessBridgeError): WB.quorum([], "a", 1, 0)


class TestCommitmentAndPacking(unittest.TestCase):
    def test_exact_round_trip(self):
        c = WB.QuorumCommitment("log-a", 12108, R1, 3, WB.witness_set_digest(["w1","w2"]))
        rt = WB.decode_commitment(c.encode())
        self.assertEqual((rt.log_id, rt.tree_size, rt.root, rt.witness_count, rt.witness_set_digest),
                         (c.log_id, c.tree_size, c.root, c.witness_count, c.witness_set_digest))

    def test_set_digest_is_order_independent_and_deduped(self):
        a = WB.witness_set_digest(["w1","w2","w3"])
        self.assertEqual(a, WB.witness_set_digest(["w3","w1","w2","w1"]))
        self.assertNotEqual(a, WB.witness_set_digest(["w1","w2"]))

    def test_malformed_commitments_are_refused(self):
        for bad in ("", "a:1", "a:x:%s:1:%s" % (WB.b64u(R1), WB.b64u(R1)), "a:1:zz:1:zz"):
            with self.assertRaises(WB.WitnessBridgeError): WB.decode_commitment(bad)

    def test_the_sample_estimate_over_promised_and_the_exact_function_does_not(self):
        cs = coms(120)
        est = WB.commitments_per_operation(cs[0]); ex = WB.max_commitments_that_fit(cs)
        self.assertGreater(est, ex)
        with self.assertRaises(WB.WitnessBridgeError): WB.pack_commitments(cs[:est])
        self.assertLessEqual(len(WB.pack_commitments(cs[:ex]).encode()), 8192)

    def test_split_covers_every_commitment_exactly_once(self):
        cs = coms(120); chunks = WB.split_into_operations(cs)
        flat = [c for ch in chunks for c in ch]
        self.assertEqual([c.log_id for c in flat], [c.log_id for c in cs])
        for ch in chunks: self.assertLessEqual(len(WB.pack_commitments(ch).encode()), 8192)

    def test_each_chunk_unpacks_exactly(self):
        for ch in WB.split_into_operations(coms(95)):
            out = WB.unpack_commitments(WB.pack_commitments(ch))
            self.assertEqual([c.root for c in out], [c.root for c in ch])

    def test_empty_inputs_are_refused(self):
        with self.assertRaises(WB.WitnessBridgeError): WB.pack_commitments([])
        with self.assertRaises(WB.WitnessBridgeError): WB.max_commitments_that_fit([])
        with self.assertRaises(WB.WitnessBridgeError): WB.split_into_operations([])

    def test_a_commitment_too_wide_for_the_budget_is_refused(self):
        with self.assertRaises(WB.WitnessBridgeError): WB.split_into_operations([WB.QuorumCommitment("x"*9000, 1, R1, 1, "0"*64)])

    def test_version_mismatch_on_unpack_is_refused(self):
        pay = WB.pack_commitments(coms(2))
        with self.assertRaises(WB.WitnessBridgeError): WB.unpack_commitments("99" + pay[2:])


class TestAnchorOperation(unittest.TestCase):
    def test_posting_authority_and_no_fee(self):
        op = WB.build_anchor_op("headcorner", coms(3))
        self.assertEqual(op[0], "custom_json")
        self.assertEqual(op[1]["required_posting_auths"], ["headcorner"])
        self.assertEqual(op[1]["required_auths"], [])
        self.assertEqual(op[1]["id"], WB.BRIDGE_ANCHOR_ID)
        self.assertNotIn("fee", op[1]); self.assertNotIn("amount", op[1])

    def test_plan_never_signs_or_broadcasts(self):
        pl = WB.plan("headcorner", coms(20))
        self.assertEqual(pl["fee"], 0); self.assertEqual(pl["authority"], "posting")
        self.assertEqual(pl["signing"], "external-only")
        self.assertEqual(pl["broadcast"], "never-performed-here")
        self.assertFalse(pl["signaturesVerified"])

    def test_plan_reports_budget_usage(self):
        pl = WB.plan("headcorner", coms(20))
        self.assertLessEqual(pl["payloadBytes"], 8192); self.assertEqual(pl["budgetBytes"], 8192)


if __name__ == "__main__":
    unittest.main(verbosity=2)
