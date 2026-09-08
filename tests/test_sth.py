"""Tests for Signed Tree Head anchoring and the two Merkle conventions.

The convention table below is MEASURED, not taken from a docstring. An earlier
revision of docs/THE-MISSING-LINK.md claimed the jumpper and roshpina kernel
conventions matched; that was read off a comment and was wrong. These tests pin
the real relationship so it cannot be assumed again.
"""

import hashlib
import unittest

from jumpper import merkle as MK
from jumpper import sth as S


def lh(s):
    return hashlib.sha256(s.encode()).hexdigest()


def leaves(n):
    return [lh("k-%d-%d" % (n, i)) for i in range(n)]


class TestConventionDivergence(unittest.TestCase):
    """The two implementations agree only when every tree level is even."""

    def test_agree_for_one_two_and_powers_of_two(self):
        for n in (1, 2, 4, 8, 16, 64, 256):
            lv = leaves(n)
            self.assertEqual(S.root_duplicate(lv), S.root_self_pair(lv), "n=%d" % n)

    def test_differ_for_every_other_count(self):
        for n in (3, 5, 6, 7, 9, 10, 11, 12, 13, 14, 15, 17, 100, 255):
            lv = leaves(n)
            self.assertNotEqual(S.root_duplicate(lv), S.root_self_pair(lv), "n=%d" % n)

    def test_predicate_matches_measurement_for_n_1_to_64(self):
        for n in range(1, 65):
            lv = leaves(n)
            agree = S.root_duplicate(lv) == S.root_self_pair(lv)
            self.assertEqual(agree, S.conventions_agree(n), "n=%d" % n)

    def test_predicate_is_power_of_two_or_trivial(self):
        for n in range(1, 200):
            self.assertEqual(S.conventions_agree(n), n in (1, 2) or (n & (n - 1)) == 0)

    def test_unknown_convention_is_refused_not_guessed(self):
        with self.assertRaises(S.SthError):
            S.root_for_convention(leaves(3), "bogus")
        with self.assertRaises(S.SthError):
            S.root_for_convention(leaves(3), "")

    def test_dispatcher_selects_the_right_rule(self):
        lv = leaves(5)
        self.assertEqual(S.root_for_convention(lv, S.CONV_SELFPAIR), S.root_self_pair(lv))
        self.assertEqual(S.root_for_convention(lv, S.CONV_DUPLICATE), MK.root(lv))

    def test_duplicate_never_rehashes_the_last_node(self):
        lv = leaves(3)
        self.assertEqual(MK.build(lv)[1][-1], lv[-1])

    def test_self_pair_does_rehash_the_last_node(self):
        lv = leaves(3)
        self.assertNotEqual(S.root_self_pair(lv), MK.root(lv))

    def test_both_reject_empty(self):
        with self.assertRaises(S.SthError):
            S.root_self_pair([])
        with self.assertRaises(ValueError):
            S.root_duplicate([])


class TestSignedTreeHead(unittest.TestCase):
    def make(self, log="tenant-a", size=1000, root="ab" * 32, conv=S.CONV_SELFPAIR):
        return S.SignedTreeHead(log_id=log, tree_size=size, root=root,
                                timestamp="2026-09-08T00:00:00Z", convention=conv)

    def test_rejects_bad_root(self):
        for bad in ("ab" * 31, "AB" * 32, "zz" * 32, ""):
            with self.assertRaises(S.SthError):
                self.make(root=bad)

    def test_rejects_negative_tree_size(self):
        with self.assertRaises(S.SthError):
            self.make(size=-1)

    def test_rejects_unknown_convention(self):
        with self.assertRaises(S.SthError):
            self.make(conv="rfc6962-maybe")

    def test_digest_depends_on_convention(self):
        a = self.make(conv=S.CONV_SELFPAIR).digest()
        b = self.make(conv=S.CONV_DUPLICATE).digest()
        self.assertNotEqual(a, b)
        self.assertEqual(len(a), 64)

    def test_as_dict_exposes_convention(self):
        d = self.make().as_dict()
        self.assertEqual(d["convention"], S.CONV_SELFPAIR)
        self.assertEqual(d["treeSize"], 1000)


class TestCompactEncoding(unittest.TestCase):
    def heads(self, n=5, log="tenant-a", conv=S.CONV_SELFPAIR):
        return [S.SignedTreeHead(log, 1000 + i, ("ab" if i % 2 else "cd") * 32,
                                 "2026-09-08T00:00:00Z", convention=conv) for i in range(n)]

    def test_roundtrip_is_exact(self):
        h = self.heads()
        rt = S.decode_heads(S.encode_heads(h))
        self.assertEqual([(x.tree_size, x.root, x.log_id, x.convention) for x in rt],
                         [(x.tree_size, x.root, x.log_id, x.convention) for x in h])

    def test_roundtrip_both_conventions(self):
        for conv in S.CONVENTIONS:
            h = self.heads(conv=conv)
            self.assertEqual(S.decode_heads(S.encode_heads(h))[0].convention, conv)

    def test_one_log_per_batch(self):
        mixed = self.heads(2, "a") + self.heads(2, "b")
        with self.assertRaises(S.SthError):
            S.encode_heads(mixed)

    def test_one_convention_per_batch(self):
        mixed = self.heads(2, conv=S.CONV_SELFPAIR) + self.heads(2, conv=S.CONV_DUPLICATE)
        with self.assertRaises(S.SthError):
            S.encode_heads(mixed)

    def test_rejects_empty_and_malformed(self):
        with self.assertRaises(S.SthError):
            S.encode_heads([])
        for bad in ("", "2|a|self-pair", "9|a|self-pair|1:x", "2||self-pair|1:ab",
                    "2|a|bogus|1:ab", "2|a|self-pair|1:!!!"):
            with self.assertRaises(S.SthError):
                S.decode_heads(bad)

    def test_compact_form_fits_many_heads_per_operation(self):
        sample = self.heads(1)[0]
        n = S.heads_per_operation(sample)
        self.assertGreater(n, 150)
        self.assertLessEqual(S.encoded_size(self.heads(n)), 8192)
        with self.assertRaises(S.SthError):
            S.encode_heads(self.heads(n + 1))

    def test_capacity_estimate_is_not_optimistic(self):
        """Regression: probing with tree_size=1 over-estimated capacity and
        produced a payload that could never be broadcast."""
        for size in (1, 999, 1000, 99999, 10 ** 9):
            for conv in S.CONVENTIONS:
                sample = S.SignedTreeHead("tenant-a", size, "ab" * 32,
                                          "2026-09-08T00:00:00Z", convention=conv)
                n = S.heads_per_operation(sample)
                self.assertLessEqual(S.encoded_size([sample] * n), 8192,
                                     "size=%d conv=%s n=%d" % (size, conv, n))

    def test_capacity_shrinks_with_wider_tree_size(self):
        small = S.SignedTreeHead("tenant-a", 1, "ab" * 32, "t", convention=S.CONV_SELFPAIR)
        wide = S.SignedTreeHead("tenant-a", 10 ** 9, "ab" * 32, "t", convention=S.CONV_SELFPAIR)
        self.assertGreater(S.heads_per_operation(small), S.heads_per_operation(wide))

    def test_encoded_size_is_linear_in_head_count(self):
        s1 = S.encoded_size(self.heads(1))
        s10 = S.encoded_size(self.heads(10))
        self.assertLess((s10 - s1) / 9, 60)


class TestAnchorOperation(unittest.TestCase):
    def heads(self, n=5):
        return [S.SignedTreeHead("tenant-a", 1000 + i, "ab" * 32,
                                 "2026-09-08T00:00:00Z", convention=S.CONV_SELFPAIR)
                for i in range(n)]

    def test_uses_posting_not_active(self):
        op = S.build_anchor_op("headcorner", self.heads())
        self.assertEqual(op[0], "custom_json")
        self.assertEqual(op[1]["required_posting_auths"], ["headcorner"])
        self.assertEqual(op[1]["required_auths"], [])
        self.assertEqual(op[1]["id"], S.ANCHOR_ID)

    def test_carries_no_fee_field(self):
        op = S.build_anchor_op("headcorner", self.heads())
        self.assertNotIn("fee", op[1])
        self.assertNotIn("amount", op[1])

    def test_plan_never_signs(self):
        p = S.plan_anchor("headcorner", self.heads())
        self.assertEqual(p["fee"], 0)
        self.assertEqual(p["authority"], "posting")
        self.assertEqual(p["signing"], "external-only")
        self.assertEqual(p["headCount"], 5)
        self.assertEqual(p["op"][1]["signatures"] if "signatures" in p["op"][1] else None, None)
        self.assertEqual(len(p["payloadDigest"]), 64)

    def test_payload_digest_is_stable(self):
        h = self.heads()
        self.assertEqual(S.plan_anchor("a", h)["payloadDigest"], S.plan_anchor("a", h)["payloadDigest"])

    def test_verify_against_chain_matches_and_rejects(self):
        h = self.heads(3)
        payload = S.encode_heads(h)
        blob = ('{"protocol":"saos-jumpper/v1","action":"sth-anchor","sth":%s}'
                % __import__("json").dumps(payload))
        hexdata = "0x" + blob.encode().hex()
        good = S.verify_against_chain(hexdata, h)
        self.assertTrue(good["match"], good)
        bad = S.verify_against_chain(hexdata, self.heads(4))
        self.assertFalse(bad["match"])
        self.assertEqual(bad["reason"], "head-mismatch")

    def test_verify_reports_decode_failures_honestly(self):
        r = S.verify_against_chain("0xzz", self.heads(1))
        self.assertFalse(r["match"])
        self.assertEqual(r["reason"], "calldata-decode-failed")
        blob = '{"protocol":"x"}'
        r2 = S.verify_against_chain("0x" + blob.encode().hex(), self.heads(1))
        self.assertFalse(r2["match"])
        self.assertEqual(r2["reason"], "no-sth-field")


if __name__ == "__main__":
    unittest.main(verbosity=2)
