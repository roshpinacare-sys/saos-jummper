# hardening:allow-file ALL reason=fixtures are the real fork record and the real correction operation
"""Tests for the correction decoder, against the real 831-byte artifact."""

import json
import os
import unittest

from jumpper import remedy as RM

HERE = os.path.dirname(os.path.abspath(__file__))
FORKS = json.load(open(os.path.join(HERE, "fixtures_forks.json")))
OP = json.load(open(os.path.join(HERE, "fixtures_op.json")))
PAYLOAD = OP["operation"][1]["json"]

R1 = "a54a51c7524dabc41d09d859f5d642aa836947482ef30467aef6e5a3f66416d0"
R2 = "d93e5a50d5e731ca81555b6bfc5dfd7fbc07e9b6e21357ca330e27dd9d3ea05d"
R3 = "6d4c4a120df44afb530180f78688cc15fffa66688e20ef80675710fad8f30843"


class TestRoundTripOnTheRealArtifact(unittest.TestCase):
    def test_the_real_payload_decodes(self):
        d = RM.decode_corrections(PAYLOAD)
        self.assertEqual(d["version"], 1)
        self.assertEqual(d["logId"], "saos-dex.anchor.v1")
        self.assertEqual(d["status"], "AMBIGUOUS")

    def test_all_eight_heights_and_seventeen_roots_survive(self):
        d = RM.decode_corrections(PAYLOAD)
        self.assertEqual(d["count"], 8)
        self.assertEqual(d["totalRoots"], 17)
        self.assertEqual(d["heights"], [12, 552, 1224, 1392, 1416, 1476, 1668, 1764])

    def test_re_encoding_is_byte_identical(self):
        d = RM.decode_corrections(PAYLOAD)
        self.assertEqual(RM.encode_corrections(d["corrections"]), PAYLOAD)

    def test_the_decoded_record_matches_the_source_forks(self):
        d = RM.decode_corrections(PAYLOAD)
        src = RM.corrections_from_report(FORKS)
        self.assertEqual(sorted(c.height for c in src), d["heights"])
        self.assertEqual(sum(len(c.roots) for c in src), d["totalRoots"])
        by = {c.height: sorted(c.roots) for c in src}
        for c in d["corrections"]:
            self.assertEqual(sorted(c.roots), by[c.height], c.height)

    def test_height_552_keeps_all_three_roots(self):
        d = RM.decode_corrections(PAYLOAD)
        c = [x for x in d["corrections"] if x.height == 552][0]
        self.assertEqual(len(c.roots), 3)
        self.assertEqual(len(set(c.roots)), 3)

    def test_payload_size_is_reported(self):
        d = RM.decode_corrections(PAYLOAD)
        self.assertEqual(d["payloadBytes"], len(PAYLOAD.encode()))
        self.assertLessEqual(d["payloadBytes"], 8192)


class TestMalformedPayloadsAreRefusedNotPartiallyDecoded(unittest.TestCase):
    def test_empty_and_non_string(self):
        for bad in ("", "   ", None, 42):
            with self.assertRaises(RM.RemedyError): RM.decode_corrections(bad)

    def test_wrong_part_count(self):
        for bad in ("1", "1|a", "1|a|AMBIGUOUS", "1|a|AMBIGUOUS|x|y"):
            with self.assertRaises(RM.RemedyError): RM.decode_corrections(bad)

    def test_bad_version(self):
        with self.assertRaises(RM.RemedyError): RM.decode_corrections("9|a|AMBIGUOUS|1:2:x+y")
        with self.assertRaises(RM.RemedyError): RM.decode_corrections("x|a|AMBIGUOUS|1:2:x+y")

    def test_empty_log_id_and_unknown_status(self):
        with self.assertRaises(RM.RemedyError): RM.decode_corrections("1||AMBIGUOUS|1:2:x+y")
        with self.assertRaises(RM.RemedyError): RM.decode_corrections("1|a|MAYBE|1:2:x+y")

    def test_no_entries(self):
        with self.assertRaises(RM.RemedyError): RM.decode_corrections("1|a|AMBIGUOUS|")

    def test_bad_entry_shape(self):
        good = RM.encode_corrections([RM.Correction("a", 1, RM.AMBIGUOUS, 2, [R1, R2])])
        base = good.rsplit(";", 1)[0] if ";" in good else good
        head = good.split("|")[0] + "|" + good.split("|")[1] + "|" + good.split("|")[2] + "|"
        for bad in ("x:2:" + RM.b64u(R1) + "+" + RM.b64u(R2),
                    "1:x:" + RM.b64u(R1) + "+" + RM.b64u(R2),
                    "1:2",
                    "1:2:3:4"):
            with self.assertRaises(RM.RemedyError): RM.decode_corrections(head + bad)

    def test_declared_count_must_match_the_roots_present(self):
        head = "1|a|AMBIGUOUS|"
        with self.assertRaises(RM.RemedyError):
            RM.decode_corrections(head + "1:3:" + RM.b64u(R1) + "+" + RM.b64u(R2))

    def test_malformed_base64url_is_refused(self):
        with self.assertRaises(RM.RemedyError): RM.decode_corrections("1|a|AMBIGUOUS|1:2:!!!+" + RM.b64u(R2))

    def test_a_root_that_is_not_64_lowercase_hex_is_refused(self):
        import base64 as _b64
        def b64u_raw(raw: bytes) -> str:
            return _b64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
        # 64 characters but not hex - reaches the decoder's own validation rather
        # than failing inside the encoder, which only accepts hex in the first place
        non_hex = b64u_raw(b"z" * 64)
        with self.assertRaises(RM.RemedyError):
            RM.decode_corrections("1|a|AMBIGUOUS|1:2:" + non_hex + "+" + RM.b64u(R2))
        # and a root that decodes to fewer than 64 characters
        short = b64u_raw(b"abc")
        with self.assertRaises(RM.RemedyError):
            RM.decode_corrections("1|a|AMBIGUOUS|1:2:" + short + "+" + RM.b64u(R2))

    def test_ambiguous_with_fewer_than_two_distinct_roots_is_refused(self):
        same = RM.b64u(R1) + "+" + RM.b64u(R1)
        with self.assertRaises(RM.RemedyError):
            RM.decode_corrections("1|a|AMBIGUOUS|1:2:" + same)

    def test_negative_height_is_refused(self):
        with self.assertRaises(RM.RemedyError):
            RM.decode_corrections("1|a|AMBIGUOUS|-1:2:" + RM.b64u(R1) + "+" + RM.b64u(R2))


class TestDecodeAgreesWithEncode(unittest.TestCase):
    def test_a_synthetic_batch_round_trips(self):
        cs = [RM.Correction("log-x", h, RM.AMBIGUOUS, 2, [R1, R2]) for h in (1, 7, 99)]
        pay = RM.encode_corrections(cs)
        d = RM.decode_corrections(pay)
        self.assertEqual(d["heights"], [1, 7, 99])
        self.assertEqual(d["totalRoots"], 6)
        self.assertEqual(RM.encode_corrections(d["corrections"]), pay)

    def test_decoded_corrections_can_be_re_applied(self):
        d = RM.decode_corrections(PAYLOAD)
        anchors = [{"height": c.height, "root": r} for c in d["corrections"] for r in c.roots]
        r = RM.apply_corrections(anchors, d["corrections"])
        self.assertEqual(r["resolvedCount"], 0)
        self.assertEqual(r["ambiguousCount"], 8)
        self.assertEqual(r["unrecordedCount"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
