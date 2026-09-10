# hardening:allow-file ALL reason=fixtures reproduce the real forked anchor stream read from HIVE mainnet
"""Tests for fork watch, pinned to the real HIVE mainnet anchor stream."""

import json
import unittest

from jumpper import forkwatch as FW

R1 = "d7220b5e9ecc953e7e8ddf0b" + "0" * 40
R2 = "84ae0a0a08ef2f44becc99e4" + "0" * 40
R3 = "74b29867195898f6691ce331" + "0" * 40

def a(idx, ts, height, root, epoch=None, auth="posting", n=248):
    return FW.Anchor(index=idx, timestamp=ts, height=height, root=root,
                     epoch=epoch, authority=auth, payload_bytes=n)

def row(idx, ts, aid, height, root, posting=False, epoch=None):
    body = {"protocol": "saos-dex/v1", "action": "chain-seal",
            "height": height, "stateRoot": root}
    if epoch is not None:
        body["epoch"] = epoch
    op = ["custom_json", {"required_auths": [] if posting else ["headcorner"],
                          "required_posting_auths": ["headcorner"] if posting else [],
                          "id": aid, "json": json.dumps(body)}]
    return [idx, {"timestamp": ts, "block": 109800000 + idx, "trx_id": "t" + str(idx), "op": op}]


class TestForkDetection(unittest.TestCase):
    def test_the_real_height_1764_case(self):
        s = [a(49833, "2026-09-09T18:27:21", 1764, R1), a(49834, "2026-09-09T18:27:51", 1764, R2)]
        f = FW.detect_forks(s)
        self.assertEqual(len(f), 1); self.assertEqual(f[0].severity, "critical")
        self.assertEqual(f[0].span_seconds, 30); self.assertEqual(len(f[0].roots), 2)

    def test_same_root_repeated_is_not_a_fork(self):
        self.assertEqual(FW.detect_forks([a(1, "2026-09-09T18:27:21", 10, R1), a(2, "2026-09-09T18:27:51", 10, R1)]), [])

    def test_three_roots_on_one_height(self):
        s = [a(1, "2026-09-07T21:57:33", 552, R1), a(2, "2026-09-07T22:02:12", 552, R2), a(3, "2026-09-07T22:04:36", 552, R3)]
        f = FW.detect_forks(s); self.assertEqual(len(f[0].roots), 3); self.assertEqual(f[0].severity, "high")

    def test_severity_scales_with_the_span(self):
        for ts2, want in (("2026-09-09T18:32:00", "critical"), ("2026-09-09T20:00:00", "high"), ("2026-09-12T18:27:21", "medium")):
            f = FW.detect_forks([a(1, "2026-09-09T18:27:21", 5, R1), a(2, ts2, 5, R2)])
            self.assertEqual(f[0].severity, want, ts2)

    def test_an_epoch_makes_the_same_height_legitimate(self):
        s = [a(1, "2026-09-09T18:27:21", 12, R1, epoch="A"), a(2, "2026-09-09T18:27:51", 12, R2, epoch="B")]
        self.assertEqual(FW.detect_forks(s), [])

    def test_a_fork_within_one_epoch_is_still_a_fork(self):
        s = [a(1, "2026-09-09T18:27:21", 12, R1, epoch="A"), a(2, "2026-09-09T18:27:51", 12, R2, epoch="A")]
        self.assertEqual(len(FW.detect_forks(s)), 1)

    def test_anchors_without_a_root_are_ignored(self):
        self.assertEqual(FW.detect_forks([a(1, "2026-09-09T18:27:21", 5, None)]), [])


class TestResetDetection(unittest.TestCase):
    def test_a_restart_is_a_reset(self):
        r = FW.detect_resets([a(1, "2026-09-09T18:00:00", 14304, R1), a(2, "2026-09-09T18:21:39", 4920, R2)])
        self.assertEqual(len(r), 1); self.assertEqual(r[0]["kind"], "reset")

    def test_a_repeat_is_distinguished_from_a_reset(self):
        self.assertEqual(FW.detect_resets([a(1, "2026-09-09T18:00:00", 552, R1), a(2, "2026-09-09T18:02:00", 552, R2)])[0]["kind"], "repeat")

    def test_monotonic_growth_has_no_resets(self):
        self.assertEqual(FW.detect_resets([a(i, "2026-09-09T18:00:00", 12 * i, R1) for i in range(1, 20)]), [])

    def test_resets_are_scoped_to_one_epoch(self):
        s = [a(1, "2026-09-09T18:00:00", 500, R1, epoch="A"), a(2, "2026-09-09T19:00:00", 12, R2, epoch="B")]
        self.assertEqual(FW.detect_resets(s), [])


class TestAudit(unittest.TestCase):
    def test_the_verdict_names_the_forks(self):
        s = [a(49833, "2026-09-09T18:27:21", 1764, R1), a(49834, "2026-09-09T18:27:51", 1764, R2), a(49835, "2026-09-09T18:30:00", 1776, R3)]
        r = FW.audit(s)
        self.assertIn("FORKED", r["verdict"])
        self.assertEqual(r["heightsWithMultipleRoots"], 1); self.assertEqual(r["criticalForks"], 1)
        self.assertEqual(r["anchors"], 3); self.assertEqual(r["distinctHeights"], 2)

    def test_a_clean_stream_says_so(self):
        self.assertEqual(FW.audit([a(i, "2026-09-09T18:00:00", 12 * i, R1) for i in range(1, 10)])["verdict"], "no contradictions found")

    def test_budget_utilisation_is_reported(self):
        r = FW.audit([a(1, "2026-09-09T18:00:00", 12, R1, n=248)])
        self.assertEqual(r["avgPayloadBytes"], 248.0); self.assertAlmostEqual(r["budgetUsedPct"], 3.03, delta=0.05)

    def test_authority_mix_is_reported(self):
        s = [a(1, "2026-09-09T18:00:00", 12, R1, auth="active"), a(2, "2026-09-09T18:01:00", 24, R2, auth="posting")]
        self.assertEqual(FW.audit(s)["authorityCounts"], {"active": 1, "posting": 1})

    def test_epoch_namespacing_is_reported_as_absent(self):
        r = FW.audit([a(1, "2026-09-09T18:00:00", 12, R1)])
        self.assertFalse(r["epochNamespaced"]); self.assertEqual(r["epochs"], [])

    def test_an_empty_stream_is_refused(self):
        with self.assertRaises(FW.ForkWatchError): FW.audit([])


class TestHistoryParsing(unittest.TestCase):
    def test_it_extracts_only_the_requested_protocol(self):
        hist = [row(1, "2026-09-09T18:27:21", "saos-dex.anchor.v1", 1764, R1),
                row(2, "2026-09-09T18:28:00", "saos.weave.v1", 5, R2)]
        out = FW.parse_history(hist, "saos-dex.anchor.v1")
        self.assertEqual(len(out), 1); self.assertEqual(out[0].height, 1764)
        self.assertEqual(out[0].root, R1); self.assertEqual(out[0].authority, "active")
        self.assertGreater(out[0].payload_bytes, 100)

    def test_posting_authority_is_detected(self):
        self.assertEqual(FW.parse_history([row(1, "t", "x", 1, R1, posting=True)], "x")[0].authority, "posting")

    def test_epoch_is_carried_through_when_present(self):
        self.assertEqual(FW.parse_history([row(1, "t", "x", 1, R1, epoch="proc-7")], "x")[0].epoch, "proc-7")

    def test_malformed_rows_are_skipped_not_fatal(self):
        self.assertEqual(FW.parse_history([[], [1], [1, "x"], [1, {}]], "z"), [])

    def test_unparseable_json_is_skipped(self):
        r = row(1, "t", "x", 1, R1); r[1]["op"][1]["json"] = "not json"
        self.assertEqual(FW.parse_history([r], "x"), [])

    def test_empty_history(self):
        self.assertEqual(FW.parse_history([], "x"), []); self.assertEqual(FW.parse_history(None, "x"), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
