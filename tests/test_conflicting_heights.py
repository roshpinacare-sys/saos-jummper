# hardening:allow-file ALL reason=fixtures reproduce the real conflicting-height defect measured on HIVE mainnet 2026-09-10
"""Tests for conflicting_height_audit.

Fixtures reproduce the real defect measured on HIVE mainnet: heights 1476, 1668
and 1764 each carried two different state roots, and the counter reset 4488 to 12
with no epoch field in any payload."""

import json
import unittest

from jumpper import liveops as LO

R_A = "d7220b5e9ecc953e7e8ddf0b682b7e15384e8ec0bc46bb22e145d74bcba9f2db"
R_B = "84ae0a0a08ef2f44becc99e40f9995e6fe82d9931ed6e2412b23ca999f86b90d"
R_C = "74b29867195898f6691ce331cbdbcd3fed35ed8a74e1cc63fb6f4fa2ce6765b5"
R_D = "e375e0f5d7fe98c69ea720d0f96e9fb2146e6c352b87e8b0f9a4f1ceb53d9631"

def anchor(idx, ts, blk, trx, height, root, extra=None):
    payload = {"protocol": "saos-dex/v1", "action": "chain-seal", "height": height,
               "stateRoot": root, "digest": root[:64]}
    if extra: payload.update(extra)
    return {"op": "custom_json", "index": idx, "timestamp": ts, "block": blk, "trx_id": trx,
            "data": {"id": "saos-dex.anchor.v1", "json": json.dumps(payload)},
            "serialised_bytes": 249}

def real_defect():
    return [
        anchor(49824, "2026-09-09T18:19:18", 109770341, "fcf8d68b", 1668, R_C),
        anchor(49825, "2026-09-09T18:22:36", 109770407, "bd8ffe25", 1668, R_D),
        anchor(49833, "2026-09-09T18:27:21", 109770502, "0825c6b3", 1764, R_A),
        anchor(49834, "2026-09-09T18:27:51", 109770512, "9029171e", 1764, R_B),
        anchor(49861, "2026-09-09T20:54:30", 109774000, "aa11bb22", 4488, R_A),
        anchor(49862, "2026-09-09T22:10:06", 109775000, "cc33dd44", 12, R_B),
    ]


class TestTheRealDefect(unittest.TestCase):
    def setUp(self):
        self.r = LO.conflicting_height_audit(real_defect(), ["saos-dex.anchor.v1"])

    def test_two_conflicting_heights_are_found(self):
        self.assertEqual(self.r["conflictingHeights"], 2)
        self.assertEqual(sorted(c["height"] for c in self.r["conflicts"]), [1668, 1764])

    def test_severity_is_critical(self):
        self.assertEqual(self.r["severity"], "critical")

    def test_the_counter_reset_is_reported_with_no_epoch(self):
        self.assertEqual(len(self.r["resets"]), 1)
        rs = self.r["resets"][0]
        self.assertEqual(rs["fromHeight"], 4488); self.assertEqual(rs["toHeight"], 12)
        self.assertFalse(rs["hasEpochField"])
        self.assertFalse(self.r["anyEpochFieldPresent"])

    def test_the_1764_pair_is_30_seconds_apart_with_different_blocks(self):
        c = [x for x in self.r["conflicts"] if x["height"] == 1764][0]
        a, b = c["records"]
        self.assertEqual(a["timestamp"], "2026-09-09T18:27:21")
        self.assertEqual(b["timestamp"], "2026-09-09T18:27:51")
        self.assertEqual(a["block"], 109770502); self.assertEqual(b["block"], 109770512)
        self.assertNotEqual(a["trx"], b["trx"])
        self.assertEqual(c["distinctRoots"], 2)

    def test_verdict_names_the_missing_epoch_field(self):
        self.assertIn("epoch field ABSENT", self.r["verdict"])

    def test_records_are_ordered_by_time(self):
        for c in self.r["conflicts"]:
            ts = [x["timestamp"] for x in c["records"]]
            self.assertEqual(ts, sorted(ts))


class TestDetectorSemantics(unittest.TestCase):
    def test_a_clean_log_reports_clean(self):
        good = [anchor(1, '2026-01-01T00:00:00', 1, 't1', 1, R_A),
                anchor(2, '2026-01-01T00:01:00', 2, 't2', 2, R_B)]
        r = LO.conflicting_height_audit(good, ["saos-dex.anchor.v1"])
        self.assertEqual(r["conflictingHeights"], 0); self.assertEqual(r["severity"], "none")
        self.assertIn("clean", r["verdict"])

    def test_the_same_root_twice_is_a_duplicate_not_a_conflict(self):
        dup = [anchor(1, '2026-01-01T00:00:00', 1, 't1', 1, R_A),
               anchor(2, '2026-01-01T00:01:00', 2, 't2', 1, R_A)]
        r = LO.conflicting_height_audit(dup, ["saos-dex.anchor.v1"])
        self.assertEqual(r["conflictingHeights"], 0); self.assertEqual(r["distinctHeights"], 1)

    def test_an_epoch_field_downgrades_critical_to_high(self):
        ep = [anchor(1, '2026-01-01T00:00:00', 1, 't1', 1, R_A, {'epoch': 'e1'}),
              anchor(2, '2026-01-01T00:01:00', 2, 't2', 1, R_B, {'epoch': 'e2'})]
        r = LO.conflicting_height_audit(ep, ["saos-dex.anchor.v1"])
        self.assertEqual(r["conflictingHeights"], 1)
        self.assertFalse(r["conflicts"][0]["sameEpoch"])
        self.assertIn("epoch boundary", r["conflicts"][0]["verdict"])
        self.assertEqual(r["severity"], "high")
        self.assertTrue(r["anyEpochFieldPresent"])

    def test_other_protocol_ids_are_ignored(self):
        r = LO.conflicting_height_audit(real_defect(), ["does-not-exist"])
        self.assertEqual(r["anchorsExamined"], 0); self.assertEqual(r["severity"], "none")

    def test_seq_is_accepted_as_a_height_field(self):
        sq = [{'op': 'custom_json', 'index': 1, 'timestamp': 't1', 'block': 1, 'trx_id': 'a',
               'data': {'id': 'w.v1', 'json': json.dumps({'seq': 1, 'root': R_A})}, 'serialised_bytes': 1},
              {'op': 'custom_json', 'index': 2, 'timestamp': 't2', 'block': 2, 'trx_id': 'b',
               'data': {'id': 'w.v1', 'json': json.dumps({'seq': 1, 'root': R_B})}, 'serialised_bytes': 1}]
        r = LO.conflicting_height_audit(sq, ["w.v1"])
        self.assertEqual(r["conflictingHeights"], 1)

    def test_malformed_json_is_skipped_not_fatal(self):
        bad = [{'op': 'custom_json', 'index': 1, 'timestamp': 't', 'block': 1, 'trx_id': 'x',
                'data': {'id': 'saos-dex.anchor.v1', 'json': '{not json'}, 'serialised_bytes': 1}]
        self.assertEqual(LO.conflicting_height_audit(bad, ["saos-dex.anchor.v1"])["anchorsExamined"], 0)

    def test_a_record_without_a_root_is_skipped(self):
        nr = [{'op': 'custom_json', 'index': 1, 'timestamp': 't', 'block': 1, 'trx_id': 'x',
               'data': {'id': 'saos-dex.anchor.v1', 'json': json.dumps({'height': 1})}, 'serialised_bytes': 1}]
        self.assertEqual(LO.conflicting_height_audit(nr, ["saos-dex.anchor.v1"])["anchorsExamined"], 0)

    def test_non_custom_json_ops_are_ignored(self):
        other = [{'op': 'transfer', 'index': 1, 'timestamp': 't', 'block': 1, 'trx_id': 'x',
                  'data': {'amount': '1 HIVE'}, 'serialised_bytes': 1}]
        self.assertEqual(LO.conflicting_height_audit(other, ["saos-dex.anchor.v1"])["anchorsExamined"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
