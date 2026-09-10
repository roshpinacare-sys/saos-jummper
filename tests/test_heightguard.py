# hardening:allow-file ALL reason=fixtures reproduce the eight real on-chain height collisions
"""Tests for the height guard, pinned to the real forked anchor stream.

Measured from 162 saos-dex.anchor.v1 operations by headcorner on HIVE mainnet,
500 history entries spanning 2026-09-03T02:58:06 to 2026-09-10T18:03:06:
153 distinct heights, 8 carrying contradictory roots, 6 counter resets,
4 repeats, and no epoch field in any payload."""

import unittest

from jumpper import heightguard as HG

R1 = "d7220b5e9ecc953e7e8ddf0b0000000000000000000000000000000000000001"
R2 = "84ae0a0a08ef2f44becc99e40000000000000000000000000000000000000002"
R3 = "647ac665dceb6b32910da2f30000000000000000000000000000000000000003"

def c(epoch, height, root, ts, block=None, tx=None):
    return HG.Commitment(epoch=epoch, height=height, root=root, timestamp=ts,
                         block=block, tx_id=tx)

H1764 = [c("", 1764, R1, "2026-09-09T18:27:21", 109770502, "49833"),
         c("", 1764, R2, "2026-09-09T18:27:51", 109770512, "49834")]

H552 = [c("", 552, R1, "2026-09-07T21:57:33", 109717232, "49715"),
        c("", 552, R2, "2026-09-07T22:02:12", 109717324, "49716"),
        c("", 552, R3, "2026-09-07T22:04:36", 109717372, "49717")]

CLEAN = [c("e1", 10, R1, "2026-09-09T10:00:00"), c("e1", 11, R2, "2026-09-09T10:01:00"),
         c("e2", 10, R3, "2026-09-09T11:00:00")]


class TestTheRealForksAreDetected(unittest.TestCase):
    def test_the_height_1764_collision(self):
        r = HG.audit(H1764)
        self.assertIn("FORKED", r["verdict"]); self.assertEqual(r["forks"], 1)
        f = r["forkDetails"][0]
        self.assertEqual(f["height"], 1764); self.assertEqual(f["distinctRoots"], 2)
        self.assertEqual(f["firstAt"], "2026-09-09T18:27:21")
        self.assertEqual(f["lastAt"], "2026-09-09T18:27:51")

    def test_the_three_root_height_552(self):
        f = HG.audit(H552)["forkDetails"][0]
        self.assertEqual(f["distinctRoots"], 3); self.assertEqual(f["anchors"], 3)

    def test_records_carry_blocks_and_txids_so_a_verifier_can_follow(self):
        rec = HG.audit(H1764)["forkDetails"][0]["records"]
        self.assertEqual([x["block"] for x in rec], [109770502, 109770512])
        self.assertEqual([x["txId"] for x in rec], ["49833", "49834"])

    def test_no_epoch_is_reported_as_a_finding(self):
        r = HG.audit(H1764)
        self.assertFalse(r["epochPresent"])
        self.assertIn("collide with committed roots", r["epochAdvice"])

    def test_a_clean_stream_with_epochs_says_so(self):
        r = HG.audit(CLEAN)
        self.assertIn("CLEAN", r["verdict"]); self.assertEqual(r["forks"], 0)
        self.assertTrue(r["epochPresent"]); self.assertIsNone(r["epochAdvice"])


class TestTheGuardRefusesContradiction(unittest.TestCase):
    def test_a_first_commitment_is_allowed(self):
        self.assertEqual(HG.HeightLedger().check("", 1764, R1)["decision"], HG.ALLOW)

    def test_a_contradicting_root_at_the_same_key_is_refused(self):
        led = HG.HeightLedger(); led.add(H1764[0]); v = led.check("", 1764, R2)
        self.assertEqual(v["decision"], HG.REFUSE)
        self.assertEqual(v["conflictingCount"], 1)
        self.assertIn("permanent public contradiction", v["reason"])
        self.assertEqual(v["conflicts"][0]["block"], 109770502)

    def test_republishing_the_same_root_is_idempotent(self):
        led = HG.HeightLedger(); led.add(H1764[0])
        self.assertEqual(led.check("", 1764, R1)["decision"], HG.REPUBLISH)

    def test_an_epoch_makes_the_same_height_legitimate(self):
        led = HG.HeightLedger(); led.add(H1764[0])
        self.assertEqual(led.check("e2", 1764, R2)["decision"], HG.ALLOW)

    def test_a_missing_epoch_is_allowed_but_flagged(self):
        v = HG.HeightLedger().check("", 999, R1)
        self.assertEqual(v["decision"], HG.ALLOW); self.assertTrue(v["missingEpoch"])
        self.assertIn("will collide with this height", v["reason"])

    def test_an_epoch_supplied_clears_the_flag(self):
        self.assertFalse(HG.HeightLedger().check("e1", 999, R1)["missingEpoch"])

    def test_a_fork_inside_one_epoch_is_still_a_fork(self):
        led = HG.HeightLedger(); led.add(c("e1", 12, R1, "t1"))
        self.assertEqual(led.check("e1", 12, R2)["decision"], HG.REFUSE)

    def test_malformed_inputs_are_refused(self):
        led = HG.HeightLedger()
        with self.assertRaises(HG.HeightGuardError): led.check("", "x", R1)
        with self.assertRaises(HG.HeightGuardError): led.check("", 1, "short")
        with self.assertRaises(HG.HeightGuardError): led.check("", True, R1)
        with self.assertRaises(HG.HeightGuardError): led.add(c("", 1, "short", "t"))


class TestResets(unittest.TestCase):
    def test_a_restart_is_a_reset(self):
        s = sorted([c("e1", 1416, R1, "2026-09-07T14:42:57"), c("e1", 552, R2, "2026-09-07T21:57:33")], key=lambda x: x.timestamp)
        r = HG.HeightLedger().resets(s)
        self.assertEqual(len(r), 1); self.assertEqual(r[0]["from"], 1416)
        self.assertEqual(r[0]["to"], 552); self.assertEqual(r[0]["drop"], 864)

    def test_a_repeat_is_distinguished_from_a_reset(self):
        r = HG.HeightLedger().resets([c("e1", 552, R1, "t1"), c("e1", 552, R2, "t2")])
        self.assertTrue(r[0].get("repeat")); self.assertEqual(r[0]["drop"], 0)

    def test_monotonic_growth_has_no_resets(self):
        self.assertEqual(HG.HeightLedger().resets([c("e1", i, R1, "t%d" % i) for i in range(1, 6)]), [])

    def test_resets_are_scoped_to_one_epoch(self):
        self.assertEqual(HG.HeightLedger().resets([c("e1", 500, R1, "t1"), c("e2", 10, R2, "t2")]), [])


class TestAuditSemantics(unittest.TestCase):
    def test_an_empty_stream_is_refused(self):
        with self.assertRaises(HG.HeightGuardError): HG.audit([])

    def test_the_verdict_names_the_count(self):
        r = HG.audit(H1764 + H552)
        self.assertEqual(r["forks"], 2); self.assertIn("2 height", r["verdict"])

    def test_resets_and_repeats_are_counted_separately(self):
        r = HG.audit([c("e1", 100, R1, "t1"), c("e1", 100, R2, "t2"), c("e1", 5, R3, "t3")])
        self.assertEqual(r["repeats"], 1); self.assertEqual(r["resets"], 1)

class TestRemediationReport(unittest.TestCase):
    """The report must not invent a canonical root the chain cannot support."""


    def test_forks_are_ambiguous_with_no_canonical_root(self):
        r = HG.remediation_report(H1764 + H552)
        self.assertEqual(r["forkedHeights"], 2)
        for e in r["entries"]:
            self.assertEqual(e["status"], "AMBIGUOUS"); self.assertIsNone(e["canonicalRoot"])


    def test_tightest_window_comes_first(self):
        r = HG.remediation_report(H1764 + H552)
        wins = [e["windowSeconds"] for e in r["entries"]]
        self.assertEqual(wins, sorted(wins))
        self.assertEqual(r["entries"][0]["height"], 1764)
        self.assertEqual(r["entries"][0]["windowSeconds"], 30)


    def test_the_real_windows_are_reproduced(self):
        e = [x for x in HG.remediation_report(H552)["entries"] if x["height"] == 552][0]
        self.assertEqual(e["windowSeconds"], 423); self.assertEqual(e["distinctRoots"], 3)


    def test_records_carry_block_and_txid(self):
        e = HG.remediation_report(H1764)["entries"][0]
        self.assertEqual([x["block"] for x in e["records"]], [109770502, 109770512])
        self.assertEqual([x["txId"] for x in e["records"]], ["49833", "49834"])


    def test_epoch_absence_and_counters(self):
        r = HG.remediation_report(H1764)
        self.assertFalse(r["epochPresent"]); self.assertEqual(r["counterResets"], 0)
        self.assertEqual(r["counterRepeats"], 1)


    def test_a_clean_stream_reports_zero_forks(self):
        r = HG.remediation_report(CLEAN)
        self.assertEqual(r["forkedHeights"], 0); self.assertTrue(r["epochPresent"])


    def test_the_remedy_names_the_epoch_and_the_check(self):
        m = " ".join(HG.remediation_report(H1764)["remedy"])
        self.assertIn("epoch", m); self.assertIn("HeightLedger.check()", m)
        self.assertIn("do not delete", m.lower())


    def test_the_resolution_says_the_chain_cannot_decide(self):
        self.assertIn("cannot decide", HG.remediation_report(H1764)["entries"][0]["resolution"])


    def test_an_empty_stream_is_refused(self):
        with self.assertRaises(HG.HeightGuardError): HG.remediation_report([])


    def test_resets_and_repeats_are_counted_separately(self):
        s = [c("e1", 1416, R1, "2026-09-07T14:42:57"), c("e1", 552, R2, "2026-09-07T21:57:33"),
             c("e1", 552, R3, "2026-09-07T22:04:36")]
        r = HG.remediation_report(s)
        self.assertEqual(r["counterResets"], 1); self.assertEqual(r["counterRepeats"], 1)
        self.assertEqual(r["forkedHeights"], 1)


    def test_span_seconds_handles_unusable_timestamps(self):
        self.assertIsNone(HG._span_seconds(None, "2026-09-09T18:27:51"))
        self.assertIsNone(HG._span_seconds("not-a-date", "2026-09-09T18:27:51"))
        self.assertEqual(HG._span_seconds("2026-09-09T18:27:21", "2026-09-09T18:27:51"), 30)





if __name__ == "__main__":
    unittest.main(verbosity=2)
