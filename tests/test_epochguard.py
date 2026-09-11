# hardening:allow-file ALL reason=fixtures are the real non-increasing height sequence read off HIVE mainnet
"""Tests for the epoch lifecycle, against the real height stream.

The sequence below was read out of 173 saos-dex.anchor.v1 anchors on HIVE mainnet
(account headcorner, 2026-09-04 to 2026-09-11). It contains 6 backwards steps and
4 repeats, and it produced 8 heights carrying two or three contradictory roots.
Without an epoch the same sequence collides twice; with one it collides zero times.
"""

import unittest

from jumpper import epochguard as EG
from jumpper import heightguard as HG

REAL = [1416, 552, 552, 552, 12, 2088, 444, 14304, 4920, 23028, 1224, 1392, 1476, 1668, 1764]
R1 = "a54a51c7524dabc41d09d859f5d642aa836947482ef30467aef6e5a3f66416d0"
R2 = "d93e5a50d5e731ca81555b6bfc5dfd7fbc07e9b6e21357ca330e27dd9d3ea05d"
R3 = "6d4c4a120df44afb530180f78688cc15fffa66688e20ef80675710fad8f30843"


class TestTheRealSequenceNoLongerCollides(unittest.TestCase):
    def test_zero_collisions_on_the_real_stream(self):
        r = EG.assign_stream(REAL)
        self.assertEqual(r["totalPairs"], 15)
        self.assertEqual(r["uniquePairs"], 15)
        self.assertEqual(r["collisions"], 0)

    def test_the_same_sequence_without_an_epoch_collides_twice(self):
        bare = [("", h) for h in REAL]
        self.assertEqual(len(bare) - len(set(bare)), 2)

    def test_seven_bumps_for_six_backwards_steps_and_four_repeats(self):
        r = EG.assign_stream(REAL)
        self.assertEqual(r["bumpCount"], 7)
        self.assertEqual(len(r["epochs"]), 8)

    def test_a_monotonic_stream_never_bumps(self):
        r = EG.assign_stream([23028, 23772, 24480, 25212, 25932, 26460, 27072])
        self.assertEqual(r["bumpCount"], 0)
        self.assertEqual(r["collisions"], 0)
        self.assertEqual(len(r["epochs"]), 1)

    def test_every_assignment_carries_a_usable_epoch(self):
        for a in EG.assign_stream(REAL)["assignments"]:
            self.assertTrue(a["epoch"], a)
            self.assertIn(a["action"], (EG.FIRST, EG.CONTINUE, EG.BUMPED))


class TestAssign(unittest.TestCase):
    def test_first_height_is_marked_first(self):
        a = EG.EpochTracker().assign(100)
        self.assertEqual(a["action"], EG.FIRST); self.assertIsNone(a["previousHeight"])

    def test_an_increasing_height_continues_without_bumping(self):
        t = EG.EpochTracker(); t.assign(100)
        a = t.assign(200)
        self.assertEqual(a["action"], EG.CONTINUE); self.assertEqual(a["epoch"], "e0")
        self.assertEqual(a["previousHeight"], 100)

    def test_a_backwards_height_bumps(self):
        t = EG.EpochTracker(); t.assign(1416)
        a = t.assign(552)
        self.assertEqual(a["action"], EG.BUMPED); self.assertEqual(a["epoch"], "e1")
        self.assertEqual(a["epochBefore"], "e0"); self.assertEqual(a["epochAfter"], "e1")
        self.assertIn("backwards", a["reason"])

    def test_a_repeated_height_bumps_too(self):
        t = EG.EpochTracker(); t.assign(552)
        a = t.assign(552)
        self.assertEqual(a["action"], EG.BUMPED); self.assertIn("repeated", a["reason"])

    def test_bumps_are_recorded_for_audit(self):
        t = EG.EpochTracker()
        for h in REAL: t.assign(h)
        self.assertEqual(len(t.bumps), 7)
        self.assertTrue(all("epochBefore" in b and "epochAfter" in b for b in t.bumps))

    def test_bad_heights_are_refused(self):
        for bad in (-1, True, "100", None, 1.5):
            with self.assertRaises(EG.EpochError): EG.EpochTracker().assign(bad)


class TestRestartSurvival(unittest.TestCase):
    def test_state_round_trips(self):
        t = EG.EpochTracker()
        for h in [1416, 552, 2088]: t.assign(h)
        st = t.state(); t2 = EG.EpochTracker.from_state(st)
        self.assertEqual(t2.epoch, t.epoch)
        self.assertEqual(st["epochIndex"], 1); self.assertEqual(st["lastHeight"], 2088)

    def test_a_reloaded_tracker_keeps_bumping(self):
        t = EG.EpochTracker(); t.assign(1764)
        t2 = EG.EpochTracker.from_state(t.state())
        self.assertEqual(t2.assign(1800)["action"], EG.CONTINUE)
        self.assertEqual(t2.assign(50)["action"], EG.BUMPED)
        self.assertEqual(t2.epoch, "e1")

    def test_a_reloaded_tracker_does_not_reuse_an_epoch(self):
        t = EG.EpochTracker()
        for h in REAL: t.assign(h)
        t2 = EG.EpochTracker.from_state(t.state())
        self.assertNotEqual(t2.assign(12)["epoch"], "e0")

    def test_bad_state_is_refused(self):
        for bad in ("x", None, [], {"epochIndex": -3}, {"epochIndex": True},
                    {"lastHeight": "x"}, {"lastHeight": -1}):
            with self.assertRaises(EG.EpochError): EG.EpochTracker.from_state(bad)

    def test_a_minimal_state_is_accepted(self):
        self.assertEqual(EG.EpochTracker.from_state({}).epoch, "e0")


class TestTheForkIsPreventedNotDetected(unittest.TestCase):
    def test_a_repeated_height_with_a_different_root_does_not_fork(self):
        t = EG.EpochTracker(); led = HG.HeightLedger()
        v1 = EG.guard_before_broadcast(t, led, 1764, R1, "2026-09-09T18:27:21")
        v2 = EG.guard_before_broadcast(t, led, 1764, R2, "2026-09-09T18:27:51")
        self.assertTrue(v1["publish"]); self.assertTrue(v2["publish"])
        self.assertNotEqual(v1["epoch"], v2["epoch"])
        self.assertEqual(v2["epochAction"], EG.BUMPED)
        self.assertEqual(len(led.forks()), 0)

    def test_without_the_bump_the_ledger_would_have_refused(self):
        led = HG.HeightLedger()
        led.add(HG.Commitment(epoch="e0", height=1764, root=R1, timestamp="t1"))
        v = led.check("e0", 1764, R2)
        self.assertNotEqual(v["decision"], "allow")

    def test_the_same_root_republished_is_idempotent(self):
        t = EG.EpochTracker(); led = HG.HeightLedger()
        EG.guard_before_broadcast(t, led, 1764, R1, "t1")
        t2 = EG.EpochTracker.from_state(t.state())
        v = EG.guard_before_broadcast(t2, led, 1764, R1, "t1")
        self.assertTrue(v["publish"]); self.assertEqual(len(led.forks()), 0)

    def test_three_roots_at_one_height_never_share_an_epoch(self):
        t = EG.EpochTracker(); led = HG.HeightLedger()
        seen = set()
        for r in (R1, R2, R3):
            v = EG.guard_before_broadcast(t, led, 552, r, "t")
            self.assertTrue(v["publish"]); seen.add(v["epoch"])
        self.assertEqual(len(seen), 3)
        self.assertEqual(len(led.forks()), 0)

    def test_the_verdict_carries_the_ledger_reason(self):
        t = EG.EpochTracker(); led = HG.HeightLedger()
        v = EG.guard_before_broadcast(t, led, 1764, R1, "t1")
        self.assertIn("decision", v); self.assertIn("ledger", v)
        self.assertEqual(v["epoch"], "e0")


if __name__ == "__main__":
    unittest.main(verbosity=2)
