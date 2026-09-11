# hardening:allow-file ALL reason=fixtures reproduce the real eight-identity committer census
"""Tests for committer watch, against the real identity census: 271 commits across
five repositories carrying eight distinct committer identities."""

import unittest

from jumpper import committerwatch as CW

RELAY = "src/lib/dex/relay.ts"

def C(sha, ident, when, msg, files, repo="saos-dex"):
    return CW.Commit(sha, ident, when, msg, tuple(files), repo)

def two_identities_on_one_file():
    return [C("a" * 40, "Z User", "2026-09-11T05:21:52Z", "roast-78", [RELAY]),
            C("b" * 40, "roshpinacare-sys", "2026-09-11T05:26:18Z", "broadcast r29", [RELAY])]

def fanout():
    return [C("c" * 40, "saos-agent", "2026-09-11T15:28:17Z", "sync", ["README.md"], "Saosmartwallet"),
            C("d" * 40, "saos-agent", "2026-09-11T15:28:18Z", "sync", ["README.md"], "roshpina"),
            C("e" * 40, "saos-agent", "2026-09-11T15:28:21Z", "sync", ["README.md"], "saos-jummper")]


class TestIdentityCollisions(unittest.TestCase):
    def test_two_identities_on_one_file_is_a_collision(self):
        r = CW.identity_collisions(two_identities_on_one_file())
        self.assertEqual(r["sharedFiles"], 1)
        self.assertEqual(r["detail"][RELAY], ["Z User", "roshpinacare-sys"])

    def test_one_identity_writing_a_file_is_not_a_collision(self):
        r = CW.identity_collisions([C("a" * 40, "Z User", "t", "m", [RELAY])])
        self.assertEqual(r["sharedFiles"], 0)
        self.assertIn("no file", r["verdict"])

    def test_two_identities_on_different_files_is_not_a_collision(self):
        r = CW.identity_collisions([C("a" * 40, "Z User", "t", "m", ["x.ts"]),
                                    C("b" * 40, "saos-bot", "t", "m", ["y.ts"])])
        self.assertEqual(r["sharedFiles"], 0)

    def test_commits_with_no_files_are_tolerated(self):
        r = CW.identity_collisions([C("a" * 40, "Z User", "t", "m", [])])
        self.assertEqual(r["files"], 0); self.assertEqual(r["sharedFiles"], 0)

    def test_the_census_identities_are_all_counted(self):
        cs = [C("a" * 40, i, "t", "m", [RELAY]) for i in
              ("Z User", "roshpinacare-sys", "saos-agent", "saos-bot")]
        self.assertEqual(CW.identity_collisions(cs)["identityCount"], 4)


class TestBurstRisk(unittest.TestCase):
    def test_a_cross_identity_burst_inside_the_window_is_detected(self):
        r = CW.burst_risk(two_identities_on_one_file(), window_seconds=900)
        self.assertEqual(r["burstCount"], 1)
        self.assertEqual(r["bursts"][0]["secondsApart"], 266)
        self.assertEqual(r["bursts"][0]["file"], RELAY)

    def test_the_same_identity_repeatedly_is_not_a_burst(self):
        cs = [C("a" * 40, "Z User", "2026-09-11T05:21:52Z", "m", [RELAY]),
              C("b" * 40, "Z User", "2026-09-11T05:26:18Z", "m", [RELAY])]
        self.assertEqual(CW.burst_risk(cs)["burstCount"], 0)

    def test_outside_the_window_is_not_a_burst(self):
        r = CW.burst_risk(two_identities_on_one_file(), window_seconds=60)
        self.assertEqual(r["burstCount"], 0)

    def test_bursts_are_sorted_closest_first(self):
        cs = [C("a" * 40, "A", "2026-09-11T00:00:00Z", "m", ["f"]),
              C("b" * 40, "B", "2026-09-11T00:10:00Z", "m", ["f"]),
              C("c" * 40, "C", "2026-09-11T00:10:30Z", "m", ["f"])]
        b = CW.burst_risk(cs, window_seconds=3600)["bursts"]
        self.assertEqual(b[0]["secondsApart"], 30)

    def test_an_unparseable_timestamp_is_skipped_not_guessed(self):
        cs = [C("a" * 40, "A", "not-a-date", "m", ["f"]),
              C("b" * 40, "B", "2026-09-11T00:00:00Z", "m", ["f"])]
        self.assertEqual(CW.burst_risk(cs)["burstCount"], 0)

    def test_a_non_positive_window_is_refused(self):
        with self.assertRaises(CW.CommitterWatchError):
            CW.burst_risk(two_identities_on_one_file(), window_seconds=0)


class TestBroadcastFanout(unittest.TestCase):
    def test_one_identity_across_three_repositories_is_detected(self):
        r = CW.broadcast_fanout(fanout(), window_seconds=600)
        self.assertEqual(len(r["fanouts"]), 1)
        self.assertEqual(r["fanouts"][0]["repoCount"], 3)
        self.assertEqual(r["fanouts"][0]["identity"], "saos-agent")

    def test_one_repository_is_not_a_fanout(self):
        cs = [C("a" * 40, "saos-agent", "2026-09-11T15:28:17Z", "m", ["x"], "r1"),
              C("b" * 40, "saos-agent", "2026-09-11T15:28:18Z", "m", ["y"], "r1")]
        self.assertEqual(CW.broadcast_fanout(cs)["fanouts"], [])

    def test_commits_without_a_repo_are_ignored(self):
        cs = [C("a" * 40, "A", "2026-09-11T00:00:00Z", "m", ["x"], ""),
              C("b" * 40, "A", "2026-09-11T00:00:01Z", "m", ["y"], "")]
        self.assertEqual(CW.broadcast_fanout(cs)["fanouts"], [])


class TestVerifyClaim(unittest.TestCase):
    def test_an_add_claim_with_the_marker_present_is_consistent(self):
        v = CW.verify_claim("fix(relay): epoch field in the canonical payload",
                            "const payload = { epoch, height };", "epoch")
        self.assertTrue(v["consistent"]); self.assertTrue(v["markerPresent"])

    def test_an_add_claim_with_the_marker_absent_is_inconsistent(self):
        v = CW.verify_claim("fix(relay): epoch field in the canonical payload",
                            "const payload = { height, stateRoot };", "epoch")
        self.assertFalse(v["consistent"])
        self.assertIn("ABSENT", v["verdict"])

    def test_a_remove_claim_with_the_marker_absent_is_consistent(self):
        v = CW.verify_claim("remove the devnet default", "const R = [mainnet];", "devnet")
        self.assertTrue(v["consistent"])

    def test_a_remove_claim_with_the_marker_still_there_is_inconsistent(self):
        v = CW.verify_claim("remove the devnet default", "const R = [devnet];", "devnet")
        self.assertFalse(v["consistent"])
        self.assertIn("STILL PRESENT", v["verdict"])

    def test_an_unclassified_message_reports_none_not_a_guess(self):
        v = CW.verify_claim("chore: tidy", "x = 1", "anything")
        self.assertIsNone(v["consistent"])
        self.assertEqual(v["verdict"], "unclassified")

    def test_the_marker_match_is_case_insensitive(self):
        self.assertTrue(CW.verify_claim("add Epoch handling", "const EPOCH = 1", "epoch")["consistent"])

    def test_empty_inputs_are_refused(self):
        with self.assertRaises(CW.CommitterWatchError): CW.verify_claim("", "x", "y")
        with self.assertRaises(CW.CommitterWatchError): CW.verify_claim("add x", "x", "")


class TestReportAndInputs(unittest.TestCase):
    def test_report_combines_all_three_views(self):
        r = CW.report(two_identities_on_one_file() + fanout())
        self.assertEqual(r["commits"], 5)
        self.assertEqual(r["sharedFiles"], 1)
        self.assertEqual(r["bursts"], 1)
        self.assertEqual(r["fanouts"], 1)
        self.assertEqual(r["closestBurstSeconds"], 266)
        self.assertEqual(sorted(r["repos"]), ["Saosmartwallet", "roshpina", "saos-dex", "saos-jummper"])

    def test_an_empty_history_is_refused(self):
        with self.assertRaises(CW.CommitterWatchError): CW.report([])

    def test_from_api_rejects_a_commit_without_a_sha(self):
        with self.assertRaises(CW.CommitterWatchError):
            CW.Commit.from_api({"commit": {"author": {"name": "x"}}})

    def test_from_api_builds_a_commit(self):
        c = CW.Commit.from_api({"sha": "f" * 40,
            "commit": {"author": {"name": "Z User", "date": "2026-09-11T05:21:52Z"},
                       "message": "roast-78"},
            "files": [{"filename": RELAY}]}, repo="saos-dex")
        self.assertEqual(c.identity, "Z User")
        self.assertEqual(c.files, (RELAY,))
        self.assertEqual(c.repo, "saos-dex")

    def test_an_unnamed_author_becomes_unknown_not_empty(self):
        c = CW.Commit.from_api({"sha": "f" * 40, "commit": {"author": {}, "message": "m"}})
        self.assertEqual(c.identity, "unknown")


if __name__ == "__main__":
    unittest.main(verbosity=2)
