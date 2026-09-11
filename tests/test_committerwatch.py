# hardening:allow-file ALL reason=fixtures reproduce the real saos-dex committer sample
"""Tests for committer watch, calibrated on the real saos-dex sample."""

import unittest

from jumpper import committerwatch as CW

REAL = [
    {"sha": "e6b17895", "name": "roshpinacare-sys", "email": "a@b", "date": "d",
     "msg": "broadcast: v71", "files": ["broadcasts/v71.md"], "add": 44, "dele": 0},
    {"sha": "85878717", "name": "Z User", "email": "z@y", "date": "d",
     "msg": "roast-82", "files": ["a.ts", "b.ts", "c.ts", "d.ts", "e.ts",
                                  "f.ts", "g.ts", "h.ts", "i.ts"],
     "add": 118, "dele": 216},
    {"sha": "ae711603", "name": "Z User", "email": "z@y", "date": "d",
     "msg": "roast-81", "files": ["j.ts", "k.ts", "l.ts", "m.ts"], "add": 73, "dele": 37},
]


def C(name, files, add=0, dele=0, msg="m", email=None, sha="s"):
    return {"sha": sha, "name": name, "email": email, "date": "d", "msg": msg,
            "files": files, "add": add, "dele": dele}


class TestIdentityCollapse(unittest.TestCase):
    def test_hyphen_and_space_variants_are_one_actor(self):
        r = CW.identity_report([C("saos-dex-agent", [], 1), C("saos-dex agent", [], 1),
                                C("SAOS-DEX_AGENT", [], 1)])
        self.assertEqual(r["distinctNames"], 3)
        self.assertEqual(r["effectiveIdentities"], 1)
        self.assertEqual(r["probableSameActorCount"], 1)

    def test_distinct_actors_stay_distinct(self):
        r = CW.identity_report(REAL)
        self.assertEqual(r["distinctNames"], 2)
        self.assertEqual(r["effectiveIdentities"], 2)
        self.assertEqual(r["probableSameActor"], {})

    def test_emails_shared_across_names_are_reported(self):
        r = CW.identity_report([C("alice", [], email="x@y"), C("bob", [], email="x@y")])
        self.assertEqual(r["emailsSharedAcrossNames"], ["x@y"])
        self.assertEqual(r["distinctEmails"], 1); self.assertEqual(r["distinctNames"], 2)

    def test_empty_input(self):
        r = CW.identity_report([])
        self.assertEqual(r["commits"], 0); self.assertEqual(r["effectiveIdentities"], 0)

    def test_a_non_sequence_is_refused(self):
        with self.assertRaises(CW.CommitterWatchError): CW.identity_report("x")


class TestFileContention(unittest.TestCase):
    def test_the_real_sample_has_no_contention(self):
        r = CW.file_contention(REAL)
        self.assertEqual(r["contestedFiles"], 0)
        self.assertEqual(r["distinctFiles"], 14)   # 1 broadcaster + 9 + 4 editor files
        self.assertIn("no file", r["verdict"])

    def test_two_identities_on_one_file_is_contention(self):
        r = CW.file_contention([C("a", ["shared.ts"], 1), C("b", ["shared.ts"], 1)])
        self.assertEqual(r["contestedFiles"], 1); self.assertEqual(r["contentionRate"], 100.0)
        self.assertEqual(r["contested"]["shared.ts"], ["a", "b"])

    def test_the_same_actor_under_two_spellings_is_not_contention(self):
        r = CW.file_contention([C("saos-dex-agent", ["x.ts"]), C("saos-dex agent", ["x.ts"])])
        self.assertEqual(r["contestedFiles"], 0)

    def test_disjoint_files_are_not_contention(self):
        r = CW.file_contention([C("a", ["x.ts"]), C("b", ["y.ts"])])
        self.assertEqual(r["contestedFiles"], 0); self.assertEqual(r["distinctFiles"], 2)


class TestRoleSeparation(unittest.TestCase):
    def test_append_only_is_a_broadcaster(self):
        r = CW.role_separation([C("bot", ["log.md"], add=40, dele=0)])
        self.assertEqual(r["identities"]["bot"]["role"], "append-only-broadcaster")

    def test_any_deletion_makes_it_an_editor(self):
        r = CW.role_separation([C("bot", ["log.md"], add=40, dele=1)])
        self.assertEqual(r["identities"]["bot"]["role"], "code-editor")

    def test_touching_two_files_makes_it_an_editor(self):
        r = CW.role_separation([C("bot", ["a", "b"], add=40, dele=0)])
        self.assertEqual(r["identities"]["bot"]["role"], "code-editor")

    def test_the_real_sample_splits_cleanly(self):
        r = CW.role_separation(REAL)
        self.assertEqual(r["verdict"], "1 editor(s), 1 broadcaster(s)")
        self.assertEqual(r["broadcasters"], ["roshpinacare-sys"])
        self.assertEqual(r["editors"], ["Z User"])
        self.assertEqual(r["identities"]["roshpinacare-sys"]["maxFilesPerCommit"], 1)
        self.assertEqual(r["identities"]["Z User"]["maxFilesPerCommit"], 9)


class TestDeletionRisk(unittest.TestCase):
    def test_the_real_refactor_is_flagged_for_a_human(self):
        r = CW.deletion_risk(REAL)
        self.assertEqual(r["count"], 1); self.assertEqual(r["commits"][0]["sha"], "85878717")
        self.assertEqual(r["commits"][0]["net"], -98)
        self.assertIn("human must decide", r["verdict"])

    def test_a_small_net_deletion_is_not_flagged(self):
        self.assertEqual(CW.deletion_risk([C("a", ["x","y","z","w"], add=10, dele=20)])["count"], 0)

    def test_a_large_deletion_in_one_file_is_not_flagged(self):
        self.assertEqual(CW.deletion_risk([C("a", ["x"], add=0, dele=500)])["count"], 0)

    def test_thresholds_are_honoured(self):
        rows = [C("a", ["1","2","3","4","5"], add=0, dele=100)]
        self.assertEqual(CW.deletion_risk(rows, net_threshold=200)["count"], 0)
        self.assertEqual(CW.deletion_risk(rows, file_threshold=9)["count"], 0)

    def test_results_are_sorted_worst_first(self):
        rows = [C("a", ["1","2","3","4"], add=0, dele=60, sha="aaa"),
                C("b", ["1","2","3","4"], add=0, dele=300, sha="bbb")]
        self.assertEqual([x["sha"][:3] for x in CW.deletion_risk(rows)["commits"]], ["bbb", "aaa"])


class TestWatch(unittest.TestCase):
    def test_the_real_sample_is_medium_not_critical(self):
        r = CW.watch(REAL)
        self.assertEqual(r["severity"], "medium")
        self.assertEqual(r["contention"]["contestedFiles"], 0)

    def test_contention_raises_severity_to_high(self):
        rows = REAL + [C("roshpinacare-sys", ["a.ts"], add=1)]
        self.assertEqual(CW.watch(rows)["severity"], "high")

    def test_a_lone_broadcaster_is_low(self):
        rows = [C("bot", ["log%d.md" % i], add=10) for i in range(4)]
        self.assertEqual(CW.watch(rows)["severity"], "low")

    def test_a_bad_input_is_refused(self):
        with self.assertRaises(CW.CommitterWatchError): CW.watch({})

    def test_the_verdict_carries_the_sub_verdicts(self):
        v = CW.watch(REAL)["verdict"]
        for frag in ("severity", "identities", "identity", "editor"):
            self.assertIn(frag, v)


if __name__ == "__main__":
    unittest.main(verbosity=2)
