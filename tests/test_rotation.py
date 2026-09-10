"""Tests for the rotation contract.

The centrepiece is a replay of the real incident: on 2026-09-08T21:17:42 the
account headcorner had all four authorities replaced on HIVE mainnet (block
109,745,168, trx 92654439d97f4cd30a70a5ced46b2bd93488b722) by the estate's own
steem/agent/keyrotate.cjs, whose default target is the primary account. The owner
had no way to learn the new keys because the evidence file stores them MASKED.

These tests assert that the gate refuses that exact rotation, and that the handoff
it requires would have been usable.
"""

import unittest

from jumpper import rotation as RT

# The real public keys set at 21:17:42, read from HIVE mainnet.
REAL_KEYS = {"hive": {
    "owner":   "STM8mSbBz8zsMfBow2xa1yfTuNhdp6KZf3v7kAs1BSQAB1AMQM1Fw",
    "active":  "STM8c9vp3hUnNsXHaWLPTpcYWkPpK5GrnySgN51FiGX9dxhwVz8YZ",
    "posting": "STM6u99ogJKojfZC94VCs73N3wVRxnm9XTjVSmkSm2BE59yDEuH6b",
    "memo":    "STM7pmsRp7QrEnuGT6EWfnJMuSiAU9wXSoNUJRBYQio5qfGCSrax5"}}

# The MASKED form the real rotation_evidence.json actually stored for account ynet.
MASKED_KEYS = {"hive": {"owner": "STM86gwPfu\u2026", "active": "STM5ct91t6\u2026",
                        "posting": "STM7NLcn7x\u2026", "memo": "STM8PyKK8i\u2026"}}

REPO = "/home/z/steem"
OUTSIDE = "/home/z/.secrets/handoff-headcorner.json"
INSIDE = "/home/z/steem/agent/keys/handoff.json"
SCHEME = "sha256(username+role+master) via steem-js getPrivateKeys"
PRIMARY = ["headcorner"]


def handoff(path=OUTSIDE, keys=None, chains=("hive",), root=REPO):
    return RT.build_handoff("headcorner", list(chains), keys or REAL_KEYS, SCHEME,
                            path, repo_root=root, rotated_at="2026-09-08T21:17:42Z")


def gate(**kw):
    d = {"account": "headcorner", "chains": ["hive"], "primary_accounts": PRIMARY,
         "confirm_primary": True, "backup_verified": True,
         "handoff": handoff(), "repo_root": REPO}
    d.update(kw)
    return RT.rotation_gate(d["account"], d["chains"], d["primary_accounts"],
                            d["confirm_primary"], d["backup_verified"], d["handoff"],
                            repo_root=d.get("repo_root"), dry_run=d.get("dry_run", False))


class TestTheRealIncidentIsRefused(unittest.TestCase):
    def test_the_2026_09_08_rotation_denies_on_three_checks(self):
        g = RT.rotation_gate("headcorner", ["hive"], PRIMARY,
                             confirm_primary=False, backup_verified=False,
                             handoff=None, repo_root=REPO)
        self.assertEqual(g["decision"], RT.DENY)
        self.assertEqual(sorted(g["failedChecks"]),
                         ["backup-verified", "handoff-built", "primary-confirmation"])

    def test_the_reason_for_each_refusal_is_specific(self):
        g = RT.rotation_gate("headcorner", ["hive"], PRIMARY, False, False, None, repo_root=REPO)
        details = {c["name"]: c["detail"] for c in g["checks"]}
        self.assertIn("primary account", details["primary-confirmation"])
        self.assertIn("unrecoverable", details["backup-verified"])
        # the default-fallback explanation appears when the account is missing
        g2 = RT.rotation_gate(None, ["hive"], PRIMARY, True, True, handoff(), repo_root=REPO)
        d2 = {c["name"]: c["detail"] for c in g2["checks"]}
        self.assertIn("AGENT_ACCOUNT", d2["explicit-account"])
        self.assertIn("no way to learn the new keys", details["handoff-built"])

    def test_with_every_control_satisfied_it_allows(self):
        g = gate()
        self.assertEqual(g["decision"], RT.ALLOW)
        self.assertEqual(g["failedChecks"], [])

    def test_a_refused_rotation_is_still_recorded(self):
        g = RT.rotation_gate("headcorner", ["hive"], PRIMARY, False, False, None, repo_root=REPO)
        rec = RT.audit_record("headcorner", ["hive"], g, actor="keyrotate.cjs")
        self.assertEqual(rec["event"], "key_rotation_attempt")
        self.assertEqual(rec["decision"], RT.DENY)
        self.assertEqual(rec["actor"], "keyrotate.cjs")
        self.assertTrue(rec["failedChecks"])

    def test_dry_run_reports_the_refusal_without_authorising(self):
        g = RT.rotation_gate("headcorner", ["hive"], PRIMARY, False, False, None,
                             repo_root=REPO, dry_run=True)
        self.assertEqual(g["decision"], RT.DENY)
        self.assertTrue(g["dryRun"])
        self.assertIn("does not authorise", g["note"])


class TestNoDefaultAccount(unittest.TestCase):
    def test_a_missing_account_denies(self):
        self.assertEqual(gate(account=None)["decision"], RT.DENY)

    def test_the_refusal_names_the_default_fallback_as_the_cause(self):
        g = gate(account=None)
        d = [c["detail"] for c in g["checks"] if c["name"] == "explicit-account"][0]
        self.assertIn("default", d)

    def test_a_primary_account_needs_its_own_confirmation(self):
        self.assertEqual(gate(confirm_primary=False)["decision"], RT.DENY)
        self.assertEqual(gate(confirm_primary=True)["decision"], RT.ALLOW)

    def test_a_non_primary_account_does_not(self):
        g = RT.rotation_gate("ynet", ["hive"], PRIMARY, False, True, handoff(), repo_root=REPO)
        self.assertNotIn("primary-confirmation", [c["name"] for c in g["checks"]])

    def test_no_chains_denies(self):
        self.assertEqual(gate(chains=[])["decision"], RT.DENY)


class TestHandoffIsUsableByTheOwner(unittest.TestCase):
    def test_masked_keys_are_refused(self):
        with self.assertRaises(RT.RotationError) as cm:
            handoff(keys=MASKED_KEYS)
        self.assertIn("MASKED", str(cm.exception))

    def test_a_missing_role_is_refused(self):
        partial = {"hive": {"owner": REAL_KEYS["hive"]["owner"]}}
        with self.assertRaises(RT.RotationError):
            handoff(keys=partial)

    def test_every_role_is_required_on_every_chain(self):
        two = dict(REAL_KEYS); two["steem"] = dict(REAL_KEYS["hive"])
        art = handoff(keys=two, chains=("hive", "steem"))
        self.assertEqual(RT.validate_public_keys(art.public_keys, ["hive", "steem"]), [])

    def test_a_handoff_inside_the_repository_is_refused(self):
        with self.assertRaises(RT.RotationError):
            handoff(path=INSIDE)

    def test_the_gate_also_catches_an_inside_path_built_directly(self):
        art = RT.HandoffArtifact("headcorner", ["hive"], REAL_KEYS, SCHEME,
                                 "2026-09-08T21:17:42Z", "2026-10-08T21:17:42Z", INSIDE)
        self.assertEqual(gate(handoff=art)["decision"], RT.DENY)

    def test_without_repo_root_the_location_cannot_be_verified_so_it_denies(self):
        """A check that cannot be evaluated is not a pass. Before this was fixed the
        gate returned ALLOW because `repo_root and _inside(...)` short-circuited."""
        self.assertEqual(gate(repo_root=None)["decision"], RT.DENY)
        d = [c["detail"] for c in gate(repo_root=None)["checks"] if c["name"] == "handoff-built"][0]
        self.assertIn("cannot be verified", d)

    def test_recovery_deadline_is_thirty_days_out(self):
        art = handoff()
        self.assertEqual(art.recovery_deadline, "2026-10-08T21:17:42Z")
        self.assertEqual(RT.RECOVERY_WINDOW_DAYS, 30)

    def test_the_scheme_is_named_but_carries_no_master(self):
        art = handoff()
        self.assertIn("getPrivateKeys", art.derivation_scheme)
        self.assertNotIn("=", art.derivation_scheme)

    def test_a_scheme_that_carries_a_master_value_is_refused(self):
        with self.assertRaises(RT.RotationError):
            RT.build_handoff("headcorner", ["hive"], REAL_KEYS,
                             "FACTORY_MASTER=SuperSecretValue123", OUTSIDE, repo_root=REPO)

    def test_txids_and_notes_survive_serialisation(self):
        art = RT.build_handoff("headcorner", ["hive"], REAL_KEYS, SCHEME, OUTSIDE,
                               repo_root=REPO, rotated_at="2026-09-08T21:17:42Z",
                               txids={"hive": "92654439d97f4cd30a70a5ced46b2bd93488b722"},
                               notes=["steem rotation unverified - node unreachable"])
        d = art.as_dict()
        self.assertEqual(d["txids"]["hive"][:8], "92654439")
        self.assertEqual(d["notes"][0][:5], "steem")


class TestSecretScanning(unittest.TestCase):
    def test_a_built_handoff_is_secret_free(self):
        self.assertEqual(RT.scan_for_secrets(RT._serialise(handoff())), [])

    def test_wif_is_detected(self):
        self.assertIn("WIF private key", RT.scan_for_secrets('{"k":"5J' + "a" * 49 + '"}'))

    def test_extended_private_key_is_detected(self):
        self.assertIn("extended private key", RT.scan_for_secrets("xprv" + "A" * 70))

    def test_pem_private_key_is_detected(self):
        self.assertIn("PEM private key",
                      RT.scan_for_secrets("-----BEGIN EC PRIVATE KEY-----"))

    def test_a_master_value_is_detected(self):
        self.assertIn("master secret value", RT.scan_for_secrets("FACTORY_MASTER=abcdefgh12345678"))

    def test_a_twelve_word_mnemonic_is_detected(self):
        words = "abandon ability able about above absent absorb abstract absurd abuse access accident"
        self.assertIn("12-word mnemonic", RT.scan_for_secrets(words))

    def test_public_keys_are_not_flagged(self):
        for k in REAL_KEYS["hive"].values():
            self.assertEqual(RT.scan_for_secrets(k), [], k)

    def test_clean_text_is_not_flagged(self):
        self.assertEqual(RT.scan_for_secrets("account headcorner rotated at 21:17:42"), [])


class TestInputValidation(unittest.TestCase):
    def test_required_arguments(self):
        with self.assertRaises(RT.RotationError):
            RT.build_handoff("", ["hive"], REAL_KEYS, SCHEME, OUTSIDE, repo_root=REPO)
        with self.assertRaises(RT.RotationError):
            RT.build_handoff("headcorner", [], REAL_KEYS, SCHEME, OUTSIDE, repo_root=REPO)
        with self.assertRaises(RT.RotationError):
            RT.build_handoff("headcorner", ["hive"], REAL_KEYS, "", OUTSIDE, repo_root=REPO)
        with self.assertRaises(RT.RotationError):
            RT.build_handoff("headcorner", ["hive"], REAL_KEYS, SCHEME, "", repo_root=REPO)

    def test_a_handoff_that_cannot_be_inspected_denies_rather_than_crashing(self):
        class Bad:
            public_keys = None
            chains = ["hive"]
            handoff_path = OUTSIDE
        g = gate(handoff=Bad())
        self.assertEqual(g["decision"], RT.DENY)
        d = [c["detail"] for c in g["checks"] if c["name"] == "handoff-built"][0]
        self.assertIn("could not be evaluated", d)


if __name__ == "__main__":
    unittest.main(verbosity=2)
