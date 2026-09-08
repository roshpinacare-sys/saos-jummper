"""Tests for network attestation - the honest third state.

Fixtures mirror the real defects found in the estate (findings.json F-02..F-04)
and the real endpoints verified live on 2026-09-08.
"""

import unittest

from jumpper import netattest as N

ETH_MAIN = "https://ethereum-rpc.publicnode.com"
SOL_MAIN = "https://api.mainnet-beta.solana.com"
SOL_DEV = "https://api.devnet.solana.com"
HIVE_MAIN = "https://api.openhive.network"
TRON_MAIN = "https://api.trongrid.io"
ROOT64 = "ab" * 32


class TestHostExtraction(unittest.TestCase):
    def test_strips_query_and_path(self):
        self.assertEqual(N.host_of("https://x.io/rpc?key=SECRET123&v=1"), "x.io")

    def test_never_leaks_the_key(self):
        self.assertNotIn("SECRET", N.host_of("https://x.io/rpc?key=SECRET123"))

    def test_lowercases(self):
        self.assertEqual(N.host_of("https://API.Hive.Blog/x"), "api.hive.blog")

    def test_garbage_returns_empty(self):
        self.assertEqual(N.host_of("not a url"), "")


class TestClassification(unittest.TestCase):
    def test_ethereum_default_is_mainnet(self):
        self.assertEqual(N.classify_host("ETHEREUM", ETH_MAIN), N.MAINNET)

    def test_solana_mainnet(self):
        self.assertEqual(N.classify_host("SOLANA", SOL_MAIN), N.MAINNET)

    def test_solana_devnet_detected(self):
        self.assertEqual(N.classify_host("SOLANA", SOL_DEV), N.DEVNET)

    def test_hive_and_tron_mainnet(self):
        self.assertEqual(N.classify_host("HIVE", HIVE_MAIN), N.MAINNET)
        self.assertEqual(N.classify_host("TRON", TRON_MAIN), N.MAINNET)

    def test_ethereum_testnets_detected(self):
        for h in ("https://rpc.sepolia.org", "https://goerli.example.com"):
            self.assertIn(N.classify_host("ETHEREUM", h), (N.TESTNET, N.DEVNET))

    def test_unknown_host_is_unknown_not_mainnet(self):
        self.assertEqual(N.classify_host("SOLANA", "https://some-random-rpc.io"), N.UNKNOWN)

    def test_accepts_bare_host(self):
        self.assertEqual(N.classify_host("SOLANA", "api.devnet.solana.com"), N.DEVNET)


class TestThreeStateVerdict(unittest.TestCase):
    def test_verified_on_mainnet_is_verified(self):
        r = N.make_record("ETHEREUM", ETH_MAIN, "0x94", ROOT64, 108, True, block_ref="25929672")
        self.assertEqual(r.state, "verified")
        self.assertTrue(r.network_matches_expected)

    def test_unverified_is_unproven_not_failed(self):
        r = N.make_record("SOLANA", SOL_MAIN, "iHD5", ROOT64, 1, False)
        self.assertEqual(r.state, "unproven")

    def test_verified_on_devnet_is_flagged(self):
        r = N.make_record("SOLANA", SOL_DEV, "sig", ROOT64, 1, True)
        self.assertEqual(r.state, "verified-wrong-network")
        self.assertFalse(r.network_matches_expected)

    def test_unproven_on_devnet_is_still_unproven(self):
        r = N.make_record("SOLANA", SOL_DEV, "sig", ROOT64, 1, False)
        self.assertEqual(r.state, "unproven")

    def test_finality_per_chain(self):
        self.assertEqual(N.make_record("ETHEREUM", ETH_MAIN, "t", ROOT64, 1, True).finality, "finalized")
        self.assertEqual(N.make_record("SOLANA", SOL_MAIN, "t", ROOT64, 1, True).finality, "finalized")
        self.assertEqual(N.make_record("HIVE", HIVE_MAIN, "t", ROOT64, 1, True).finality, "irreversible")
        self.assertEqual(N.make_record("TRON", TRON_MAIN, "t", ROOT64, 1, True).finality, "solidity")

    def test_requires_inputs(self):
        with self.assertRaises(N.NetworkAttestationError):
            N.make_record("SOLANA", SOL_MAIN, "", ROOT64, 1, True)
        with self.assertRaises(N.NetworkAttestationError):
            N.make_record("SOLANA", "", "t", ROOT64, 1, True)
        with self.assertRaises(N.NetworkAttestationError):
            N.make_record("SOLANA", "not a url", "t", ROOT64, 1, True)


class TestAudit(unittest.TestCase):
    def test_never_counts_unproven_as_verified(self):
        recs = [
            N.make_record("ETHEREUM", ETH_MAIN, "a", ROOT64, 1, True),
            N.make_record("HIVE", HIVE_MAIN, "b", ROOT64, 2, True),
            N.make_record("SOLANA", SOL_MAIN, "c", ROOT64, 3, False),
        ]
        a = N.audit_records(recs)
        self.assertEqual(a["verifiedMainnet"], 2)
        self.assertEqual(a["unproven"], 1)
        self.assertEqual(a["total"], 3)
        self.assertIn("all verified anchors are on mainnet", a["verdict"])

    def test_reproduces_the_estate_solana_situation(self):
        recs = [N.make_record("SOLANA", SOL_MAIN, "sig%d" % i, ROOT64, i, False) for i in range(27)]
        a = N.audit_records(recs)
        self.assertEqual(a["total"], 27)
        self.assertEqual(a["verifiedMainnet"], 0)
        self.assertEqual(a["unproven"], 27)

    def test_flags_nonmainnet_hosts(self):
        recs = [N.make_record("SOLANA", SOL_DEV, "x", ROOT64, 1, True)]
        a = N.audit_records(recs)
        self.assertEqual(a["verifiedWrongNetwork"], 1)
        self.assertEqual(a["nonMainnetHosts"], ["api.devnet.solana.com"])
        self.assertIn("NON-MAINNET", a["verdict"])


class TestSolanaVerificationFix(unittest.TestCase):
    def test_solana_requires_history_search(self):
        self.assertTrue(N.requires_history_search("SOLANA"))

    def test_ethereum_does_not(self):
        self.assertFalse(N.requires_history_search("ETHEREUM"))

    def test_correct_params_set_history_true(self):
        p = N.correct_solana_params("sig")
        self.assertEqual(p["params"][1]["searchTransactionHistory"], True)

    def test_note_explains_the_failure_mode(self):
        self.assertIn("ephemeral", N.correct_solana_params("sig")["note"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
