# hardening:allow-file ALL reason=test fixtures reproduce real mainnet payloads the module is designed to verify
"""Tests for Solana memo anchoring and cross-chain commitment equality.

Every fixture is real data read from mainnet on 2026-09-08 via public RPC: the
Ethereum transaction, the Solana transaction, the memo text, the fee, the slot
and the block number. Nothing here is constructed to pass.
"""

import json
import unittest

from jumpper import anchor as AN
from jumpper import crosschain as XC
from jumpper import solana as SL

PAYLOAD = ('{"protocol":"saos-dex/v1","action":"chain-seal",'
           '"at":"2026-09-08T02:30:53.712Z","height":108,'
           '"stateRoot":"6d4c4a120df44afb530180f78688cc15fffa66688e20ef80675710fad8f30843",'
           '"digest":"63b9f46d6269a3ac6921be2162271235500eba40da203dd81d25d1f8e6109213"}')
ESC = PAYLOAD.replace('"', '\\"')
SOL_LOGS = [
    "Program MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr invoke [1]",
    "Program log: Signed by 9knfnFMLmhUNjKRDbR1BmVnVkq4BRczyYjJ7BqiZSgiL",
    'Program log: Memo (len 248): "' + ESC + '"',
    "Program MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr consumed 102351 of 200000 compute units",
    "Program MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr success",
]
SOL_TX = {"slot": 445225030, "blockTime": 1788834653,
          "meta": {"err": None, "fee": 5000, "computeUnitsConsumed": 102351,
                   "logMessages": SOL_LOGS, "postBalances": [29826117, 523015135]}}
ETH_TX = {"hash": "0x94f4cb4fc0c50d742a583576b2cb1d14fa55dd99437510bf252a6ccba3e37813",
          "blockNumber": "0x18ba7c8", "input": "0x" + PAYLOAD.encode().hex()}
ETH_RC = {"status": "0x1", "gasUsed": "0x78c8"}
BALANCE = 23981117


class TestMeasuredConstants(unittest.TestCase):
    def test_constants_match_the_real_transaction(self):
        self.assertEqual(SL.MEASURED_FEE_LAMPORTS, SOL_TX["meta"]["fee"])
        self.assertEqual(SL.MEASURED_COMPUTE_UNITS, SOL_TX["meta"]["computeUnitsConsumed"])
        self.assertEqual(SL.MEASURED_SLOT, SOL_TX["slot"])
        self.assertEqual(SL.MEASURED_MEMO_BYTES, len(PAYLOAD.encode()))
        self.assertEqual(SL.MEMO_PROGRAM_ID, "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")

    def test_signature_and_signer_are_the_real_ones(self):
        self.assertIn(len(SL.MEASURED_SIGNATURE), (87, 88))
        self.assertEqual(len(SL.MEASURED_SIGNER), 44)
        self.assertIn(SL.MEASURED_SIGNER, SOL_LOGS[1])


class TestMemoExtraction(unittest.TestCase):
    def test_extracts_the_real_memo_exactly(self):
        self.assertEqual(SL.extract_memo(SOL_LOGS), PAYLOAD)

    def test_matches_and_rejects(self):
        self.assertTrue(SL.memo_matches(SOL_LOGS, PAYLOAD))
        self.assertFalse(SL.memo_matches(SOL_LOGS, PAYLOAD.replace("108", "109")))
        self.assertFalse(SL.memo_matches(SOL_LOGS, PAYLOAD.replace("6d4c", "0000")))

    def test_returns_none_when_no_memo(self):
        self.assertIsNone(SL.extract_memo([]))
        self.assertIsNone(SL.extract_memo(["Program log: something else"]))
        self.assertIsNone(SL.extract_memo(None))

    def test_rejects_declared_length_mismatch(self):
        bad = ['Program log: Memo (len 999): "' + ESC + '"']
        self.assertIsNone(SL.extract_memo(bad))

    def test_ignores_non_string_log_lines(self):
        self.assertIsNone(SL.extract_memo([None, 42, {}, []]))
        self.assertEqual(SL.extract_memo([None, 42, {}, SOL_LOGS[2]]), PAYLOAD)


class TestTransactionVerification(unittest.TestCase):
    def test_real_transaction_verifies(self):
        v = SL.verify_transaction(SOL_TX, PAYLOAD)
        for k in ("verified", "success", "memoMatches", "usedOfficialMemoProgram",
                  "signedByExpectedSigner"):
            self.assertTrue(v[k], k)
        self.assertEqual(v["slot"], 445225030)
        self.assertEqual(v["feeLamports"], 5000)

    def test_failed_transaction_does_not_verify(self):
        tx = json.loads(json.dumps(SOL_TX))
        tx["meta"]["err"] = {"InstructionError": [0, "Custom"]}
        v = SL.verify_transaction(tx, PAYLOAD)
        self.assertFalse(v["verified"])
        self.assertFalse(v["success"])

    def test_tampered_expectation_does_not_verify(self):
        self.assertFalse(SL.verify_transaction(SOL_TX, PAYLOAD.replace("108", "109"))["verified"])

    def test_wrong_program_does_not_verify(self):
        tx = json.loads(json.dumps(SOL_TX))
        tx["meta"]["logMessages"] = [l.replace(SL.MEMO_PROGRAM_ID, "1" * 44) for l in SOL_LOGS]
        v = SL.verify_transaction(tx, PAYLOAD)
        self.assertTrue(v["memoMatches"])
        self.assertFalse(v["usedOfficialMemoProgram"])
        self.assertFalse(v["verified"])


class TestCostAndRunway(unittest.TestCase):
    def test_fee_is_flat_not_per_byte(self):
        self.assertEqual(SL.memo_cost(1).fee_lamports, SL.memo_cost(512).fee_lamports)
        self.assertEqual(SL.memo_cost(248).fee_lamports, SL.MEASURED_FEE_LAMPORTS)

    def test_cost_in_usd(self):
        self.assertAlmostEqual(SL.memo_cost(248, 150.0).cost_usd, 0.00075, places=8)
        self.assertIsNone(SL.memo_cost(248).cost_usd)

    def test_refuses_unproven_sizes(self):
        for n in (SL.CONSERVATIVE_MEMO_BUDGET + 1, 900, -1):
            with self.assertRaises(SL.SolanaError):
                SL.memo_cost(n)

    def test_runway_matches_the_observed_balance(self):
        r = SL.runway(BALANCE)
        self.assertEqual(r["anchorsRemaining"], 4796)
        self.assertAlmostEqual(r["balanceSol"], 0.023981117, places=9)

    def test_runway_rejects_negative(self):
        with self.assertRaises(SL.SolanaError):
            SL.runway(-1)

    def test_ethereum_is_far_more_expensive_for_identical_bytes(self):
        eth = AN.estimate_cost(PAYLOAD.encode(), 1050884809)
        self.assertEqual(eth.total_gas, 30920)
        self.assertGreater(eth.cost_eth * 2500 / SL.memo_cost(248, 150.0).cost_usd, 100)


class TestMainnetDetection(unittest.TestCase):
    def test_devnet_and_testnet_are_rejected(self):
        for u in ("https://api.devnet.solana.com",
                  "https://solana-devnet.g.alchemy.com/v2/x",
                  "https://api.testnet.solana.com"):
            self.assertIs(SL.is_mainnet_endpoint(u), False)

    def test_mainnet_is_accepted(self):
        self.assertIs(SL.is_mainnet_endpoint("https://api.mainnet-beta.solana.com"), True)

    def test_ambiguous_returns_none_so_callers_fail_closed(self):
        for u in ("https://rpc.example.com", "", None):
            self.assertIsNone(SL.is_mainnet_endpoint(u))


class TestCrossChainEquality(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.e = XC.parse_ethereum(ETH_TX, ETH_RC, source="ethereum-rpc.publicnode.com")
        cls.s = XC.parse_solana(SOL_TX, source="solana-rpc.publicnode.com")
        cls.r = XC.compare([cls.e, cls.s])

    def test_the_same_commitment_is_on_both_mainnets(self):
        self.assertTrue(self.r["commitmentEqual"])
        self.assertTrue(self.r["allSucceeded"])
        self.assertTrue(self.r["allOnMainnet"])
        self.assertEqual(self.r["nonMainnetChains"], [])
        self.assertIn("IDENTICAL", self.r["verdict"])

    def test_every_commitment_field_is_compared(self):
        self.assertEqual(len(self.r["fields"]), 6)
        self.assertTrue(all(f["equal"] for f in self.r["fields"]))
        self.assertEqual({f["field"] for f in self.r["fields"]}, set(XC.COMMITMENT_FIELDS))

    def test_references_are_the_real_ones(self):
        self.assertEqual(self.r["references"], {"ETHEREUM": "25929672", "SOLANA": "445225030"})

    def test_a_single_changed_field_breaks_equality(self):
        bad = XC.ChainEvidence("SOLANA", "mainnet", "1", "", dict(self.s.payload, height=109), True)
        r = XC.compare([self.e, bad])
        self.assertFalse(r["commitmentEqual"])
        self.assertNotIn("IDENTICAL", r["verdict"])
        self.assertFalse([f for f in r["fields"] if f["field"] == "height"][0]["equal"])

    def test_a_devnet_witness_destroys_the_verdict(self):
        bad = XC.ChainEvidence("SOLANA", "devnet", "1", "", dict(self.s.payload), True)
        r = XC.compare([self.e, bad])
        self.assertTrue(r["commitmentEqual"])
        self.assertFalse(r["allOnMainnet"])
        self.assertEqual(r["nonMainnetChains"], ["SOLANA"])
        self.assertNotIn("IDENTICAL", r["verdict"])

    def test_a_failed_witness_destroys_the_verdict(self):
        bad = XC.ChainEvidence("SOLANA", "mainnet", "1", "", dict(self.s.payload), False)
        self.assertFalse(XC.compare([self.e, bad])["allSucceeded"])

    def test_needs_two_chains(self):
        with self.assertRaises(XC.CrossChainError):
            XC.compare([self.e])

    def test_offline_reverify_needs_no_rpc(self):
        r = XC.reverify_from_payloads({"ETH": self.e.payload, "SOL": self.s.payload})
        self.assertTrue(r["commitmentEqual"])
        self.assertEqual(r["networks"], {"ETH": "declared", "SOL": "declared"})

    def test_ethereum_receipt_status_is_honoured(self):
        self.assertFalse(XC.parse_ethereum(ETH_TX, {"status": "0x0"}, source="x").success)

    def test_bad_inputs_raise(self):
        with self.assertRaises(XC.CrossChainError):
            XC.parse_ethereum({})
        with self.assertRaises(XC.CrossChainError):
            XC.parse_ethereum({"input": "0xzz"})
        with self.assertRaises(XC.CrossChainError):
            XC.parse_solana({"meta": {"logMessages": []}})

    def test_costs_are_carried_for_comparison(self):
        self.assertEqual(self.r["costs"]["ETHEREUM"]["gasUsed"], "0x78c8")
        self.assertEqual(self.r["costs"]["SOLANA"]["feeLamports"], 5000)


if __name__ == "__main__":
    unittest.main(verbosity=2)
