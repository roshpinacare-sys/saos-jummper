# hardening:allow-file ALL reason=fixtures are the four real xlock/xunlock memos read off HIVE mainnet
"""Tests for memo-lock reconciliation, against the four real operations."""

import json
import unittest

from jumpper import xlock as XL


def T(i, ts, amt, memo, trx, frm="headcorner", to="headcorner"):
    return [i, {"timestamp": ts, "block": 1, "trx_id": trx,
                "op": ["transfer", {"to": to, "from": frm, "amount": amt, "memo": memo}]}]


REAL = [
    T(49621, "2026-09-04T19:20:21", "0.001 HIVE", "saos:xlock:PHIVE:0.001",
      "13141ef37777142f11622649d0e022c8402fa0ed"),
    T(49625, "2026-09-04T22:23:48", "0.002 HIVE", "saos:xlock:PHIVE:0.002:rt66",
      "bb3156cdc725b15785d9b67b6c3f47fcc8d12040"),
    T(49626, "2026-09-04T22:37:51", "0.001 HIVE",
      "saos:xunlock:PHIVE:0.001:rt66:7bdec0aa64c761672680c7dfa7ffcdebacddac7e",
      "454d2d22e7301561680efb66d99e43b37bcde227"),
    T(49697, "2026-09-07T11:49:39", "0.050 HIVE", "saos:xlock:PHIVE:0.050",
      "44be4de1e510cf50dd1d5e7a828000b043815d11"),
]

CLEAN = [
    T(1, "t", "1.000 HIVE", "saos:xlock:PHIVE:1.000:r1", "aa", "alice", "escrow"),
    T(2, "t", "1.000 HIVE", "saos:xunlock:PHIVE:1.000:r1:aa", "bb", "escrow", "alice"),
]


def ops():
    return XL.parse_history(REAL)


def rec():
    return XL.reconcile(ops())


class TestParsingTheRealOperations(unittest.TestCase):
    def test_all_four_are_parsed(self):
        self.assertEqual(len(ops()), 4)

    def test_every_one_is_a_self_transfer(self):
        self.assertTrue(all(o.is_self_transfer for o in ops()))

    def test_actions_amounts_and_tokens(self):
        o = ops()
        self.assertEqual([x.action for x in o], ["xlock", "xlock", "xunlock", "xlock"])
        self.assertEqual([x.amount for x in o], ["0.001", "0.002", "0.001", "0.050"])
        self.assertEqual({x.asset for x in o}, {"HIVE"})
        self.assertEqual({x.token for x in o}, {"PHIVE"})

    def test_reference_ids(self):
        self.assertEqual([x.ref_id for x in ops()], [None, "rt66", "rt66", None])

    def test_the_cited_txid_is_carried(self):
        self.assertEqual(ops()[2].cited_txid,
                         "7bdec0aa64c761672680c7dfa7ffcdebacddac7e")

    def test_non_xlock_memos_are_ignored(self):
        rows = REAL + [T(90, "t", "1.000 HIVE", "hello world", "aa"),
                       T(91, "t", "1.000 HIVE", "saos:rc-route", "bb"),
                       T(92, "t", "1.000 HIVE", "saos:xlock:PHIVE", "cc")]
        self.assertEqual(len(XL.parse_history(rows)), 4)

    def test_malformed_rows_are_skipped(self):
        self.assertEqual(XL.parse_history([[], [1], [1, "x"]]), [])


class TestReconciliationOfTheRealLedger(unittest.TestCase):
    def test_it_does_not_reconcile(self):
        r = rec()
        self.assertNotEqual(r["verdict"], "RECONCILED")
        self.assertEqual((r["locks"], r["unlocks"]), (3, 1))
        self.assertEqual(r["findingCount"], 8)
        self.assertEqual((r["critical"], r["high"]), (4, 3))

    def test_custody_is_unchanged_and_enforcement_is_none(self):
        r = rec()
        self.assertIn("unchanged", r["custody"])
        self.assertIn("none", r["enforcement"])

    def test_self_transfer_is_flagged_for_every_operation(self):
        self.assertEqual([f["kind"] for f in rec()["findings"]].count("self-transfer"), 4)

    def test_format_drift_is_scoped_to_the_lock_messages(self):
        f = [x for x in rec()["findings"] if x["kind"] == "inconsistent-format"]
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["action"], "xlock")
        self.assertEqual(f[0]["fieldCounts"], [4, 5])
        self.assertEqual(sorted(f[0]["indices"]), [49621, 49625, 49697])

    def test_the_two_referenceless_locks_are_flagged(self):
        f = [x for x in rec()["findings"] if x["kind"] == "lock-without-reference"][0]
        self.assertEqual(sorted(f["indices"]), [49621, 49697])
        self.assertIn("0.050", f["amounts"])

    def test_the_foreign_txid_is_flagged_as_graphene_format(self):
        f = [x for x in rec()["findings"] if x["kind"] == "unlock-cites-foreign-txid"][0]
        self.assertTrue(f["isGrapheneFormat"])
        self.assertIn("cannot be followed", f["detail"])

    def test_the_amount_mismatch_is_reconciled_exactly(self):
        r = rec()
        self.assertEqual(r["balances"], {"rt66": {"locked": "0.002", "unlocked": "0.001"}})
        f = [x for x in r["findings"] if x["kind"] == "amount-mismatch"][0]
        self.assertEqual(f["delta"], "0.001")


class TestTheCheckerDiscriminates(unittest.TestCase):
    def test_a_balanced_protocol_between_two_parties_reconciles(self):
        r = XL.reconcile(XL.parse_history(CLEAN))
        self.assertEqual(r["verdict"], "RECONCILED")
        self.assertEqual(r["findingCount"], 0)
        self.assertEqual(r["custody"], "changed")

    def test_a_lock_beside_an_unlock_is_not_format_drift(self):
        r = XL.reconcile(XL.parse_history(CLEAN))
        self.assertNotIn("inconsistent-format", [f["kind"] for f in r["findings"]])

    def test_an_unlock_citing_its_own_lock_txid_is_not_foreign(self):
        r = XL.reconcile(XL.parse_history(CLEAN))
        self.assertNotIn("unlock-cites-foreign-txid", [f["kind"] for f in r["findings"]])

    def test_an_empty_ledger_reconciles(self):
        self.assertEqual(XL.reconcile([])["verdict"], "RECONCILED")


class TestAdditionalDefects(unittest.TestCase):
    def test_a_memo_quantity_that_disagrees_with_the_transfer(self):
        r = XL.reconcile(XL.parse_history(
            [T(1, "t", "5.000 HIVE", "saos:xlock:PHIVE:1.000:r1", "aa")]))
        self.assertIn("memo-amount-mismatch", [f["kind"] for f in r["findings"]])

    def test_an_unparseable_quantity_is_flagged(self):
        r = XL.reconcile(XL.parse_history(
            [T(1, "t", "1.000 HIVE", "saos:xlock:PHIVE:notanumber:r1", "aa")]))
        self.assertIn("unparseable-quantity", [f["kind"] for f in r["findings"]])

    def test_an_unlock_citing_an_unknown_reference_is_flagged(self):
        r = XL.reconcile(XL.parse_history(
            [T(1, "t", "1.000 HIVE", "saos:xunlock:PHIVE:1.000:nosuchref:aa", "bb")]))
        self.assertIn("unlock-unknown-ref", [f["kind"] for f in r["findings"]])

    def test_serialisation_is_json_safe(self):
        json.dumps(rec())
        json.dumps(XL.parse_history(REAL)[0].as_dict())


if __name__ == "__main__":
    unittest.main(verbosity=2)
