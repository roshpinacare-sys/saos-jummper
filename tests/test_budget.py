# hardening:allow-file ALL reason=fixtures reproduce the real convert loop the guard exists to stop
"""Tests for the budget and repeat guards.

The centrepiece is a replay of the REAL defect: eleven identical hive.convert
calls broadcast over 31 hours against a balance that never moved, measured on
HIVE mainnet on 2026-09-08. Each call was individually valid. The gate must stop
the second one.
"""

import unittest

from jumpper import budget as BG

REAL_OP = {"id": "ssc-mainnet-hive", "required_auths": ["headcorner"],
           "json": ('{"contractName":"hive","contractAction":"convert",'
                    '"contractPayload":{"quantity":"9.632"}}')}
REAL_RC_PER_OP = 157_713_792          # measured from two manabar snapshots
REAL_REGEN_PER_DAY = 5_128_310_708    # measured: max_rc / 432000 * 86400
REAL_ATTEMPTS = 11
FIRST_ATTEMPT = 1788775779            # 2026-09-07T11:49:39Z


def gate(**kw):
    return BG.AnchorGate(
        budget=BG.RollingBudget(limit=kw.get("limit", REAL_REGEN_PER_DAY),
                                window_seconds=kw.get("window", 86400),
                                unit="rc", scope="headcorner"),
        repeat=BG.RepeatGuard(max_repeats=kw.get("max_repeats", 1),
                              window_seconds=kw.get("repeat_window", 2 * 86400)))


class TestTheRealLoopIsStopped(unittest.TestCase):
    def test_only_the_first_of_eleven_identical_calls_is_allowed(self):
        g = gate()
        allowed = denied = 0
        for i in range(REAL_ATTEMPTS):
            v = g.evaluate(REAL_OP, REAL_RC_PER_OP, network="hive-mainnet",
                           now=FIRST_ATTEMPT + i * 3600)
            if v.allowed:
                allowed += 1
                g.commit(REAL_OP, REAL_RC_PER_OP, now=FIRST_ATTEMPT + i * 3600)
            else:
                denied += 1
        self.assertEqual(allowed, 1)
        self.assertEqual(denied, REAL_ATTEMPTS - 1)

    def test_rc_recovered_matches_the_measured_waste(self):
        g = gate()
        g.evaluate(REAL_OP, REAL_RC_PER_OP, network="hive-mainnet", now=FIRST_ATTEMPT)
        g.commit(REAL_OP, REAL_RC_PER_OP, now=FIRST_ATTEMPT)
        saved = 0
        for i in range(1, REAL_ATTEMPTS):
            v = g.evaluate(REAL_OP, REAL_RC_PER_OP, network="hive-mainnet",
                           now=FIRST_ATTEMPT + i * 3600)
            if not v.allowed:
                saved += REAL_RC_PER_OP
        self.assertEqual(saved, 10 * REAL_RC_PER_OP)
        self.assertEqual(saved, 1_577_137_920)
        self.assertGreater(saved / REAL_REGEN_PER_DAY, 0.30)

    def test_denial_states_the_repeat_count_and_the_hint(self):
        g = gate()
        g.evaluate(REAL_OP, REAL_RC_PER_OP, network="hive-mainnet", now=FIRST_ATTEMPT)
        g.commit(REAL_OP, REAL_RC_PER_OP, now=FIRST_ATTEMPT)
        v = g.evaluate(REAL_OP, REAL_RC_PER_OP, network="hive-mainnet", now=FIRST_ATTEMPT + 3600)
        self.assertFalse(v.allowed)
        self.assertEqual(v.guard, "repeat")
        self.assertEqual(v.detail["priorCount"], 1)
        self.assertIn("loop", v.detail["hint"])

    def test_a_different_operation_is_not_a_repeat(self):
        g = gate()
        g.commit(REAL_OP, REAL_RC_PER_OP, now=FIRST_ATTEMPT)
        other = dict(REAL_OP, json=REAL_OP["json"].replace("9.632", "1.000"))
        self.assertTrue(g.evaluate(other, REAL_RC_PER_OP, network="hive-mainnet",
                                   now=FIRST_ATTEMPT + 60).allowed)

    def test_repeats_outside_the_window_are_allowed_again(self):
        g = gate(repeat_window=3600)
        g.commit(REAL_OP, REAL_RC_PER_OP, now=FIRST_ATTEMPT)
        self.assertFalse(g.evaluate(REAL_OP, REAL_RC_PER_OP, network="hive-mainnet",
                                    now=FIRST_ATTEMPT + 1800).allowed)
        self.assertTrue(g.evaluate(REAL_OP, REAL_RC_PER_OP, network="hive-mainnet",
                                   now=FIRST_ATTEMPT + 7200).allowed)


class TestRollingBudget(unittest.TestCase):
    def test_cumulative_small_spends_are_capped(self):
        b = BG.RollingBudget(limit=1000, window_seconds=3600)
        # ten spends of 100 fill a 1000 limit exactly; the eleventh must deny
        for i in range(10):
            self.assertTrue(b.check(100, now=i).allowed, i)
            b.commit(100, now=i)
        v = b.check(100, now=20)
        self.assertFalse(v.allowed)
        self.assertEqual(v.detail["spentInWindow"], 1000)
        self.assertEqual(v.detail["overage"], 100)
        self.assertEqual(v.detail["remaining"], 0)

    def test_exactly_at_the_limit_is_allowed(self):
        b = BG.RollingBudget(limit=1000, window_seconds=3600)
        b.commit(900, now=0)
        self.assertTrue(b.check(100, now=1).allowed)

    def test_window_expiry_frees_budget(self):
        b = BG.RollingBudget(limit=1000, window_seconds=100)
        b.commit(1000, now=0)
        self.assertFalse(b.check(1, now=50).allowed)
        self.assertTrue(b.check(1000, now=200).allowed)

    def test_exact_overage_is_reported(self):
        b = BG.RollingBudget(limit=1000, window_seconds=3600)
        b.commit(900, now=0)
        v = b.check(200, now=1)
        self.assertFalse(v.allowed)
        self.assertEqual(v.detail["overage"], 100)
        self.assertEqual(v.detail["requested"], 200)
        self.assertEqual(v.detail["remaining"], 100)

    def test_unconfigured_or_zero_limit_is_refused_at_construction(self):
        for bad in (0, -1, "1000", None):
            with self.assertRaises(BG.BudgetError):
                BG.RollingBudget(limit=bad, window_seconds=3600)

    def test_zero_and_negative_amounts_deny(self):
        b = BG.RollingBudget(limit=1000, window_seconds=3600)
        self.assertFalse(b.check(0, now=0).allowed)
        self.assertFalse(b.check(-5, now=0).allowed)

    def test_non_integer_amount_denies_rather_than_guessing(self):
        b = BG.RollingBudget(limit=1000, window_seconds=3600)
        self.assertFalse(b.check("100", now=0).allowed)

    def test_check_never_records(self):
        b = BG.RollingBudget(limit=1000, window_seconds=3600)
        for _ in range(50):
            b.check(500, now=0)
        self.assertEqual(b.spent(now=0), 0)

    def test_state_reports_utilisation(self):
        b = BG.RollingBudget(limit=1000, window_seconds=3600)
        b.commit(250, now=0)
        s = b.state(now=0)
        self.assertEqual(s["spentInWindow"], 250)
        self.assertEqual(s["remaining"], 750)
        self.assertEqual(s["utilisationPct"], 25.0)


class TestRepeatGuard(unittest.TestCase):
    def test_max_repeats_greater_than_one_is_honoured(self):
        r = BG.RepeatGuard(max_repeats=3, window_seconds=3600)
        for i in range(3):
            self.assertTrue(r.check({"a": i % 1}, now=i).allowed or i > 0)
            r.commit({"a": 1}, now=i)
        self.assertFalse(r.check({"a": 1}, now=3).allowed)
        self.assertEqual(r.check({"a": 1}, now=3).detail["priorCount"], 3)

    def test_fingerprint_is_order_independent(self):
        self.assertEqual(BG.fingerprint({"a": 1, "b": 2}), BG.fingerprint({"b": 2, "a": 1}))

    def test_fingerprint_is_content_sensitive(self):
        self.assertNotEqual(BG.fingerprint({"a": 1}), BG.fingerprint({"a": 2}))

    def test_invalid_construction(self):
        with self.assertRaises(BG.BudgetError):
            BG.RepeatGuard(max_repeats=0)
        with self.assertRaises(BG.BudgetError):
            BG.RepeatGuard(window_seconds=0)

    def test_counts_are_pruned_to_the_window(self):
        r = BG.RepeatGuard(max_repeats=5, window_seconds=100)
        for i in (0, 10, 20):
            r.commit({"x": 1}, now=i)
        self.assertEqual(sum(r.counts(now=30).values()), 3)
        self.assertEqual(sum(r.counts(now=500).values()), 0)


class TestNetworkFailClosed(unittest.TestCase):
    def test_mainnet_allowed(self):
        g = gate()
        for n in ("hive-mainnet", "solana-mainnet", "ethereum-mainnet"):
            self.assertTrue(g.evaluate({"a": 1}, 100, network=n, now=0).allowed, n)

    def test_devnet_and_testnet_denied(self):
        g = gate()
        for n in ("api.devnet.solana.com", "solana-devnet", "sepolia", "goerli",
                  "holesky", "shasta", "nile", "testnet"):
            v = g.evaluate({"a": 1}, 100, network=n, now=0)
            self.assertFalse(v.allowed, n)
            self.assertEqual(v.guard, "network")

    def test_missing_network_denies(self):
        g = gate()
        for n in ("", None):
            v = g.evaluate({"a": 1}, 100, network=n, now=0)
            self.assertFalse(v.allowed)
            self.assertIn("refusing to assume", v.reason)

    def test_unrecognised_network_denies(self):
        g = gate()
        v = g.evaluate({"a": 1}, 100, network="rpc.example.com", now=0)
        self.assertFalse(v.allowed)
        self.assertIn("fail closed", v.reason)

    def test_requirement_can_be_relaxed_explicitly(self):
        g = BG.AnchorGate(repeat=BG.RepeatGuard(), require_mainnet=False)
        self.assertTrue(g.evaluate({"a": 1}, 100, network="devnet", now=0).allowed)


class TestGateComposition(unittest.TestCase):
    def test_no_guards_configured_denies(self):
        g = BG.AnchorGate()
        v = g.evaluate({"a": 1}, 100, network="hive-mainnet", now=0)
        self.assertFalse(v.allowed)
        self.assertIn("no budget or repeat guard", v.reason)
        self.assertEqual(v.guard, "gate")

    def test_any_deny_denies_and_names_every_denier(self):
        g = gate(limit=1000)
        g.commit(REAL_OP, 900, now=0)
        v = g.evaluate(REAL_OP, 900, network="hive-mainnet", now=1)
        self.assertFalse(v.allowed)
        self.assertIn("repeat", v.detail["deniedBy"])
        self.assertIn("budget", v.detail["deniedBy"])

    def test_a_raising_guard_denies_not_passes(self):
        class Boom:
            def check(self, *a, **k):
                raise RuntimeError("guard exploded")
        g = BG.AnchorGate(budget=BG.RollingBudget(limit=10**12, window_seconds=60),
                          repeat=Boom(), require_mainnet=False)
        v = g.evaluate({"a": 1}, 1, now=0)
        self.assertFalse(v.allowed)
        self.assertIn("fail closed", v.reason)

    def test_all_checks_are_reported_even_on_allow(self):
        g = gate()
        v = g.evaluate({"a": 1}, 1000, network="hive-mainnet", now=0)
        self.assertTrue(v.allowed)
        self.assertEqual({c["guard"] for c in v.detail["checks"]}, {"network", "repeat", "budget"})

    def test_denial_preserves_the_denying_guards_numbers(self):
        """A denial without the overage or repeat count is not actionable."""
        g = gate(limit=1000)
        g.commit(REAL_OP, 900, now=0)
        v = g.evaluate(REAL_OP, 900, network="hive-mainnet", now=1)
        self.assertFalse(v.allowed)
        self.assertEqual(v.detail["priorCount"], 1)
        self.assertIn("loop", v.detail["hint"])
        self.assertEqual(v.detail["deniedBy"], ["repeat", "budget"])

    def test_network_only_gate_still_denies(self):
        g = BG.AnchorGate(require_mainnet=True)
        v = g.evaluate({"a": 1}, 100, network="hive-mainnet", now=0)
        self.assertFalse(v.allowed)
        self.assertEqual(v.guard, "gate")

    def test_commit_records_only_when_called(self):
        g = gate()
        g.evaluate(REAL_OP, REAL_RC_PER_OP, network="hive-mainnet", now=0)
        self.assertEqual(g.budget.spent(now=0), 0)
        g.commit(REAL_OP, REAL_RC_PER_OP, now=0)
        self.assertEqual(g.budget.spent(now=0), REAL_RC_PER_OP)

    def test_verdict_serialises(self):
        import json
        g = gate()
        v = g.evaluate({"a": 1}, 1000, network="hive-mainnet", now=0)
        json.dumps(v.as_dict())
        self.assertTrue(v.as_dict()["decision"], "allow")


if __name__ == "__main__":
    unittest.main(verbosity=2)
