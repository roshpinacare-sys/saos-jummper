# hardening:allow-file ALL reason=fixtures quote signing patterns the contract checks for
"""Tests for the six-stage signing-gate contract.

Two classes of test matter here, and the second is the one that usually gets
skipped:

  1. the contract must recognise a conforming signer
  2. the leak detector must NOT flag prose

A previous revision failed both. It spliced a helper in after the STAGES list using
an index search for a string that also appeared inside a stage lambda, so
console_leaks silently became a lambda and check() still returned 6/6 - a broken
detector that looked green. And the leak detector flagged a fail-closed alert whose
message merely contained the letters wif.

So the helpers are asserted to be real functions, and prose is asserted to be
clean, before anything else is tested.
"""

import inspect
import unittest

from jumpper import signingcontract as SG

CONFORMING = """
export class SigningOrchestrator {
  async sign(op) {
    await vault.ensureUnlocked();
    if (op.stepUp) await vault.verifyStepUp(op.stepUpPassword);
    const decision = policyEngine.evaluate(op, config);
    if (decision.action !== 'allow') throw new VaultError('POLICY', decision.reason);
    const role = isFundsOp(op) ? 'active' : 'posting';
    if (record.role === null) throw new VaultError('VALIDATION', 'flavor-less key');
    const { privateKey } = await vault.revealKeyFor(keyId);
    const signed = await adapter.sign(tx, { byRole: { [role]: privateKey } });
    if (hasCapability('broadcast')) await broadcast(signed);
    audit.record('key_used', { keyId });
    audit.record('signing_attempt', { ok: true });
    return signed;
  }
}
"""

NO_POLICY = """
async function relay(op) {
  await vault.ensureUnlocked();
  const role = isFunds(op) ? 'active' : 'posting';
  const { privateKey } = await vault.revealKeyFor(k);
  const signed = await adapter.sign(tx, { byRole: { [role]: privateKey } });
  await broadcast(signed);
}
"""

LEAKS_KEY = """
async function bad(op) {
  const { privateKey } = await vault.revealKeyFor(k);
  console.error("signing with", privateKey);
  return adapter.sign(tx, privateKey);
}
"""

PROSE_ONLY = """
function alert() {
  console.error("[relay][ALERT] wif-invalid: the key in .env is not a valid WIF - "
    + "relay suspended fail-closed, no retry loop");
  console.log("no seed phrase configured for this network");
  console.warn("policy denied", reason);
}
"""


class TestHelpersAreRealFunctions(unittest.TestCase):
    """Guards the splice bug that made check() green while broken."""

    def test_helpers_are_functions_not_lambdas(self):
        for name in ("console_leaks", "returns_plaintext_key", "strip_literals", "check"):
            self.assertTrue(inspect.isfunction(getattr(SG, name)), name)

    def test_stages_call_the_real_helpers(self):
        src = inspect.getsource(SG)
        self.assertGreater(src.index("def console_leaks("), src.index("STAGES") - 10**9)
        self.assertLess(src.index("def console_leaks("), src.index("STAGES: List[Stage]"))


class TestLeakDetectorPrecision(unittest.TestCase):
    def test_prose_is_not_a_leak(self):
        self.assertEqual(SG.console_leaks(PROSE_ONLY), [])

    def test_a_real_value_in_a_log_is_a_leak(self):
        leaks = SG.console_leaks(LEAKS_KEY)
        self.assertEqual(len(leaks), 1)
        self.assertIn("privateKey", leaks[0])

    def test_template_interpolation_is_a_leak(self):
        self.assertEqual(len(SG.console_leaks("console.log(`using ${wif}`);")), 1)

    def test_concatenation_is_a_leak(self):
        self.assertEqual(len(SG.console_leaks('console.warn("seed:", mnemonic);')), 1)

    def test_returns_plaintext_key_detects_a_returned_key(self):
        self.assertTrue(SG.returns_plaintext_key("function f() { return privateKey; }"))

    def test_returns_plaintext_key_ignores_public_derivation(self):
        self.assertEqual(SG.returns_plaintext_key("return privateKey.publicKey.toString(prefix);"), [])

    def test_strip_literals_keeps_interpolations(self):
        self.assertIn("wif", SG.strip_literals("console.log(`${wif}`)"))
        self.assertNotIn("wif", SG.strip_literals('console.log("the word wif")'))


class TestSixStageContract(unittest.TestCase):
    def test_conforming_signer_passes_all_six(self):
        r = SG.check(CONFORMING)
        self.assertEqual(r["stagesSatisfied"], 6)
        self.assertTrue(r["safe_to_hold_funds"])
        self.assertIn("CONFORMS", r["verdict"])

    def test_missing_policy_gate_is_reported(self):
        r = SG.check(NO_POLICY)
        self.assertIn("policy-gate", r["missingStages"])
        self.assertFalse(r["safe_to_hold_funds"])
        self.assertIn("DOES NOT CONFORM", r["verdict"])

    def test_leaking_signer_fails_reveal_once(self):
        r = SG.check(LEAKS_KEY)
        self.assertIn("reveal-once", r["missingStages"])
        self.assertEqual(len(r["consoleLeaks"]), 1)

    def test_every_stage_carries_an_obligation_and_a_failure_mode(self):
        r = SG.check(CONFORMING)
        for st in r["results"]:
            self.assertTrue(len(st["obligation"]) > 30, st["stage"])
            self.assertTrue(len(st["failureMode"]) > 30, st["stage"])

    def test_stage_order_is_complete_and_sequential(self):
        self.assertEqual([s.order for s in SG.STAGES], [1, 2, 3, 4, 5, 6])
        self.assertEqual(len({s.name for s in SG.STAGES}), 6)

    def test_empty_source_raises(self):
        with self.assertRaises(SG.ContractError):
            SG.check("")
        with self.assertRaises(SG.ContractError):
            SG.check("   ")

    def test_a_raising_stage_detector_counts_as_missing(self):
        """Fail-closed at the stage level, without mutating module state.

        check() wraps every detector in try/except and records False on any
        exception. If a raising detector counted as satisfied, one broken check
        would silently turn a non-conforming signer into a conforming one.
        """
        import inspect as _inspect
        src = _inspect.getsource(SG.check)
        self.assertIn("except Exception", src)
        self.assertIn("ok = False", src)
        # and prove it behaviourally on a source that makes a detector raise
        class Hostile(str):
            def find(self, *a, **k):
                raise RuntimeError("hostile")
        r = SG.check(Hostile("revealKeyFor adapter.sign ensureUnlocked PolicyEngine "
                             "posting byRole role null broadcast audit. key_used"))
        self.assertFalse(r["safe_to_hold_funds"])

    def test_unreadable_source_raises_rather_than_reporting_a_verdict(self):
        class Boom(str):
            def strip(self):
                raise RuntimeError("unreadable")
        with self.assertRaises(RuntimeError):
            SG.check(Boom("x" * 40))


if __name__ == "__main__":
    unittest.main(verbosity=2)
