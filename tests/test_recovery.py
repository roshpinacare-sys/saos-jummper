# hardening:allow-file ALL reason=fixtures reproduce the real Shamir reconstruction defect the contract detects
"""Tests for the recovery contract.

Calibrated against real source read out of Saosmartwallet/packages/core:
backup.ts (26,905 chars), vault.ts (43,402), encoding.ts (4,195),
crypto/shamir.ts (8,092) and bridges/router.ts (16,560).

The centrepiece is a defect the first version of this contract MISSED. R-05 asked
"does threshold reconstruction refuse too-few shares?" and answered by searching
the whole file for the word threshold plus a length comparison. backup.ts passes a
threshold to shardSecret, so the property read as satisfied - while the function
that actually reconstructs, reconstructSecret in shamir.ts, never receives a
threshold at all and therefore cannot check one. R-05 is now scoped to the
reconstruction function's own brace-matched body.
"""

NL = chr(10)

import unittest

from jumpper import recovery as RC

# The real signature: no threshold parameter.
REAL_RECON = """
export async function reconstructSecret(shares: Share[]): Promise<Uint8Array> {
  if (!Array.isArray(shares) || shares.length === 0) {
    throw new VaultError("SHAMIR_INVALID", "no shares provided");
  }
  const parsed = [];
  for (const s of shares) { parsed.push({ x: s.index, data: b64ToBytes(s.data) }); }
  const secretLength = Math.max(...parsed.map((p) => p.data.length));
  const secret = new Uint8Array(secretLength);
  for (let i = 0; i < secretLength; i++) {
    secret[i] = lagrangeAtZero(parsed.filter((p) => p.data.length > i), i);
  }
  return secret;
}
"""

# The same function with the guard it is missing.
FIXED_RECON = """
export async function reconstructSecret(shares, threshold) {
  if (!Array.isArray(shares) || shares.length === 0) throw new VaultError("SHAMIR_INVALID", "no shares");
  if (shares.length < threshold) throw new VaultError("SHAMIR_INVALID", "insufficient shares");
  return lagrange(shares);
}
"""

CALLER_ONLY = """
export async function createBackup(state, password, opts) {
  const recoveryKey = randomBytes(32);
  const shares = await shardSecret(recoveryKey, opts.threshold, opts.totalShares);
  return { shares };
}
"""


class TestReconstructionGuardIsFunctionScoped(unittest.TestCase):
    """The false positive that shipped, and the fix."""

    def test_real_reconstruction_is_correctly_flagged(self):
        self.assertFalse(RC.reconstruction_refuses_too_few(REAL_RECON))

    def test_a_caller_passing_threshold_does_not_satisfy_it(self):
        self.assertFalse(RC.reconstruction_refuses_too_few(CALLER_ONLY))

    def test_a_correct_guard_is_recognised(self):
        self.assertTrue(RC.reconstruction_refuses_too_few(FIXED_RECON))

    def test_insufficient_shares_wording_is_recognised(self):
        src = "function reconstruct(shares, t) { if (shares.length < t) throw new Error('insufficient shares'); }"
        self.assertTrue(RC.reconstruction_refuses_too_few(src))

    def test_absent_function_is_not_a_satisfied_property(self):
        self.assertFalse(RC.reconstruction_refuses_too_few("const x = 1;"))
        self.assertIsNone(RC.function_body("const x = 1;"))

    def test_function_body_is_brace_matched(self):
        src = "function reconstructSecret(a) { if (a) { return 1; } return 2; }"
        body = RC.function_body(src)
        self.assertTrue(body.endswith("}"))
        self.assertEqual(body.count("{"), body.count("}"))

    def test_alternate_reconstruction_names_are_found(self):
        for name in ("combineShares", "recoverSecret", "reconstruct", "recoverKey"):
            src = "function %s(shares, threshold) { if (shares.length < threshold) throw new Error('x'); }" % name
            self.assertTrue(RC.reconstruction_refuses_too_few(src), name)


class TestScopePreventsCategoryErrors(unittest.TestCase):
    def test_properties_declare_a_scope(self):
        for pr in RC.PROPERTIES:
            self.assertIn(pr.scope, (RC.UNIVERSAL, RC.BACKUP, RC.VAULT), pr.pid)

    def test_backup_only_properties_are_not_applied_to_a_vault(self):
        ids = {pr.pid for pr in RC.PROPERTIES if pr.scope == RC.BACKUP}
        self.assertTrue({"R-02", "R-05", "R-06", "R-07", "R-08"} <= ids)
        r = RC.check("class SovereignVault { lock() { key.fill(0); } }", kind=RC.VAULT)
        checked = {x["id"] for x in r["results"]}
        self.assertFalse(checked & ids, checked)

    def test_unknown_kind_is_refused(self):
        with self.assertRaises(RC.RecoveryError):
            RC.check("x = 1", kind="nonsense")

    def test_empty_source_is_refused(self):
        for bad in ("", "   "):
            with self.assertRaises(RC.RecoveryError):
                RC.check(bad)


class TestPublicKeyedMacFinding(unittest.TestCase):
    REAL = """
function packageChecksum(encryptedState) {
  return createHash("sha256").update(canonicalJson(encryptedState), "utf8").digest("hex");
}
function packageSignature(backup) {
  return createHmac("sha256", utf8(backup.metadata.checksum))
    .update(packagePreimage(backup), "utf8").digest("base64");
}
"""

    def test_detects_a_mac_keyed_by_public_package_data(self):
        self.assertTrue(RC.public_keyed_mac(self.REAL))

    def test_does_not_flag_a_properly_keyed_mac(self):
        good = 'createHmac("sha256", derivedKey).update(preimage, "utf8").digest("base64");'
        self.assertFalse(RC.public_keyed_mac(good))

    def test_the_finding_is_reported_with_its_severity_reasoning(self):
        r = RC.check(self.REAL + REAL_RECON, kind=RC.BACKUP)
        self.assertTrue(r["publicKeyedMac"])
        self.assertIn("AEAD", r["finding"])
        self.assertIn("LOW", r["finding"])


class TestConstantTimeProperty(unittest.TestCase):
    def test_a_named_primitive_in_a_shared_module_is_accepted(self):
        src = 'import { bytesEqual } from "../encoding";' + NL + "if (!bytesEqual(a,b)) throw x;"
        self.assertTrue([pr for pr in RC.PROPERTIES if pr.pid == "R-01"][0].detect(src))

    def test_the_xor_accumulate_body_is_accepted_alone(self):
        src = "for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];"
        self.assertTrue([pr for pr in RC.PROPERTIES if pr.pid == "R-01"][0].detect(src))

    def test_a_plain_equality_check_is_not_accepted(self):
        src = "if (hmacA === hmacB) return true;"
        self.assertFalse([pr for pr in RC.PROPERTIES if pr.pid == "R-01"][0].detect(src))


class TestPackageEvaluation(unittest.TestCase):
    def test_package_verdict_uses_the_union(self):
        files = {"crypto/shamir.ts": FIXED_RECON,
                 "backup/backup.ts": "const k = randomBytes(32); k.fill(0); fresh vault only; "
                                     "aes-256-gcm authTag seal(state); inactiveDays beneficiar; "
                                     "beneficiaries.length; import { bytesEqual } from '../encoding';"}
        r = RC.check_package(files, kind=RC.BACKUP)
        self.assertEqual(r["fileCount"], 2)
        self.assertIn("perFile", r)
        self.assertIn("delegationNote", r)

    def test_empty_package_is_refused(self):
        with self.assertRaises(RC.RecoveryError):
            RC.check_package({})

    def test_per_file_results_are_reported_alongside_the_union(self):
        r = RC.check_package({"a.ts": "const x = 1;"}, kind=RC.BACKUP)
        self.assertEqual(r["propertiesTotal"], 8)
        self.assertEqual(r["perFile"]["a.ts"]["total"], 8)
        self.assertEqual(r["missingRequired"], [x["id"] for x in r["results"] if x["status"] == RC.ABSENT])


class TestAntiMockContract(unittest.TestCase):
    def test_held_when_all_four_present(self):
        src = ("const leg = { amount, source: 'eth-gas' }; "
               "if (!ok) return { readiness: 'gated', gateReason: 'unfunded' }; "
               "assertExecutable(path); const gas = measuredGasPrice;")
        self.assertTrue(RC.check_anti_mock(src)["allPresent"])

    def test_broken_when_a_claim_is_missing(self):
        r = RC.check_anti_mock("const leg = { amount };")
        self.assertFalse(r["allPresent"])
        self.assertIn("BROKEN", r["verdict"])

    def test_empty_source_is_refused(self):
        with self.assertRaises(RC.RecoveryError):
            RC.check_anti_mock("")


class TestFailClosed(unittest.TestCase):
    def test_a_raising_detector_counts_as_absent(self):
        import inspect
        src = inspect.getsource(RC.check)
        self.assertIn("except Exception", src)
        self.assertIn("ok = False", src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
