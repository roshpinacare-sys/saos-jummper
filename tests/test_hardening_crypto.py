# hardening:allow-file ALL reason=fixtures quote both the defective patterns and the correct crypto the rules are calibrated against
"""Tests for the crypto-hygiene rules H-18 to H-21.

Calibrated in both directions. Each rule must fire on the defective pattern it was
written for, and must stay quiet on the real, correct implementations read out of
Saosmartwallet/packages/core/src/crypto - otherwise the rule is noise and will be
disabled, which is worse than not having it.

Multi-line fixtures are joined with chr(10) rather than an escape sequence, so the
file survives being generated, transported and rewritten without a backslash being
silently eaten. That has already bitten this repository twice.
"""

import unittest

from jumpper import hardening as HD

NL = chr(10)


def j(*lines):
    return NL.join(lines)


def ids(src, path="x.ts"):
    return {v.rid for v in HD.scan_file(path, src)}


class TestH18SingleHashAsKdf(unittest.TestCase):
    def test_fires_on_sha256_of_a_password(self):
        self.assertIn("H-18", ids("const k = sha256(password + salt);"))
        self.assertIn("H-18", ids("let key = sha256(passphrase)"))
        self.assertIn("H-18", ids("h = sha256(secret.encode())"))

    def test_quiet_on_a_real_kdf(self):
        good = j("import argon2 from 'argon2';",
                 "export const DEFAULT_KDF_PARAMS = { memoryCost: 65536, timeCost: 3, parallelism: 1 };",
                 "export async function deriveMasterKey(password, salt) { return argon2.hash(password, salt); }")
        self.assertNotIn("H-18", ids(good, "kdf.ts"))

    def test_quiet_on_sha256_of_non_secret_data(self):
        self.assertNotIn("H-18", ids("const root = sha256(canonical(state));"))
        self.assertNotIn("H-18", ids("digest = sha256(payload_bytes)"))

    def test_is_blocking(self):
        self.assertEqual(HD.RULE_BY_ID["H-18"].action, HD.BLOCK)
        self.assertEqual(HD.RULE_BY_ID["H-18"].severity, HD.HIGH)


class TestH19NonConstantTimeCompare(unittest.TestCase):
    def test_fires_on_equality_check_of_a_digest(self):
        self.assertIn("H-19", ids("if (digest === expectedDigest) ok = true"))
        self.assertIn("H-19", ids("return signature == computed"))
        self.assertIn("H-19", ids("if (mac === m) return true"))

    def test_quiet_on_timing_safe_compare(self):
        good = j("import { timingSafeEqual } from 'node:crypto';",
                 "return timingSafeEqual(pad(a), pad(b));")
        self.assertNotIn("H-19", ids(good, "kdf.ts"))

    def test_quiet_on_python_compare_digest(self):
        self.assertNotIn("H-19", ids("return hmac.compare_digest(a, b)", "x.py"))

    def test_quiet_on_non_secret_equality(self):
        self.assertNotIn("H-19", ids("if (height === 108) seal()"))
        self.assertNotIn("H-19", ids("if (status === 'ok') return"))

    def test_is_blocking(self):
        self.assertEqual(HD.RULE_BY_ID["H-19"].action, HD.BLOCK)


class TestH20ThrowingCredentialCheck(unittest.TestCase):
    def test_fires_on_throwing_password_check(self):
        self.assertIn("H-20", ids("throw new Error('invalid password supplied');"))
        self.assertIn("H-20", ids("throw new VaultError('wrong passphrase');"))
        self.assertIn("H-20", ids("throw new Error('incorrect credential');"))

    def test_quiet_on_boolean_verification(self):
        good = j("export async function verifyPassword(p, v) {",
                 "  return timingSafeEqual(pad(p), pad(v));",
                 "}")
        self.assertNotIn("H-20", ids(good, "kdf.ts"))

    def test_quiet_on_throwing_for_malformed_input(self):
        self.assertNotIn("H-20", ids("throw new Error('malformed verifier record');"))
        self.assertNotIn("H-20", ids("throw new Error('invalid base64url');"))

    def test_is_reporting_not_blocking(self):
        self.assertEqual(HD.RULE_BY_ID["H-20"].action, HD.REPORT)


class TestH21RelativePackageImports(unittest.TestCase):
    def test_fires_on_relative_cross_package_import(self):
        src = 'import { SteemAdapter } from "../../packages/chains/steem/src/adapter";'
        self.assertIn("H-21", ids(src, "src/lib/vault-runtime.ts"))

    def test_quiet_on_a_named_workspace_import(self):
        self.assertNotIn("H-21", ids('import { VaultKeys } from "@saos/core";'))

    def test_quiet_on_local_relative_imports(self):
        self.assertNotIn("H-21", ids('import { db } from "./vault-stores";'))
        self.assertNotIn("H-21", ids('import x from "../utils/x";'))

    def test_is_reporting_not_blocking(self):
        self.assertEqual(HD.RULE_BY_ID["H-21"].action, HD.REPORT)


class TestRegistryAfterExtension(unittest.TestCase):
    def test_twenty_one_rules_unique_and_ordered(self):
        got = [r.rid for r in HD.RULES]
        self.assertEqual(len(got), 21)
        self.assertEqual(got, sorted(set(got)))

    def test_blocking_outnumbers_reporting(self):
        self.assertEqual(len(HD.rules_for(action=HD.BLOCK)), 14)
        self.assertEqual(len(HD.rules_for(action=HD.REPORT)), 7)

    def test_every_new_rule_documents_its_real_origin(self):
        for rid in ("H-18", "H-19", "H-20", "H-21"):
            r = HD.RULE_BY_ID[rid]
            self.assertTrue(len(r.origin) > 40, rid)
            self.assertTrue(len(r.why) > 40, rid)
            self.assertTrue(len(r.fix) > 40, rid)

    def test_the_good_crypto_directory_passes_as_a_whole(self):
        """The four real files from packages/core, as summarised from source, must
        produce zero blocking violations. If they do not, the rules are
        miscalibrated and will be switched off."""
        tree = {
            "packages/core/src/crypto/kdf.ts": j(
                "import { timingSafeEqual, randomBytes } from 'node:crypto';",
                "export const DEFAULT_KDF_PARAMS = { memoryCost: 65536, timeCost: 3, parallelism: 1 };",
                "export async function deriveMasterKey(password, salt) { return argon2(password, salt, DEFAULT_KDF_PARAMS); }",
                "export async function verifyPassword(p, v) { return timingSafeEqual(pad(p), pad(v)); }"),
            "packages/core/src/crypto/cipher.ts": j(
                "export function seal(plain, key, opts) { return createCipheriv('aes-256-gcm', key, iv); }",
                "export function open(payload, key) { return createDecipheriv('chacha20-poly1305', key, iv); }",
                "export function sha256(b) { return createHash('sha256').update(b).digest(); }"),
            "packages/core/src/crypto/shamir.ts": j(
                "export async function shardSecret(secret, threshold, total) { return shares; }",
                "export async function reconstructSecret(shares) { if (shares.length < t) throw new Error('insufficient shares'); }"),
            "packages/core/src/vault/keys.ts": j(
                "export class VaultKeys {",
                "  addKey(input) { return sealed; }",
                "  revealKey(sealed, session) { return pk; }",
                "}"),
        }
        r = HD.scan_tree(tree)
        self.assertTrue(r["pass"], r["blocking"])
        self.assertEqual(r["blockingCount"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
