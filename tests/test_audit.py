# hardening:allow-file ALL reason=fixtures reproduce the two real audit hash functions being compared
"""Tests for audit hash-chain coverage.

The centrepiece is a negative result that a test produced and the code then had to
admit: verify_chain over a TRUNCATED chain returns intact=True. Dropping the tail
leaves a shorter chain that is still internally consistent. A hash chain alone
cannot detect truncation - only an external commitment to the head can. That is
the argument for anchoring, and it is now stated in the code rather than hidden by
an optimistic return value.
"""

import unittest

from jumpper import audit as AU

RECORDS = [
    {"who": "agent-a", "when": "2026-09-08T12:00:00Z", "what": "transfer",
     "which": "tx-1", "outcome": "denied", "why": "over budget"},
    {"who": "agent-b", "when": "2026-09-08T12:00:03Z", "what": "seal",
     "which": "batch-7", "outcome": "success", "why": None},
    {"who": "agent-a", "when": "2026-09-08T12:00:09Z", "what": "anchor",
     "which": "height-42", "outcome": "success", "why": None},
]


def chain():
    return AU.build_chain("vault-1", RECORDS)


class TestCoverageOfTheTwoRealImplementations(unittest.TestCase):
    def test_saosmartwallet_is_sound(self):
        d = AU.SAOSMARTWALLET.as_dict()
        self.assertTrue(d["sound"])
        self.assertEqual(d["unansweredQuestions"], [])
        self.assertTrue(d["genesisBoundToInstance"])

    def test_saosmartwallet_own_hash_is_not_counted_as_unbound(self):
        # eventHash cannot be part of the preimage that produces it
        self.assertEqual(AU.SAOSMARTWALLET.unbound, [])

    def test_roshpina_leaves_who_when_why_unanswered(self):
        d = AU.ROSHPINA.as_dict()
        self.assertFalse(d["sound"])
        self.assertEqual(sorted(d["unansweredQuestions"]), ["when", "who", "why"])

    def test_roshpina_unbound_fields_are_the_substantive_ones(self):
        self.assertEqual(AU.ROSHPINA.unbound,
                         ["actionId", "occurredAt", "reason", "source"])

    def test_roshpina_self_referential_fields_are_excluded_from_the_noise(self):
        for f in ("hash", "signature"):
            self.assertNotIn(f, AU.ROSHPINA.unbound)
            self.assertIn(f, AU.ROSHPINA.record_fields)

    def test_roshpina_genesis_is_a_shared_literal(self):
        self.assertFalse(AU.ROSHPINA.genesis_bound_to_instance)

    def test_the_two_are_mutually_unverifiable(self):
        self.assertNotEqual(set(AU.SAOSMARTWALLET.hashed_fields),
                            set(AU.ROSHPINA.hashed_fields))

    def test_verdicts_are_actionable_not_vague(self):
        self.assertIn("SOUND", AU.SAOSMARTWALLET.as_dict()["verdict"])
        self.assertIn("UNSOUND", AU.ROSHPINA.as_dict()["verdict"])
        self.assertIn("occurredAt", AU.ROSHPINA.as_dict()["verdict"])


class TestCoverageClassifier(unittest.TestCase):
    def test_unknown_naming_is_matched_loosely(self):
        """A different vocabulary for the same seven questions is still sound."""
        names = ["actor", "at", "kind", "status", "previous", "detail", "object"]
        c = AU.coverage("x", hashed_fields=names, record_fields=names,
                        genesis_bound_to_instance=True)
        self.assertTrue(c.sound, c.unanswered)
        self.assertEqual(c.unanswered, [])

    def test_omitting_why_alone_makes_it_unsound(self):
        """WHY is the question an audit log exists to answer for a refusal."""
        names = ["actor", "at", "kind", "status", "previous", "object"]
        c = AU.coverage("x", hashed_fields=names, record_fields=names,
                        genesis_bound_to_instance=True)
        self.assertFalse(c.sound)
        self.assertEqual(c.unanswered, ["why"])

    def test_omitting_which_alone_makes_it_unsound(self):
        names = ["actor", "at", "kind", "status", "previous", "detail"]
        c = AU.coverage("x", hashed_fields=names, record_fields=names,
                        genesis_bound_to_instance=True)
        self.assertFalse(c.sound)
        self.assertEqual(c.unanswered, ["which"])

    def test_a_shared_genesis_literal_makes_it_unsound_even_with_full_coverage(self):
        names = ["actor", "at", "kind", "status", "previous", "detail", "object"]
        c = AU.coverage("x", hashed_fields=names, record_fields=names,
                        genesis_bound_to_instance=False)
        self.assertFalse(c.sound)
        self.assertEqual(c.unanswered, [])

    def test_a_minimal_chain_binding_only_order_is_unsound(self):
        c = AU.coverage("x", hashed_fields=["id", "prevHash"],
                        record_fields=["id", "prevHash", "source", "occurredAt"],
                        genesis_bound_to_instance=True)
        self.assertFalse(c.sound)
        self.assertIn("who", c.unanswered)
        self.assertIn("when", c.unanswered)


class TestReferenceChain(unittest.TestCase):
    def test_a_freshly_built_chain_verifies(self):
        r = AU.verify_chain("vault-1", chain())
        self.assertTrue(r["intact"])
        self.assertEqual(r["length"], 3)
        self.assertFalse(r["truncated"])

    def test_tampering_with_who_breaks_it(self):
        c = chain(); c[0]["who"] = "agent-evil"
        r = AU.verify_chain("vault-1", c)
        self.assertFalse(r["intact"]); self.assertEqual(r["firstBadSeq"], 0)

    def test_tampering_with_when_breaks_it(self):
        c = chain(); c[1]["when"] = "2020-01-01T00:00:00Z"
        self.assertFalse(AU.verify_chain("vault-1", c)["intact"])

    def test_tampering_with_why_breaks_it(self):
        c = chain(); c[0]["why"] = "approved by the owner"
        r = AU.verify_chain("vault-1", c)
        self.assertFalse(r["intact"])
        self.assertIn("bound field", r["reason"])

    def test_tampering_with_outcome_breaks_it(self):
        c = chain(); c[0]["outcome"] = "success"
        self.assertFalse(AU.verify_chain("vault-1", c)["intact"])

    def test_reordering_breaks_it(self):
        self.assertFalse(AU.verify_chain("vault-1", list(reversed(chain())))["intact"])

    def test_a_different_instance_id_breaks_it(self):
        r = AU.verify_chain("vault-2", chain())
        self.assertFalse(r["intact"])
        self.assertIn("previousHash", r["reason"])

    def test_genesis_requires_an_instance_id(self):
        with self.assertRaises(AU.AuditError):
            AU.genesis_hash("")

    def test_genesis_differs_per_instance(self):
        self.assertNotEqual(AU.genesis_hash("a"), AU.genesis_hash("b"))

    def test_records_missing_required_fields_are_refused(self):
        with self.assertRaises(AU.AuditError):
            AU.build_chain("v", [{"who": "a", "when": "t", "outcome": "ok"}])


class TestTruncationIsNotDetectableByAChainAlone(unittest.TestCase):
    """The negative result. Documented in the module, pinned here."""

    def test_a_truncated_chain_still_verifies_without_an_external_commitment(self):
        c = chain()
        r = AU.verify_chain("vault-1", c[:1])
        self.assertTrue(r["intact"])
        self.assertFalse(r["truncated"])

    def test_expected_length_detects_it(self):
        r = AU.verify_chain("vault-1", chain()[:1], expected_length=3)
        self.assertTrue(r["intact"])
        self.assertTrue(r["truncated"])
        self.assertIn("tail is missing", r["reason"])

    def test_expected_head_detects_it(self):
        c = chain()
        r = AU.verify_chain("vault-1", c[:1], expected_head=c[-1]["hash"])
        self.assertTrue(r["truncated"])

    def test_a_complete_chain_is_not_reported_as_truncated(self):
        c = chain()
        r = AU.verify_chain("vault-1", c, expected_length=3, expected_head=c[-1]["hash"])
        self.assertTrue(r["intact"])
        self.assertFalse(r["truncated"])
        self.assertIsNone(r["reason"])

    def test_an_empty_chain_is_intact_and_not_truncated(self):
        r = AU.verify_chain("vault-1", [])
        self.assertTrue(r["intact"])
        self.assertFalse(r["truncated"])

    def test_head_hash_is_reported_so_it_can_be_anchored(self):
        r = AU.verify_chain("vault-1", chain(), expected_length=3)
        self.assertEqual(len(r["headHash"]), 64)


if __name__ == "__main__":
    unittest.main(verbosity=2)
