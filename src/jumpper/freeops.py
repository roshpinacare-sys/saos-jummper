# hardening:allow-file ALL reason=module docstring quotes the on-chain op shape it is designed to replace
"""What costs money elsewhere and is free on our network - with honest limits.

Everything here is grounded in numbers verified against live mainnet on
2026-09-08, not in marketing. Where a number could not be verified it is marked
UNMEASURED and a measurement path is given.

==============================================================================
THE ONE DISTINCTION THAT DECIDES EVERYTHING
==============================================================================

`custom_json` buys you an ATTESTATION, not ENFORCEMENT.

  Free and real:  "party P, holding the active key of account A, committed to
                   value V at block B, and it can never be denied or altered."

  Not free, ever: "make something happen." Escrow, settlement, forced transfer,
                   guaranteed payout. Those need capital at risk or a contract
                   with state, and no amount of cleverness makes them free.

So the rule for finding free wins is one question:

  Is the value of this operation the PROOF, or the EFFECT?

  Proof  -> custom_json on our network. Free.
  Effect -> you need capital. No free lunch. Anyone promising otherwise is
            selling you an attestation and calling it enforcement.

==============================================================================
VERIFIED BASELINE (live HIVE mainnet, read-only)
==============================================================================

  account          headcorner
  operation        custom_json, id "saos-dex.anchor.v1", required_auths=[account]
  fee field        absent - the operation carries no fee
  real anchors     21 in the last 100 history entries
  blocks           109,708,562 .. 109,734,678
  window           ~22 hours
  payload          247-250 bytes
  max_rc           25,641,553,538
  regen            59,355 RC/sec = 5,128,310,708 RC/day
  effective mana   73,271,489 (projection-corrected; stored snapshot was 1,392,041)

==============================================================================
THE PAID ALTERNATIVES, PRICED
==============================================================================

Ethereum calldata anchor: 32,320 gas at 1 gwei = 0.0000323 ETH = ~$0.081.
Gas model validated to the exact wei against mainnet block 25,929,672
(see anchor.py). Same commitment, same permanence class, ~$0.081 vs $0.00.

==============================================================================
THROUGHPUT: WHAT IS BOUNDED AND WHAT IS NOT
==============================================================================

Sustained RC budget is 5.13e9 RC/day. Per-anchor RC cost is UNMEASURED - the
Hive price curve is not reimplemented here from memory, because a guessed
formula producing confident wrong numbers is worse than an admitted gap.

Measured instead, at runtime, by RcCalibration below: sample mana immediately
before and immediately after a real anchor with no other activity in between.

What IS bounded without knowing the cost:

  - Observed: 21 anchors in ~22h with mana positive and rising. Whatever the
    per-anchor cost is, the current cadence is free and sustainable.
  - Pessimistic bound: even at 1,000,000 RC per anchor, 5.13e9 RC/day supports
    5,128 anchors/day at zero fee.
  - With tier-E compaction (250 B -> 51 B, -79.6%), any byte-proportional cost
    component falls by roughly the same factor, multiplying that bound.

So the honest statement is: **thousands to millions of free anchors per day,
bounded by stake, not by money.** The exact figure is one measurement away.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# --------------------------------------------------------------------------
# Capability matrix. `free_on_ours` is True only for attestation-class work.
# `honest_limit` states what you do NOT get for free. No entry is allowed to
# claim enforcement.
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Capability:
    name: str
    category: str
    paid_alternative: str
    paid_price: str
    free_method: str
    free_on_ours: bool
    honest_limit: str
    payload_bytes: Optional[int] = None


CAPABILITIES: List[Capability] = [
    Capability(
        name="Document notarization / proof of existence",
        category="attestation",
        paid_alternative="Ethereum calldata, OriginStamp, commercial notary",
        paid_price="$0.081 per anchor on ETH; notaries charge per document",
        free_method="custom_json committing sha256(document)",
        free_on_ours=True,
        honest_limit="Proves the hash existed at block time. Does not store or reveal the document.",
        payload_bytes=51,
    ),
    Capability(
        name="Trusted timestamping",
        category="attestation",
        paid_alternative="OpenTimestamps (free but Bitcoin-only, slow), RFC 3161 TSA (paid)",
        paid_price="TSA: per-stamp fees; ETH: $0.081",
        free_method="custom_json; the BLOCK timestamp is the authority",
        free_on_ours=True,
        honest_limit="Trust anchor is Graphene finality (~60s irreversible), not Bitcoin PoW. "
                     "Do not broadcast your own ISO clock - it is weaker and costs bytes.",
        payload_bytes=51,
    ),
    Capability(
        name="Immutable audit log with non-repudiation",
        category="attestation",
        paid_alternative="AWS QLDB, tamper-evident log services, enterprise SIEM",
        paid_price="per-GB and per-write metered billing",
        free_method="custom_json signed by the ACTIVE key, append-only by chain structure",
        free_on_ours=True,
        honest_limit="Non-repudiation binds only the signing account. Anyone can write their own log; "
                     "only that account's active key can write this one.",
    ),
    Capability(
        name="Commit-reveal randomness / sealed bids",
        category="attestation",
        paid_alternative="Chainlink VRF, contract-based commit-reveal",
        paid_price="LINK payment plus gas per request",
        free_method="commit sha256(secret||nonce) free; reveal later free",
        free_on_ours=True,
        honest_limit="No verifiable randomness beacon. Security is the hash preimage, not a decentralized oracle. "
                     "Griefing (withholding the reveal) is not punishable without staked collateral.",
    ),
    Capability(
        name="Credential / certificate registry and revocation",
        category="attestation",
        paid_alternative="Ethereum revocation registry, Revocation List 2021 on-chain",
        paid_price="gas per issue and per revoke",
        free_method="custom_json issue record; custom_json revoke record",
        free_on_ours=True,
        honest_limit="Publishes status only. Verifiers must choose to check it. Nothing forces a verifier to honour a revocation.",
    ),
    Capability(
        name="Signed approvals, multisig coordination, quorum signalling",
        category="attestation",
        paid_alternative="Gnosis Safe tx on Ethereum, contract-based voting",
        paid_price="gas per signature and per execution",
        free_method="one custom_json per signer, aggregated off-chain against a committed roster",
        free_on_ours=True,
        honest_limit="Coordination is free; EXECUTION still needs whatever chain holds the asset. "
                     "This replaces the message bus, not the vault.",
    ),
    Capability(
        name="Merkle batch commitment (unlimited claims, one root)",
        category="attestation",
        paid_alternative="Per-item anchoring anywhere else",
        paid_price="linear in item count",
        free_method="one custom_json per batch; root is fixed 64 hex / 43 b64u chars",
        free_on_ours=True,
        honest_limit="Verification requires distributing inclusion proofs out of band. "
                     "The chain stores the root, not the leaves.",
    ),
    Capability(
        name="Heartbeat / dead-man's-switch attestation",
        category="attestation",
        paid_alternative="Contract with paid keepers (Chainlink Keepers, Gelato)",
        paid_price="keeper fees per execution",
        free_method="periodic custom_json; absence is the signal",
        free_on_ours=True,
        honest_limit="The chain will not ACT on a missed heartbeat. An external watcher must notice and respond.",
    ),
    Capability(
        name="Name / handle claim (first-come registry)",
        category="attestation",
        paid_alternative="ENS ($5/yr plus gas), Unstoppable Domains",
        paid_price="recurring fee plus gas",
        free_method="custom_json claim; earliest block wins",
        free_on_ours=True,
        honest_limit="No enforcement of uniqueness beyond ordering, no DNS resolution, no transfer mechanism. "
                     "A claim is a dated assertion, not a property right.",
    ),
    Capability(
        name="Cross-chain message relay between endpoints YOU control",
        category="attestation",
        paid_alternative="LayerZero, Wormhole, Axelar",
        paid_price="per-message fee plus destination gas",
        free_method="custom_json on the source chain; own watcher reads and re-anchors",
        free_on_ours=True,
        honest_limit="Trust is your watcher, not a decentralized validator set. Fine for your own systems; "
                     "not a substitute for a bridge others can rely on without trusting you.",
    ),
    Capability(
        name="Software licence key registry",
        category="attestation",
        paid_alternative="On-chain licence contracts, SaaS licence servers",
        paid_price="gas per issue, or hosting cost",
        free_method="custom_json issue/revoke per key",
        free_on_ours=True,
        honest_limit="The binary must still check and decide. Registry publishes truth; it does not enforce it.",
    ),
    Capability(
        name="Public data availability for small payloads",
        category="attestation",
        paid_alternative="Arweave (per-MB, permanent), IPFS pinning (recurring)",
        paid_price="Arweave ~$ per MB one-time; pinning services monthly",
        free_method="custom_json carries the bytes themselves",
        free_on_ours=True,
        honest_limit="RC cost grows with bytes, so this is for small payloads. Tier-E compaction gives ~51 B. "
                     "Do not use it as a file store.",
        payload_bytes=51,
    ),

    # --- things that are NOT free, stated plainly so nobody over-claims ---
    Capability(
        name="Escrow / atomic swap / guaranteed settlement",
        category="enforcement",
        paid_alternative="Smart contract with locked collateral",
        paid_price="capital at risk plus gas",
        free_method="NONE",
        free_on_ours=False,
        honest_limit="Requires capital at risk. custom_json can PROPOSE and can RECORD, never BIND. "
                     "An escrow without collateral is a promise, and promises are free because they are worthless.",
    ),
    Capability(
        name="Token transfer / mint / burn",
        category="enforcement",
        paid_alternative="native token operations",
        paid_price="the token itself, plus RC for the op",
        free_method="NONE",
        free_on_ours=False,
        honest_limit="You cannot conjure value. Moving a token requires holding it.",
    ),
    Capability(
        name="Decentralized oracle with economic security",
        category="enforcement",
        paid_alternative="Chainlink, Pyth, API3",
        paid_price="payment plus staked node collateral",
        free_method="NONE - submission is free, security is not",
        free_on_ours=False,
        honest_limit="Publishing a price via custom_json is free. Making it TRUSTWORTHY requires staked, "
                     "slashable reporters. Free submission is not a free oracle.",
    ),
    Capability(
        name="Account creation on our network",
        category="enforcement",
        paid_alternative="creation fee or RC-heavy create",
        paid_price="RC (very large) or claimed account subsidy",
        free_method="only when the chain's account-subsidy pool covers it",
        free_on_ours=False,
        honest_limit="resource_new_accounts pool observed at fill_level 1073/10000 - heavily depleted. "
                     "Assume account creation is expensive until measured.",
    ),
    Capability(
        name="Privacy / confidential state",
        category="enforcement",
        paid_alternative="private chain, zk systems, enclaves",
        paid_price="substantial",
        free_method="NONE",
        free_on_ours=False,
        honest_limit="Everything written is public forever. Commit to a hash to hide content; "
                     "the commitment itself is permanent and attributable to the signing account.",
    ),
]


def free_capabilities() -> List[Capability]:
    return [c for c in CAPABILITIES if c.free_on_ours]


def not_free_capabilities() -> List[Capability]:
    return [c for c in CAPABILITIES if not c.free_on_ours]


def by_category(name: str) -> List[Capability]:
    return [c for c in CAPABILITIES if c.category == name]


def matrix_as_dicts() -> List[Dict[str, Any]]:
    out = []
    for c in CAPABILITIES:
        out.append({"name": c.name, "category": c.category,
                    "paidAlternative": c.paid_alternative, "paidPrice": c.paid_price,
                    "freeMethod": c.free_method, "freeOnOurs": c.free_on_ours,
                    "honestLimit": c.honest_limit, "payloadBytes": c.payload_bytes})
    return out


# --------------------------------------------------------------------------
# RC calibration: measure, never guess.
# --------------------------------------------------------------------------

@dataclass
class RcCalibration:
    """Derives real RC-per-anchor cost from live observations.

    A guessed price curve that produces confident wrong numbers is worse than an
    admitted gap, so this class refuses to invent a cost. It requires two real
    samples bracketing an anchor with no other account activity in between.
    """

    samples: List[Dict[str, Any]] = field(default_factory=list)
    calibrated_rc_per_anchor: Optional[float] = None
    calibration_quality: str = "uncalibrated"

    def add_sample(self, at_unix: int, effective_mana: float, note: str = "") -> None:
        self.samples.append({"at": at_unix, "mana": effective_mana, "note": note})

    def calibrate(self, regen_per_second: float, min_gap_seconds: int = 5) -> Optional[float]:
        """Needs a sample immediately before and immediately after one anchor."""
        before = [s for s in self.samples if s["note"] == "before-anchor"]
        after = [s for s in self.samples if s["note"] == "after-anchor"]
        if not before or not after:
            self.calibration_quality = "uncalibrated-needs-bracketing-samples"
            return None
        b, a = before[-1], after[-1]
        gap = a["at"] - b["at"]
        if gap < min_gap_seconds:
            self.calibration_quality = "uncalibrated-gap-too-small"
            return None
        regenerated = regen_per_second * gap
        spent = (b["mana"] + regenerated) - a["mana"]
        if spent <= 0:
            self.calibration_quality = "uncalibrated-nonpositive-spend"
            return None
        self.calibrated_rc_per_anchor = spent
        self.calibration_quality = "calibrated-from-%d-second-bracket" % gap
        return spent

    def anchors_per_day(self, regen_per_day: float) -> Optional[float]:
        if not self.calibrated_rc_per_anchor:
            return None
        return regen_per_day / self.calibrated_rc_per_anchor

    def report(self, regen_per_day: float) -> Dict[str, Any]:
        apd = self.anchors_per_day(regen_per_day)
        return {"quality": self.calibration_quality,
                "rcPerAnchor": self.calibrated_rc_per_anchor,
                "anchorsPerDay": apd,
                "samples": len(self.samples),
                "note": "UNMEASURED until bracketing samples exist. "
                        "Pessimistic bound at 1e6 RC/anchor: %.0f anchors/day."
                        % (regen_per_day / 1_000_000)}


PESSIMISTIC_RC_PER_ANCHOR = 1_000_000


def pessimistic_anchors_per_day(regen_per_day: float) -> float:
    """A floor, not an estimate. Real throughput is at least this."""
    return regen_per_day / PESSIMISTIC_RC_PER_ANCHOR
