"""Rotation contract - the control that was missing on 2026-09-08.

WHAT HAPPENED
-------------
At 2026-09-08T21:17:42 the account headcorner had all four authorities
(owner, active, posting, memo) replaced on HIVE mainnet:

    block   109,745,168
    trx     92654439d97f4cd30a70a5ced46b2bd93488b722
    op      account_update

Nothing was taken - the balance stayed at 9.682 HIVE and vesting at
17,511.838295 VESTS. It was the estate's own script, steem/agent/keyrotate.cjs,
whose default target is:

    const ACCOUNT = (process.env.AGENT_ACCOUNT || 'headcorner').toLowerCase();

Run with no arguments, it rotates the PRIMARY account. And it left the owner no
way to learn the new keys: the evidence file it writes stores masked public keys
(STM86gwPfu...), so even the evidence cannot be used to verify a recovery.

The owner recovered because the scheme is deterministic - keys derive from
sha256(username + role + FACTORY_MASTER) via steem.auth.getPrivateKeys, and the
master lived in a gitignored .env on the agent machine. That was luck of design,
not a control. If the derivation had been random, or the machine gone, the account
would have been unrecoverable until the 30-day recover_account window closed.

WHAT THIS MODULE ADDS
---------------------
Three controls, none of which require any cryptography:

1. No default account. A rotation with no explicit target is refused. The primary
   account additionally requires a second, separate confirmation.
2. A handoff artifact that the owner can actually use: all four public keys
   UNMASKED, the chain, the derivation scheme NAME (never the master), the
   recovery-window deadline, and a destination that must be OUTSIDE the repository.
3. A gate that runs before the broadcast, not after: explicit target, primary
   confirmation, verified backup, handoff destination outside the repo, and an
   audit record of the attempt whether it proceeds or is refused.

This module never derives, holds, reads or writes a private key. It is policy.
"""

from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

ALLOW = "allow"
DENY = "deny"
ROLES = ("owner", "active", "posting", "memo")
RECOVERY_WINDOW_DAYS = 30      # Hive/Steem recover_account window from last_owner_update

# Patterns that must never appear in a handoff artifact. A handoff is meant to be
# readable by the owner and storable outside the repo; if it carries secret
# material it becomes a second breach surface instead of a recovery aid.
FORBIDDEN = (
    (r"\b5[HJK][1-9A-HJ-NP-Za-km-z]{40,}\b", "WIF private key"),
    (r"\bxprv[1-9A-HJ-NP-Za-km-z]{60,}\b", "extended private key"),
    (r"\bL[1-9A-HJ-NP-Za-km-z]{40,}\b", "compressed WIF"),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "PEM private key"),
    (r"FACTORY_MASTER\s*[:=]\s*\S{8,}", "master secret value"),
    (r"\b(?:[a-z]{3,8}\s+){11}[a-z]{3,8}\b", "12-word mnemonic"),
)


class RotationError(ValueError):
    pass


@dataclass(frozen=True)
class HandoffArtifact:
    """What the owner receives on every rotation. No secrets, by construction."""

    account: str
    chains: Sequence[str]
    public_keys: Dict[str, Dict[str, str]]     # chain -> role -> public key
    derivation_scheme: str                      # the NAME of the scheme, never the master
    rotated_at: str
    recovery_deadline: str
    handoff_path: str
    txids: Dict[str, str] = field(default_factory=dict)
    notes: Sequence[str] = ()

    def as_dict(self) -> Dict[str, Any]:
        return {"account": self.account, "chains": list(self.chains),
                "publicKeys": {c: dict(v) for c, v in self.public_keys.items()},
                "derivationScheme": self.derivation_scheme,
                "rotatedAt": self.rotated_at,
                "recoveryDeadline": self.recovery_deadline,
                "handoffPath": self.handoff_path, "txids": dict(self.txids),
                "notes": list(self.notes)}


def scan_for_secrets(text: str) -> List[str]:
    """Return every secret pattern found. Must be empty for any artifact we emit."""
    found = []
    for rx, label in FORBIDDEN:
        if re.search(rx, text):
            found.append(label)
    return found


def validate_public_keys(public_keys: Dict[str, Dict[str, str]],
                         chains: Sequence[str]) -> List[str]:
    """Every chain must carry all four roles, unmasked. Masked keys are useless
    for verification, which is exactly how the 2026-09-08 rotation left its owner.
    """
    problems: List[str] = []
    for chain in chains:
        roles = public_keys.get(chain) or {}
        for role in ROLES:
            k = roles.get(role)
            if not k:
                problems.append("%s/%s missing" % (chain, role))
                continue
            if "..." in k or k.endswith("\u2026") or len(k) < 40:
                problems.append("%s/%s is MASKED or truncated (%r) - an owner cannot "
                                "verify a recovery against it" % (chain, role, k[:20]))
    return problems


def build_handoff(account: str, chains: Sequence[str],
                  public_keys: Dict[str, Dict[str, str]],
                  derivation_scheme: str, handoff_path: str,
                  repo_root: Optional[str] = None,
                  rotated_at: Optional[str] = None,
                  txids: Optional[Dict[str, str]] = None,
                  notes: Sequence[str] = ()) -> HandoffArtifact:
    """Build the artifact, refusing if it is incomplete or carries a secret."""
    if not account:
        raise RotationError("account required")
    if not chains:
        raise RotationError("at least one chain required")
    if not derivation_scheme:
        raise RotationError("derivation scheme name required so the owner knows how "
                            "to re-derive; the master itself must never appear")
    if not handoff_path:
        raise RotationError("handoff destination required")
    if repo_root and _inside(repo_root, handoff_path):
        raise RotationError("handoff must be written OUTSIDE the repository tree; "
                            "%r is inside %r" % (handoff_path, repo_root))
    problems = validate_public_keys(public_keys, chains)
    if problems:
        raise RotationError("handoff is not usable by the owner: " + "; ".join(problems))
    ts = rotated_at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    deadline = _plus_days(ts, RECOVERY_WINDOW_DAYS)
    art = HandoffArtifact(account=account, chains=list(chains), public_keys=public_keys,
                          derivation_scheme=derivation_scheme, rotated_at=ts,
                          recovery_deadline=deadline, handoff_path=handoff_path,
                          txids=dict(txids or {}), notes=list(notes))
    blob = _serialise(art)
    leaks = scan_for_secrets(blob)
    if leaks:
        raise RotationError("handoff would contain secret material: " + ", ".join(leaks))
    if "FACTORY_MASTER" in art.derivation_scheme and "=" in art.derivation_scheme:
        raise RotationError("derivation scheme must name the scheme, not carry the master")
    return art


def _serialise(art: HandoffArtifact) -> str:
    import json
    return json.dumps(art.as_dict(), sort_keys=True, separators=(",", ":"))


def _inside(root: str, path: str) -> bool:
    try:
        r = os.path.abspath(root)
        p = os.path.abspath(path)
    except (TypeError, ValueError):
        return False
    return p == r or p.startswith(r + os.sep)


def _plus_days(iso: str, days: int) -> str:
    try:
        t = time.strptime(iso, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return "unknown"
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.mktime(t) + days * 86400))


# ---------------------------------------------------------------------------
# The gate
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class GateCheck:
    name: str
    passed: bool
    detail: str


def rotation_gate(account: Optional[str], chains: Sequence[str],
                  primary_accounts: Sequence[str], confirm_primary: bool,
                  backup_verified: bool, handoff: Optional[HandoffArtifact],
                  repo_root: Optional[str] = None,
                  dry_run: bool = False) -> Dict[str, Any]:
    """Everything that must be true BEFORE an account_update is broadcast.

    AND-composed and fail-closed: any failed check denies, and a check that cannot
    be evaluated denies. A refused rotation is still recorded, because the record of
    an attempt is what tells you an agent tried.
    """
    checks: List[GateCheck] = []

    if not account:
        checks.append(GateCheck("explicit-account", False,
                                "no account supplied; refusing to fall back to a default. "
                                "The 2026-09-08 rotation happened because AGENT_ACCOUNT "
                                "was unset and the script defaulted to the primary account"))
    else:
        checks.append(GateCheck("explicit-account", True, account))

    if account and account in set(primary_accounts):
        checks.append(GateCheck("primary-confirmation", bool(confirm_primary),
                                "confirmed for the primary account" if confirm_primary else
                                "%r is a primary account and requires a separate explicit "
                                "confirmation" % account))

    if not chains:
        checks.append(GateCheck("chains-declared", False, "no chains declared"))
    else:
        checks.append(GateCheck("chains-declared", True, ", ".join(chains)))

    checks.append(GateCheck("backup-verified", bool(backup_verified),
                            "a verified backup exists" if backup_verified else
                            "no verified backup; a rotation without one is unrecoverable "
                            "if the derivation is ever lost"))

    if handoff is None:
        checks.append(GateCheck("handoff-built", False,
                                "no handoff artifact; the owner would have no way to learn "
                                "the new keys"))
    else:
        try:
            usable = not validate_public_keys(handoff.public_keys, handoff.chains)
            leaked = scan_for_secrets(_serialise(handoff))
        except Exception as exc:
            # A handoff object that cannot be inspected is not a pass. Raising here
            # would abort the whole gate and leave the caller with no verdict at all,
            # which is worse than a denial.
            checks.append(GateCheck("handoff-built", False,
                                    "handoff could not be evaluated (%s: %s); "
                                    "an unevaluated check denies"
                                    % (type(exc).__name__, str(exc)[:80])))
            usable = leaked = None
        if usable is not None:
            # Without repo_root the gate cannot tell where the handoff lands. That is
            # not a pass - it is an unevaluated check, and unevaluated means deny.
            if not repo_root:
                inside = None
            else:
                inside = _inside(repo_root, handoff.handoff_path)
            ok = usable and not leaked and inside is False
            detail = []
            if not usable:
                detail.append("public keys missing or masked")
            if inside is None:
                detail.append("repo_root not supplied, so the handoff location cannot be "
                              "verified as outside the repository")
            elif inside:
                detail.append("handoff path is inside the repository")
            if leaked:
                detail.append("handoff carries secret material: " + ", ".join(leaked))
            checks.append(GateCheck("handoff-built", ok,
                                    "; ".join(detail) or "usable, outside repo, secret-free"))

    failed = [c for c in checks if not c.passed]
    decision = DENY if (failed and not dry_run) else (ALLOW if not failed else DENY)
    return {
        "decision": decision,
        "account": account,
        "chains": list(chains),
        "dryRun": dry_run,
        "checks": [{"name": c.name, "passed": c.passed, "detail": c.detail} for c in checks],
        "failedChecks": [c.name for c in failed],
        "reason": ("all checks passed" if not failed else
                   "refused: " + "; ".join(c.name for c in failed)),
        "note": ("dry_run still reports the refusal so the operator sees it before "
                 "committing; it does not authorise a broadcast" if dry_run and failed else None),
    }


def audit_record(account: Optional[str], chains: Sequence[str], gate: Dict[str, Any],
                 actor: str = "unknown") -> Dict[str, Any]:
    """Record the attempt whether or not it proceeded. A refused rotation that is
    not recorded is indistinguishable from a rotation nobody tried."""
    return {"event": "key_rotation_attempt", "account": account,
            "chains": list(chains), "actor": actor,
            "decision": gate["decision"], "failedChecks": gate["failedChecks"],
            "reason": gate["reason"],
            "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
