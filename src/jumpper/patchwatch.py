"""Patch watch - did the recommended fixes actually land?

This engagement produced recommendations across five repositories. Some were
applied by other agents and tagged in source (FIX(CROSS-F-01),
FIX(CROSS-F-02, saos-jummper), FIX(SETTLE-7)); some were not. A recommendation
nobody can check the status of quietly stops mattering.

This module reads real source and reports PRESENT, ABSENT or INDETERMINATE per
item. It never edits anything and never guesses: a check that cannot decide says
so, and a check that raises is indeterminate rather than green - because a
fail-absent check reads as a pass to any caller that only inspects the verdict.

Calibrated against the live saos-dex relay sources on 2026-09-11.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Sequence

PRESENT = "present"
ABSENT = "absent"
INDETERMINATE = "indeterminate"

class PatchWatchError(ValueError):
    pass

@dataclass(frozen=True)
class Fix:
    fid: str
    title: str
    repo: str
    path: str
    severity: str
    why: str
    present_rx: Optional[str]
    absent_rx: Optional[str]
    requires: Optional[str] = None

@dataclass(frozen=True)
class FixResult:
    fix: Fix
    status: str
    evidence: str
    def as_dict(self) -> Dict[str, Any]:
        return {"id": self.fix.fid, "title": self.fix.title, "repo": self.fix.repo,
                "path": self.fix.path, "severity": self.fix.severity,
                "status": self.status, "evidence": self.evidence, "why": self.fix.why}

def _has(rx: Optional[str], src: str) -> bool:
    return bool(rx) and bool(re.search(rx, src))

def _line_of(rx: Optional[str], src: str) -> str:
    if not rx:
        return ""
    m = re.search(rx, src)
    if not m:
        return ""
    s = src.rfind(chr(10), 0, m.start()) + 1
    e = src.find(chr(10), m.end())
    return src[s:e if e > 0 else len(src)].strip()[:140]

FIXES: List[Fix] = [
    Fix('P-01', 'epoch field in the canonical anchor payload', 'saos-dex',
        'src/lib/dex/relay.ts', 'critical',
        'Height restarts every process incarnation; 8 heights on HIVE mainnet already carry contradictory roots.',
        'epoch\\s*[:,]', 'stateRoot'),
    Fix('P-02', 'POSTING authority for attestations instead of ACTIVE', 'saos-dex',
        'src/lib/dex/relay.ts', 'critical',
        'ACTIVE can transfer every asset; 57 of 62 attestations were signed with it.',
        'required_posting_auths\\s*:\\s*auth', 'required_auths\\s*:\\s*\\[account\\]'),
    Fix('P-03', 'searchTransactionHistory true in the Solana verifier', 'saos-dex',
        'src/lib/dex/relay-sol.ts', 'high',
        'False pins verified at 0; 27 successful mainnet anchors read as failures.',
        'searchTransactionHistory\\s*:\\s*true', 'searchTransactionHistory\\s*:\\s*false'),
    Fix('P-04', 'RC manabar projected forward, not read as a balance', 'saos-dex',
        'src/lib/dex/relay.ts', 'high',
        'A stale snapshot under-reported RC by 52.6x and declared HIVE blocked while it worked.',
        None, 'current_mana'),
    Fix('P-05', 'three-state verified flag, not an optimistic counter', 'saos-dex',
        'src/lib/dex/relay.ts', 'high',
        'verified=18 against anchored=16 is arithmetically impossible.',
        'verified\\s*:\\s*boolean\\s*\\|\\s*null', 'verified\\s*\\+=\\s*1'),
    Fix('P-06', 'no silent devnet default for the Solana endpoint', 'saos-dex',
        'src/lib/dex/relay-sol.ts', 'high',
        'It defaulted to devnet while Ethereum defaulted to mainnet, recorded identically.',
        None, 'api\\.devnet\\.solana\\.com'),
    Fix('P-07', 'digest and at dropped from the anchor payload', 'saos-dex',
        'src/lib/dex/relay.ts', 'medium',
        'digest is recomputable by anyone; at is the operator clock where the block timestamp is authority.',
        None, 'digest\\s*:\\s*job\\.info\\.digest'),
    Fix('P-08', 'network and endpoint host recorded with every anchor', 'saos-dex',
        'src/lib/dex/relay.ts', 'high',
        'No network identifier meant an anchor could not be told from a devnet one afterwards.',
        None, None),
    Fix('P-09', 'threshold parameter in Shamir reconstructSecret', 'Saosmartwallet',
        'packages/core/src/crypto/shamir.ts', 'high',
        'One share returns that share as the secret; two of three returns a WRONG secret silently.',
        'reconstructSecret\\s*\\([^)]*threshold', 'reconstructSecret\\s*\\(\\s*shares'),
    Fix('P-10', 'audit hash binds source, occurredAt, reason, actionId', 'roshpina',
        'kernel/orchestrator/audit.ts', 'high',
        'computeHash binds 5 of 11 fields, so who/when/why can be rewritten and verifyChain still passes.',
        None, None),
    Fix('P-11', 'xlock memos carry a mandatory reference id', 'saos-dex',
        'src/lib/dex/relay.ts', 'medium',
        'Two of three xlock ops carry no reference id, including the largest at 0.050 HIVE.',
        None, None),
    Fix('P-12', 'vault passphrase out of the committed state file', 'saos-dex',
        'state/pool.json', 'critical',
        'Ciphertext with its password beside it is plaintext with extra steps.',
        None, 'pass.{0,4}:'),
]

# P-04 needs BOTH a projection constant and a clamp; P-08 and P-10 and P-11 need
# compound conditions. Those are expressed as explicit predicates rather than
# shoehorned into a single regex, because a regex that approximates a conjunction
# is how a checker starts reporting green on code that is not fixed.
COMPOUND = {
    "P-04": lambda s: _has(r"432000", s) and _has(r"Math\.min\s*\(", s),
    "P-08": lambda s: _has(r"network\s*:", s) and _has(r"endpoint", s),
    "P-10": lambda s: _has(r"record\.source", s) and _has(r"record\.occurredAt", s),
    "P-11": lambda s: _has(r"xlock.{0,40}ref", s),
}
APPLIES = {
    "P-04": r"current_mana", "P-08": r"interface AnchorRecord",
    "P-10": r"computeHash", "P-11": r"xlock",
}

def check_fix(fix: Fix, source: Optional[str]) -> FixResult:
    """Evaluate one fix. A missing or empty file is INDETERMINATE, never a pass."""
    if source is None:
        return FixResult(fix, INDETERMINATE, "file not supplied; cannot decide")
    if not source.strip():
        return FixResult(fix, INDETERMINATE, "file is empty; cannot decide")
    try:
        if fix.fid in COMPOUND:
            gate = APPLIES.get(fix.fid)
            if gate and not _has(gate, source):
                return FixResult(fix, INDETERMINATE, "the code this applies to is not in this file")
            verdict = bool(COMPOUND[fix.fid](source))
        else:
            if fix.present_rx and _has(fix.present_rx, source):
                verdict = True
            elif fix.absent_rx and _has(fix.absent_rx, source):
                verdict = False
            else:
                verdict = None
    except Exception as exc:
        return FixResult(fix, INDETERMINATE,
            "check raised %s; treated as indeterminate, not as a pass" % type(exc).__name__)
    if verdict is None:
        return FixResult(fix, INDETERMINATE,
            "neither marker found, so this cannot decide")
    ev = _line_of(fix.present_rx or fix.absent_rx, source)
    return FixResult(fix, PRESENT if verdict else ABSENT, ev)

def watch(sources: Dict[str, str], only: Optional[Sequence[str]] = None) -> Dict[str, Any]:
    """Evaluate every fix against the supplied sources, keyed by repo/path."""
    if not isinstance(sources, dict):
        raise PatchWatchError("sources must be a mapping of repo/path to content")
    out: List[FixResult] = []
    for fix in FIXES:
        if only and fix.fid not in only:
            continue
        out.append(check_fix(fix, sources.get(fix.repo + "/" + fix.path)))
    counts = {PRESENT: 0, ABSENT: 0, INDETERMINATE: 0}
    for r in out:
        counts[r.status] = counts.get(r.status, 0) + 1
    open_crit = [r.fix.fid for r in out if r.status != PRESENT and r.fix.severity == "critical"]
    return {"results": [r.as_dict() for r in out], "total": len(out),
            "present": counts[PRESENT], "absent": counts[ABSENT],
            "indeterminate": counts[INDETERMINATE], "openCritical": open_crit,
            "verdict": ("all checks present" if counts[ABSENT] == 0 and counts[INDETERMINATE] == 0
                        else "%d present, %d absent, %d indeterminate; open critical: %s"
                        % (counts[PRESENT], counts[ABSENT], counts[INDETERMINATE], open_crit or "none"))}
