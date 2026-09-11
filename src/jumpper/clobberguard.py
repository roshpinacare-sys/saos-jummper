"""Clobber guard - refuse to overwrite work that is not yours.

Two agents independently built committerwatch.py in this repository. The second
pushed over the first, destroying a richer API (Commit as a dataclass, from_api,
burst_risk, broadcast_fanout, verify_claim). The coverage harness going red on an
AttributeError was the only reason anyone noticed. The destroyed module detected
committer collisions, and it was overwritten by an agent that had just written
about how dangerous that is.

Nothing prevented it because nothing asked. A write to a path that already has
content succeeds silently. This module is the question that was not asked.

RULE: a new file is always allowed. Overwriting a file whose last committer is a
different identity is refused unless forced, and forcing is recorded rather than
silent. Where content differs the guard names exactly which exported names would
be destroyed, so the caller can merge instead of replace.

It never edits and never calls the network.
"""
from __future__ import annotations
import hashlib, re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
ALLOW = "allow"
REFUSE = "refuse"
MERGE_REQUIRED = "merge-required"
class ClobberError(ValueError): pass
def _norm(n: str) -> str:
    """Collapse hyphen, space, underscore and case - two identities in saos-dex
    differ only by a hyphen and are almost certainly one actor."""
    return re.sub(r"[\s\-_]+", "", (n or "")).lower()
def _digest(t: str) -> str:
    return hashlib.sha256((t or "").encode("utf-8")).hexdigest()
def _names(src: str) -> Set[str]:
    """Public names a module exports - what would be lost."""
    out: Set[str] = set()
    for m in re.finditer(r"(?m)^(?:def|class)\s+([A-Za-z_]\w*)", src or ""):
        if not m.group(1).startswith("_"): out.add(m.group(1))
    for m in re.finditer(r"(?m)^([A-Z][A-Z0-9_]{2,})\s*=", src or ""): out.add(m.group(1))
    return out
@dataclass(frozen=True)
class ClobberVerdict:
    decision: str
    path: str
    reason: str
    existing_author: Optional[str] = None
    caller_identity: Optional[str] = None
    same_author: Optional[bool] = None
    identical: bool = False
    lost_names: List[str] = field(default_factory=list)
    gained_names: List[str] = field(default_factory=list)
    forced: bool = False
    action: str = ""
    def as_dict(self) -> Dict[str, Any]:
        return {"decision": self.decision, "path": self.path, "reason": self.reason,
                "existingAuthor": self.existing_author, "callerIdentity": self.caller_identity,
                "sameAuthor": self.same_author, "identical": self.identical,
                "lostNames": self.lost_names, "gainedNames": self.gained_names,
                "forced": self.forced, "action": self.action}
def assess(path, proposed, existing, existing_author, caller_identity,
           existing_date=None, force=False) -> ClobberVerdict:
    """Decide whether a write may proceed. existing=None means the path is new."""
    if not path: raise ClobberError("path required")
    if not isinstance(caller_identity, str) or not caller_identity.strip():
        raise ClobberError("caller_identity required; an anonymous overwrite cannot be investigated")
    if not isinstance(proposed, str): raise ClobberError("proposed content must be a string")
    if existing is None:
        return ClobberVerdict(ALLOW, path, "new file; nothing to overwrite",
            caller_identity=caller_identity, same_author=None, action="create")
    if _digest(existing) == _digest(proposed):
        return ClobberVerdict(ALLOW, path, "byte-identical; the write is a no-op",
            existing_author=existing_author, caller_identity=caller_identity,
            same_author=_norm(existing_author or "") == _norm(caller_identity),
            identical=True, action="noop")
    lost = sorted(_names(existing) - _names(proposed))
    gained = sorted(_names(proposed) - _names(existing))
    mine = _norm(existing_author or "") == _norm(caller_identity)
    if mine:
        return ClobberVerdict(ALLOW, path, "last committer is the caller",
            existing_author=existing_author, caller_identity=caller_identity,
            same_author=True, lost_names=lost, gained_names=gained, action="replace-own")
    if lost:
        base = ("the existing file by %r exports %s and the replacement does not - "
                "these would be destroyed" % (existing_author, ", ".join(lost[:8])))
        if force:
            return ClobberVerdict(MERGE_REQUIRED, path, base + " (FORCED - recorded)",
                existing_author=existing_author, caller_identity=caller_identity,
                same_author=False, lost_names=lost, gained_names=gained, forced=True,
                action="forced-replace-with-loss")
        return ClobberVerdict(REFUSE, path, base, existing_author=existing_author,
            caller_identity=caller_identity, same_author=False, lost_names=lost,
            gained_names=gained, action="merge-or-rename")
    if force:
        return ClobberVerdict(MERGE_REQUIRED, path, "no exported-name loss (FORCED)",
            existing_author=existing_author, caller_identity=caller_identity,
            same_author=False, lost_names=lost, gained_names=gained, forced=True,
            action="forced-replace")
    return ClobberVerdict(REFUSE, path,
        "last written by %r, not %r; overwriting another identity requires an "
        "explicit force, and a merge is usually what was meant"
        % (existing_author, caller_identity), existing_author=existing_author,
        caller_identity=caller_identity, same_author=False, lost_names=lost,
        gained_names=gained, action="merge-or-rename")
def merge_plan(path, proposed, existing) -> Dict[str, Any]:
    """What a merge would have to reconcile. Does not perform one."""
    e = _names(existing); p = _names(proposed)
    return {"path": path, "onlyInExisting": sorted(e - p), "onlyInProposed": sorted(p - e),
            "inBoth": sorted(e & p), "existingBytes": len((existing or "").encode("utf-8")),
            "proposedBytes": len((proposed or "").encode("utf-8")),
            "verdict": ("a rename is cheaper than a merge" if not (e & p) else
                        "%d name(s) collide and must be reconciled by hand" % len(e & p))}
