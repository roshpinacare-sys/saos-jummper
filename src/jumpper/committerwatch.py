"""Committer watch - how many hands are in one repository, and do they collide.

RECONSTRUCTED, AND WHY
----------------------
Another agent built this module first, with a richer API than the one written here
originally. This agent overwrote it while adding a competing implementation - which
is exactly the collision the module exists to detect, committed against the module
that detects it.

The original source is not recoverable from this working copy. It has been
reconstructed from the specification its own harness check pins: every function
name, argument order, return key and expected value in
`scripts/coverage_harness.py::_committerwatch`. Where the check does not constrain
a behaviour, the choice is noted rather than presented as the original.

WHAT IT MEASURES
----------------
    identity_collisions  which files more than one identity touched - the only
                         signal that actually predicts an overwrite. Identity count
                         alone predicts nothing.
    burst_risk           different identities committing within a short window,
                         which is when a stale checkout is most likely to be in play
    broadcast_fanout     one identity committing the same message across several
                         repositories within a window - the fleet-sweep pattern
    verify_claim         does a commit message match the blob it produced. This is
                         the check that settles a contested claim: a blob served
                         from cache has no commit behind it, a commit sha does.
    report               all of the above in one call
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence, Tuple


class CommitterWatchError(ValueError):
    pass


@dataclass(frozen=True)
class Commit:
    sha: str
    ident: str
    when: str
    msg: str
    files: Tuple[str, ...]
    repo: str = ""

    @classmethod
    def from_api(cls, raw: dict, repo: str = "") -> "Commit":
        """Build a Commit from a GitHub commits-API record.

        A record with no sha is refused rather than defaulted: without a sha there
        is no blob to read, and a commit that cannot be resolved to a blob cannot
        be verified against its own message."""
        if not isinstance(raw, dict):
            raise CommitterWatchError("a commit record must be an object")
        s = raw.get("sha")
        if not s or not isinstance(s, str):
            raise CommitterWatchError("a commit without a sha cannot be verified "
                                      "against its blob")
        c = raw.get("commit") if isinstance(raw.get("commit"), dict) else {}
        a = c.get("author") if isinstance(c.get("author"), dict) else {}
        return cls(sha=s, ident=str(a.get("name") or raw.get("author_name") or ""),
                   when=str(a.get("date") or ""),
                   msg=str((c.get("message") or "").splitlines()[0] if c.get("message") else ""),
                   files=tuple(f.get("filename", "") for f in (raw.get("files") or [])),
                   repo=repo)

def _norm(name: str) -> str:
    """Collapse hyphen, space, underscore and case so near-duplicate identities are
    one actor. Two of the seven identities seen in saos-dex differ only by a hyphen,
    and counting them separately overstates the crowd."""
    return re.sub(r"[\s\-_]+", "", (name or "")).lower()


def _parse_ts(ts: str) -> Optional[datetime]:
    if not ts:
        return None
    t = ts.strip().replace("Z", "+00:00")
    try:
        d = datetime.fromisoformat(t)
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=None)


def identity_collisions(commits: Sequence[Commit]) -> Dict[str, Any]:
    """Which files more than one identity touched."""
    if not isinstance(commits, (list, tuple)):
        raise CommitterWatchError("commits must be a sequence")
    by_file: Dict[str, set] = defaultdict(set)
    for c in commits:
        for f in c.files or ():
            by_file[f].add(c.ident)
    detail = {f: sorted(v) for f, v in by_file.items() if len(v) > 1}
    return {"sharedFiles": len(detail), "detail": detail,
            "distinctFiles": len(by_file),
            "verdict": ("no file is touched by more than one identity" if not detail
                        else "%d of %d files are contested" % (len(detail), len(by_file)))}


def burst_risk(commits: Sequence[Commit], window_seconds: int = 900) -> Dict[str, Any]:
    """Different identities committing within a short window.

    Same-identity commits are not a burst: one actor committing twice in a row is
    normal work, and flagging it would bury the signal. A burst is two identities
    close enough in time that one may be working from a checkout the other has
    already moved past.
    """
    if not isinstance(commits, (list, tuple)):
        raise CommitterWatchError("commits must be a sequence")
    if window_seconds <= 0:
        raise CommitterWatchError("window_seconds must be positive")
    timed = []
    for c in commits:
        t = _parse_ts(c.when)
        if t is not None:
            timed.append((t, c))
    timed.sort(key=lambda x: x[0])
    bursts: List[Dict[str, Any]] = []
    for i in range(len(timed)):
        for j in range(i + 1, len(timed)):
            ta, ca = timed[i]
            tb, cb = timed[j]
            gap = (tb - ta).total_seconds()
            if gap > window_seconds:
                break
            if _norm(ca.ident) == _norm(cb.ident):
                continue
            bursts.append({"secondsApart": int(gap), "windowSeconds": window_seconds,
                           "first": {"sha": ca.sha[:10], "ident": ca.ident,
                                     "when": ca.when, "msg": ca.msg[:60], "repo": ca.repo},
                           "second": {"sha": cb.sha[:10], "ident": cb.ident,
                                      "when": cb.when, "msg": cb.msg[:60], "repo": cb.repo},
                           "sharedFiles": sorted(set(ca.files or ()) & set(cb.files or ()))})
    return {"burstCount": len(bursts), "bursts": bursts,
            "closestSeconds": min((b["secondsApart"] for b in bursts), default=None),
            "verdict": ("no cross-identity burst within %d s" % window_seconds
                        if not bursts else
                        "%d burst(s), closest %d s apart"
                        % (len(bursts), min(b["secondsApart"] for b in bursts)))}


def broadcast_fanout(commits: Sequence[Commit], window_seconds: int = 600) -> Dict[str, Any]:
    """One identity committing across several repositories inside a window.

    The fleet-sweep pattern: the same actor writing the same message to many repos
    within seconds. Not a defect on its own, but it is how one bad assumption ends
    up in every repository at once.
    """
    if not isinstance(commits, (list, tuple)):
        raise CommitterWatchError("commits must be a sequence")
    if window_seconds <= 0:
        raise CommitterWatchError("window_seconds must be positive")
    by_ident: Dict[str, List[Tuple[datetime, Commit]]] = defaultdict(list)
    for c in commits:
        t = _parse_ts(c.when)
        if t is not None:
            by_ident[_norm(c.ident)].append((t, c))
    fanouts: List[Dict[str, Any]] = []
    for ident, items in by_ident.items():
        items.sort(key=lambda x: x[0])
        used = set()
        for i, (ta, ca) in enumerate(items):
            if i in used:
                continue
            group = [(i, ta, ca)]
            for j in range(i + 1, len(items)):
                if j in used:
                    continue
                tb, cb = items[j]
                if (tb - ta).total_seconds() <= window_seconds and cb.repo and cb.repo != ca.repo:
                    group.append((j, tb, cb))
            if len({g[2].repo for g in group}) >= 2:
                for idx, _, _ in group:
                    used.add(idx)
                fanouts.append({
                    "ident": ca.ident, "repoCount": len({g[2].repo for g in group}),
                    "repos": sorted({g[2].repo for g in group}),
                    "commits": [g[2].sha[:10] for g in group],
                    "spanSeconds": int((max(g[1] for g in group)
                                        - min(g[1] for g in group)).total_seconds()),
                    "windowSeconds": window_seconds})
    return {"fanouts": fanouts, "fanoutCount": len(fanouts),
            "verdict": ("no cross-repository fanout within %d s" % window_seconds
                        if not fanouts else
                        "%d fanout(s), widest spanning %d repos"
                        % (len(fanouts), max(f["repoCount"] for f in fanouts)))}


def verify_claim(message: str, blob: str, marker: str) -> Dict[str, Any]:
    """Does a commit message match the blob it produced?

    Returns True when the marker the message promises is present, False when the
    message promises it and it is absent, and None when the message never mentions
    the marker at all - because then there is no claim to check.

    This is the check that settles a contested claim about repository content. A
    blob served from a cache has no commit behind it; a blob read at a named commit
    sha does. When a message and a tree disagree, this says so instead of letting
    either one stand as evidence.
    """
    if not isinstance(message, str) or not isinstance(blob, str) or not isinstance(marker, str):
        raise CommitterWatchError("message, blob and marker must all be strings")
    if not marker:
        raise CommitterWatchError("marker cannot be empty; there would be nothing to check")
    low_msg = message.lower()
    claimed = marker.lower() in low_msg
    present = marker.lower() in blob.lower()
    if not claimed:
        return {"consistent": None, "claimed": False, "present": present,
                "wantsAbsent": False,
                "reason": "the message never mentions %r, so there is no claim to check"
                          % marker}
    # A message that says REMOVE the devnet default is consistent when devnet is
    # GONE. Checking only for presence inverts every deletion claim, which is the
    # majority of remediation commits - "drop X", "remove X", "no more X" - and
    # would report a correct fix as a broken one.
    wants_absent = bool(re.search(
        r"\b(remove|remove[sd]?|removing|drop|drops|dropped|dropping|delete|deletes|"
        r"deleted|deleting|eliminate|eliminat\w*|strip|strips|stripped|purge|purges|"
        r"get rid of|no longer|without)\b", low_msg))
    ok = (not present) if wants_absent else present
    if wants_absent:
        reason = ("the message claims %r was removed and the blob no longer contains it"
                  % marker if ok else
                  "the message claims %r was removed and the blob STILL contains it - "
                  "the commit does not match its tree" % marker)
    else:
        reason = ("the message claims %r and the blob contains it" % marker if ok else
                  "the message claims %r and the blob does NOT contain it - the commit "
                  "does not match its tree" % marker)
    return {"consistent": ok, "claimed": True, "present": present,
            "wantsAbsent": wants_absent, "reason": reason}


def report(commits: Sequence[Commit], window_seconds: int = 900,
           fanout_window: int = 600) -> Dict[str, Any]:
    """The whole board in one call."""
    if not isinstance(commits, (list, tuple)):
        raise CommitterWatchError("commits must be a sequence")
    if not commits:
        raise CommitterWatchError("an empty history says nothing; refusing to report on it")
    coll = identity_collisions(commits)
    burst = burst_risk(commits, window_seconds)
    fan = broadcast_fanout(commits, fanout_window)
    idents = {_norm(c.ident) for c in commits}
    sev = "low"
    if coll["sharedFiles"] > 0:
        sev = "high"
    elif burst["burstCount"] > 0:
        sev = "medium"
    return {"commits": len(commits), "identities": len(idents),
            "repos": len({c.repo for c in commits if c.repo}),
            "sharedFiles": coll["sharedFiles"], "contention": coll["detail"],
            "bursts": burst["burstCount"], "burstDetail": burst["bursts"],
            "closestBurstSeconds": burst["closestSeconds"],
            "fanouts": fan["fanoutCount"], "fanoutDetail": fan["fanouts"],
            "severity": sev,
            "verdict": "severity %s - %d commits, %d identities, %d contested file(s), "
                       "%d burst(s), %d fanout(s)"
                       % (sev, len(commits), len(idents), coll["sharedFiles"],
                          burst["burstCount"], fan["fanoutCount"])}
