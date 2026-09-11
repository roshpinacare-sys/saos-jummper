"""Committer watch - who is writing what, and where they will collide.

WHY THIS EXISTS
---------------
Eight distinct committer identities were measured across five repositories in this
organisation over 271 commits spanning 2026-09-07 to 2026-09-11:

    Z User                       32 saos-dex   32 Saosmartwallet   38 steem
    roshpinacare-sys             26 saos-dex   28 roshpina   26 Saosmartwallet
                                 17 steem      58 saos-jummper
    saos-control-center-agent     1 in each of four repositories
    saos-agent                    1 in each of four repositories
    cloud-heart[bot]              3 steem
    saos-bot, saos-dex-agent, SAOS Operator    1 each

Two of those differ only by a hyphen or a space. Seventeen of one hundred
saos-dex commits are automated broadcast commits. There is no lock, no rebase
discipline and no ownership map.

That is the condition under which a stale checkout overwrites fresh work. It
already produced one near-miss that this agent misread as a loss: a commit titled
"relay: EPOCH-PATCH-SPEC adopted" was reported as absent from the tree, because a
single contents-API read returned a cached pre-patch blob. The work was never lost.
The next time it may be.

WHAT THIS MODULE MEASURES
-------------------------
1. identity collision   - how many distinct identities have written one file
2. burst risk           - different identities committing the same file within a
                          window, which is when a stale tree wins
3. broadcast fan-out    - one identity writing many repositories at once, which is
                          how a single stale checkout reaches every repo
4. claim verification   - does a commit whose message claims a change actually
                          contain it. A commit message is not evidence; the blob is.

It reads history supplied by the caller. It never writes, never pushes, and never
infers an identity that is not in the data.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple


class CommitterWatchError(ValueError):
    pass


@dataclass(frozen=True)
class Commit:
    sha: str
    identity: str
    when: str          # ISO-8601, as GitHub returns it
    message: str
    files: Sequence[str] = ()
    repo: str = ""

    @classmethod
    def from_api(cls, raw: Dict[str, Any], repo: str = "") -> "Commit":
        """Build from a GitHub /commits list entry. Files are not in the list
        response, so they arrive empty unless the caller fetched the detail."""
        if not isinstance(raw, dict):
            raise CommitterWatchError("commit must be an object")
        c = raw.get("commit") or {}
        author = c.get("author") or {}
        sha = raw.get("sha")
        if not sha:
            raise CommitterWatchError("commit has no sha")
        return cls(sha=str(sha), identity=str(author.get("name") or "unknown"),
                   when=str(author.get("date") or ""), message=str(c.get("message") or ""),
                   files=tuple(f.get("filename", "") for f in (raw.get("files") or [])),
                   repo=repo)


def _seconds(iso: str) -> Optional[float]:
    """Parse GitHub's ISO-8601 into epoch seconds. Returns None rather than guessing."""
    if not iso:
        return None
    import datetime as _dt
    try:
        s = iso.replace("Z", "+00:00")
        return _dt.datetime.fromisoformat(s).timestamp()
    except ValueError:
        return None


def identity_collisions(commits: Sequence[Commit]) -> Dict[str, Any]:
    """Which files have been written by more than one identity."""
    per_file: Dict[str, Set[str]] = {}
    for c in commits:
        for f in c.files:
            per_file.setdefault(f, set()).add(c.identity)
    shared = {f: sorted(v) for f, v in per_file.items() if len(v) > 1}
    identities = sorted({c.identity for c in commits})
    return {"identities": identities, "identityCount": len(identities),
            "files": len(per_file), "sharedFiles": len(shared),
            "detail": dict(sorted(shared.items(), key=lambda kv: (-len(kv[1]), kv[0]))),
            "verdict": ("no file is written by more than one identity"
                        if not shared else
                        "%d file(s) written by multiple identities; max %d"
                        % (len(shared), max(len(v) for v in shared.values())))}


def burst_risk(commits: Sequence[Commit], window_seconds: float = 900.0) -> Dict[str, Any]:
    """Same file, different identities, inside a window - the overwrite condition.

    A burst is not proof of a loss. It is the condition in which a stale checkout
    wins, and it is measurable before anything is lost.
    """
    if window_seconds <= 0:
        raise CommitterWatchError("window_seconds must be positive")
    by_file: Dict[str, List[Commit]] = {}
    for c in commits:
        for f in c.files:
            by_file.setdefault(f, []).append(c)
    bursts: List[Dict[str, Any]] = []
    for f, cs in by_file.items():
        timed = sorted([(t, c) for c in cs if (t := _seconds(c.when)) is not None],
                       key=lambda x: x[0])
        for i in range(len(timed)):
            for j in range(i + 1, len(timed)):
                gap = timed[j][0] - timed[i][0]
                if gap > window_seconds:
                    break
                if timed[i][1].identity != timed[j][1].identity:
                    bursts.append({"file": f, "secondsApart": int(gap),
                                   "first": {"sha": timed[i][1].sha[:10],
                                             "identity": timed[i][1].identity,
                                             "when": timed[i][1].when},
                                   "second": {"sha": timed[j][1].sha[:10],
                                              "identity": timed[j][1].identity,
                                              "when": timed[j][1].when}})
    bursts.sort(key=lambda b: b["secondsApart"])
    return {"windowSeconds": window_seconds, "burstCount": len(bursts),
            "bursts": bursts[:20],
            "verdict": ("no cross-identity bursts inside %ds" % window_seconds
                        if not bursts else
                        "%d cross-identity burst(s); closest %ds apart on %s"
                        % (len(bursts), bursts[0]["secondsApart"], bursts[0]["file"]))}


def broadcast_fanout(commits: Sequence[Commit],
                     window_seconds: float = 600.0) -> Dict[str, Any]:
    """One identity writing several repositories inside a short window.

    A single stale checkout that reaches every repository at once is how a local
    mistake becomes an estate-wide one.
    """
    by_id: Dict[str, List[Commit]] = {}
    for c in commits:
        if c.repo:
            by_id.setdefault(c.identity, []).append(c)
    out: List[Dict[str, Any]] = []
    for ident, cs in by_id.items():
        timed = sorted([(t, c) for c in cs if (t := _seconds(c.when)) is not None],
                       key=lambda x: x[0])
        for i in range(len(timed)):
            group: List[Commit] = [timed[i][1]]
            repos = {timed[i][1].repo}
            for j in range(i + 1, len(timed)):
                if timed[j][0] - timed[i][0] > window_seconds:
                    break
                group.append(timed[j][1]); repos.add(timed[j][1].repo)
            if len(repos) > 1:
                out.append({"identity": ident, "repos": sorted(repos),
                            "repoCount": len(repos), "commits": len(group),
                            "spanSeconds": int(timed[min(len(group), len(timed)) - 1][0] - timed[i][0]),
                            "at": timed[i][1].when})
                break
    out.sort(key=lambda x: -x["repoCount"])
    return {"windowSeconds": window_seconds, "fanouts": out,
            "verdict": ("no identity wrote more than one repository inside %ds" % window_seconds
                        if not out else
                        "%s wrote %d repositories within %ds at %s"
                        % (out[0]["identity"], out[0]["repoCount"], window_seconds, out[0]["at"]))}


CLAIM_WORDS = {
    "add": r"\b(add|added|adds|introduce|introduced|new)\b",
    "fix": r"\b(fix|fixed|fixes|patch|patched|correct|corrected)\b",
    "remove": r"\b(remove|removed|removes|delete|deleted|drop|dropped)\b",
}


def verify_claim(message: str, blob: str, marker: str) -> Dict[str, Any]:
    """Does a commit that claims a change actually contain it?

    A commit message is not evidence. This agent reported a patch as missing because
    it trusted one read, and then reported it as present because it trusted a commit
    title; the blob at a named sha was the only thing that settled it. This check
    makes that discipline mechanical.
    """
    if not message:
        raise CommitterWatchError("empty message; nothing to verify")
    if not marker:
        raise CommitterWatchError("marker required; a claim with no observable is unverifiable")
    intent = [k for k, rx in CLAIM_WORDS.items() if re.search(rx, message, re.I)]
    present = marker.lower() in blob.lower()
    if not intent:
        verdict = "unclassified"
        ok = None
    elif "remove" in intent and "add" not in intent and "fix" not in intent:
        ok = not present
        verdict = "claim says remove; marker %s" % ("absent - consistent" if ok else "STILL PRESENT")
    else:
        ok = present
        verdict = "claim says add or fix; marker %s" % ("present - consistent" if ok else "ABSENT - the commit does not contain what its message claims")
    return {"intent": intent, "marker": marker, "markerPresent": present,
            "consistent": ok, "verdict": verdict}


def report(commits: Sequence[Commit], window_seconds: float = 900.0,
           fanout_window: float = 600.0) -> Dict[str, Any]:
    """The whole picture in one call."""
    if not commits:
        raise CommitterWatchError("no commits supplied; nothing to measure")
    coll = identity_collisions(commits)
    burst = burst_risk(commits, window_seconds)
    fan = broadcast_fanout(commits, fanout_window)
    return {"commits": len(commits),
            "repos": sorted({c.repo for c in commits if c.repo}),
            "identities": coll["identities"],
            "identityCount": coll["identityCount"],
            "sharedFiles": coll["sharedFiles"],
            "bursts": burst["burstCount"],
            "closestBurstSeconds": burst["bursts"][0]["secondsApart"] if burst["bursts"] else None,
            "fanouts": len(fan["fanouts"]),
            "collision": coll["verdict"], "burst": burst["verdict"],
            "fanout": fan["verdict"],
            "detail": {"collisions": coll["detail"], "bursts": burst["bursts"],
                       "fanouts": fan["fanouts"]}}
