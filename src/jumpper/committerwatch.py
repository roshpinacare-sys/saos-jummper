"""Committer watch - how many hands are in one repository, and do they collide.

WHY THIS EXISTS
---------------
While verifying whether an epoch patch had landed in saos-dex, the commit history
showed seven distinct committer identities across the last hundred commits, two of
which differ only by a hyphen:

    Z User 41 · roshpinacare-sys 32 · saos-dex-agent 4 · saos-bot 1
    saos-dex agent 1 (same actor as saos-dex-agent, probably) · agent-25-a 1

That was first reported as a critical operational risk, on the reasoning that seven
identities writing one file from separate working trees is how a stale checkout
overwrites fresh work.

MEASURED, IT IS NOT THAT SEVERE
-------------------------------
File lists were fetched for the 14 most recent saos-dex commits:

    distinct files touched    24
    touched by more than one   0

The identities are not racing. They have separated by role:

    roshpinacare-sys   11 of 14 commits, every one a broadcast, every one +N/-0 on
                       exactly one file - append-only log writes
    Z User              3 of 14 commits, every one a roast, with real additions and
                       deletions across up to 9 files - code work

So the honest severity is LOW for present contention and MEDIUM for latent risk:
the separation is a convention nobody enforces, and one identity doing a 9-file
refactor (+118/-216) while another appends to the same repository is one stale
checkout away from a loss. It has not happened. It is not prevented.

WHAT THIS MODULE MEASURES
-------------------------
The four things that decide whether concurrent committers are actually dangerous,
rather than counting identities and alarming:

    identity_report    who commits, how often, and which names are near-duplicates
                       of each other (hyphen, space, case) and probably one actor
    file_contention    which files more than one identity touched - the only signal
                       that actually predicts an overwrite
    role_separation    append-only broadcasters versus code editors, inferred from
                       additions, deletions and files per commit
    deletion_risk      commits that delete far more than they add across many files,
                       which is what a stale checkout looks like from outside

It never edits anything and never calls the network. The caller supplies commit
records; this module only measures them.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from typing import Any, Dict, List, Sequence, Set


class CommitterWatchError(ValueError):
    pass


def _norm(name: str) -> str:
    """Collapse hyphen, space, underscore and case so near-duplicate identities are
    recognised as one actor. Two of the seven identities in saos-dex differ only by
    a hyphen, and counting them separately overstates the crowd."""
    return re.sub(r"[\s\-_]+", "", (name or "")).lower()


def identity_report(commits: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """Who commits, how often, and which names are probably the same actor."""
    if not isinstance(commits, (list, tuple)):
        raise CommitterWatchError("commits must be a sequence")
    raw: Counter = Counter()
    emails: Dict[str, Set[str]] = defaultdict(set)
    groups: Dict[str, Set[str]] = defaultdict(set)
    for c in commits:
        n = c.get("name") or c.get("author") or ""
        if not n:
            continue
        raw[n] += 1
        if c.get("email"):
            emails[n].add(c["email"])
        groups[_norm(n)].add(n)
    merged = {k: sorted(v) for k, v in groups.items() if len(v) > 1}
    all_emails = {e for s in emails.values() for e in s}
    shared = sorted({e for e, n in Counter(e for s in emails.values() for e in s).items()
                     if n > 1})
    return {"commits": len(commits), "distinctNames": len(raw),
            "distinctEmails": len(all_emails), "counts": dict(raw.most_common()),
            "probableSameActor": merged, "probableSameActorCount": len(merged),
            "effectiveIdentities": len(groups), "emailsSharedAcrossNames": shared,
            "verdict": "%d name(s) collapse to %d effective identities"
                       % (len(raw), len(groups))}


def file_contention(commits: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """Which files more than one identity touched. This is the only signal that
    actually predicts an overwrite; identity count alone does not."""
    by_file: Dict[str, Set[str]] = defaultdict(set)
    for c in commits:
        who = _norm(c.get("name") or c.get("author") or "?")
        for f in c.get("files") or []:
            by_file[f].add(who)
    contested = {f: sorted(v) for f, v in by_file.items() if len(v) > 1}
    total = len(by_file)
    return {"distinctFiles": total, "contestedFiles": len(contested),
            "contested": contested,
            "contentionRate": round(len(contested) / total * 100, 2) if total else 0.0,
            "verdict": ("no file is touched by more than one identity" if not contested
                        else "%d of %d files are contested" % (len(contested), total))}


def role_separation(commits: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """Classify each identity as an append-only broadcaster or a code editor.

    Inferred, not declared: a broadcaster adds and never deletes and touches one
    file per commit. An editor deletes. The distinction matters because only the
    editor can lose someone's work.
    """
    per: Dict[str, Dict[str, Any]] = {}
    for c in commits:
        who = c.get("name") or c.get("author") or "?"
        k = _norm(who)
        d = per.setdefault(k, {"commits": 0, "add": 0, "dele": 0, "maxFiles": 0,
                               "msgs": [], "names": set()})
        d["commits"] += 1
        d["add"] += c.get("add") or 0
        d["dele"] += c.get("dele") or 0
        nf = len(c.get("files") or [])
        d["maxFiles"] = max(d["maxFiles"], nf)
        if len(d["msgs"]) < 3:
            d["msgs"].append((c.get("msg") or "")[:48])
        d["names"].add(who)
    out: Dict[str, Any] = {}
    for k, d in per.items():
        appends = d["dele"] == 0 and d["maxFiles"] <= 1
        out[sorted(d["names"])[0]] = {
            "role": "append-only-broadcaster" if appends else "code-editor",
            "commits": d["commits"], "additions": d["add"], "deletions": d["dele"],
            "maxFilesPerCommit": d["maxFiles"], "sampleMessages": d["msgs"]}
    editors = sorted(k for k, v in out.items() if v["role"] == "code-editor")
    return {"identities": out, "editors": editors,
            "broadcasters": sorted(k for k, v in out.items() if v["role"] != "code-editor"),
            "verdict": "%d editor(s), %d broadcaster(s)"
                       % (len(editors), len(out) - len(editors))}


def deletion_risk(commits: Sequence[Dict[str, Any]], net_threshold: int = 50,
                  file_threshold: int = 4) -> Dict[str, Any]:
    """Commits that delete far more than they add across many files.

    That is what a stale checkout looks like from the outside - and also what a
    legitimate large refactor looks like. This module does not pretend to tell them
    apart. It lists them so a human can, which is the honest limit of what commit
    metadata supports.
    """
    out: List[Dict[str, Any]] = []
    for c in commits:
        add = c.get("add") or 0
        dele = c.get("dele") or 0
        nf = len(c.get("files") or [])
        if dele - add >= net_threshold and nf >= file_threshold:
            out.append({"sha": (c.get("sha") or "")[:10], "name": c.get("name"),
                        "date": c.get("date"), "additions": add, "deletions": dele,
                        "net": add - dele, "files": nf, "msg": (c.get("msg") or "")[:60]})
    out.sort(key=lambda x: x["net"])
    return {"count": len(out), "commits": out,
            "verdict": ("no large net-deletion commits" if not out else
                        "%d commit(s) delete far more than they add; a stale checkout "
                        "and a legitimate refactor look identical here, so a human "
                        "must decide" % len(out))}


def watch(commits: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """The whole board in one call."""
    if not isinstance(commits, (list, tuple)):
        raise CommitterWatchError("commits must be a sequence")
    ident = identity_report(commits)
    cont = file_contention(commits)
    roles = role_separation(commits)
    dele = deletion_risk(commits)
    sev = "low"
    if cont["contestedFiles"] > 0:
        sev = "high"
    elif ident["effectiveIdentities"] > 3 and len(roles["editors"]) > 1:
        sev = "medium"
    elif dele["count"] > 0:
        sev = "medium"
    return {"identities": ident, "contention": cont, "roles": roles,
            "deletionRisk": dele, "severity": sev,
            "verdict": "severity %s - %s; %s; %s"
                       % (sev, ident["verdict"], cont["verdict"], roles["verdict"])}
