"""Safe write - clobberguard wired into the actual write path.

clobberguard.assess() answers whether a write may proceed. An answer nobody asks
for is not a control, and this module exists because the module it enforces was
built one round after an agent overwrote another agent's work without asking.

The failure was not a missing check. It was a write path that never called one:
fetch the sha, PUT the content, done. This replaces that path. It fetches the
existing blob AND its last committer, asks assess(), and only then writes - or
refuses and says exactly what would have been destroyed.

Every decision is recorded, including the allowed ones, because a guard whose
passes are invisible cannot be distinguished from a guard that is not running.

It performs no merge and makes no judgement about whether a force was wise. It
reports the force and moves on; the record is the control.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from . import clobberguard as CG


class SafeWriteError(ValueError):
    pass


@dataclass
class WriteLog:
    """Every decision, allowed and refused. Append-only."""
    entries: List[Dict[str, Any]] = field(default_factory=list)

    def add(self, verdict: CG.ClobberVerdict, repo: str, wrote: bool,
            status: Optional[int] = None, error: Optional[str] = None) -> None:
        self.entries.append({"repo": repo, "path": verdict.path,
                             "decision": verdict.decision, "action": verdict.action,
                             "forced": verdict.forced, "wrote": wrote,
                             "lostNames": verdict.lost_names,
                             "httpStatus": status, "error": error,
                             "existingAuthor": verdict.existing_author,
                             "callerIdentity": verdict.caller_identity})

    def refused(self) -> List[Dict[str, Any]]:
        return [e for e in self.entries if e["decision"] == CG.REFUSE]

    def forced(self) -> List[Dict[str, Any]]:
        return [e for e in self.entries if e["forced"]]

    def summary(self) -> Dict[str, Any]:
        return {"total": len(self.entries),
                "wrote": sum(1 for e in self.entries if e["wrote"]),
                "refused": len(self.refused()), "forced": len(self.forced()),
                "namesLostByForce": sorted({n for e in self.forced()
                                            for n in e["lostNames"]})}


def read_existing(get_json: Callable[[str], Any], get_raw: Callable[[str], str],
                  get_last_author: Callable[[str], Optional[str]],
                  path: str) -> Dict[str, Any]:
    """Fetch the current blob and who last wrote it.

    The last author is what makes the guard work. A blob alone tells you content
    exists; it does not tell you whose content it is, and overwriting your own work
    is legitimate while overwriting someone else is not."""
    meta = get_json(path)
    if not isinstance(meta, dict):
        raise SafeWriteError("metadata fetch did not return an object for %r" % path)
    if meta.get("_status") == 404 or meta.get("type") is None and "content" not in meta:
        return {"exists": False, "content": None, "author": None, "sha": None}
    raw = get_raw(path)
    if raw is None:
        raise SafeWriteError("could not read the existing content of %r; refusing to "
                             "write blind over a file whose content is unknown" % path)
    return {"exists": True, "content": raw,
            "author": get_last_author(path), "sha": meta.get("sha")}


def plan(path: str, proposed: str, existing: Dict[str, Any], caller_identity: str,
         force: bool = False) -> CG.ClobberVerdict:
    """Ask the guard. Does not write."""
    if not isinstance(existing, dict):
        raise SafeWriteError("existing must be the dict read_existing returns")
    return CG.assess(path, proposed,
                     existing.get("content") if existing.get("exists") else None,
                     existing.get("author"), caller_identity, force=force)


def write(path: str, proposed: str, existing: Dict[str, Any], caller_identity: str,
          put: Callable[..., Any], log: WriteLog, repo: str = "",
          force: bool = False, message: str = "") -> Dict[str, Any]:
    """Plan, then write only if the guard allows. Returns the decision and outcome.

    A refusal is returned, not raised - the caller needs the reason and the list of
    names that would have been destroyed, and an exception loses both. A transport
    failure after an allowed decision IS raised, because that is not a judgement
    the guard can make."""
    verdict = plan(path, proposed, existing, caller_identity, force=force)
    if verdict.decision == CG.REFUSE:
        log.add(verdict, repo, wrote=False)
        return {"wrote": False, "verdict": verdict.as_dict(),
                "reason": verdict.reason, "wouldHaveDestroyed": verdict.lost_names,
                "suggestedAction": verdict.action,
                "mergePlan": CG.merge_plan(path, proposed, existing.get("content") or "")}
    sha = existing.get("sha") if existing.get("exists") else None
    body = {"message": message or ("update %s" % path),
            "content": base64.b64encode(proposed.encode("utf-8")).decode("ascii"),
            "branch": "main"}
    if sha:
        body["sha"] = sha
    try:
        resp = put(path, body)
    except Exception as exc:
        log.add(verdict, repo, wrote=False, error=type(exc).__name__)
        raise SafeWriteError("write failed after the guard allowed it: %s: %s"
                             % (type(exc).__name__, exc)) from exc
    status = getattr(resp, "status_code", None)
    ok = status in (200, 201)
    log.add(verdict, repo, wrote=ok, status=status,
            error=None if ok else str(getattr(resp, "text", ""))[:200])
    if not ok:
        raise SafeWriteError("the remote refused the write (HTTP %s) even though the "
                             "guard allowed it" % status)
    return {"wrote": True, "verdict": verdict.as_dict(), "httpStatus": status}


def write_many(items: List[Dict[str, Any]], caller_identity: str,
               put: Callable[..., Any], log: Optional[WriteLog] = None,
               repo: str = "", force: bool = False) -> Dict[str, Any]:
    """Write a batch, stopping at the first refusal.

    Stopping rather than skipping is deliberate: a batch that half-applies leaves
    the repository in a state nobody described, which is how the epoch work ended
    up in a commit whose message did not match its tree."""
    log = log if log is not None else WriteLog()
    done: List[str] = []
    for it in items:
        r = write(it["path"], it["content"], it["existing"], caller_identity,
                  put, log, repo=repo, force=force, message=it.get("message", ""))
        if not r["wrote"]:
            return {"wrote": done, "stoppedAt": it["path"], "reason": r["reason"],
                    "wouldHaveDestroyed": r["wouldHaveDestroyed"],
                    "suggestedAction": r["suggestedAction"], "log": log.summary()}
        done.append(it["path"])
    return {"wrote": done, "stoppedAt": None, "log": log.summary()}
