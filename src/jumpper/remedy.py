"""Correction anchor - publishing the fork record where the forks are.

heightguard.remediation_report() produces a machine-readable correction record
for the eight heights on HIVE mainnet that carry contradictory roots. It is a
good record. It also sits in a repository file, while the contradictory roots sit
on a public chain where any verifier meets them without ever seeing the record.

This module closes that distance: it turns the report into a zero-fee custom_json
so the correction is published in the same place, under the same account, with the
same permanence as the thing it corrects.

WHAT IT DELIBERATELY DOES NOT DO
--------------------------------
It does not declare a canonical root. Two signed commitments at one height are
both real, and which one the state machine actually produced is a fact about the
operator's process, not about the ledger. Picking the earliest would be a
convention dressed as a finding, and a verifier who trusted it would be trusting
us rather than the chain. So every forked height publishes as AMBIGUOUS with all
of its roots, and CANONICAL is refused unless the operator supplies a root.

It does not retract anything. The original anchors are permanent and stay
readable. A correction that hides the original is worse than the original,
because it removes the evidence that a correction was needed.

It never signs and never broadcasts.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence

from .graphene import b64u, unb64u
from .authority import ATTESTATION, build_custom_json_by_policy
from .protocol import HIVE_CUSTOM_JSON_DATA_MAX_LENGTH

CORRECTION_ANCHOR_ID = "saos-height-correction.v1"
CORRECTION_VERSION = 1
AMBIGUOUS = "AMBIGUOUS"
CANONICAL = "CANONICAL"
SUPERSEDED = "SUPERSEDED"
STATUSES = (AMBIGUOUS, CANONICAL, SUPERSEDED)


class RemedyError(ValueError):
    pass


@dataclass(frozen=True)
class Correction:
    log_id: str
    height: int
    status: str
    distinct_roots: int
    roots: Sequence[str]
    epoch: Optional[int] = None
    canonical_root: Optional[str] = None
    first_committed_at: Optional[str] = None
    last_committed_at: Optional[str] = None

    def __post_init__(self) -> None:
        if self.status not in STATUSES:
            raise RemedyError("status must be one of %r" % (STATUSES,))
        if not self.log_id:
            raise RemedyError("log_id required")
        if not isinstance(self.height, int) or isinstance(self.height, bool) or self.height < 0:
            raise RemedyError("height must be a non-negative integer")
        for r in self.roots:
            if len(r) != 64 or any(c not in "0123456789abcdef" for c in r):
                raise RemedyError("every root must be 64-char lowercase hex")
        if self.status == CANONICAL and not self.canonical_root:
            # Fail closed. A CANONICAL record with no root claims that some root
            # wins, on nobody's authority, about nothing. That is worse than
            # AMBIGUOUS because a verifier would trust it.
            raise RemedyError("CANONICAL requires canonical_root; refusing to "
                            "publish an authority nobody supplied")
        if self.canonical_root and self.canonical_root not in self.roots:
            raise RemedyError("canonical_root must be one of the committed roots; "
                            "inventing another would be a new fork")
        if self.distinct_roots < 1:
            raise RemedyError("distinct_roots must be >= 1")
        if self.status == AMBIGUOUS and self.distinct_roots < 2:
            raise RemedyError("AMBIGUOUS requires at least two distinct roots")

    def as_dict(self) -> Dict[str, Any]:
        return {"logId": self.log_id, "epoch": self.epoch, "height": self.height,
                "status": self.status, "distinctRoots": self.distinct_roots,
                "roots": list(self.roots), "canonicalRoot": self.canonical_root,
                "firstCommittedAt": self.first_committed_at,
                "lastCommittedAt": self.last_committed_at}


def corrections_from_report(report: Dict[str, Any]) -> List[Correction]:
    """Build corrections from heightguard.remediation_report() output."""
    if not isinstance(report, dict):
        raise RemedyError("report must be an object")
    log_id = report.get("logId") or "saos-dex.anchor.v1"
    entries = report.get("entries")
    if not entries:
        raise RemedyError("report carries no entries; nothing to correct")
    out: List[Correction] = []
    for e in entries:
        recs = e.get("records") or []
        roots = [r.get("root") for r in recs if r.get("root")]
        out.append(Correction(
            log_id=log_id, height=e["height"], status=e.get("status") or AMBIGUOUS,
            distinct_roots=e.get("distinctRoots") or len(set(roots)),
            roots=roots, epoch=e.get("epoch"), canonical_root=e.get("canonicalRoot"),
            first_committed_at=e.get("firstCommittedAt"),
            last_committed_at=e.get("lastCommittedAt")))
    return out


def encode_corrections(cs: Sequence[Correction], sep: str = ",") -> str:
    """Compact payload: version|logId|status;height:rootCount:rootsB64u;...

    Roots go as base64url (43 chars instead of 64 hex) and the log id and status
    appear once per batch. The eight real forks encode to well under the 8,192-byte
    free budget, so the whole record goes on chain in ONE zero-fee operation."""
    if not cs:
        raise RemedyError("cannot encode zero corrections")
    if len({c.log_id for c in cs}) != 1:
        raise RemedyError("one correction batch covers exactly one log_id")
    if len({c.status for c in cs}) != 1:
        raise RemedyError("one correction batch carries one status")
    parts = []
    for c in sorted(cs, key=lambda x: x.height):
        parts.append("%d:%d:%s" % (c.height, len(c.roots),
                                    "+".join(b64u(r) for r in c.roots)))
    payload = "%d|%s|%s|%s" % (CORRECTION_VERSION, cs[0].log_id, cs[0].status,
                                sep.join(parts))
    n = len(payload.encode("utf-8"))
    if n > HIVE_CUSTOM_JSON_DATA_MAX_LENGTH:
        raise RemedyError("payload of %d bytes exceeds the %d-byte custom_json "
                          "budget; split it" % (n, HIVE_CUSTOM_JSON_DATA_MAX_LENGTH))
    return payload


def build_correction_op(account: str, cs: Sequence[Correction]) -> List[Any]:
    """The zero-fee custom_json. POSTING authority - this is an attestation."""
    return build_custom_json_by_policy(account, encode_corrections(cs),
                                       ATTESTATION, CORRECTION_ANCHOR_ID)


def plan(account: str, cs: Sequence[Correction]) -> Dict[str, Any]:
    """Everything needed to hand this to an external signer. Signs nothing."""
    op = build_correction_op(account, cs)
    payload = op[1]["json"]
    n = len(payload.encode("utf-8"))
    return {"account": account, "anchorId": CORRECTION_ANCHOR_ID,
            "authority": "posting", "fee": 0, "corrections": len(cs),
            "payloadBytes": n, "budgetBytes": HIVE_CUSTOM_JSON_DATA_MAX_LENGTH,
            "budgetUsedPct": round(n / HIVE_CUSTOM_JSON_DATA_MAX_LENGTH * 100, 2),
            "fitsInOneOperation": n <= HIVE_CUSTOM_JSON_DATA_MAX_LENGTH,
            "signing": "external-only", "broadcast": "never-performed-here",
            "retracts": False,
            "note": "the original anchors stay readable; this record sits beside them"}


def apply_corrections(anchors: Sequence[Dict[str, Any]],
                      cs: Sequence[Correction]) -> Dict[str, Any]:
    """What a verifier should conclude after reading both the forks and the record.

    A height is resolved only when a CANONICAL correction names a root that is
    actually among the committed ones. AMBIGUOUS corrections resolve nothing -
    they make the ambiguity explicit, which is the honest outcome and the one the
    eight real forks get."""
    by_height: Dict[int, Correction] = {c.height: c for c in cs}
    heights = sorted({a.get("height") for a in anchors if a.get("height") is not None})
    resolved: List[int] = []
    ambiguous: List[int] = []
    unrecorded: List[int] = []
    for h in heights:
        c = by_height.get(h)
        if c is None:
            unrecorded.append(h)
        elif c.status == CANONICAL and c.canonical_root:
            roots = {a.get("root") for a in anchors if a.get("height") == h}
            (resolved if c.canonical_root in roots else ambiguous).append(h)
        else:
            ambiguous.append(h)
    amb = len(ambiguous); unrec = len(unrecorded)
    verdict = ("all forked heights resolved" if not amb and not unrec else
               "%d height(s) remain ambiguous and %d have no correction record"
               % (amb, unrec))
    return {"heights": len(heights), "resolved": resolved, "ambiguous": ambiguous,
            "unrecorded": unrecorded, "resolvedCount": len(resolved),
            "ambiguousCount": amb, "unrecordedCount": unrec, "verdict": verdict}


def decode_corrections(payload: str, sep: str = ",") -> Dict[str, Any]:
    """Decode a correction payload back into structured records.

    Format: version|logId|status;height:rootCount:root1B64u+root2B64u;...
    Roots are base64url of the 32-byte digest, so 43 characters rather than 64 hex
    - which is what lets all eight forked heights and their seventeen roots fit in
    831 bytes of an 8,192-byte free budget.

    Every field is validated on the way in, and a payload that does not parse is an
    error rather than a partial result: a verifier that silently dropped a height
    would report fewer contradictions than the chain contains, which is worse than
    refusing to answer."""
    if not isinstance(payload, str) or not payload.strip():
        raise RemedyError("payload must be a non-empty string")
    parts = payload.split("|")
    if len(parts) != 4:
        raise RemedyError("payload must be version|logId|status|entries, got %d parts"
                        % len(parts))
    try:
        version = int(parts[0])
    except ValueError as exc:
        raise RemedyError("version must be an integer") from exc
    if version != CORRECTION_VERSION:
        raise RemedyError("unsupported correction payload version %d; this decoder "
                          "handles %d" % (version, CORRECTION_VERSION))
    log_id = parts[1]
    if not log_id:
        raise RemedyError("logId is empty")
    status = parts[2]
    if status not in STATUSES:
        raise RemedyError("status %r is not one of %r" % (status, STATUSES))
    if not parts[3]:
        raise RemedyError("payload carries no entries")
    out: List[Correction] = []
    for chunk in parts[3].split(sep):
        fields = chunk.split(":")
        if len(fields) != 3:
            raise RemedyError("entry %r must be height:rootCount:roots" % chunk[:40])
        try:
            height = int(fields[0]); count = int(fields[1])
        except ValueError as exc:
            raise RemedyError("height and rootCount must be integers in %r"
                                % chunk[:40]) from exc
        if height < 0 or count < 1:
            raise RemedyError("height must be >= 0 and rootCount >= 1 in %r" % chunk[:40])
        roots: List[str] = []
        for enc in fields[2].split("+"):
            try:
                raw = unb64u(enc)
            except Exception as exc:
                raise RemedyError("malformed base64url root in entry %r: %s"
                                  % (chunk[:40], exc)) from exc
            if len(raw) != 64 or any(c not in "0123456789abcdef" for c in raw):
                raise RemedyError("decoded root is not 64-char lowercase hex in entry %r"
                                  % chunk[:40])
            roots.append(raw)
        if len(roots) != count:
            raise RemedyError("entry for height %d declares %d roots but carries %d"
                              % (height, count, len(roots)))
        if status == AMBIGUOUS and len(set(roots)) < 2:
            raise RemedyError("an AMBIGUOUS entry for height %d carries fewer than "
                              "two distinct roots" % height)
        out.append(Correction(log_id=log_id, height=height, status=status,
                              distinct_roots=count, roots=roots))
    if not out:
        raise RemedyError("payload decoded to zero corrections")
    return {"version": version, "logId": log_id, "status": status,
            "corrections": out, "count": len(out),
            "heights": sorted(c.height for c in out),
            "totalRoots": sum(len(c.roots) for c in out),
            "payloadBytes": len(payload.encode("utf-8"))}
