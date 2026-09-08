#!/usr/bin/env python3
# hardening:allow-file ALL reason=this gate documents the patterns it detects in its own help text
"""Hardening gate - run this before every commit and every push.

    python scripts/harden-check.py <path> [--waivers waivers.json] [--json]
    python scripts/harden-check.py --list-rules
    python scripts/harden-check.py --waive H-01 --glob 'src/vault/*.ts' \
        --reason 'ticket SAOS-42' --by owner --days 7 [--out waivers.json]

Exit codes:
    0  PASS      no blocking violations
    1  BLOCKED   at least one blocking violation - fix it or file a scoped,
                 expiring waiver
    2  usage or IO error

The gate never prints a secret value. For the secret-bearing rules (H-08, H-09,
H-10) evidence is reduced to location plus field name. A gate that echoes the
password it just found turns one exposure into two.
"""

import argparse
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
for cand in (os.path.join(ROOT, "src"), ROOT):
    if os.path.isdir(os.path.join(cand, "jumpper")):
        sys.path.insert(0, cand)
        break

from jumpper import hardening as HD   # noqa: E402

SKIP_DIRS = {".git", "node_modules", ".next", "__pycache__", ".venv", "venv",
             "dist", "build", ".cache", "coverage"}
TEXT_EXT = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py", ".json", ".md",
            ".yml", ".yaml", ".toml", ".sh", ".env", ".example", ".prisma",
            ".html", ".css", ".txt", ".gitignore", ""}
MAX_BYTES = 2_000_000
# Path-shaped rules must still fire for binary-ish files we do not read.
PATH_ONLY_RULES = ("H-04", "H-07")


def collect(path):
    """Return {relpath: content-or-None}. None means path-only, content not read."""
    files = {}
    for dirpath, dirnames, filenames in os.walk(path):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, path).replace(os.sep, "/")
            ext = os.path.splitext(fn)[1].lower()
            try:
                size = os.path.getsize(full)
            except OSError:
                continue
            if size > MAX_BYTES or ext not in TEXT_EXT:
                files[rel] = None
            else:
                try:
                    with open(full, "r", encoding="utf-8", errors="replace") as fh:
                        files[rel] = fh.read()
                except OSError:
                    files[rel] = None
    return files


def load_waivers(path):
    if not path or not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as fh:
        raw = json.load(fh)
    items = raw.get("waivers", raw) if isinstance(raw, dict) else raw
    out = []
    for w in items:
        try:
            out.append(HD.waiver(w["rid"], w["pathGlob"], w["reason"], w["approvedBy"],
                                 int(w["expiresAt"])))
        except (HD.HardeningError, KeyError, ValueError, TypeError) as exc:
            print("  invalid waiver ignored: %s" % exc, file=sys.stderr)
    return out


def report(res, as_json=False):
    if as_json:
        print(json.dumps(res, indent=1, sort_keys=True))
        return
    print("=" * 74)
    print("HARDENING GATE  -  %s" % res["verdict"])
    print("=" * 74)
    print("files scanned : %d" % res["filesScanned"])
    print("blocking      : %d" % res["blockingCount"])
    print("reporting     : %d" % res["reportingCount"])
    print("by severity   : %s" % json.dumps(res["bySeverity"]))
    if res["waivers"]:
        print("active waivers: %d  (all listed below, every run)" % len(res["waivers"]))
        for w in res["waivers"]:
            print("   %s on %s by %s until %d  valid=%s  reason=%s"
                  % (w["rid"], w["pathGlob"], w["approvedBy"], w["expiresAt"],
                     w["valid"], w["reason"][:60]))
    if res["violations"]:
        print("\n%-6s %-9s %-7s %s" % ("RULE", "SEVERITY", "ACTION", "WHERE / EVIDENCE"))
        print("-" * 74)
        for v in res["violations"]:
            where = v["path"] + ((":%d" % v["line"]) if v.get("line") else "")
            print("%-6s %-9s %-7s %s" % (v["id"], v["severity"], v["action"], where))
            print("       %s" % v["title"])
            print("       evidence: %s" % v["evidence"][:150])
            print("       fix     : %s" % v["fix"][:150])
    else:
        print("\nno violations")
    print("\n" + ("GATE PASSED" if res["pass"] else "GATE BLOCKED - do not push"))


def do_waive(a):
    days = a.days
    if not days or days <= 0:
        print("a waiver needs --days > 0; a permanent waiver is a disabled rule", file=sys.stderr)
        return 2
    expires = int(time.time()) + days * 86400
    try:
        w = HD.waiver(a.waive, a.glob, a.reason, a.by, expires)
    except HD.HardeningError as exc:
        print("refused: %s" % exc, file=sys.stderr)
        return 2
    entry = {"rid": w.rid, "pathGlob": w.path_glob, "reason": w.reason,
             "approvedBy": w.approved_by, "expiresAt": w.expires_at,
             "createdAt": int(time.time())}
    out = a.out or os.path.join(ROOT, "waivers.json")
    data = {"waivers": []}
    if os.path.exists(out):
        try:
            with open(out, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (json.JSONDecodeError, OSError):
            pass
    data.setdefault("waivers", [])
    data["waivers"] = [x for x in data["waivers"]
                       if not (x.get("rid") == entry["rid"] and x.get("pathGlob") == entry["pathGlob"])]
    data["waivers"].append(entry)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=1, sort_keys=True)
    print("waiver written to %s" % out)
    print("  rule      : %s  (%s)" % (w.rid, HD.RULE_BY_ID[w.rid].title))
    print("  scope     : %s" % w.path_glob)
    print("  expires   : %d (%d days)" % (w.expires_at, days))
    print("  approvedBy: %s" % w.approved_by)
    print("  reason    : %s" % w.reason)
    print("\nThis file is committed on purpose. A hidden waiver is a disabled rule.")
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="harden-check", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("path", nargs="?", help="directory or file to scan")
    p.add_argument("--waivers", default=os.path.join(ROOT, "waivers.json"))
    p.add_argument("--json", action="store_true")
    p.add_argument("--list-rules", action="store_true")
    p.add_argument("--waive", metavar="RID")
    p.add_argument("--glob", default="")
    p.add_argument("--reason", default="")
    p.add_argument("--by", default="")
    p.add_argument("--days", type=int, default=0)
    p.add_argument("--out", default="")
    a = p.parse_args(argv)

    if a.list_rules:
        for r in HD.RULES:
            print("%-6s %-9s %-7s %s" % (r.rid, r.severity, r.action, r.title))
            print("       origin: %s" % r.origin[:120])
            print("       fix   : %s" % r.fix[:120])
        return 0

    if a.waive:
        if not (a.glob and a.reason and a.by):
            print("--waive needs --glob, --reason and --by", file=sys.stderr)
            return 2
        return do_waive(a)

    if not a.path:
        p.error("a path is required (or use --list-rules / --waive)")
    if not os.path.exists(a.path):
        print("no such path: %s" % a.path, file=sys.stderr)
        return 2

    if os.path.isfile(a.path):
        base = os.path.dirname(a.path) or "."
        rel = os.path.relpath(a.path, base).replace(os.sep, "/")
        with open(a.path, "r", encoding="utf-8", errors="replace") as fh:
            files = {rel: fh.read()}
    else:
        files = collect(a.path)

    # path-only rules still need to fire for files we did not read
    readable = {k: (v if v is not None else "") for k, v in files.items()}
    waivers = load_waivers(a.waivers)
    res = HD.scan_tree(readable, waivers)
    res["skippedAsBinary"] = sorted([k for k, v in files.items() if v is None])[:20]
    report(res, a.json)
    return 0 if res["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
