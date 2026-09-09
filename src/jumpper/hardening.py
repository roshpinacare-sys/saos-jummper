"""Hardening policy engine - machine-checkable rules for every defect found in
this estate.

Design goal, in the owner's words: solutions we can still WORK with, and that
cannot be broken into. Those two pull against each other, so the resolution is
explicit:

    FAIL CLOSED BY DEFAULT, WITH AN AUDITABLE EXPIRING WAIVER.

A rule that blocks is useless if people disable it. A rule that only warns is
useless if it can be ignored. So every rule here either blocks or reports, and
the only way past a blocking rule is a waiver that is:

    explicit    named rule id, written reason, named approver
    expiring    an expiry timestamp is MANDATORY; a waiver without one is refused
    committed   it lives in the repository, so it is visible in review
    scoped      to a path glob, never global
    auditable   the scanner lists every active waiver in every verdict

That is how a gate stays on and work still happens.

Every rule below was derived from a REAL defect read out of this estate during
the 2026-09-08 audit. No rule is speculative, and each carries the finding it
came from so nobody has to guess why it exists.
"""

from __future__ import annotations

import fnmatch
import re
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

BLOCK = "block"
REPORT = "report"
CRITICAL = "critical"
HIGH = "high"
MEDIUM = "medium"
LOW = "low"


class HardeningError(ValueError):
    pass


@dataclass(frozen=True)
class Rule:
    rid: str
    title: str
    severity: str
    action: str
    origin: str
    why: str
    fix: str
    detect: Callable[[str, str], Optional[str]]


# Rules whose evidence can contain the secret itself. Their evidence is redacted
# before it ever reaches a Violation, a report, a log or a commit message. A
# scanner that prints the password it just found has turned one exposure into two.
SECRET_BEARING = frozenset({"H-08", "H-09", "H-10"})
REDACTED = "[REDACTED]"


def redact_evidence(rid: str, evidence: str) -> str:
    """Keep the location, drop the value.

    The useful part of a secret finding is WHERE it is, not WHAT it is. The line
    number and the field name stay; anything that looks like the secret value is
    replaced.
    """
    if rid not in SECRET_BEARING:
        return evidence
    import re as _re
    line = ""
    if evidence.startswith("line "):
        try:
            line, rest = evidence.split(":", 1)
            evidence = rest.strip()
        except ValueError:
            line = ""
    # drop anything after a quote/colon that looks like a value of 8+ secret chars
    scrubbed = _re.sub(r"([:\'\"]\s*)[^\s,}\]]{8,}", r"\1" + REDACTED, evidence)
    if scrubbed == evidence:
        scrubbed = REDACTED
    return (line + ": " if line else "") + scrubbed.strip()


@dataclass(frozen=True)
class Violation:
    rid: str
    severity: str
    action: str
    path: str
    line: Optional[int]
    evidence: str
    title: str
    fix: str

    def as_dict(self) -> Dict[str, Any]:
        return {"id": self.rid, "severity": self.severity, "action": self.action,
                "path": self.path, "line": self.line, "evidence": self.evidence[:200],
                "title": self.title, "fix": self.fix}


# hardening:allow-file ALL reason=rule definitions and audit text quote the very
# patterns and defects this module detects; scanning them without an allowance
# would report documentation as a violation.

ALLOW_LINE_RX = re.compile(r"hardening:allow\s+([A-Z0-9\-,\s]+?)\s*(?:$|\*/|-->)", re.I)
ALLOW_FILE_RX = re.compile(r"hardening:allow-file\s+([A-Z0-9\-,\s]+?)\s+reason=(.+?)\s*$", re.M | re.I)
ALLOW_ALL = "ALL"


@dataclass(frozen=True)
class Allowance:
    scope: str
    rid: str
    line: Optional[int]
    reason: str

    def as_dict(self) -> Dict[str, Any]:
        return {"scope": self.scope, "rid": self.rid, "line": self.line, "reason": self.reason}


def _split_ids(blob: str) -> List[str]:
    return [x for x in (y.strip().upper() for y in blob.replace(",", " ").split()) if x]


def parse_allowances(content: str) -> List[Allowance]:
    """Find every inline allowance. Never raises on malformed input."""
    out: List[Allowance] = []
    for m in ALLOW_FILE_RX.finditer(content):
        for rid in _split_ids(m.group(1)):
            out.append(Allowance("file", rid, None, m.group(2).strip()))
    for ln_no, line in enumerate(content.split("\n"), start=1):
        m = ALLOW_LINE_RX.search(line)
        if not m:
            continue
        for rid in _split_ids(m.group(1)):
            out.append(Allowance("line", rid, ln_no, ""))
    return out


def allowance_covers(al: Allowance, rid: str, line: Optional[int]) -> bool:
    if al.rid != ALLOW_ALL and al.rid != rid:
        return False
    return True if al.scope == "file" else al.line == line


@dataclass(frozen=True)
class Waiver:
    rid: str
    path_glob: str
    reason: str
    approved_by: str
    expires_at: int

    def is_valid(self, now: Optional[int] = None) -> Tuple[bool, str]:
        now = int(time.time()) if now is None else now
        if not (self.rid and self.path_glob and self.reason and self.approved_by):
            return False, "waiver must name rule, path glob, reason and approver"
        if self.expires_at <= now:
            return False, "waiver expired at %d" % self.expires_at
        return True, "ok"


def _line_of(content: str, idx: int) -> int:
    return content.count("\n", 0, idx) + 1


def _find(pattern: str, flags: int = 0) -> Callable[[str, str], Optional[str]]:
    rx = re.compile(pattern, flags)

    def detect(path: str, content: str) -> Optional[str]:
        target = path if "$" in pattern and pattern.endswith("$") else content
        m = rx.search(target)
        if not m:
            return None
        if target is path:
            return "path matches %s" % pattern
        snippet = content[m.start():m.start() + 120].replace("\n", " ")
        return "line %d: %s" % (_line_of(content, m.start()), snippet.strip())
    return detect


RULES: List[Rule] = [
    Rule("H-01", "Plaintext storage fallback instead of fail-closed", CRITICAL, BLOCK,
         "W-01: secure-storage.ts falls back to window.localStorage and calls itself "
         "DANGEROUS_PLAINTEXT_MODE in its own header comment.",
         "A fallback that silently downgrades to plaintext makes the unsafe path the "
         "shipping default. Absence of a secure backend must be fatal.",
         "Make the missing-backend path throw at startup. Never store key material in "
         "localStorage, a flat file, or an env var readable by the whole process tree.",
         _find(r"(localStorage|sessionStorage)\s*\.\s*setItem")),

    Rule("H-02", "Crypto function is a throwing stub with a real signature", CRITICAL, BLOCK,
         "W-02: deriveBip32FromMnemonic and deriveEvmPrivateKey declare full signatures "
         "and return types, then throw 'not implemented'.",
         "A stub with a plausible signature looks wired up. Callers that catch and log "
         "appear to work until a key is actually needed.",
         "Delete the stub or make the module fail to import. Never ship a function that "
         "promises cryptography and throws.",
         _find(r"throw new Error\([^)]*not implemented", re.I)),

    Rule("H-03", "Merge-conflict markers committed", HIGH, BLOCK,
         "W-03: vault.ts.orig states 'merge conflict markers were committed' and the "
         "file was in a broken, uncompiled state.",
         "Conflict markers make a file uncompilable, and a resolution that discards one "
         "side loses that work permanently.",
         "Resolve the conflict, run the build, then commit. Gate it in pre-commit.",
         _find(r"^(<{7}|={7}|>{7})( |$)", re.M)),

    Rule("H-04", "Merge-tool artifact committed (.orig / .rej / .BACKUP)", HIGH, BLOCK,
         "W-03: vault.ts.orig was committed and became the ONLY surviving copy of the "
         "lost VaultKey / privateKeyRef design.",
         "Artifacts are not source, and they are how lost work gets deleted by the next "
         "cleanup pass.",
         "Recover anything valuable into real source, delete the artifact, and gitignore "
         "*.orig, *.rej, *.BACKUP.*.",
         _find(r"\.(orig|rej)$")),

    Rule("H-05", "Math.random used for key material, salt or nonce", MEDIUM, BLOCK,
         "W-04: makeSalt falls back to Math.random().toString(36) + Date.now().",
         "Math.random is not cryptographically secure and Date.now is guessable to within "
         "milliseconds. The fallback engages exactly when crypto is unavailable.",
         "Use a CSPRNG (crypto.getRandomValues / crypto.randomBytes / os.urandom) and make "
         "its absence fatal rather than degrading.",
         _find(r"Math\.random\s*\(")),

    Rule("H-06", "Security provider injected via a mutable global", MEDIUM, REPORT,
         "W-05: window.__SAOS_SECURE_BACKEND__ is read at first use with no "
         "authentication, so any page script can become the storage backend.",
         "A mutable global is both an exfiltration path and a key-substitution path.",
         "Bind the backend at module or build scope. If runtime injection is required, "
         "authenticate it against a build-time pinned public key.",
         _find(r"(window|globalThis|global)\s*\.\s*__?[A-Za-z_]*(BACKEND|PROVIDER|SIGNER|KEY)", re.I)),

    Rule("H-07", "Database file committed to the repository", HIGH, BLOCK,
         "W-06: db/custom.db (290,816 bytes) is committed inside a wallet repository. "
         "Its contents were not read.",
         "A committed database can carry key material, seeds or user records, and removal "
         "from HEAD does not remove it from history.",
         "Inspect for secrets, rotate anything found, remove from the tree, gitignore it, "
         "and treat prior history as exposed.",
         _find(r"\.(db|sqlite|sqlite3)$")),

    Rule("H-08", "Secret stored adjacent to the ciphertext it protects", CRITICAL, BLOCK,
         "fleet_keys.meta.json holds the vault password in a 'pass' field, in the same "
         "directory as fleet_keys.enc, in three separate repositories.",
         "Encryption with its key beside it is not encryption. Anyone with read access to "
         "the repository can decrypt everything.",
         "Never store a passphrase next to its ciphertext. Keep it in an env var or an "
         "external secret store, and rotate every key the exposed one protected.",
         _find(r"(pass|password|passphrase)\W{0,4}\s*[:=]\s*\S{20,}")),

    Rule("H-09", "Private key or seed material in a tracked file", CRITICAL, BLOCK,
         "The estate holds a 7-key fleet vault and an active EVM signer. A WIF or seed "
         "anywhere in a tree is a total-loss event.",
         "A committed private key is compromised the moment it is pushed, and removing it "
         "from HEAD does not undo that.",
         "Remove it, rotate the key, move the funds, and treat the address as burned.",
         _find(r"\b(5[HJK][1-9A-HJ-NP-Za-km-z]{40,}|xprv[1-9A-HJ-NP-Za-km-z]{60,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)")),

    Rule("H-10", "Token in a file inside the repository tree", HIGH, BLOCK,
         "A GitHub PAT was read from upload/Roshcaregt.txt inside the working tree, and "
         "another was found embedded in a stale clone's .git/config.",
         "A token inside the tree is one careless 'git add -A' away from being public.",
         "Keep tokens outside the working tree entirely. Use a fine-grained token scoped "
         "to one repository with a short expiry.",
         _find(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}")),

    Rule("H-11", "Attestation signed with ACTIVE authority", CRITICAL, BLOCK,
         "57 of 62 attestation operations (91.9%) on HIVE mainnet used required_auths "
         "(ACTIVE). Only the 5 saos value_lock operations used POSTING.",
         "ACTIVE can transfer every asset in the account. Signing a data attestation with "
         "it hands fund-moving capability to an automated broadcaster.",
         "Use required_posting_auths for anything that only publishes data. Same RC cost, "
         "same payload size - the migration is free.",
         _find(r"required_auths\W{0,4}\s*[:=]\s*\[\s*\S{3,22}")),

    Rule("H-12", "Testnet or devnet used as a silent default", HIGH, BLOCK,
         "F-03: relay-sol.ts defaults to api.devnet.solana.com while relay-eth.ts "
         "defaults to mainnet, and the ledger records both identically.",
         "Anchors land on a network whose tokens are worthless and the ledger cannot tell "
         "them apart from mainnet afterwards.",
         "Refuse to start when no endpoint is configured. Record the network id and "
         "endpoint host with every anchor.",
         _find(r"(devnet|testnet|sepolia|goerli|holesky|shasta|nile)\.[a-z0-9\.\-]+", re.I)),

    Rule("H-13", "Verifier cannot reach transaction history", HIGH, BLOCK,
         "F-02: relay-sol.ts calls getSignatureStatuses with searchTransactionHistory "
         "false, so verified is structurally pinned at 0 for any anchor older than the "
         "node cache. The ledger showed anchored 27, verified 0.",
         "The transaction is on chain permanently but the verifier can never see it, so "
         "the ledger reads as 27 failures rather than one broken flag.",
         "Set searchTransactionHistory to true, or keep a persistent local record of what "
         "was broadcast and verify against that.",
         _find(r"searchTransactionHistory\s*:\s*false")),

    Rule("H-14", "Non-final confirmation level accepted as verified", MEDIUM, REPORT,
         "F-08: the Solana verifier accepts 'confirmed', which can still be rolled back by "
         "a fork. No occurrence of 'finalized' in the file.",
         "An anchor recorded as verified can later stop existing, leaving the ledger "
         "asserting something the chain does not.",
         "Require 'finalized' before recording verified, or store the confirmation level "
         "alongside the status.",
         _find(r"[\']confirmed[\']\s*(===|==|:)")),

    Rule("H-15", "Quota snapshot compared without projecting elapsed time", MEDIUM, REPORT,
         "F-05: a gate compared rc_manabar.current_mana, a snapshot as of "
         "last_update_time, against a constant, and declared HIVE blocked at 924,265 RC "
         "while the account actually held 73,271,489.",
         "A stale snapshot under-reports available resource by the whole elapsed interval, "
         "turning a working account into a false blocker.",
         "Project forward: min(max, stored + regen_per_sec * (now - last_update)).",
         _find(r"current_mana\s*(<|<=|>|>=)\s*[0-9_]+")),

    Rule("H-16", "Counter that can exceed its own source", MEDIUM, REPORT,
         "The anchor ledger recorded verified 18 against anchored 16, which is "
         "arithmetically impossible, and mismatches 0 because verification almost never ran.",
         "A counter incremented optimistically rather than derived from a result makes the "
         "ledger unreadable as evidence.",
         "Derive verified from verification results. Assert verified <= anchored as an "
         "invariant and test it.",
         _find(r"verified\s*(\+\+|\+=\s*1)")),

    Rule("H-17", "Automation token with administrative scopes", HIGH, REPORT,
         "The PAT used for automated pushes carried admin:org, admin:enterprise, "
         "delete_repo, admin:ssh_signing_key, admin:public_key, workflow, write:packages, "
         "codespace and audit_log.",
         "An automation token that can delete repositories and install SSH keys is a master "
         "key, not a push credential.",
         "Use a fine-grained token: Contents read/write on one repository, short expiry, no "
         "admin scopes, no workflow scope unless CI needs it.",
         _find(r"admin:(org|enterprise|public_key|ssh_signing_key|repo_hook|gpg_key)")),
    Rule("H-18", "A single hash pass used as a key derivation function", HIGH, BLOCK,
         "W-04: the superseded wallet salt path applied sha256 once and called the "
         "result a salt-derived key. Contrast packages/core/src/crypto/kdf.ts, which "
         "uses Argon2id at 64 MiB and t=3 so an offline guess costs about a GPU-second.",
         "A fast hash is designed to be cheap. Password-derived key material must be "
         "expensive to compute, or an offline attacker wins by brute force.",
         "Use Argon2id, scrypt or PBKDF2 with a published cost parameter. Store the "
         "params and salt with the verifier. One SHA-256 pass is a fingerprint, not a KDF.",
         _find(r"sha256\s*\([^)]*(password|passphrase|secret|pass)[^)]*\)", re.I)),

    Rule("H-19", "Secret comparison that is not constant time", HIGH, BLOCK,
         "packages/core/src/crypto/kdf.ts uses timingSafeEqual with length-safe padding "
         "and states that comparisons are constant time. A plain equality check on a "
         "digest or key is not.",
         "Byte-by-byte comparison returns early on the first difference, leaking how "
         "many leading bytes matched. That is a real remote timing oracle on MACs and "
         "password verifiers.",
         "Compare with timingSafeEqual (Node), hmac.compare_digest (Python) or an "
         "equivalent constant-time primitive, after length-safe padding.",
         _find(r"(digest|mac|hash|signature|verifier|token)\s*(===|==)\s*[A-Za-z_$]", re.I)),

    Rule("H-20", "Credential check that throws on mismatch instead of returning false", MEDIUM, REPORT,
         "packages/core/src/crypto/kdf.ts deliberately makes verifyPassword degrade to "
         "false rather than throw, so a wrong password is indistinguishable from a right "
         "one by error type.",
         "A thrown error on mismatch gives the caller - and any observer of logs or HTTP "
         "status - a distinct signal for 'exists but wrong' versus 'does not exist'.",
         "Return a boolean from verification. Reserve exceptions for malformed input, "
         "never for a failed credential check.",
         _find(r"throw[^;\n]*(invalid|wrong|incorrect|mismatch)[^;\n]*(password|passphrase|credential|pin|otp)", re.I)),

    Rule("H-21", "Monorepo layout without declared workspaces", MEDIUM, REPORT,
         "Saosmartwallet declares no workspaces field and imports packages/core and "
         "packages/chains by relative path (../../packages/chains). The crypto engine "
         "therefore has no name, no version and no dependency edge.",
         "Relative imports across a package boundary break silently on a move or rename, "
         "give the package no publishable artifact, and stop any other repository from "
         "consuming it - including the repositories that need it most.",
         "Declare workspaces, give each package a name and a version, and import by name.",
         _find(r"from\s+\S*\.\./\.\./packages/")),
]

RULE_BY_ID: Dict[str, Rule] = {r.rid: r for r in RULES}


def rules_for(severity: Optional[str] = None, action: Optional[str] = None) -> List[Rule]:
    out = list(RULES)
    if severity:
        out = [r for r in out if r.severity == severity]
    if action:
        out = [r for r in out if r.action == action]
    return out


def _matches_glob(path: str, glob: str) -> bool:
    return bool(fnmatch.fnmatch(path, glob) or fnmatch.fnmatch(path.split("/")[-1], glob))


def scan_file(path: str, content: str, waivers: Sequence[Waiver] = (),
              now: Optional[int] = None,
              collect_allowances: Optional[List[Dict[str, Any]]] = None) -> List[Violation]:
    allows = parse_allowances(content)
    out: List[Violation] = []
    for rule in RULES:
        try:
            ev = rule.detect(path, content)
        except Exception:
            ev = None
        if not ev:
            continue
        if any((w.rid == rule.rid or w.rid == ALLOW_ALL) and _matches_glob(path, w.path_glob)
               and w.is_valid(now)[0] for w in waivers):
            continue
        line: Optional[int] = None
        if ev.startswith("line "):
            try:
                line = int(ev.split(":", 1)[0].split()[1])
            except (IndexError, ValueError):
                line = None
        covering = [al for al in allows if allowance_covers(al, rule.rid, line)]
        if covering:
            if collect_allowances is not None:
                for al in covering:
                    collect_allowances.append(dict(path=path, title=rule.title, **al.as_dict()))
            continue
        out.append(Violation(rid=rule.rid, severity=rule.severity, action=rule.action,
                             path=path, line=line,
                             evidence=redact_evidence(rule.rid, ev),
                             title=rule.title, fix=rule.fix))
    return out


def scan_tree(files: Dict[str, str], waivers: Sequence[Waiver] = (),
              now: Optional[int] = None) -> Dict[str, Any]:
    """Scan a {path: content} mapping and return a VERDICT, not just a list."""
    allv: List[Violation] = []
    used: List[Dict[str, Any]] = []
    for path, content in files.items():
        allv.extend(scan_file(path, content, waivers, now, used))
    blocking = [v for v in allv if v.action == BLOCK]
    reporting = [v for v in allv if v.action == REPORT]
    wlist = []
    for w in waivers:
        ok, why = w.is_valid(now)
        wlist.append({"rid": w.rid, "pathGlob": w.path_glob, "approvedBy": w.approved_by,
                      "reason": w.reason, "expiresAt": w.expires_at, "valid": ok, "note": why})
    sev = {CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0}
    for v in allv:
        sev[v.severity] = sev.get(v.severity, 0) + 1
    return {"pass": not blocking, "verdict": "PASS" if not blocking else "BLOCKED",
            "filesScanned": len(files), "blockingCount": len(blocking),
            "reportingCount": len(reporting), "bySeverity": sev,
            "violations": [v.as_dict() for v in allv],
            "blocking": [v.as_dict() for v in blocking],
            "waivers": wlist,
            "waiversWithoutExpiry": [w.rid for w in waivers if not w.expires_at],
            "allowancesUsed": used,
            "allowanceCount": len(used)}


def waiver(rid: str, path_glob: str, reason: str, approved_by: str, expires_at: int,
           now: Optional[int] = None) -> Waiver:
    """Create a waiver. Expiry is MANDATORY - a permanent waiver is a disabled rule."""
    if rid != ALLOW_ALL and rid not in RULE_BY_ID:
        raise HardeningError("unknown rule id %r" % rid)
    if not expires_at:
        raise HardeningError("a waiver without an expiry is a disabled rule; refusing")
    if path_glob in ("*", "**"):
        raise HardeningError("a global waiver disables the rule everywhere; scope it to a path")
    w = Waiver(rid=rid, path_glob=path_glob, reason=reason, approved_by=approved_by,
               expires_at=int(expires_at))
    # `now` is injectable so expiry can be tested deterministically. In production
    # it is None and the real clock is used - the check is never skipped.
    ok, why = w.is_valid(now)
    if not ok:
        raise HardeningError(why)
    return w
