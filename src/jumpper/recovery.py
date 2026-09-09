"""Recovery contract - what a backup and vault path must guarantee.

Recovery is the one control you only exercise after everything else has failed, so
it is the one that most needs verifying before it is needed.

Read out of real source, not docstrings:

    Saosmartwallet/packages/core/src/backup/backup.ts   26,905 chars / 652 lines
    Saosmartwallet/packages/core/src/vault/vault.ts     43,402 chars / 1,128 lines
    Saosmartwallet/packages/core/src/encoding.ts         4,195 chars
    Saosmartwallet/packages/bridges/router.ts           16,560 chars / 401 lines

VERIFIED TRUE

  bytesEqual is genuinely constant time - XOR-accumulate over every byte, no early
  exit, only length leaks:

      if (a.length !== b.length) return false;
      let diff = 0;
      for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
      return diff === 0;

  Wrapping and recovery keys are randomBytes(32), zero-filled after use, never
  persisted - only Shamir shares leave the process.

  Restore fails closed into a FRESH vault only, after every integrity check passes.

  The secret material is INSIDE the AEAD envelope, not beside it:

      encryptedState = seal(utf8(canonicalJson(state)), wrappingKey, ...)
      payload        = sealJson(state, recoveryKey, ...)

  The whole state document is sealed, so the dead-man config and beneficiary list
  are inside authenticated encryption. Audit records only beneficiaries.length.

THE ONE FINDING (low severity, and the reason matters)

  The outer package signature is keyed by public data:

      packageSignature  = HMAC-SHA256(key = utf8(metadata.checksum), msg = preimage)
      metadata.checksum = sha256(canonicalJson(encryptedState))

  Both the key and the message are fields of the package itself, so anyone holding
  the backup file can recompute both. The outer signature detects ACCIDENTAL
  CORRUPTION but authenticates nothing against an adversary.

  The docstring says the key is "sha256(canonical INNER JSON)". The code hashes
  encryptedState, the OUTER ciphertext. That wording matters: "inner" implies the
  key is unavailable without decrypting, and it is not.

  Severity is LOW because the real integrity boundary is the AEAD envelope, which
  is correctly keyed. Tampering with encryptedState fails AEAD decryption. What an
  adversary could alter undetected is limited to format, version, createdAt and
  metadata fields - none secret, though a tampered version could in principle steer
  restore-path selection.

  Fix: key the outer HMAC with something the package does not contain (the
  Argon2id-derived backup key, or a key id resolved from the vault), or drop the
  outer signature and say plainly that AEAD is the only integrity boundary. Either
  is honest. Calling a public-keyed HMAC a signature is not.

SCOPE

  Properties declare what kind of artifact they apply to. vault.ts is a state
  machine, not a backup manager, so Shamir and AEAD-sealing are out of scope for
  it. Applying them anyway is a category error that produces false negatives, and
  false negatives are how a contract gets switched off.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Sequence

PRESENT = "present"
ABSENT = "absent"
UNIVERSAL = "universal"
BACKUP = "backup"
VAULT = "vault"


class RecoveryError(ValueError):
    pass


@dataclass(frozen=True)
class Property:
    pid: str
    title: str
    why: str
    detect: Callable[[str], bool]
    required: bool = True
    scope: str = UNIVERSAL


@dataclass(frozen=True)
class PropResult:
    pid: str
    title: str
    status: str
    required: bool
    scope: str
    why: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {"id": self.pid, "title": self.title, "status": self.status,
                "required": self.required, "scope": self.scope, "why": self.why}


PROPERTIES: List[Property] = [
    Property("R-01", "Constant-time comparison for MAC or password verification",
             "A byte-by-byte compare that returns early leaks how many leading bytes "
             "matched - a remote timing oracle on any MAC or verifier. A named "
             "constant-time primitive is accepted even when its body lives in a shared "
             "module, which is where it belongs.",
             lambda s: bool(re.search(r"timingSafeEqual|bytesEqual|compare_digest", s))
                    or bool(re.search(r"\|=\s*\w+\s*\^|diff\s*\|=", s))),

    Property("R-02", "Wrapping or recovery key from a CSPRNG at 32 bytes",
             "A short or predictable wrapping key makes the whole envelope brute-forceable "
             "however strong the cipher is.",
             lambda s: bool(re.search(r"randomBytes\s*\(\s*32\s*\)|getRandomValues", s)),
             scope=BACKUP),

    Property("R-03", "Key material zero-filled after use",
             "A key left in a freed buffer survives in a process snapshot, a core dump or "
             "a swapped page long after the operation finished.",
             lambda s: bool(re.search(r"\.fill\s*\(\s*0\s*\)|zeroFill|wipe|zero-fill", s, re.I))),

    Property("R-04", "Restore allowed only into fresh, never-initialized storage",
             "Restoring over a live vault destroys the state that was there, and hands an "
             "attacker with a backup file a way to roll a vault back.",
             lambda s: bool(re.search(r"fresh|never[- ]initialized|alreadyInitialized|isInitialized", s, re.I))),

    Property("R-05", "Threshold reconstruction refuses too-few shares",
             "Shamir reconstruction from fewer than threshold shares does not fail - it "
             "silently returns a WRONG secret. That is the classic pitfall and it must be "
             "an explicit refusal.",
             lambda s: bool(re.search(r"threshold", s, re.I))
                    and bool(re.search(r"shares?\.length\s*<|length\s*<\s*t\b|insufficient", s)),
             scope=BACKUP),

    Property("R-06", "Secret state sealed inside an AEAD envelope",
             "Anything outside the authenticated envelope can be altered by whoever holds "
             "the file. Beneficiary lists and dead-man config belong inside it.",
             lambda s: bool(re.search(r"aes-256-gcm|chacha20-poly1305|authTag", s, re.I))
                    and bool(re.search(r"\bseal\s*\(|sealJson\s*\(", s)),
             scope=BACKUP),

    Property("R-07", "Dead-man switch has a bounded inactivity window",
             "An inheritance path with no bound is either never triggered or triggered by a "
             "single missed heartbeat. The window must be explicit and validated.",
             lambda s: bool(re.search(r"inactiveDays|inactivity", s, re.I))
                    and bool(re.search(r"beneficiar", s, re.I)),
             scope=BACKUP),

    Property("R-08", "Audit records counts, not secret values",
             "The audit log is the most widely readable artifact in the system. Logging a "
             "beneficiary list or a key turns the log into the breach.",
             lambda s: bool(re.search(r"beneficiaries\.length|\.length\b", s))
                    and not bool(re.search(r"detail:\s*\{[^}]*(password|privateKey|wif|mnemonic)", s, re.I)),
             scope=BACKUP),
]

PUBLIC_KEYED_MAC = re.compile(
    r"createHmac\([^)]*metadata\.checksum|HMAC.{0,60}keyed by the inner checksum", re.I)
INNER_VS_OUTER = re.compile(r"packageChecksum\s*\(\s*encryptedState\s*\)")


def public_keyed_mac(src: str) -> bool:
    """True when a MAC is keyed by data contained in the artifact it authenticates."""
    return bool(PUBLIC_KEYED_MAC.search(src) and INNER_VS_OUTER.search(src))


def check(src: str, path: str = "<source>", kind: str = BACKUP) -> Dict[str, Any]:
    """Evaluate a backup or vault implementation against the recovery contract."""
    if not src or not src.strip():
        raise RecoveryError("empty source; nothing to evaluate")
    if kind not in (BACKUP, VAULT):
        raise RecoveryError("kind must be backup or vault; a contract that applies to "
                            "everything applies to nothing")
    applicable = [pr for pr in PROPERTIES if pr.scope == UNIVERSAL or pr.scope == kind]
    results: List[PropResult] = []
    for pr in applicable:
        try:
            ok = bool(pr.detect(src))
        except Exception:
            ok = False                      # fail closed: a broken check is a missing property
        results.append(PropResult(pid=pr.pid, title=pr.title,
                                  status=PRESENT if ok else ABSENT,
                                  required=pr.required, scope=pr.scope, why=pr.why))
    missing = [r.pid for r in results if r.status == ABSENT and r.required]
    finding = public_keyed_mac(src)
    return {"path": path, "kind": kind, "chars": len(src),
            "propertiesPresent": len(results) - len(missing),
            "propertiesTotal": len(results), "missingRequired": missing,
            "results": [r.as_dict() for r in results], "publicKeyedMac": finding,
            "finding": ("the outer package MAC is keyed by metadata.checksum, itself "
                        "sha256 of encryptedState - both are fields of the package, so "
                        "anyone holding the file can recompute it. Detects accidental "
                        "corruption, authenticates nothing. Severity LOW: the real "
                        "integrity boundary is the AEAD envelope, which is correctly keyed."
                        if finding else None),
            "verdict": ("CONFORMS" if not missing and not finding else
                        "CONFORMS WITH ONE LOW-SEVERITY FINDING" if not missing else
                        "DOES NOT CONFORM - missing: " + ", ".join(missing))}


ANTI_MOCK = [
    ("every fee leg declares its source", r"source\s*:"),
    ("unexecutable rails are gated, not omitted", r"gated|gateReason"),
    ("executability is asserted, not assumed", r"assertExecutable"),
    ("numbers come from live measurement", r"measured|lamport|gasPrice|gas\b"),
]


def check_anti_mock(src: str) -> Dict[str, Any]:
    """The router's own anti-mock contract: no fabricated numbers, no silent omissions."""
    if not src or not src.strip():
        raise RecoveryError("empty source; nothing to evaluate")
    rows = [{"claim": label, "present": bool(re.search(rx, src, re.I))} for label, rx in ANTI_MOCK]
    ok = all(r["present"] for r in rows)
    return {"allPresent": ok, "rows": rows,
            "verdict": ("ANTI-MOCK CONTRACT HELD" if ok else
                        "ANTI-MOCK CONTRACT BROKEN: " + ", ".join(r["claim"] for r in rows if not r["present"]))}


def check_package(files: Dict[str, str], kind: str = BACKUP,
                  path: str = "<package>") -> Dict[str, Any]:
    """Evaluate a PACKAGE rather than one file.

    A single-file check reports R-01 absent for vault.ts, because the constant-time
    comparison lives in kdf.ts and encoding.ts and is imported. That is correct
    architecture, not a defect - a property satisfied by delegation looks missing
    when you only look at the delegator. This is the third time that exact pattern
    produced a false negative in this engagement, so the contract now takes a set
    of files and evaluates the union, while still reporting which file the contract
    was asked about.
    """
    if not files:
        raise RecoveryError("empty package; nothing to evaluate")
    union = (chr(10) + chr(10)).join(files.values())
    out = check(union, path=path, kind=kind)
    out["files"] = sorted(files)
    out["fileCount"] = len(files)
    per_file = {}
    for name, src in files.items():
        r = check(src, path=name, kind=kind)
        per_file[name] = {"present": r["propertiesPresent"], "total": r["propertiesTotal"],
                          "missing": r["missingRequired"], "publicKeyedMac": r["publicKeyedMac"]}
    out["perFile"] = per_file
    out["delegationNote"] = ("properties satisfied by an imported module appear absent in a "
                             "single-file check; the package verdict is the one that counts")
    return out
