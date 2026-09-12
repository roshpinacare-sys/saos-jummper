"""Secret sweep - find the PATTERN, not the filename.

fleet_keys.enc and fleet_keys.meta.json were reported and both were removed. The
fix was real, and it missed two more instances of the same thing, because the
search looked for the name fleet_keys rather than for the shape: an encrypted
archive plus a plaintext credential that opens it, in one repository.

It never prints a secret value - every finding is a path, a field name and a
length. A sweeper that echoes what it finds turns one exposure into two, which is
what happened earlier in this engagement when a scanner printed the vault password
it was looking for."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

CRITICAL = "critical"
HIGH = "high"
MEDIUM = "medium"

_DQ = chr(34)
_SQ = chr(39)

CIPHERTEXT_EXT = (
    ".enc", ".gpg", ".pgp", ".age", ".sealed", ".encrypted",
    ".tar.enc", ".zip.enc", ".key.enc", ".pem.enc",
)
CIPHERTEXT_NAME = re.compile(r"(vault|keys?|secret|keystore|keyring|wallet|backup|recovery|treasure)", re.I)
CIPHERTEXT_DATA_EXT = (".enc", ".bin", ".dat", ".db", ".sqlite", ".tar", ".zip", ".bak", ".dump")

# Credential literal in a key: value pair. Optional quotes wrap the key name,
# because a JSON key is quoted - an earlier version required the colon to follow
# the name immediately, so the closing quote broke the match and no quoted key was
# ever found. That is the only shape a machine-written credential file has, so the
# sweeper reported recovery-meta.json, the exact file it exists to find, as clean.
# Built by concatenation rather than as one literal, because embedding both quote
# characters in a raw string is the escaping trap that broke this module twice
# while it was being written.
CREDENTIAL_FIELD = re.compile(
    "[" + _DQ + _SQ + r"]?([A-Za-z_][A-Za-z0-9_]{1,40})[" + _DQ + _SQ + r"]?\s*[:=]\s*"
    + _DQ + r"([^" + _DQ + r"]{6,})" + _DQ, re.M)
CREDENTIAL_NAME = re.compile(r"(pass|passwd|password|passphrase|secret|privatekey|privkey|mnemonic|seed|token|apikey|api_key|credential|master)", re.I)
NOT_A_SECRET = re.compile(r"(hash|sha|digest|id$|_id|path|file|name|salt$|iv$|tag$|nonce|prefix|hint|label|type|kind|format|version|note|comment)$", re.I)

# Shell and code metacharacters. A value containing them is a command recipe, not
# a literal credential. The README beside these archives documents its own decrypt
# command as -pass pass:"$(python3 -c ...)", which an earlier version of this
# sweeper reported as a 47-character plaintext password. Reporting a documented
# command as a leaked secret is a false positive, and a sweeper that cries wolf
# gets ignored - which is how the real one survives.
CODE_CHARS = ("$(", "`", ";", "|", "&&", "import ", "print(", "{", "}")


class SecretSweepError(ValueError):
    pass


@dataclass(frozen=True)
class Finding:
    kind: str
    severity: str
    path: str
    detail: str
    field: Optional[str] = None
    value_length: Optional[int] = None
    def as_dict(self) -> Dict[str, Any]:
        return {"kind": self.kind, "severity": self.severity, "path": self.path,
                "detail": self.detail, "field": self.field,
                "valueLength": self.value_length}


def is_ciphertext_shape(path: str, size: Optional[int] = None) -> bool:
    """Does this path look like an encrypted container?"""
    p = (path or "").lower()
    if not p:
        return False
    if any(p.endswith(e) for e in CIPHERTEXT_EXT):
        return True
    base = p.rsplit("/", 1)[-1]
    if base.startswith(".") and not CIPHERTEXT_NAME.search(base):
        return False
    return bool(CIPHERTEXT_NAME.search(base)) and p.endswith(CIPHERTEXT_DATA_EXT)


def credential_fields(text: str) -> List[Tuple[str, int]]:
    """(field name, value length) for every credential-shaped literal. Lengths,
    never values."""
    out: List[Tuple[str, int]] = []
    if not text:
        return out
    for m in CREDENTIAL_FIELD.finditer(text):
        name, value = m.group(1), m.group(2)
        if not CREDENTIAL_NAME.search(name):
            continue
        if NOT_A_SECRET.search(name):
            continue
        if len(value) < 8:
            continue
        if any(ch in value for ch in CODE_CHARS):
            continue
        out.append((name, len(value)))
    return out


def sweep(files: Sequence[Dict[str, Any]], repo: str = "",
          texts: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Sweep one repository. files is a list of {path, size}; texts is optional.

    Without text only the ciphertext side can be assessed, and that is reported as
    unassessed rather than as clean."""
    if not isinstance(files, (list, tuple)):
        raise SecretSweepError("files must be a sequence of {path, size} objects")
    texts = texts or {}
    findings: List[Finding] = []
    cipher: List[str] = []
    creds: List[Tuple[str, str, int]] = []
    for f in files:
        if not isinstance(f, dict) or "path" not in f:
            continue
        path = f["path"]
        if is_ciphertext_shape(path, f.get("size")):
            cipher.append(path)
        if path in texts:
            for name, ln in credential_fields(texts[path]):
                creds.append((path, name, ln))
                findings.append(Finding("plaintext-credential", CRITICAL, path,
                    "field %r holds a %d-character literal in a committed file"
                    % (name, ln), field=name, value_length=ln))
    cipher = sorted(set(cipher))
    if cipher and creds:
        for cp in cipher:
            for (fp, name, ln) in creds:
                findings.append(Finding("ciphertext-beside-its-key", CRITICAL, cp,
                    "encrypted container in the same repository as a plaintext "
                    "credential (%s in %s, %d chars). Ciphertext with its password "
                    "beside it is plaintext with extra steps." % (name, fp, ln)))
    elif cipher and not texts:
        findings.append(Finding("unassessed", HIGH, cipher[0],
            "%d file(s) look like encrypted containers but no file text was "
            "supplied, so the credential side could not be assessed. Absence of a "
            "finding is not evidence of safety." % len(cipher)))
    counts = {CRITICAL: 0, HIGH: 0, MEDIUM: 0}
    for x in findings:
        counts[x.severity] = counts.get(x.severity, 0) + 1
    kinds = sorted({x.kind for x in findings})
    return {"repo": repo, "files": len(files), "ciphertext": cipher,
            "ciphertextCount": len(cipher),
            "credentialFields": [{"path": p, "field": n, "length": l} for p, n, l in creds],
            "findings": [x.as_dict() for x in findings],
            "critical": counts[CRITICAL], "high": counts[HIGH],
            "textSupplied": len(texts),
            "verdict": ("clean" if not findings else
                        "%d finding(s): %s" % (len(findings), ", ".join(kinds)))}


def sweep_many(repos: Dict[str, Sequence[Dict[str, Any]]],
               texts: Optional[Dict[str, Dict[str, str]]] = None) -> Dict[str, Any]:
    """Sweep several repositories, worst first."""
    texts = texts or {}
    out = [sweep(fs, repo=r, texts=texts.get(r, {})) for r, fs in repos.items()]
    out.sort(key=lambda x: (-x["critical"], -x["high"]))
    tc = sum(x["critical"] for x in out)
    return {"repos": out, "repoCount": len(out), "totalCritical": tc,
            "totalHigh": sum(x["high"] for x in out),
            "verdict": ("no critical exposure across %d repositories" % len(out)
                        if tc == 0 else
                        "%d critical finding(s) across %d repositories" % (tc, len(out)))}
