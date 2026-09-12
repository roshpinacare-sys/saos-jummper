"""GitHub backend for safewrite - the adapter that makes the guard a one-call change.

safewrite takes four callables: get_json, get_raw, get_last_author and put. That
is the right shape for a control, and the wrong shape for adoption - nobody
rewrites their write path to pass four functions when a bare requests.put is one
line. This module supplies them for the GitHub Contents API so the swap is:

    before   requests.put(url, headers=H, json={message, content, branch, sha})
    after    ghwrite.safe_write(backend, path, content, identity, message)

Verified against the live API before this was written: the last-author lookup
returns distinct identities per path (roshpinacare-sys for this repository's own
modules, Z User for saos-dex/src/lib/dex/relay.ts, SAOS Operator for
roshpina/kernel/orchestrator/audit.ts), and the contents metadata response
already carries the base64 blob, so one call yields both the sha and the content.

It performs no merge and makes no judgement about whether a force was wise.
"""

from __future__ import annotations

import base64
from typing import Any, Dict, List, Optional

from . import safewrite as SW
from .safewrite import WriteLog

API = "https://api.github.com"


class GitHubBackendError(ValueError):
    pass


class GitHubBackend:
    """Contents-API adapter. Holds a token; never logs it."""

    def __init__(self, token: str, org: str, repo: str, branch: str = "main",
                 session: Any = None, timeout: int = 45):
        if not token or not token.strip():
            raise GitHubBackendError("token required")
        if not org or not repo:
            raise GitHubBackendError("org and repo required")
        self.token = token
        self.org = org
        self.repo = repo
        self.branch = branch
        self.timeout = timeout
        self._s = session

    def _session(self) -> Any:
        if self._s is None:
            import requests
            self._s = requests.Session()
        return self._s

    def _json_headers(self) -> Dict[str, str]:
        return {"Authorization": "Bearer " + self.token,
                "Accept": "application/vnd.github+json"}

    def _url(self, path: str) -> str:
        return "%s/repos/%s/%s/contents/%s" % (API, self.org, self.repo, path)

    def get_json(self, path: str) -> Dict[str, Any]:
        r = self._session().get(self._url(path), headers=self._json_headers(),
                                timeout=self.timeout)
        if r.status_code == 404:
            return {"_status": 404}
        if r.status_code != 200:
            raise GitHubBackendError("metadata fetch for %r returned HTTP %s"
                                     % (path, r.status_code))
        j = r.json()
        j["_status"] = 200
        return j

    def get_raw(self, path: str) -> Optional[str]:
        """Decode the blob from the metadata response rather than fetching twice.

        The contents endpoint returns base64 content alongside the sha, so one call
        yields both - and reading them together means the content and the sha cannot
        disagree, which is what makes the write safe against a concurrent edit."""
        j = self.get_json(path)
        if j.get("_status") == 404 or "content" not in j:
            return None
        try:
            return base64.b64decode(j["content"]).decode("utf-8")
        except Exception as exc:
            raise GitHubBackendError("could not decode the blob for %r: %s"
                                     % (path, exc)) from exc

    def get_sha(self, path: str) -> Optional[str]:
        j = self.get_json(path)
        return j.get("sha") if j.get("_status") == 200 else None

    def get_last_author(self, path: str) -> Optional[str]:
        """Who last committed to this path. This is what makes the guard work:

        a blob alone says content exists; it does not say whose. Overwriting your
        own work is legitimate, overwriting another identity is not."""
        r = self._session().get(
            "%s/repos/%s/%s/commits" % (API, self.org, self.repo),
            headers=self._json_headers(),
            params={"path": path, "per_page": 1}, timeout=self.timeout)
        if r.status_code != 200:
            raise GitHubBackendError("history lookup for %r returned HTTP %s"
                                     % (path, r.status_code))
        j = r.json()
        if not j:
            return None
        try:
            return j[0]["commit"]["author"]["name"]
        except (KeyError, TypeError, IndexError):
            return None

    def read(self, path: str) -> Dict[str, Any]:
        """The dict safewrite expects: exists, content, author, sha."""
        j = self.get_json(path)
        if j.get("_status") == 404 or "content" not in j:
            return {"exists": False, "content": None, "author": None, "sha": None}
        try:
            content = base64.b64decode(j["content"]).decode("utf-8")
        except Exception as exc:
            raise GitHubBackendError("could not decode the blob for %r: %s"
                                     % (path, exc)) from exc
        return {"exists": True, "content": content, "sha": j.get("sha"),
                "author": self.get_last_author(path)}

    def put(self, path: str, body: Dict[str, Any]) -> Any:
        """The write. body already carries message, content, branch and sha."""
        b = dict(body)
        b.setdefault("branch", self.branch)
        return self._session().put(self._url(path), headers=self._json_headers(),
                                   json=b, timeout=self.timeout)


def safe_write(backend: GitHubBackend, path: str, content: str, identity: str,
               message: str = "", log: Optional[WriteLog] = None,
               force: bool = False) -> Dict[str, Any]:
    """Read, ask the guard, then write - or refuse and say what would be lost."""
    if not isinstance(backend, GitHubBackend):
        raise GitHubBackendError("backend must be a GitHubBackend")
    log = log if log is not None else WriteLog()
    existing = backend.read(path)
    return SW.write(path, content, existing, identity, backend.put, log,
                    repo=backend.repo, force=force,
                    message=message or ("update %s" % path))


def safe_write_many(backend: GitHubBackend,
                    items: List[Dict[str, Any]], identity: str,
                    log: Optional[WriteLog] = None,
                    force: bool = False) -> Dict[str, Any]:
    """Batch write that stops at the first refusal rather than half-applying."""
    if not isinstance(backend, GitHubBackend):
        raise GitHubBackendError("backend must be a GitHubBackend")
    log = log if log is not None else WriteLog()
    prepared = []
    for it in items:
        prepared.append({"path": it["path"], "content": it["content"],
                         "message": it.get("message", ""),
                         "existing": backend.read(it["path"])})
    return SW.write_many(prepared, identity, backend.put, log,
                         repo=backend.repo, force=force)
