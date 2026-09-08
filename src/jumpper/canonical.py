"""Deterministic JSON canonicalization.

Mirrors the proven canonical-json.ts from the audited estate: sorted keys,
-0 normalized to 0, non-finite numbers rejected, no insignificant whitespace.

Canonicalization is the foundation of every hash in this system. If two
implementations disagree on one byte, every proof breaks. Hence golden vectors.
"""

from __future__ import annotations

import json
import math
from typing import Any


class CanonicalizationError(ValueError):
    """Raised when a value cannot be canonically represented."""


def _normalize_number(value: float) -> Any:
    if not math.isfinite(value):
        raise CanonicalizationError("non-finite number rejected: %r" % (value,))
    if value == 0:
        return 0
    if float(value).is_integer():
        return int(value)
    return value


def _walk(value: Any) -> Any:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return _normalize_number(value)
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)):
        return [_walk(v) for v in value]
    if isinstance(value, dict):
        out = {}
        for key in sorted(value.keys()):
            if not isinstance(key, str):
                raise CanonicalizationError("non-string key rejected: %r" % (key,))
            out[key] = _walk(value[key])
        return out
    raise CanonicalizationError("unsupported type rejected: %s" % type(value).__name__)


def canonical(value: Any) -> str:
    """Return the canonical JSON string for value. Byte-identical for equal semantics."""
    return json.dumps(
        _walk(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def canonical_bytes(value: Any) -> bytes:
    return canonical(value).encode("utf-8")
