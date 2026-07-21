"""Canonical Bundle Hash — a Skill's content identity for caching (ADR 0001).

Pure function ``skill -> hash`` over the Loader's already-normalized files (relative POSIX
path + LF-normalized bytes, junk excluded). Sorting by path makes it order-stable, and a
length-delimited encoding of each ``(path, content)`` pair keeps two different layouts from
ever colliding. The same Skill downloaded on different machines yields the same hash, which
is what lets one Verdict be shared per Skill and an Allowlist approval evaporate the moment
content changes.
"""

from __future__ import annotations

import hashlib

from skillguard.models import Skill


def canonical_bundle_hash(skill: Skill) -> str:
    """Return the hex SHA-256 identity of ``skill``'s normalized content."""
    digest = hashlib.sha256()
    for f in sorted(skill.files, key=lambda f: f.path):
        path_bytes = f.path.encode("utf-8")
        # Length-prefix each field so no path/content boundary is ambiguous: (a,bc) and
        # (ab,c) must not hash alike.
        digest.update(str(len(path_bytes)).encode("ascii"))
        digest.update(b"\0")
        digest.update(path_bytes)
        digest.update(str(len(f.content)).encode("ascii"))
        digest.update(b"\0")
        digest.update(f.content)
    return digest.hexdigest()


def short_hash(full: str, length: int = 12) -> str:
    """A short prefix of a Canonical Bundle Hash for compact display (never for identity)."""
    return full[:length]
