"""Content-hash based AST cache for incremental scanning.

Caches per-file extraction and flaw-analysis results keyed by SHA-256 of
the file content.  When the source hasn't changed the expensive LLM call
is skipped entirely.

Cache entries are versioned — a bump to ``_CACHE_VERSION`` transparently
invalidates all stale entries.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_CACHE_VERSION = 1


def content_hash(source: str) -> str:
    """Return the SHA-256 hex digest of *source*."""
    return hashlib.sha256(source.encode("utf-8")).hexdigest()


def get_cache_dir(target_path: Path) -> Path:
    """Determine the cache directory for a scan target.

    Uses ``AAA_CACHE_DIR`` env-var if set, otherwise ``.aaa_cache/``
    relative to *target_path* (its parent if a file, itself if a directory).
    """
    env = os.environ.get("AAA_CACHE_DIR")
    if env:
        return Path(env)
    base = target_path if target_path.is_dir() else target_path.parent
    return base / ".aaa_cache"


def load_cached(
    cache_dir: Path, file_hash: str
) -> Optional[Tuple[Dict[str, Any], List[Dict]]]:
    """Load cached extraction + flaws for *file_hash*.

    Returns ``(extracted, flaws)`` on hit, ``None`` on miss or version
    mismatch.
    """
    path = cache_dir / f"{file_hash}.json"
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    if data.get("_cache_version") != _CACHE_VERSION:
        return None
    return data["extracted"], data["flaws"]


def store_cached(
    cache_dir: Path,
    file_hash: str,
    extracted: Dict[str, Any],
    flaws: List[Dict],
) -> None:
    """Persist extraction + flaws to the cache directory."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "_cache_version": _CACHE_VERSION,
        "extracted": extracted,
        "flaws": flaws,
    }
    path = cache_dir / f"{file_hash}.json"
    path.write_text(json.dumps(payload, default=str), encoding="utf-8")


def clear_cache(cache_dir: Path) -> int:
    """Remove all ``.json`` cache entries.  Returns the count of files removed."""
    if not cache_dir.is_dir():
        return 0
    count = 0
    for entry in cache_dir.glob("*.json"):
        entry.unlink()
        count += 1
    return count
