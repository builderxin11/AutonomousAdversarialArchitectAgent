"""Tests for aaa.cache — content-hash AST cache."""

from __future__ import annotations

import json
from pathlib import Path

from aaa.cache import (
    _CACHE_VERSION,
    clear_cache,
    content_hash,
    load_cached,
    store_cached,
)


class TestContentHash:
    def test_deterministic(self):
        assert content_hash("hello") == content_hash("hello")

    def test_different_content(self):
        assert content_hash("hello") != content_hash("world")

    def test_empty_string(self):
        h = content_hash("")
        assert isinstance(h, str) and len(h) == 64


class TestStoreAndLoad:
    def test_round_trip(self, tmp_path: Path):
        cache_dir = tmp_path / ".aaa_cache"
        extracted = {"functions": [{"name": "foo"}], "global_variables": [], "string_constants": []}
        flaws = [{"flaw_id": "FLAW-001", "severity": "high"}]

        h = content_hash("def foo(): pass")
        store_cached(cache_dir, h, extracted, flaws)
        result = load_cached(cache_dir, h)

        assert result is not None
        loaded_extracted, loaded_flaws = result
        assert loaded_extracted == extracted
        assert loaded_flaws == flaws

    def test_cache_miss_returns_none(self, tmp_path: Path):
        cache_dir = tmp_path / ".aaa_cache"
        cache_dir.mkdir()
        assert load_cached(cache_dir, "nonexistent_hash") is None

    def test_version_mismatch_returns_none(self, tmp_path: Path):
        cache_dir = tmp_path / ".aaa_cache"
        cache_dir.mkdir()
        h = "fakehash123"
        payload = {
            "_cache_version": _CACHE_VERSION + 999,
            "extracted": {},
            "flaws": [],
        }
        (cache_dir / f"{h}.json").write_text(json.dumps(payload))
        assert load_cached(cache_dir, h) is None

    def test_corrupted_json_returns_none(self, tmp_path: Path):
        cache_dir = tmp_path / ".aaa_cache"
        cache_dir.mkdir()
        h = "badjson"
        (cache_dir / f"{h}.json").write_text("not valid json {{{")
        assert load_cached(cache_dir, h) is None

    def test_creates_cache_dir_on_store(self, tmp_path: Path):
        cache_dir = tmp_path / "deep" / "nested" / ".aaa_cache"
        assert not cache_dir.exists()
        store_cached(cache_dir, "h", {}, [])
        assert cache_dir.exists()


class TestClearCache:
    def test_clear_removes_entries(self, tmp_path: Path):
        cache_dir = tmp_path / ".aaa_cache"
        store_cached(cache_dir, "aaa", {"a": 1}, [])
        store_cached(cache_dir, "bbb", {"b": 2}, [])

        removed = clear_cache(cache_dir)
        assert removed == 2
        assert load_cached(cache_dir, "aaa") is None
        assert load_cached(cache_dir, "bbb") is None

    def test_clear_nonexistent_dir(self, tmp_path: Path):
        assert clear_cache(tmp_path / "nope") == 0
