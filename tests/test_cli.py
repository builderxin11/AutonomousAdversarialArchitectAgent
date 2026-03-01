"""Tests for aaa.cli — argument parsing + scan orchestration."""

from __future__ import annotations

import json
import pathlib
from unittest.mock import AsyncMock, patch

import pytest

from aaa.cli import _build_parser, _run_scan_async


# ---- _build_parser ----


class TestBuildParser:
    def test_scan_minimal(self):
        parser = _build_parser()
        args = parser.parse_args(["scan", "file.py"])
        assert args.command == "scan"
        assert args.target == "file.py"
        assert args.fmt == "text"
        assert args.output is None
        assert args.no_cache is False
        assert args.glob_pattern is None

    def test_scan_full(self):
        parser = _build_parser()
        args = parser.parse_args(["scan", "f.py", "--format", "json", "-o", "out.json"])
        assert args.target == "f.py"
        assert args.fmt == "json"
        assert args.output == "out.json"

    def test_no_command(self):
        parser = _build_parser()
        args = parser.parse_args([])
        assert args.command is None

    def test_no_cache_flag(self):
        parser = _build_parser()
        args = parser.parse_args(["scan", "f.py", "--no-cache"])
        assert args.no_cache is True

    def test_glob_flag(self):
        parser = _build_parser()
        args = parser.parse_args(["scan", "src/", "--glob", "agents/*.py"])
        assert args.glob_pattern == "agents/*.py"


# ---- _run_scan_async ----


class TestRunScanAsync:
    async def test_missing_file(self):
        code = await _run_scan_async("/nonexistent/file.py", "text", None)
        assert code == 2

    async def test_compromised_returns_1(self, tmp_path: pathlib.Path):
        target = tmp_path / "victim.py"
        target.write_text("x = 1")

        mock_result = {"is_compromised": True, "eval_metrics": {}, "logic_flaws": []}
        mock_graph = AsyncMock()
        mock_graph.ainvoke.return_value = mock_result

        with patch("aaa.cli.build_aaa_graph", return_value=mock_graph):
            code = await _run_scan_async(str(target), "text", None)
        assert code == 1

    async def test_not_compromised_returns_0(self, tmp_path: pathlib.Path):
        target = tmp_path / "victim.py"
        target.write_text("x = 1")

        mock_result = {"is_compromised": False, "eval_metrics": {}, "logic_flaws": []}
        mock_graph = AsyncMock()
        mock_graph.ainvoke.return_value = mock_result

        with patch("aaa.cli.build_aaa_graph", return_value=mock_graph):
            code = await _run_scan_async(str(target), "text", None)
        assert code == 0

    async def test_output_file(self, tmp_path: pathlib.Path):
        target = tmp_path / "victim.py"
        target.write_text("x = 1")
        output = tmp_path / "report.txt"

        mock_result = {"is_compromised": False, "eval_metrics": {}, "logic_flaws": []}
        mock_graph = AsyncMock()
        mock_graph.ainvoke.return_value = mock_result

        with patch("aaa.cli.build_aaa_graph", return_value=mock_graph):
            await _run_scan_async(str(target), "text", str(output))
        assert output.exists()
        assert len(output.read_text()) > 0

    async def test_json_format_valid(self, tmp_path: pathlib.Path):
        target = tmp_path / "victim.py"
        target.write_text("x = 1")
        output = tmp_path / "report.json"

        mock_result = {"is_compromised": False, "eval_metrics": {}, "logic_flaws": []}
        mock_graph = AsyncMock()
        mock_graph.ainvoke.return_value = mock_result

        with patch("aaa.cli.build_aaa_graph", return_value=mock_graph):
            await _run_scan_async(str(target), "json", str(output))

        data = json.loads(output.read_text())
        assert "meta" in data
        assert "verdict" in data

    async def test_no_cache_flag(self, tmp_path: pathlib.Path):
        target = tmp_path / "victim.py"
        target.write_text("x = 1")

        mock_result = {"is_compromised": False, "eval_metrics": {}, "logic_flaws": []}
        mock_graph = AsyncMock()
        mock_graph.ainvoke.return_value = mock_result

        with patch("aaa.cli.build_aaa_graph", return_value=mock_graph):
            code = await _run_scan_async(str(target), "text", None, no_cache=True)
        assert code == 0
        # Verify no cache_dir passed (it should be None)
        call_args = mock_graph.ainvoke.call_args[0][0]
        assert call_args["target_metadata"]["cache_dir"] is None

    async def test_directory_scan(self, tmp_path: pathlib.Path):
        (tmp_path / "a.py").write_text("x = 1")
        (tmp_path / "b.py").write_text("y = 2")

        mock_result = {
            "is_compromised": False,
            "eval_metrics": {},
            "logic_flaws": [],
            "target_metadata": {"files_scanned": 2},
        }
        mock_graph = AsyncMock()
        mock_graph.ainvoke.return_value = mock_result

        with patch("aaa.cli.build_aaa_graph", return_value=mock_graph):
            code = await _run_scan_async(str(tmp_path), "text", None)
        assert code == 0
        # Verify files dict was passed
        call_args = mock_graph.ainvoke.call_args[0][0]
        assert "files" in call_args["target_metadata"]
        assert len(call_args["target_metadata"]["files"]) == 2

    async def test_empty_directory(self, tmp_path: pathlib.Path):
        code = await _run_scan_async(str(tmp_path), "text", None)
        assert code == 2
