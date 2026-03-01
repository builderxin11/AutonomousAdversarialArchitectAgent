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
