"""Command-line interface for AAA.

Usage::

    aaa scan <target_file>                          # text to stdout
    aaa scan <target_file> --format json             # json to stdout
    aaa scan <target_file> --output report.json      # text to file
    aaa scan <target_file> --format json -o out.json # json to file

Exit codes: 0 = not compromised, 1 = compromised, 2 = input error.
"""

from __future__ import annotations

import argparse
import asyncio
import pathlib
import sys
from typing import Optional, Sequence

from aaa.cache import get_cache_dir
from aaa.graph import build_aaa_graph
from aaa.report import build_json_report, format_json, format_text
from aaa.state import TripleAState


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aaa",
        description="AAA — Autonomous Adversarial Architect: grey-box red-teaming for AI agents.",
    )
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="Run the full AAA pipeline against a target file.")
    scan.add_argument("target", type=str, help="Path to the victim .py file.")
    scan.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        dest="fmt",
        help="Output format (default: text).",
    )
    scan.add_argument(
        "--output", "-o",
        type=str,
        default=None,
        help="Write report to PATH instead of stdout.",
    )
    scan.add_argument(
        "--no-cache",
        action="store_true",
        default=False,
        help="Disable the content-hash AST cache.",
    )
    scan.add_argument(
        "--glob",
        type=str,
        default=None,
        dest="glob_pattern",
        help="Glob pattern for directory scanning (default: '**/*.py').",
    )
    return parser


async def _run_scan_async(
    target: str,
    fmt: str,
    output: Optional[str],
    *,
    no_cache: bool = False,
    glob_pattern: Optional[str] = None,
) -> int:
    target_path = pathlib.Path(target).resolve()
    if not target_path.exists():
        print(f"Error: target not found: {target}", file=sys.stderr)
        return 2

    cache_dir = None if no_cache else str(get_cache_dir(target_path))

    if target_path.is_dir():
        # Multi-file mode
        from aaa.nodes.auditor import _collect_files

        files = _collect_files(target_path, glob_pattern)
        if not files:
            print(f"Error: no Python files found in {target}", file=sys.stderr)
            return 2

        initial_state: TripleAState = {
            "target_metadata": {
                "source_code": "",
                "files": files,
                "cache_dir": cache_dir,
            },
            "logic_flaws": [],
            "hypotheses": [],
            "attack_tree": {},
            "internal_thought": [],
            "victim_logs": [],
            "env_snapshot": {},
            "eval_metrics": {},
            "is_compromised": False,
        }
    else:
        # Single-file mode (backward-compatible)
        source = target_path.read_text()

        initial_state = {
            "target_metadata": {
                "source_code": source,
                "cache_dir": cache_dir,
            },
            "logic_flaws": [],
            "hypotheses": [],
            "attack_tree": {},
            "internal_thought": [],
            "victim_logs": [],
            "env_snapshot": {},
            "eval_metrics": {},
            "is_compromised": False,
        }

    graph = build_aaa_graph()
    result = await graph.ainvoke(initial_state)

    report = build_json_report(result, target_file=str(target_path))
    formatted = format_json(report) if fmt == "json" else format_text(report)

    if output:
        pathlib.Path(output).write_text(formatted, encoding="utf-8")
    else:
        print(formatted)

    return 1 if result.get("is_compromised") else 0


def _run_scan(
    target: str,
    fmt: str,
    output: Optional[str],
    *,
    no_cache: bool = False,
    glob_pattern: Optional[str] = None,
) -> int:
    return asyncio.run(
        _run_scan_async(target, fmt, output, no_cache=no_cache, glob_pattern=glob_pattern)
    )


def main(argv: Optional[Sequence[str]] = None) -> None:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        sys.exit(2)

    if args.command == "scan":
        code = _run_scan(
            args.target,
            args.fmt,
            args.output,
            no_cache=args.no_cache,
            glob_pattern=getattr(args, "glob_pattern", None),
        )
        sys.exit(code)
