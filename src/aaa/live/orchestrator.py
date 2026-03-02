"""Pipeline coordinator for live agent testing.

Ties together discovery, planning, execution, and judgment into
a single ``run_live_pipeline`` call.
"""

from __future__ import annotations

import pathlib
from typing import Any

from aaa.live.discovery import discover_victim
from aaa.live.judge import judge_live_results
from aaa.live.planner import plan_live_tests
from aaa.live.runner import run_live_tests


async def run_live_pipeline(
    target_path: str,
    scan_report: dict[str, Any] | None = None,
    *,
    victim_model: str = "openai:gpt-4o-mini",
    run_scan: bool = True,
) -> dict[str, Any]:
    """Run the full live agent testing pipeline.

    Parameters
    ----------
    target_path:
        Path to the victim Python module.
    scan_report:
        Pre-existing scan report dict.  If ``None`` and *run_scan* is True,
        the full ``aaa scan`` pipeline is executed first.
    victim_model:
        Model string for the victim agent (passed to ``build_victim_agent``).
    run_scan:
        Whether to run the scan pipeline when *scan_report* is not provided.

    Returns
    -------
    dict:
        Combined report with scan results, test plan, live results, and judgment.
    """
    # 1. Run scan if needed
    if scan_report is None and run_scan:
        scan_report = await _run_scan(target_path)
    elif scan_report is None:
        raise ValueError("No scan_report provided and run_scan=False")

    # 2. Discover victim capabilities
    capabilities = discover_victim(target_path)

    # 3. Generate test plan
    plan = plan_live_tests(scan_report, capabilities)

    # 4. Execute tests
    results = await run_live_tests(plan, capabilities, model=victim_model)

    # 5. Judge results
    judgment = judge_live_results(results, scan_report)

    return {
        "scan_report": scan_report,
        "test_plan": plan.model_dump(),
        "test_results": results.model_dump(),
        "judgment": judgment.model_dump(),
        "is_compromised": judgment.is_compromised,
    }


async def _run_scan(target_path: str) -> dict[str, Any]:
    """Execute the AAA scan pipeline and return the JSON report."""
    from aaa.cache import get_cache_dir
    from aaa.graph import build_aaa_graph
    from aaa.report import build_json_report

    path = pathlib.Path(target_path).resolve()
    source = path.read_text()
    cache_dir = str(get_cache_dir(path))

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
    return build_json_report(result, target_file=str(path))
