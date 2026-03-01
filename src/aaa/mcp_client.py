"""Live MCP Server Scanner.

Connects to a running MCP server (via stdio or SSE transport), pulls all tool
schemas via ``tools/list``, and runs the two-layer poisoning detection (regex +
LLM) directly on them — no source code needed.

Usage::

    aaa scan-mcp http://localhost:8000/sse           # SSE transport (auto-detected)
    aaa scan-mcp python my_server.py                 # stdio transport (auto-detected)
    aaa scan-mcp --transport stdio -- python my_server.py  # explicit transport
    aaa scan-mcp --fast http://localhost:8000/sse     # regex only, skip LLM
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.sse import sse_client

from aaa.mcp import analyze_tool_schemas_llm, scan_tool_descriptions

AAA_VERSION = "0.1.0"


# ---------------------------------------------------------------------------
# 1. Fetch tools from a live MCP server
# ---------------------------------------------------------------------------

async def fetch_mcp_tools(
    transport: str,
    target: str,
    args: Optional[List[str]] = None,
    timeout: float = 30.0,
) -> List[Dict[str, Any]]:
    """Connect to an MCP server and return all tool schemas.

    Parameters
    ----------
    transport:
        ``"stdio"`` or ``"sse"``.
    target:
        For stdio: the command to launch (e.g. ``"python"``).
        For sse: the server URL (e.g. ``"http://localhost:8000/sse"``).
    args:
        Additional command-line arguments for stdio transport.
    timeout:
        Connection timeout in seconds.

    Returns
    -------
    List of tool dicts with keys: ``name``, ``description``, ``input_schema``,
    ``lineno`` (always 0 for live servers).
    """
    args = args or []

    if transport == "stdio":
        server_params = StdioServerParameters(command=target, args=args)
        async with stdio_client(server_params) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                result = await session.list_tools()
                return [
                    {
                        "name": t.name,
                        "description": t.description or "",
                        "input_schema": t.inputSchema,
                        "lineno": 0,
                    }
                    for t in result.tools
                ]

    if transport == "sse":
        async with sse_client(target, timeout=timeout) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                result = await session.list_tools()
                return [
                    {
                        "name": t.name,
                        "description": t.description or "",
                        "input_schema": t.inputSchema,
                        "lineno": 0,
                    }
                    for t in result.tools
                ]

    raise ValueError(f"Unknown transport: {transport!r}. Use 'stdio' or 'sse'.")


# ---------------------------------------------------------------------------
# 2. Orchestrate full scan
# ---------------------------------------------------------------------------

async def scan_mcp_server(
    transport: str,
    target: str,
    args: Optional[List[str]] = None,
    *,
    fast: bool = False,
    timeout: float = 30.0,
) -> Dict[str, Any]:
    """Scan a live MCP server for tool schema poisoning.

    Parameters
    ----------
    transport:
        ``"stdio"`` or ``"sse"``.
    target:
        Command (stdio) or URL (sse).
    args:
        Extra command args for stdio.
    fast:
        If ``True``, skip LLM analysis (regex only).
    timeout:
        Connection timeout in seconds.

    Returns
    -------
    Full scan report dict.
    """
    tools = await fetch_mcp_tools(transport, target, args, timeout=timeout)

    # Adapt to the format scan_tool_descriptions expects (docstring key)
    adapted = [
        {
            "name": t["name"],
            "docstring": t["description"],
            "lineno": t["lineno"],
        }
        for t in tools
    ]

    # Layer 1: Deterministic regex patterns (always)
    regex_findings = scan_tool_descriptions(adapted)

    # Layer 2: LLM semantic analysis (unless --fast)
    llm_findings: List[Dict] = []
    if not fast:
        llm_findings = analyze_tool_schemas_llm(adapted, "")

    return _build_report(
        transport=transport,
        target=target,
        tools=tools,
        regex_findings=regex_findings,
        llm_findings=llm_findings,
    )


# ---------------------------------------------------------------------------
# 3. Report builder
# ---------------------------------------------------------------------------

def _build_report(
    *,
    transport: str,
    target: str,
    tools: List[Dict[str, Any]],
    regex_findings: list,
    llm_findings: List[Dict],
) -> Dict[str, Any]:
    """Assemble the canonical scan report dict."""
    # Convert SchemaFinding dataclass instances to plain dicts
    findings = [
        {
            "tool_name": f.tool_name,
            "pattern": f.pattern,
            "risk_level": f.risk_level,
            "matched_text": f.matched_text,
            "explanation": f.explanation,
        }
        for f in regex_findings
    ]

    # Count risk levels across both layers
    all_risks: List[str] = [f["risk_level"] for f in findings]
    all_risks.extend(f.get("severity", "medium") for f in llm_findings)

    critical = all_risks.count("critical")
    high = all_risks.count("high")
    medium = all_risks.count("medium")

    # Determine poisoned tool names
    poisoned_names = {f["tool_name"] for f in findings}
    poisoned_names.update(f.get("function", "") for f in llm_findings if f.get("function"))

    if critical > 0:
        risk_level = "critical"
    elif high > 0:
        risk_level = "high"
    elif medium > 0:
        risk_level = "medium"
    else:
        risk_level = "clean"

    return {
        "meta": {
            "aaa_version": AAA_VERSION,
            "scan_type": "mcp_server",
            "transport": transport,
            "target": target,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools_scanned": len(tools),
        },
        "tools": [
            {
                "name": t["name"],
                "description": t["description"],
                "input_schema": t["input_schema"],
            }
            for t in tools
        ],
        "findings": findings,
        "llm_findings": llm_findings,
        "summary": {
            "total_tools": len(tools),
            "clean_tools": len(tools) - len(poisoned_names),
            "poisoned_tools": len(poisoned_names),
            "critical_findings": critical,
            "high_findings": high,
            "medium_findings": medium,
            "risk_level": risk_level,
        },
    }


# ---------------------------------------------------------------------------
# 4. Text formatter
# ---------------------------------------------------------------------------

def format_mcp_report_text(report: Dict[str, Any]) -> str:
    """Render an MCP scan report as human-readable text."""
    lines: List[str] = []
    w = lines.append

    w("=" * 60)
    w("  AAA MCP Server Scan Report")
    w("=" * 60)

    meta = report.get("meta", {})
    w(f"  Transport: {meta.get('transport', 'N/A')}")
    w(f"  Target:    {meta.get('target', 'N/A')}")
    w(f"  Tools:     {meta.get('tools_scanned', 0)}")
    w("")

    # Tool inventory
    w("[1] TOOL INVENTORY")
    w("-" * 40)
    findings = report.get("findings", [])
    llm_findings = report.get("llm_findings", [])
    poisoned_names = {f["tool_name"] for f in findings}
    poisoned_names.update(f.get("function", "") for f in llm_findings if f.get("function"))

    for tool in report.get("tools", []):
        name = tool["name"]
        status = "POISONED" if name in poisoned_names else "CLEAN"
        w(f"  [{status}] {name}")
        desc = tool.get("description", "")
        if desc:
            w(f"    {desc[:120]}")
    w("")

    # Findings
    w("[2] FINDINGS")
    w("-" * 40)
    if not findings and not llm_findings:
        w("  No findings.")
    else:
        # Group regex findings by tool
        by_tool: Dict[str, List[Dict]] = {}
        for f in findings:
            by_tool.setdefault(f["tool_name"], []).append(f)

        for tool_name, tool_findings in by_tool.items():
            w(f"  {tool_name}:")
            for f in tool_findings:
                w(f"    [{f['risk_level'].upper()}] {f['pattern']}")
                w(f"      Match: {f['matched_text']}")
                w(f"      {f['explanation']}")
            w("")

        # LLM findings
        if llm_findings:
            w("  LLM Semantic Analysis:")
            for f in llm_findings:
                sev = f.get("severity", "unknown").upper()
                w(f"    [{sev}] {f.get('flaw_id', 'N/A')}: {f.get('function', 'N/A')}")
                w(f"      {f.get('description', '')}")
                w(f"      Trust: {f.get('trust_assumption', 'N/A')}")
                w(f"      Vector: {f.get('exploitation_vector', 'N/A')}")
            w("")

    # Summary
    w("[3] SUMMARY")
    w("-" * 40)
    summary = report.get("summary", {})
    w(f"  Total tools:       {summary.get('total_tools', 0)}")
    w(f"  Clean tools:       {summary.get('clean_tools', 0)}")
    w(f"  Poisoned tools:    {summary.get('poisoned_tools', 0)}")
    w(f"  Critical findings: {summary.get('critical_findings', 0)}")
    w(f"  High findings:     {summary.get('high_findings', 0)}")
    w(f"  Medium findings:   {summary.get('medium_findings', 0)}")
    w(f"  Overall risk:      {summary.get('risk_level', 'N/A').upper()}")

    return "\n".join(lines)
