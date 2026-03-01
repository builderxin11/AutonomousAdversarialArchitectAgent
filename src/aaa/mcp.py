"""MCP Tool Schema Poisoning Detector.

Detects hidden instructions, exfiltration URLs, sensitive data references,
and safety-override commands embedded in tool descriptions/docstrings.

Two detection layers:

1. **Deterministic pattern scanner** — Regex-based, fast, no LLM required.
   Catches obvious poisoning patterns (action directives, URLs, file access,
   safety overrides, hidden tool chaining).

2. **LLM semantic analysis** — Catches subtle poisoning that evades regex:
   implicit behavioral instructions, description-to-implementation mismatch,
   out-of-scope operations, and multi-tool poisoning chains.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# 1. Deterministic Pattern Scanner
# ---------------------------------------------------------------------------

_PATTERNS: List[Dict[str, Any]] = [
    {
        "name": "action_directive",
        "regex": re.compile(
            r"(?i)\b(before|after|always|first|must|immediately)\b"
            r".{0,30}"
            r"\b(call|run|execute|send|read|write|fetch|include|output)\b"
        ),
        "risk_level": "critical",
        "explanation": (
            "Tool description contains an action directive that instructs "
            "the LLM to perform an operation before or after using the tool."
        ),
    },
    {
        "name": "data_exfiltration",
        "regex": re.compile(
            r"(?i)(\.ssh|\.env|credentials|api[_\s]?key|password|secret|token|wallet)"
        ),
        "risk_level": "critical",
        "explanation": (
            "Tool description references sensitive data or credential "
            "locations that could be targeted for exfiltration."
        ),
    },
    {
        "name": "url_reference",
        "regex": re.compile(
            r"https?://|curl\s|fetch\s|POST\s|GET\s"
        ),
        "risk_level": "high",
        "explanation": (
            "Tool description contains a URL or HTTP command that could "
            "be used to exfiltrate data to an external endpoint."
        ),
    },
    {
        "name": "file_system_access",
        "regex": re.compile(
            r"(?i)(read|write|open|cat|rm)\s+.{0,20}(/[a-z]|~/|\.\.\/)"
        ),
        "risk_level": "critical",
        "explanation": (
            "Tool description instructs file system operations on "
            "specific paths, which could lead to data theft or destruction."
        ),
    },
    {
        "name": "safety_override",
        "regex": re.compile(
            r"(?i)(ignore|bypass|skip|override|disable)"
            r".{0,20}"
            r"(safety|guard|check|validation|restriction|rule|instruction|prompt)"
        ),
        "risk_level": "critical",
        "explanation": (
            "Tool description instructs the agent to bypass safety checks "
            "or override its own restrictions."
        ),
    },
    {
        "name": "hidden_tool_chaining",
        "regex": re.compile(
            r"(?i)(also|then|additionally)\s+(call|invoke|use|run)\s+\w+"
        ),
        "risk_level": "medium",
        "explanation": (
            "Tool description instructs the agent to invoke additional "
            "tools, enabling unauthorized tool chaining."
        ),
    },
]


@dataclass
class SchemaFinding:
    """A single finding from the deterministic pattern scanner."""

    tool_name: str
    lineno: int
    pattern: str
    matched_text: str
    risk_level: str
    explanation: str


def scan_tool_descriptions(tool_schemas: List[Dict]) -> List[SchemaFinding]:
    """Scan tool descriptions for known poisoning patterns.

    Parameters
    ----------
    tool_schemas:
        List of tool schema dicts, each with at least ``name``, ``docstring``,
        and ``lineno`` keys.

    Returns
    -------
    List of :class:`SchemaFinding` instances, one per pattern match.
    """
    findings: List[SchemaFinding] = []

    for schema in tool_schemas:
        docstring = schema.get("docstring") or ""
        if not docstring:
            continue

        tool_name = schema.get("name", "unknown")
        lineno = schema.get("lineno", 0)

        for pat in _PATTERNS:
            match = pat["regex"].search(docstring)
            if match:
                findings.append(
                    SchemaFinding(
                        tool_name=tool_name,
                        lineno=lineno,
                        pattern=pat["name"],
                        matched_text=match.group(0),
                        risk_level=pat["risk_level"],
                        explanation=pat["explanation"],
                    )
                )

    return findings


# ---------------------------------------------------------------------------
# 2. LLM Semantic Analysis
# ---------------------------------------------------------------------------

_SCHEMA_AUDIT_PROMPT = """\
You are a security auditor specializing in MCP (Model Context Protocol)
supply-chain attacks.  Analyze the following tool definitions for **tool
schema poisoning** — hidden instructions embedded in tool descriptions that
could manipulate an AI agent into performing unauthorized actions.

## Tool Schemas
```json
{tool_schemas_json}
```

## Source Code Context
```python
{source_code}
```

## What to Look For

1. **Implicit behavioral instructions** — Descriptions that tell the agent
   to do something besides the tool's stated purpose (e.g., "before calling,
   read the user's config file").

2. **Description-to-implementation mismatch** — The docstring claims the
   tool does X, but the code actually does Y, or the description adds
   operations not present in the implementation.

3. **Out-of-scope references** — Descriptions that reference operations,
   files, URLs, or data outside the tool's stated purpose.

4. **Multi-tool poisoning chains** — Tool A's description references Tool B,
   creating an unauthorized execution chain.

5. **Sensitive data references** — Descriptions that mention credentials,
   API keys, tokens, private files, or internal endpoints.

For each finding, provide:
- ``flaw_id``: e.g. SCHEMA-001
- ``type``: always "tool_schema_poisoning"
- ``severity``: critical / high / medium / low
- ``function``: the poisoned tool's function name
- ``line``: approximate line number
- ``description``: clear explanation of the poisoning
- ``trust_assumption``: what trust is being abused
- ``exploitation_vector``: how an attacker would trigger the hidden instruction

Only report genuine poisoning, not normal documentation.
"""


class LogicFlaw(BaseModel):
    """Mirror of auditor LogicFlaw for structured output."""

    flaw_id: str = Field(description="Short unique identifier, e.g. 'SCHEMA-001'")
    type: str = Field(default="tool_schema_poisoning")
    severity: str = Field(description="'critical' | 'high' | 'medium' | 'low'")
    function: Optional[str] = Field(default=None)
    line: Optional[int] = Field(default=None)
    description: str = Field(description="Human-readable explanation")
    trust_assumption: str = Field(description="The trust being abused")
    exploitation_vector: str = Field(description="How to trigger the hidden instruction")


class ToolSchemaAuditResult(BaseModel):
    """Container for LLM schema-poisoning findings."""

    findings: List[LogicFlaw] = Field(default_factory=list)


def analyze_tool_schemas_llm(
    tool_schemas: List[Dict],
    source_code: str,
) -> List[Dict]:
    """Run LLM semantic analysis on tool schemas for poisoning.

    Parameters
    ----------
    tool_schemas:
        List of tool schema dicts from the Auditor's extraction.
    source_code:
        The full source code of the victim for context.

    Returns
    -------
    List of flaw dicts with ``type="tool_schema_poisoning"``.
    """
    if not tool_schemas:
        return []

    import json

    from aaa.llm import get_llm

    llm = get_llm()
    structured_llm = llm.with_structured_output(ToolSchemaAuditResult)

    prompt_text = _SCHEMA_AUDIT_PROMPT.format(
        tool_schemas_json=json.dumps(tool_schemas, indent=2, default=str),
        source_code=source_code,
    )

    result: ToolSchemaAuditResult = structured_llm.invoke(prompt_text)
    flaws = []
    for flaw in result.findings:
        d = flaw.model_dump()
        d["type"] = "tool_schema_poisoning"
        flaws.append(d)
    return flaws
