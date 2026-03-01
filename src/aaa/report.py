"""Structured report generation for AAA scan results.

Provides a canonical JSON report schema and human-readable text formatting.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List

from aaa.state import TripleAState

AAA_VERSION = "0.1.0"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _serialize_internal_thought(messages: list) -> List[Dict[str, str]]:
    """Convert AIMessage list to plain dicts for JSON serialization."""
    entries: List[Dict[str, str]] = []
    for msg in messages:
        entries.append({
            "agent": getattr(msg, "name", "unknown") or "unknown",
            "content": msg.content if hasattr(msg, "content") else str(msg),
        })
    return entries


# ---------------------------------------------------------------------------
# Report builder
# ---------------------------------------------------------------------------

def build_json_report(state: TripleAState, target_file: str) -> Dict[str, Any]:
    """Build the canonical report dict from final pipeline state.

    The ``target_metadata`` raw source is intentionally excluded — the
    consumer already has the file.
    """
    metrics = state.get("eval_metrics", {})
    tree = state.get("attack_tree", {})
    conv_suite = state.get("env_snapshot", {}).get("conversation_attack_suite", {})

    return {
        "meta": {
            "aaa_version": AAA_VERSION,
            "target_file": target_file,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
        "verdict": {
            "is_compromised": state.get("is_compromised", False),
            "drift_score": metrics.get("drift_score"),
            "invariant_violation_index": metrics.get("invariant_violation_index"),
            "confirmed_chains": metrics.get("confirmed_chains", 0),
            "total_chains": metrics.get("total_chains", 0),
        },
        "vulnerabilities": state.get("logic_flaws", []),
        "strategic_plan": {
            "strategies": tree.get("strategies", []),
            "threat_model_summary": tree.get("threat_model_summary"),
            "prioritization_rationale": tree.get("prioritization_rationale"),
        },
        "exploit_proofs": {
            "proofs": tree.get("proofs", []),
            "overall_risk_assessment": tree.get("overall_risk_assessment"),
            "verification_evidence": tree.get("verification_evidence"),
        },
        "conversation_attacks": {
            "prompts": conv_suite.get("prompts", []),
            "attack_surface_summary": conv_suite.get("attack_surface_summary"),
        },
        "agent_reasoning": _serialize_internal_thought(
            state.get("internal_thought", [])
        ),
    }


# ---------------------------------------------------------------------------
# Formatters
# ---------------------------------------------------------------------------

def format_json(report: Dict[str, Any]) -> str:
    """Serialize *report* to pretty-printed JSON."""
    return json.dumps(report, indent=2, ensure_ascii=False)


def format_text(report: Dict[str, Any]) -> str:
    """Render *report* as human-readable text (mirrors original graph.py output)."""
    lines: List[str] = []
    w = lines.append

    w("=" * 60)
    w("  AAA Security Audit Report")
    w("=" * 60)

    # 1. Vulnerabilities
    w("\n[1] VULNERABILITY ANALYSIS (Auditor)")
    w("-" * 40)
    for flaw in report.get("vulnerabilities", []):
        w(f"  [{flaw.get('severity', 'unknown').upper()}] {flaw.get('flaw_id', 'N/A')}")
        w(f"    {flaw.get('description', '')}")
        w(f"    Function: {flaw.get('function', 'N/A')} | Line: {flaw.get('line', 'N/A')}")
        w("")

    # 2. Strategic plan
    w("[2] STRATEGIC ATTACK PLAN (Strategist)")
    w("-" * 40)
    plan = report.get("strategic_plan", {})
    for strat in plan.get("strategies", []):
        flaw_ids = ", ".join(strat.get("target_flaw_ids", []))
        w(f"  [P{strat.get('priority', '?')}] {strat.get('strategy_id', 'N/A')} ({strat.get('attack_surface', 'N/A')})")
        w(f"    Targets: {flaw_ids}")
        w(f"    Expected outcome: {strat.get('expected_outcome', 'N/A')}")
        steps = strat.get("steps", [])
        if steps:
            w("    Steps:")
            for i, step in enumerate(steps, 1):
                w(f"      {i}. [{step.get('surface', '?')}] {step.get('action', '')}")
                w(f"         Mechanism: {step.get('chaos_mechanism', '')}")
        w("")
    summary = plan.get("threat_model_summary")
    if summary:
        w(f"  Threat model: {summary}")
    rationale = plan.get("prioritization_rationale")
    if rationale:
        w(f"  Prioritization: {rationale}")
        w("")

    # 3. Exploit proofs
    w("[3] ENVIRONMENT EXPLOIT PROOFS (Executor)")
    w("-" * 40)
    proofs_section = report.get("exploit_proofs", {})
    for proof in proofs_section.get("proofs", []):
        w(f"  [{proof.get('severity', 'unknown').upper()}] {proof.get('target_flaw_id', 'N/A')}: {proof.get('flaw_summary', '')}")
        w(f"    Violated invariant: {proof.get('violated_invariant', 'N/A')}")
        w("    Preconditions:")
        for cond in proof.get("preconditions", []):
            w(f"      - {cond.get('condition', '')}")
            w(f"        Mechanism: {cond.get('chaos_mechanism', '')}")
        w(f"    Narrative: {proof.get('attack_narrative', '')}")
        w("")
    risk = proofs_section.get("overall_risk_assessment")
    if risk:
        w(f"  Risk assessment: {risk}")
        w("")

    # 4. Conversation attacks
    w("[4] CONVERSATION ATTACK SUITE (Prober)")
    w("-" * 40)
    conv = report.get("conversation_attacks", {})
    for p in conv.get("prompts", []):
        w(f"  [{p.get('severity', 'unknown').upper()}] {p.get('attack_type', 'N/A')} -> {p.get('target_flaw_id', 'N/A')}")
        prompt_text = p.get("prompt_text", "")
        w(f"    Prompt: {prompt_text[:120]}...")
        w(f"    Predicted: {p.get('predicted_behavior', '')}")
        w("")
    surface = conv.get("attack_surface_summary")
    if surface:
        w(f"  Attack surface: {surface}")
        w("")

    # 5. Judgment
    w("[5] JUDGMENT (Judge)")
    w("-" * 40)
    verdict = report.get("verdict", {})
    v_str = "COMPROMISED" if verdict.get("is_compromised") else "NOT COMPROMISED"
    w(f"  Verdict:                    {v_str}")
    w(f"  Drift score:                {verdict.get('drift_score', 'N/A')}")
    w(f"  Invariant violation index:  {verdict.get('invariant_violation_index', 'N/A')}")
    w(f"  Confirmed exploit chains:   {verdict.get('confirmed_chains', 0)} / {verdict.get('total_chains', 0)}")

    # 5. Agent reasoning
    w("\n" + "=" * 60)
    w("  Detailed Agent Reasoning")
    w("=" * 60)
    for entry in report.get("agent_reasoning", []):
        w(f"\n--- [{entry['agent'].upper()}] ---")
        w(entry["content"])

    return "\n".join(lines)
