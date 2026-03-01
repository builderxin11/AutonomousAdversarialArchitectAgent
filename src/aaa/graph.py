"""AAA Red-Team Graph — Auditor -> Executor -> Prober -> Judge pipeline.

Wires the four core nodes into a LangGraph StateGraph.  The graph accepts
a ``TripleAState`` with ``target_metadata.source_code`` populated and runs:

1. **Auditor** — static analysis of the victim's source code
2. **Executor** — proves identified flaws are exploitable via environment
3. **Prober** — generates adversarial conversation prompts
4. **Judge** — logical chain evaluation across both attack surfaces

Usage::

    from aaa.graph import build_aaa_graph

    graph = build_aaa_graph()
    result = await graph.ainvoke({
        "target_metadata": {"source_code": victim_source},
        ...
    })
"""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from aaa.nodes.auditor import auditor_node
from aaa.nodes.executor import executor_node
from aaa.nodes.judge import judge_node
from aaa.nodes.prober import prober_node
from aaa.state import TripleAState


def build_aaa_graph() -> StateGraph:
    """Construct and compile the Auditor -> Executor -> Prober -> Judge pipeline."""
    graph = StateGraph(TripleAState)

    graph.add_node("auditor", auditor_node)
    graph.add_node("executor", executor_node)
    graph.add_node("prober", prober_node)
    graph.add_node("judge", judge_node)

    graph.set_entry_point("auditor")
    graph.add_edge("auditor", "executor")
    graph.add_edge("executor", "prober")
    graph.add_edge("prober", "judge")
    graph.add_edge("judge", END)

    return graph.compile()


# ---------------------------------------------------------------------------
# Smoke-test: run full pipeline against examples/victim_service.py
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import asyncio
    import json
    import pathlib

    async def main():
        victim_path = (
            pathlib.Path(__file__).resolve().parents[2]
            / "examples"
            / "victim_service.py"
        )
        source = victim_path.read_text()

        initial_state: TripleAState = {
            "target_metadata": {"source_code": source},
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

        # === Report Output ===
        print("=" * 60)
        print("  AAA Security Audit Report")
        print("=" * 60)

        # 1. Auditor findings
        print("\n[1] VULNERABILITY ANALYSIS (Auditor)")
        print("-" * 40)
        for flaw in result["logic_flaws"]:
            print(f"  [{flaw['severity'].upper()}] {flaw['flaw_id']}")
            print(f"    {flaw['description']}")
            print(f"    Function: {flaw.get('function', 'N/A')} | Line: {flaw.get('line', 'N/A')}")
            print()

        # 2. Exploit proofs (environment)
        print("[2] ENVIRONMENT EXPLOIT PROOFS (Executor)")
        print("-" * 40)
        tree = result["attack_tree"]
        for proof in tree.get("proofs", []):
            print(f"  [{proof['severity'].upper()}] {proof['target_flaw_id']}: {proof['flaw_summary']}")
            print(f"    Violated invariant: {proof['violated_invariant']}")
            print(f"    Preconditions:")
            for cond in proof.get("preconditions", []):
                print(f"      - {cond['condition']}")
                print(f"        Mechanism: {cond['chaos_mechanism']}")
            print(f"    Narrative: {proof['attack_narrative']}")
            print()
        if tree.get("overall_risk_assessment"):
            print(f"  Risk assessment: {tree['overall_risk_assessment']}")
            print()

        # 3. Conversation attack suite
        print("[3] CONVERSATION ATTACK SUITE (Prober)")
        print("-" * 40)
        conv_suite = result.get("env_snapshot", {}).get("conversation_attack_suite", {})
        for p in conv_suite.get("prompts", []):
            print(f"  [{p['severity'].upper()}] {p['attack_type']} -> {p['target_flaw_id']}")
            print(f"    Prompt: {p['prompt_text'][:120]}...")
            print(f"    Predicted: {p['predicted_behavior']}")
            print()
        if conv_suite.get("attack_surface_summary"):
            print(f"  Attack surface: {conv_suite['attack_surface_summary']}")
            print()

        # 4. Judgment
        print("[4] JUDGMENT (Judge)")
        print("-" * 40)
        metrics = result["eval_metrics"]
        verdict = "COMPROMISED" if result["is_compromised"] else "NOT COMPROMISED"
        print(f"  Verdict:                    {verdict}")
        print(f"  Drift score:                {metrics.get('drift_score', 'N/A')}")
        print(f"  Invariant violation index:  {metrics.get('invariant_violation_index', 'N/A')}")
        print(f"  Confirmed exploit chains:   {metrics.get('confirmed_chains', 0)} / {metrics.get('total_chains', 0)}")

        # 5. Detailed reasoning from all agents
        print("\n" + "=" * 60)
        print("  Detailed Agent Reasoning")
        print("=" * 60)
        for msg in result["internal_thought"]:
            print(f"\n--- [{msg.name.upper()}] ---")
            print(msg.content)

    asyncio.run(main())
