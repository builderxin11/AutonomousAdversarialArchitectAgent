"""AAA Red-Team Graph — parallel fan-out/fan-in pipeline.

Wires the five core nodes into a LangGraph StateGraph.  The graph accepts
a ``TripleAState`` with ``target_metadata.source_code`` populated and runs:

1. **Auditor** — static analysis of the victim's source code
2. **Strategist** — Tree-of-Thought attack planning and prioritization
3. **Executor** ⇅ **Prober** — run in parallel (fan-out from Strategist)
   - Executor proves identified flaws are exploitable via environment
   - Prober generates adversarial conversation prompts
4. **Judge** — logical chain evaluation across both attack surfaces (fan-in)

State reducers on ``victim_logs`` (list concat) and ``env_snapshot``
(shallow dict merge) allow LangGraph to auto-merge the parallel outputs.

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
from aaa.nodes.strategist import strategist_node
from aaa.state import TripleAState


def build_aaa_graph() -> StateGraph:
    """Construct and compile the AAA pipeline with parallel Executor/Prober."""
    graph = StateGraph(TripleAState)

    graph.add_node("auditor", auditor_node)
    graph.add_node("strategist", strategist_node)
    graph.add_node("executor", executor_node)
    graph.add_node("prober", prober_node)
    graph.add_node("judge", judge_node)

    graph.set_entry_point("auditor")
    graph.add_edge("auditor", "strategist")

    # Fan-out: Strategist -> [Executor, Prober] in parallel
    graph.add_conditional_edges(
        "strategist",
        lambda state: ["executor", "prober"],
        ["executor", "prober"],
    )

    # Fan-in: both converge on Judge
    graph.add_edge("executor", "judge")
    graph.add_edge("prober", "judge")

    graph.add_edge("judge", END)

    return graph.compile()


if __name__ == "__main__":
    from aaa.cli import main

    main()
