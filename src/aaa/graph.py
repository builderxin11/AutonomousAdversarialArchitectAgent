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


if __name__ == "__main__":
    from aaa.cli import main

    main()
