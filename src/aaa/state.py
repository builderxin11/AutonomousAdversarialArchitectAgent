import operator
from typing import Annotated, Any, Dict, List

from langgraph.graph.message import add_messages
from typing_extensions import TypedDict


def _merge_dicts(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    """Shallow-merge two dicts — used as a LangGraph reducer for env_snapshot."""
    return {**a, **b}


class TripleAState(TypedDict):
    # --- Reconnaissance & Grey-box Context ---
    target_metadata: Dict[str, Any]

    # --- Adversarial Intelligence ---
    logic_flaws: List[Dict]
    hypotheses: List[str]
    attack_tree: Dict[str, Any]

    # --- Observation & Interaction ---
    internal_thought: Annotated[list, add_messages]
    victim_logs: Annotated[List[str], operator.add]
    env_snapshot: Annotated[Dict[str, Any], _merge_dicts]

    # --- Scoring & Evaluation ---
    eval_metrics: Dict[str, float]
    is_compromised: bool
