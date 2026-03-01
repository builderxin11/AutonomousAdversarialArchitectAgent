from typing import Annotated, Any, Dict, List

from langgraph.graph.message import add_messages
from typing_extensions import TypedDict


class TripleAState(TypedDict):
    # --- Reconnaissance & Grey-box Context ---
    target_metadata: Dict[str, Any]

    # --- Adversarial Intelligence ---
    logic_flaws: List[Dict]
    hypotheses: List[str]
    attack_tree: Dict[str, Any]

    # --- Observation & Interaction ---
    internal_thought: Annotated[list, add_messages]
    victim_logs: List[str]
    env_snapshot: Dict[str, Any]

    # --- Scoring & Evaluation ---
    eval_metrics: Dict[str, float]
    is_compromised: bool
