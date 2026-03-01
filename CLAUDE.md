# Project AAA: Autonomous Adversarial Architect (v2.0)
## Multi-Agent Framework for Grey-box Red-Teaming

---

## 1. Project Vision
Project AAA is an **Adversarial Multi-Agent Framework** designed to autonomously detect and exploit logical and systemic vulnerabilities in AI Agentic Workflows. Unlike traditional black-box testing, AAA treats the target ("Victim") as a grey-box system, combining **Static Source Code Analysis** with **Dynamic Chaos Engineering** to induce "Confused Deputy" behaviors and state inconsistencies.

---

## 2. Multi-Agent System Architecture
AAA operates as a coordinated "Red Team" managed via a cyclic **LangGraph** workflow. Each node represents a specialized agentic role:

### A. The Auditor (Static Specialist)
- **Responsibility**: Performs deep-dive analysis of the Victim's source code, System Prompts, and Tool Schemas.
- **Goal**: Map the Victim's "Trust Boundaries." It identifies gaps such as missing re-entrancy guards, lack of output validation, or implicit trust in external logs/observations.

### B. The Prober (Interaction Specialist)
- **Responsibility**: Sends non-destructive "Probe Signals" (e.g., minor latencies, benign 4xx errors) to the environment.
- **Goal**: Observe the Victim’s "Stimulus-Response" patterns to infer its hidden decision-making logic and prompt-level constraints.

### C. The Strategist (Planning Specialist)
- **Responsibility**: Uses **Tree-of-Thought (ToT)** reasoning to synthesize findings from the Auditor and Prober.
- **Goal**: Generate a multi-step "Attack Tree" that combines Environment Chaos (Physical) and Indirect Prompt Injection (Logical).

### D. The Executor (Chaos Specialist)
- **Responsibility**: Orchestrates the **Universal Mock Server** via a dedicated Control API.
- **Goal**: Manipulate the environment state in real-time (e.g., poisoning database records, triggering API timeouts) according to the Attack Tree.

### E. The Judge (Evaluation Specialist)
- **Responsibility**: Acts as the independent verification authority.
- **Goal**: Detects "Logical Drift" by comparing the actual environment state against the intended business logic invariants.



---

## 3. Evaluation & Logic Drift Analysis
The success of an attack is not determined by chat output, but by **State-Level Compromise**. The Judge node evaluates the Victim based on:

* **State Inconsistency**: Detecting cases where the `Actual Environment State` deviates from the `Logical Expected State`.
* **Invariant Violation**: Identifying if the Victim performed an action that its own code or prompt explicitly forbids (e.g., bypassing a uniqueness check).
* **Response Fragility**: Measuring the degradation of the Victim's reasoning quality under environment pressure (Chaos).



---

## 4. Technical Stack
* **Orchestration**: LangGraph (Cyclic Multi-Agent Coordination).
* **Brain**: Claude 4.5 Sonnet / Gemini 2.5 Pro.
* **Code Analysis**: Python `ast` & `tree-sitter` for structural auditing.
* **Sandbox**: FastAPI + Docker (Programmable Mock Environment).
* **Protocol**: Model Context Protocol (MCP) for standardized tool interoperability.

---

## 5. Global State Schema (TripleAState)
The Red Team shares a unified state to maintain context across reasoning loops:

```python
from typing import Annotated, List, Dict, Any
from typing_extensions import TypedDict
from langgraph.graph.message import add_messages

class TripleAState(TypedDict):
    # --- Reconnaissance & Grey-box Context ---
    target_metadata: Dict[str, Any]  # Source code, Prompts, Tool Schemas
    
    # --- Adversarial Intelligence ---
    logic_flaws: List[Dict]          # Identified vulnerabilities in Victim logic
    hypotheses: List[str]            # Probabilistic models of Victim's behavior
    attack_tree: Dict[str, Any]      # Active sequence of adversarial actions
    
    # --- Observation & Interaction ---
    internal_thought: Annotated[list, add_messages] # Internal Red Team coordination
    victim_logs: List[str]           # Captured Thought/Action logs of the Victim
    env_snapshot: Dict[str, Any]     # Real-time state of the Mock Environment
    
    # --- Scoring & Evaluation ---
    eval_metrics: Dict[str, float]   # {drift_score, invariant_violation_index}
    is_compromised: bool             # Final verdict from the Judge
```

---

## 6. Implementation Principles
1.  **Grey-box First**: Every attack must be grounded in an identified logic flaw from the Auditor. No blind brute-forcing.
2.  **Environment as a Tool**: Chaos injection (API errors, latency) is a first-class attack vector.
3.  **Atomic Verification**: The Judge must verify state changes at the data layer, ensuring the "ground truth" is respected.
4.  **Agnostic Design**: Do not hardcode specific cloud services. Use abstract models like `ResourceStore`, `AuthService`, and `NotificationGateway`.

---

## 7. Project Roadmap
- [ ] **Phase 1**: Core LangGraph scaffolding and `TripleAState` definition.
- [ ] **Phase 2**: `StaticAuditor` development (AST-based tool and prompt extraction).
- [ ] **Phase 3**: `UniversalMockServer` with programmable chaos endpoints.
- [ ] **Phase 4**: Automated "Judge" implementation for state-drift detection.