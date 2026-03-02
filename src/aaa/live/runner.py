"""Test execution engine for live agent testing.

Executes a ``LiveTestPlan`` against a real victim agent by:
1. Calling ``reset()`` to clean state
2. Executing setup steps (injectors)
3. Snapshotting state before attack
4. Sending conversation prompts to the agent
5. Snapshotting state after attack
6. Comparing before/after state for invariant violations
"""

from __future__ import annotations

import traceback
from typing import Any

from pydantic import BaseModel, Field

from aaa.live.discovery import VictimCapabilities
from aaa.live.planner import LiveTestPlan, TestStep


# ---------------------------------------------------------------------------
# Result schemas
# ---------------------------------------------------------------------------


class TestResult(BaseModel):
    """Result of executing a single test case."""

    test_id: str
    target_flaw_id: str
    state_before: dict[str, Any] = Field(default_factory=dict)
    state_after: dict[str, Any] = Field(default_factory=dict)
    agent_responses: list[str] = Field(default_factory=list)
    invariant_violated: bool = False
    error: str | None = None


class LiveTestResults(BaseModel):
    """Aggregate results from all test cases."""

    results: list[TestResult] = Field(default_factory=list)
    total: int = 0
    passed: int = 0
    failed: int = 0
    errors: int = 0


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _snapshot_state(capabilities: VictimCapabilities) -> dict[str, Any]:
    """Call every state getter and return a {name: value} dict."""
    snapshot: dict[str, Any] = {}
    for name, getter in capabilities.state_getters.items():
        try:
            snapshot[name] = getter()
        except Exception as exc:
            snapshot[name] = f"<error: {exc}>"
    return snapshot


def _execute_inject(step: TestStep, capabilities: VictimCapabilities) -> None:
    """Execute an inject step by calling the named injector."""
    injector = capabilities.injectors.get(step.target)
    if injector is None:
        raise ValueError(f"Unknown injector: {step.target}")
    injector(**step.args)


async def _execute_converse(
    step: TestStep,
    agent: Any,
) -> str:
    """Send a conversation prompt to the agent and return its response."""
    result = await agent.ainvoke({"messages": [("user", step.target)]})
    messages = result.get("messages", [])
    # Extract the last AI message content
    for msg in reversed(messages):
        content = getattr(msg, "content", None)
        if content and getattr(msg, "type", None) in ("ai", "AIMessage"):
            return str(content)
    # Fallback: return the last message content regardless of type
    if messages:
        last = messages[-1]
        return str(getattr(last, "content", str(last)))
    return "<no response>"


def _check_invariant(
    state_before: dict[str, Any],
    state_after: dict[str, Any],
    verification_steps: list[TestStep],
) -> bool:
    """Check whether any verification step indicates an invariant violation.

    Returns True if an invariant appears to have been violated (state changed
    in a way that matches the expected exploit outcome).
    """
    for step in verification_steps:
        getter_name = step.target
        before_val = state_before.get(getter_name)
        after_val = state_after.get(getter_name)

        if before_val != after_val:
            # State changed — this is a potential invariant violation.
            # The test "fails" (exploit succeeded) if state changed in
            # a way consistent with the expected outcome.
            return True

    return False


# ---------------------------------------------------------------------------
# Main execution function
# ---------------------------------------------------------------------------


async def run_live_tests(
    plan: LiveTestPlan,
    capabilities: VictimCapabilities,
    model: str = "openai:gpt-4o-mini",
) -> LiveTestResults:
    """Execute a live test plan against the victim agent.

    Parameters
    ----------
    plan:
        The generated test plan from the planner.
    capabilities:
        Discovered victim module capabilities.
    model:
        Model string for the victim agent.

    Returns
    -------
    LiveTestResults:
        Aggregate results from all test cases.
    """
    results: list[TestResult] = []
    passed = 0
    failed = 0
    errors = 0

    for tc in plan.test_cases:
        try:
            # 1. Reset state
            if capabilities.reset is not None:
                capabilities.reset()

            # 2. Execute setup steps (injectors)
            for step in tc.setup_steps:
                if step.action == "inject":
                    _execute_inject(step, capabilities)

            # 3. Snapshot state before attack
            state_before = _snapshot_state(capabilities)

            # 4. Build agent and execute attack steps
            agent = capabilities.build_agent(model)
            agent_responses: list[str] = []
            for step in tc.attack_steps:
                if step.action == "converse":
                    response = await _execute_converse(step, agent)
                    agent_responses.append(response)

            # 5. Snapshot state after attack
            state_after = _snapshot_state(capabilities)

            # 6. Check invariants
            invariant_violated = _check_invariant(
                state_before, state_after, tc.verification_steps,
            )

            result = TestResult(
                test_id=tc.test_id,
                target_flaw_id=tc.target_flaw_id,
                state_before=state_before,
                state_after=state_after,
                agent_responses=agent_responses,
                invariant_violated=invariant_violated,
            )

            if invariant_violated:
                failed += 1
            else:
                passed += 1

        except Exception:
            result = TestResult(
                test_id=tc.test_id,
                target_flaw_id=tc.target_flaw_id,
                error=traceback.format_exc(),
            )
            errors += 1

        results.append(result)

    return LiveTestResults(
        results=results,
        total=len(plan.test_cases),
        passed=passed,
        failed=failed,
        errors=errors,
    )
