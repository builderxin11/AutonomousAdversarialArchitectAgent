"""Tests for aaa.nodes.executor — exploit proof generation + Mock Server verification."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

from langchain_core.messages import AIMessage

from aaa.nodes.executor import (
    EnvironmentCondition,
    ExecutorReport,
    ExploitProof,
    executor_node,
)


def _make_state(
    logic_flaws=None,
    target_metadata=None,
    attack_tree=None,
) -> dict:
    return {
        "target_metadata": target_metadata or {"source_code": "pass"},
        "logic_flaws": logic_flaws or [],
        "hypotheses": [],
        "attack_tree": attack_tree or {},
        "internal_thought": [],
        "victim_logs": [],
        "env_snapshot": {},
        "eval_metrics": {},
        "is_compromised": False,
    }


def _fake_report() -> ExecutorReport:
    return ExecutorReport(
        proofs=[
            ExploitProof(
                target_flaw_id="FLAW-001",
                flaw_summary="Guard bypass via error flag",
                preconditions=[
                    EnvironmentCondition(
                        condition="Operation log contains 'System Error'",
                        chaos_mechanism="Set error_rate=1.0 to inject 500 errors",
                        verification_step="PATCH /_chaos/config with error_rate=1.0",
                        method="PATCH",
                        path="/_chaos/config",
                        body={"error_rate": 1.0},
                    ),
                ],
                attack_narrative="Error injection triggers guard bypass, allowing duplicate resource creation",
                violated_invariant="Resource IDs must be unique",
                severity="high",
            ),
        ],
        overall_risk_assessment="High exploitability via environment manipulation",
    )


def _fake_evidence():
    return [
        {
            "flaw_id": "FLAW-001",
            "conditions_tested": 1,
            "evidence": [
                {
                    "condition": "Operation log contains 'System Error'",
                    "chaos_mechanism": "Set error_rate=1.0 to inject 500 errors",
                    "request": "PATCH /_chaos/config",
                    "status_code": 200,
                    "response": {"status": "updated"},
                    "achievable": True,
                }
            ],
        }
    ]


class TestExecutorNodeOutput:
    """Test executor_node returns the expected structure."""

    @patch("aaa.nodes.executor._verify_conditions", new_callable=AsyncMock)
    @patch("aaa.nodes.executor._build_exploit_proofs")
    async def test_returns_required_keys(self, mock_build, mock_verify):
        mock_build.return_value = _fake_report()
        mock_verify.return_value = _fake_evidence()

        state = _make_state(logic_flaws=[{"flaw_id": "FLAW-001"}])
        result = await executor_node(state)

        assert "attack_tree" in result
        assert "victim_logs" in result
        assert "env_snapshot" in result
        assert "internal_thought" in result

    @patch("aaa.nodes.executor._verify_conditions", new_callable=AsyncMock)
    @patch("aaa.nodes.executor._build_exploit_proofs")
    async def test_attack_tree_contains_proofs(self, mock_build, mock_verify):
        mock_build.return_value = _fake_report()
        mock_verify.return_value = _fake_evidence()

        state = _make_state(logic_flaws=[{"flaw_id": "FLAW-001"}])
        result = await executor_node(state)

        tree = result["attack_tree"]
        assert "proofs" in tree
        assert "overall_risk_assessment" in tree
        assert "verification_evidence" in tree
        assert len(tree["proofs"]) == 1
        assert tree["proofs"][0]["target_flaw_id"] == "FLAW-001"

    @patch("aaa.nodes.executor._verify_conditions", new_callable=AsyncMock)
    @patch("aaa.nodes.executor._build_exploit_proofs")
    async def test_merges_strategist_attack_tree(self, mock_build, mock_verify):
        mock_build.return_value = _fake_report()
        mock_verify.return_value = _fake_evidence()

        strategist_tree = {
            "strategies": [{"strategy_id": "STRAT-001", "priority": 1}],
            "threat_model_summary": "Victim vulnerable",
            "prioritization_rationale": "Error path is critical",
        }
        state = _make_state(
            logic_flaws=[{"flaw_id": "FLAW-001"}],
            attack_tree=strategist_tree,
        )
        result = await executor_node(state)

        tree = result["attack_tree"]
        # Strategist fields preserved
        assert tree["strategies"] == strategist_tree["strategies"]
        assert tree["threat_model_summary"] == "Victim vulnerable"
        # Executor fields added
        assert "proofs" in tree
        assert "verification_evidence" in tree

    @patch("aaa.nodes.executor._verify_conditions", new_callable=AsyncMock)
    @patch("aaa.nodes.executor._build_exploit_proofs")
    async def test_strategies_passed_to_build_proofs(self, mock_build, mock_verify):
        mock_build.return_value = _fake_report()
        mock_verify.return_value = _fake_evidence()

        strategies = [{"strategy_id": "STRAT-001"}]
        state = _make_state(
            logic_flaws=[{"flaw_id": "FLAW-001"}],
            attack_tree={"strategies": strategies},
        )
        await executor_node(state)

        # _build_exploit_proofs should receive the strategies
        _, _, passed_strategies = mock_build.call_args[0]
        assert passed_strategies == strategies

    @patch("aaa.nodes.executor._verify_conditions", new_callable=AsyncMock)
    @patch("aaa.nodes.executor._build_exploit_proofs")
    async def test_victim_logs_format(self, mock_build, mock_verify):
        mock_build.return_value = _fake_report()
        mock_verify.return_value = _fake_evidence()

        state = _make_state(logic_flaws=[{"flaw_id": "FLAW-001"}])
        result = await executor_node(state)

        logs = result["victim_logs"]
        assert any("FLAW-001" in log for log in logs)
        assert any("HIGH" in log for log in logs)

    @patch("aaa.nodes.executor._verify_conditions", new_callable=AsyncMock)
    @patch("aaa.nodes.executor._build_exploit_proofs")
    async def test_internal_thought_format(self, mock_build, mock_verify):
        mock_build.return_value = _fake_report()
        mock_verify.return_value = _fake_evidence()

        state = _make_state(logic_flaws=[{"flaw_id": "FLAW-001"}])
        result = await executor_node(state)

        thoughts = result["internal_thought"]
        assert len(thoughts) == 1
        msg = thoughts[0]
        assert isinstance(msg, AIMessage)
        assert msg.name == "executor"
        assert "Exploit proofs generated: 1" in msg.content

    @patch("aaa.nodes.executor._verify_conditions", new_callable=AsyncMock)
    @patch("aaa.nodes.executor._build_exploit_proofs")
    async def test_env_snapshot(self, mock_build, mock_verify):
        mock_build.return_value = _fake_report()
        mock_verify.return_value = _fake_evidence()

        state = _make_state(logic_flaws=[{"flaw_id": "FLAW-001"}])
        result = await executor_node(state)

        snap = result["env_snapshot"]
        assert snap["mock_server_capabilities_confirmed"] is True
        assert "verification_evidence" in snap
