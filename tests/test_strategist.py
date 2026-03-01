"""Tests for aaa.nodes.strategist — Tree-of-Thought attack planning."""

from __future__ import annotations

from unittest.mock import patch

from langchain_core.messages import AIMessage

from aaa.nodes.strategist import (
    AttackStep,
    AttackStrategy,
    StrategistReport,
    strategist_node,
)


def _make_state(logic_flaws=None, target_metadata=None) -> dict:
    return {
        "target_metadata": target_metadata or {"source_code": "pass"},
        "logic_flaws": logic_flaws or [],
        "hypotheses": [],
        "attack_tree": {},
        "internal_thought": [],
        "victim_logs": [],
        "env_snapshot": {},
        "eval_metrics": {},
        "is_compromised": False,
    }


def _fake_report() -> StrategistReport:
    return StrategistReport(
        strategies=[
            AttackStrategy(
                strategy_id="STRAT-001",
                target_flaw_ids=["FLAW-001"],
                priority=1,
                attack_surface="environment",
                steps=[
                    AttackStep(
                        action="Inject 500 errors to bypass validation",
                        surface="environment",
                        chaos_mechanism="Set error_rate=1.0 via PATCH /_chaos/config",
                    ),
                ],
                expected_outcome="Victim skips uniqueness check under error condition",
                reasoning="ToT: error path lacks validation guard -> exploitable via chaos",
            ),
            AttackStrategy(
                strategy_id="STRAT-002",
                target_flaw_ids=["FLAW-001", "FLAW-002"],
                priority=2,
                attack_surface="combined",
                steps=[
                    AttackStep(
                        action="Poison data store with duplicate record",
                        surface="environment",
                        chaos_mechanism="POST /_chaos/store/inject",
                    ),
                    AttackStep(
                        action="Inject prompt to convince agent to skip verification",
                        surface="conversation",
                        chaos_mechanism="inject_malicious_data=true with override payload",
                    ),
                ],
                expected_outcome="Duplicate record created bypassing invariant",
                reasoning="ToT: combining store poisoning with prompt injection amplifies impact",
            ),
        ],
        threat_model_summary="Victim is vulnerable to environment manipulation and prompt injection",
        prioritization_rationale="STRAT-001 ranked higher due to simpler preconditions",
    )


class TestStrategistNodeOutput:
    """Test that strategist_node returns the expected structure."""

    @patch("aaa.nodes.strategist._plan_with_llm", return_value=_fake_report())
    def test_returns_required_keys(self, mock_llm):
        state = _make_state(logic_flaws=[{"flaw_id": "FLAW-001"}])
        result = strategist_node(state)

        assert "attack_tree" in result
        assert "hypotheses" in result
        assert "internal_thought" in result

    @patch("aaa.nodes.strategist._plan_with_llm", return_value=_fake_report())
    def test_attack_tree_structure(self, mock_llm):
        state = _make_state(logic_flaws=[{"flaw_id": "FLAW-001"}])
        result = strategist_node(state)

        tree = result["attack_tree"]
        assert "strategies" in tree
        assert "threat_model_summary" in tree
        assert "prioritization_rationale" in tree
        assert len(tree["strategies"]) == 2
        assert tree["strategies"][0]["strategy_id"] == "STRAT-001"
        assert tree["strategies"][0]["priority"] == 1

    @patch("aaa.nodes.strategist._plan_with_llm", return_value=_fake_report())
    def test_hypotheses_from_reasoning(self, mock_llm):
        state = _make_state(logic_flaws=[{"flaw_id": "FLAW-001"}])
        result = strategist_node(state)

        hypotheses = result["hypotheses"]
        assert len(hypotheses) == 2
        assert "error path lacks validation guard" in hypotheses[0]
        assert "store poisoning" in hypotheses[1]

    @patch("aaa.nodes.strategist._plan_with_llm", return_value=_fake_report())
    def test_internal_thought_format(self, mock_llm):
        state = _make_state(logic_flaws=[{"flaw_id": "FLAW-001"}])
        result = strategist_node(state)

        thoughts = result["internal_thought"]
        assert len(thoughts) == 1
        msg = thoughts[0]
        assert isinstance(msg, AIMessage)
        assert msg.name == "strategist"
        assert "2 attack strategies" in msg.content

    @patch(
        "aaa.nodes.strategist._plan_with_llm",
        return_value=StrategistReport(
            strategies=[],
            threat_model_summary="No actionable flaws",
            prioritization_rationale="N/A",
        ),
    )
    def test_empty_flaws_no_error(self, mock_llm):
        state = _make_state(logic_flaws=[])
        result = strategist_node(state)

        assert result["attack_tree"]["strategies"] == []
        assert result["hypotheses"] == []
        assert len(result["internal_thought"]) == 1
