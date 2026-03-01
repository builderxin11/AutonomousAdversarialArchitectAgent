"""Tests for aaa.nodes.judge — logical chain evaluation."""

from __future__ import annotations

from unittest.mock import patch

from langchain_core.messages import AIMessage

from aaa.nodes.judge import (
    ExploitChain,
    JudgmentResult,
    judge_node,
)


def _make_state(
    logic_flaws=None,
    attack_tree=None,
    env_snapshot=None,
) -> dict:
    return {
        "target_metadata": {"source_code": "pass"},
        "logic_flaws": logic_flaws or [],
        "hypotheses": [],
        "attack_tree": attack_tree or {},
        "internal_thought": [],
        "victim_logs": [],
        "env_snapshot": env_snapshot or {},
        "eval_metrics": {},
        "is_compromised": False,
    }


def _fake_compromised_result() -> JudgmentResult:
    return JudgmentResult(
        exploit_chains=[
            ExploitChain(
                flaw_id="FLAW-001",
                attack_surface="environment",
                condition_achievable=True,
                trigger_confirmed=True,
                invariant_violated="Resource IDs must be unique",
                code_trace="create_resource() L42: guard bypass when error flag set",
                severity="high",
                confidence="confirmed",
            ),
            ExploitChain(
                flaw_id="FLAW-001",
                attack_surface="conversation",
                condition_achievable=True,
                trigger_confirmed=True,
                invariant_violated="System prompt safety guarantee",
                code_trace="System prompt lacks anti-injection defense",
                severity="medium",
                confidence="likely",
            ),
        ],
        drift_score=0.85,
        invariant_violation_index=0.5,
        is_compromised=True,
        executive_summary="Victim is exploitable via error-path guard bypass",
        reasoning="Flaw FLAW-001 confirmed exploitable through environment manipulation",
    )


def _fake_safe_result() -> JudgmentResult:
    return JudgmentResult(
        exploit_chains=[
            ExploitChain(
                flaw_id="FLAW-001",
                attack_surface="environment",
                condition_achievable=True,
                trigger_confirmed=False,
                invariant_violated="N/A",
                code_trace="Guard check is actually robust under analysis",
                severity="low",
                confidence="unverified",
            ),
        ],
        drift_score=0.1,
        invariant_violation_index=0.0,
        is_compromised=False,
        executive_summary="No confirmed exploit chains",
        reasoning="Analysis shows the guard check cannot be bypassed",
    )


class TestJudgeNodeOutput:
    """Test judge_node returns the expected structure."""

    @patch("aaa.nodes.judge._evaluate", return_value=_fake_compromised_result())
    def test_returns_required_keys(self, mock_eval):
        state = _make_state()
        result = judge_node(state)

        assert "eval_metrics" in result
        assert "is_compromised" in result
        assert "internal_thought" in result

    @patch("aaa.nodes.judge._evaluate", return_value=_fake_compromised_result())
    def test_eval_metrics_fields(self, mock_eval):
        state = _make_state()
        result = judge_node(state)

        metrics = result["eval_metrics"]
        assert metrics["drift_score"] == 0.85
        assert metrics["invariant_violation_index"] == 0.5
        assert metrics["confirmed_chains"] == 1
        assert metrics["total_chains"] == 2

    @patch("aaa.nodes.judge._evaluate", return_value=_fake_compromised_result())
    def test_compromised_verdict(self, mock_eval):
        state = _make_state()
        result = judge_node(state)

        assert result["is_compromised"] is True

    @patch("aaa.nodes.judge._evaluate", return_value=_fake_compromised_result())
    def test_internal_thought_format(self, mock_eval):
        state = _make_state()
        result = judge_node(state)

        thoughts = result["internal_thought"]
        assert len(thoughts) == 1
        msg = thoughts[0]
        assert isinstance(msg, AIMessage)
        assert msg.name == "judge"
        assert "COMPROMISED" in msg.content
        assert "0.85" in msg.content

    @patch("aaa.nodes.judge._evaluate", return_value=_fake_compromised_result())
    def test_internal_thought_contains_env_chains(self, mock_eval):
        state = _make_state()
        result = judge_node(state)

        content = result["internal_thought"][0].content
        assert "environment exploit chains" in content.lower()
        assert "FLAW-001" in content

    @patch("aaa.nodes.judge._evaluate", return_value=_fake_safe_result())
    def test_not_compromised_verdict(self, mock_eval):
        state = _make_state()
        result = judge_node(state)

        assert result["is_compromised"] is False
        metrics = result["eval_metrics"]
        assert metrics["drift_score"] == 0.1
        assert metrics["confirmed_chains"] == 0

    @patch("aaa.nodes.judge._evaluate", return_value=_fake_safe_result())
    def test_not_compromised_thought(self, mock_eval):
        state = _make_state()
        result = judge_node(state)

        content = result["internal_thought"][0].content
        assert "NOT COMPROMISED" in content
