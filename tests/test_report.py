"""Tests for aaa.report — JSON/text report generation."""

from __future__ import annotations

import json

from langchain_core.messages import AIMessage

from aaa.report import (
    _serialize_internal_thought,
    build_json_report,
    format_json,
    format_text,
)


# ---- _serialize_internal_thought ----


class TestSerializeInternalThought:
    def test_aimessage_with_name(self):
        msgs = [AIMessage(content="hello", name="auditor")]
        result = _serialize_internal_thought(msgs)
        assert result == [{"agent": "auditor", "content": "hello"}]

    def test_empty_name_fallback(self):
        msgs = [AIMessage(content="x", name="")]
        result = _serialize_internal_thought(msgs)
        assert result[0]["agent"] == "unknown"

    def test_no_name_attr_fallback(self):
        msgs = [AIMessage(content="y")]
        result = _serialize_internal_thought(msgs)
        # AIMessage without name → name defaults to None → "unknown"
        assert result[0]["agent"] == "unknown"

    def test_non_message_object(self):
        """Objects without .content are str()-ified."""

        class Dummy:
            pass

        obj = Dummy()
        result = _serialize_internal_thought([obj])
        assert result[0]["agent"] == "unknown"
        assert result[0]["content"] == str(obj)


# ---- build_json_report ----


class TestBuildJsonReport:
    def test_full_state(self, sample_state):
        report = build_json_report(sample_state, target_file="victim.py")

        # Top-level keys
        assert set(report.keys()) == {
            "meta",
            "verdict",
            "vulnerabilities",
            "strategic_plan",
            "exploit_proofs",
            "conversation_attacks",
            "agent_reasoning",
        }

        # Meta
        assert report["meta"]["aaa_version"] == "0.1.0"
        assert report["meta"]["target_file"] == "victim.py"
        assert report["meta"]["timestamp"].endswith("+00:00")

    def test_empty_state(self):
        report = build_json_report({}, target_file="empty.py")
        assert report["verdict"]["is_compromised"] is False
        assert report["vulnerabilities"] == []

    def test_compromised_verdict(self, sample_state):
        report = build_json_report(sample_state, target_file="v.py")
        assert report["verdict"]["is_compromised"] is True
        assert report["verdict"]["drift_score"] == 0.85

    def test_not_compromised_verdict(self, sample_state):
        sample_state["is_compromised"] = False
        report = build_json_report(sample_state, target_file="v.py")
        assert report["verdict"]["is_compromised"] is False

    def test_strategic_plan_populated(self, sample_state):
        sample_state["attack_tree"]["strategies"] = [
            {"strategy_id": "STRAT-001", "priority": 1}
        ]
        sample_state["attack_tree"]["threat_model_summary"] = "Vulnerable"
        sample_state["attack_tree"]["prioritization_rationale"] = "High severity"
        report = build_json_report(sample_state, target_file="v.py")
        plan = report["strategic_plan"]
        assert len(plan["strategies"]) == 1
        assert plan["threat_model_summary"] == "Vulnerable"
        assert plan["prioritization_rationale"] == "High severity"

    def test_strategic_plan_empty(self):
        report = build_json_report({}, target_file="v.py")
        plan = report["strategic_plan"]
        assert plan["strategies"] == []
        assert plan["threat_model_summary"] is None


# ---- format_json ----


class TestFormatJson:
    def test_round_trip(self, sample_state):
        report = build_json_report(sample_state, target_file="v.py")
        serialized = format_json(report)
        assert json.loads(serialized) == report

    def test_unicode_preserved(self):
        report = {"note": "中文测试 — unicode"}
        serialized = format_json(report)
        assert "中文测试" in serialized


# ---- format_text ----


class TestFormatText:
    def test_section_headers(self, sample_state):
        report = build_json_report(sample_state, target_file="v.py")
        text = format_text(report)
        assert "[1]" in text
        assert "[2]" in text
        assert "[3]" in text
        assert "[4]" in text
        assert "[5]" in text
        assert "Detailed Agent Reasoning" in text

    def test_compromised_label(self, sample_state):
        report = build_json_report(sample_state, target_file="v.py")
        text = format_text(report)
        assert "COMPROMISED" in text

    def test_strategist_section_rendered(self, sample_state):
        sample_state["attack_tree"]["strategies"] = [
            {
                "strategy_id": "STRAT-001",
                "priority": 1,
                "attack_surface": "environment",
                "target_flaw_ids": ["FLAW-001"],
                "expected_outcome": "Duplicate created",
                "steps": [
                    {
                        "action": "Inject errors",
                        "surface": "environment",
                        "chaos_mechanism": "error_rate=1.0",
                    }
                ],
            }
        ]
        sample_state["attack_tree"]["threat_model_summary"] = "Vulnerable target"
        report = build_json_report(sample_state, target_file="v.py")
        text = format_text(report)
        assert "STRATEGIC ATTACK PLAN" in text
        assert "STRAT-001" in text
        assert "Inject errors" in text
        assert "Vulnerable target" in text

    def test_not_compromised_label(self, sample_state):
        sample_state["is_compromised"] = False
        report = build_json_report(sample_state, target_file="v.py")
        text = format_text(report)
        assert "NOT COMPROMISED" in text
