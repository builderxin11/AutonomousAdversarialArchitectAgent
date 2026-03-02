"""Tests for aaa.live.discovery — victim module introspection."""

from __future__ import annotations

import textwrap

import pytest

from aaa.live.discovery import VictimCapabilities, discover_victim

FINANCIAL_AGENT = "examples/financial_agent.py"
VICTIM_SERVICE = "examples/victim_service.py"


class TestDiscoverFinancialAgent:
    def test_discovers_build_agent(self):
        cap = discover_victim(FINANCIAL_AGENT)
        assert callable(cap.build_agent)

    def test_discovers_reset(self):
        cap = discover_victim(FINANCIAL_AGENT)
        assert cap.reset is not None
        assert callable(cap.reset)

    def test_discovers_state_getters(self):
        cap = discover_victim(FINANCIAL_AGENT)
        assert "accounts" in cap.state_getters
        assert "transactions" in cap.state_getters
        assert "audit_log" in cap.state_getters
        assert "policy_config" in cap.state_getters

    def test_discovers_injectors(self):
        cap = discover_victim(FINANCIAL_AGENT)
        assert "recovery_event" in cap.injectors
        assert "compliance_review" in cap.injectors

    def test_discovers_tools(self):
        cap = discover_victim(FINANCIAL_AGENT)
        assert cap.tools is not None
        assert len(cap.tools) == 6

    def test_discovers_system_prompt(self):
        cap = discover_victim(FINANCIAL_AGENT)
        assert cap.system_prompt is not None
        assert "FinanceGuard" in cap.system_prompt

    def test_getters_return_callable(self):
        cap = discover_victim(FINANCIAL_AGENT)
        for name, fn in cap.state_getters.items():
            assert callable(fn), f"Getter {name} is not callable"

    def test_injectors_return_callable(self):
        cap = discover_victim(FINANCIAL_AGENT)
        for name, fn in cap.injectors.items():
            assert callable(fn), f"Injector {name} is not callable"


class TestDiscoverVictimService:
    def test_discovers_build_agent(self):
        cap = discover_victim(VICTIM_SERVICE)
        assert callable(cap.build_agent)

    def test_discovers_reset(self):
        cap = discover_victim(VICTIM_SERVICE)
        assert cap.reset is not None

    def test_discovers_state_getters(self):
        cap = discover_victim(VICTIM_SERVICE)
        assert "store" in cap.state_getters
        assert "operation_log" in cap.state_getters

    def test_discovers_injectors(self):
        cap = discover_victim(VICTIM_SERVICE)
        assert "system_error" in cap.injectors

    def test_discovers_tools(self):
        cap = discover_victim(VICTIM_SERVICE)
        assert cap.tools is not None
        assert len(cap.tools) == 5

    def test_discovers_system_prompt(self):
        cap = discover_victim(VICTIM_SERVICE)
        assert cap.system_prompt is not None
        assert "resource" in cap.system_prompt.lower()


class TestDiscoverErrors:
    def test_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            discover_victim("/nonexistent/file.py")

    def test_missing_build_agent_raises(self, tmp_path):
        no_agent = tmp_path / "no_agent.py"
        no_agent.write_text("x = 1\n")
        with pytest.raises(ValueError, match="build_victim_agent"):
            discover_victim(str(no_agent))

    def test_module_with_only_build_agent(self, tmp_path):
        minimal = tmp_path / "minimal.py"
        minimal.write_text(textwrap.dedent("""\
            def build_victim_agent(model="test"):
                return {"model": model}
        """))
        cap = discover_victim(str(minimal))
        assert callable(cap.build_agent)
        assert cap.reset is None
        assert cap.state_getters == {}
        assert cap.injectors == {}
        assert cap.tools is None
        assert cap.system_prompt is None
