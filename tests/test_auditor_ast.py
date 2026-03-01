"""Tests for aaa.nodes.auditor — AST extraction + node post-processing."""

from __future__ import annotations

import textwrap
from unittest.mock import patch

from aaa.nodes.auditor import _extract_source_metadata, auditor_node


# ---- _extract_source_metadata ----


class TestExtractSourceMetadata:
    def test_sync_function(self):
        src = "def hello(x):\n    pass"
        meta = _extract_source_metadata(src)
        assert len(meta["functions"]) == 1
        f = meta["functions"][0]
        assert f["name"] == "hello"
        assert f["args"][0]["name"] == "x"

    def test_async_function(self):
        src = "async def fetch():\n    pass"
        meta = _extract_source_metadata(src)
        assert len(meta["functions"]) == 1
        assert meta["functions"][0]["name"] == "fetch"

    def test_decorator_extraction(self):
        src = "@tool\ndef my_tool():\n    pass"
        meta = _extract_source_metadata(src)
        assert "tool" in meta["functions"][0]["decorators"]

    def test_annotated_arg(self):
        src = "def f(x: int):\n    pass"
        meta = _extract_source_metadata(src)
        assert meta["functions"][0]["args"][0]["annotation"] == "int"

    def test_docstring(self):
        src = 'def f():\n    """My doc."""\n    pass'
        meta = _extract_source_metadata(src)
        assert meta["functions"][0]["docstring"] == "My doc."

    def test_plain_assign_string(self):
        src = 'X = "hello"'
        meta = _extract_source_metadata(src)
        assert len(meta["global_variables"]) == 1
        assert meta["global_variables"][0]["name"] == "X"
        assert len(meta["string_constants"]) == 1
        assert meta["string_constants"][0]["value"] == "hello"

    def test_annotated_assign_string(self):
        src = 'X: str = "hello"'
        meta = _extract_source_metadata(src)
        assert len(meta["global_variables"]) == 1
        assert meta["global_variables"][0]["annotation"] == "str"
        assert len(meta["string_constants"]) == 1

    def test_annotated_assign_no_value(self):
        src = "X: int"
        meta = _extract_source_metadata(src)
        assert len(meta["global_variables"]) == 1
        assert len(meta["string_constants"]) == 0

    def test_empty_source(self):
        meta = _extract_source_metadata("")
        assert meta["functions"] == []
        assert meta["global_variables"] == []
        assert meta["string_constants"] == []

    def test_nested_function_only_outer(self):
        src = textwrap.dedent("""\
            def outer():
                def inner():
                    pass
                return inner
        """)
        meta = _extract_source_metadata(src)
        assert len(meta["functions"]) == 1
        assert meta["functions"][0]["name"] == "outer"


# ---- auditor_node post-processing ----


class TestAuditorNodePostProcessing:
    def _make_state(self, source_code: str) -> dict:
        return {
            "target_metadata": {"source_code": source_code},
            "logic_flaws": [],
            "hypotheses": [],
            "attack_tree": {},
            "internal_thought": [],
            "victim_logs": [],
            "env_snapshot": {},
            "eval_metrics": {},
            "is_compromised": False,
        }

    @patch("aaa.nodes.auditor._analyze_with_llm", return_value=[])
    def test_system_prompt_extraction(self, mock_llm):
        src = 'SYSTEM_PROMPT = "You are a helpful assistant."'
        state = self._make_state(src)
        result = auditor_node(state)
        assert result["target_metadata"]["system_prompt"] == "You are a helpful assistant."

    @patch("aaa.nodes.auditor._analyze_with_llm", return_value=[])
    def test_tool_schema_extraction(self, mock_llm):
        src = textwrap.dedent("""\
            @tool
            def create_resource(resource_id: str, data: str):
                \"\"\"Create a new resource.\"\"\"
                pass

            @tool
            def delete_resource(resource_id: str):
                \"\"\"Delete a resource.\"\"\"
                pass
        """)
        state = self._make_state(src)
        result = auditor_node(state)
        schemas = result["target_metadata"]["tool_schemas"]
        assert len(schemas) == 2
        assert schemas[0]["name"] == "create_resource"
        assert schemas[1]["name"] == "delete_resource"
