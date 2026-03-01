"""Tests for aaa.graph — verify the fan-out/fan-in topology."""

from __future__ import annotations

from langgraph.graph import END

from aaa.graph import build_aaa_graph


class TestGraphTopology:
    """Verify that the compiled graph has the expected edges."""

    def setup_method(self):
        self.graph = build_aaa_graph()
        # get_graph() returns a DrawableGraph with .nodes and .edges
        self.drawable = self.graph.get_graph()
        # Build adjacency: source -> set of targets
        self.adjacency: dict[str, set[str]] = {}
        for edge in self.drawable.edges:
            self.adjacency.setdefault(edge.source, set()).add(edge.target)

    def test_auditor_to_strategist(self):
        assert "strategist" in self.adjacency.get("auditor", set())

    def test_strategist_fans_out_to_executor_and_prober(self):
        targets = self.adjacency.get("strategist", set())
        assert "executor" in targets
        assert "prober" in targets

    def test_executor_to_judge(self):
        assert "judge" in self.adjacency.get("executor", set())

    def test_prober_to_judge(self):
        assert "judge" in self.adjacency.get("prober", set())

    def test_judge_to_end(self):
        assert "__end__" in self.adjacency.get("judge", set())

    def test_no_direct_strategist_to_judge(self):
        """Strategist should NOT connect directly to judge."""
        targets = self.adjacency.get("strategist", set())
        assert "judge" not in targets

    def test_executor_does_not_connect_to_prober(self):
        """In parallel topology, executor does not chain to prober."""
        targets = self.adjacency.get("executor", set())
        assert "prober" not in targets
