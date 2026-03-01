"""Tests for aaa.llm — LLM factory provider selection logic."""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest

from aaa.llm import get_llm


class TestGetLlm:
    @patch.dict(os.environ, {}, clear=True)
    @patch("langchain_aws.ChatBedrockConverse")
    def test_default_bedrock(self, mock_cls):
        """No env vars → defaults to Bedrock."""
        mock_cls.return_value = MagicMock()
        llm = get_llm()
        mock_cls.assert_called_once()
        call_kwargs = mock_cls.call_args.kwargs
        assert call_kwargs["model"] == "us.anthropic.claude-sonnet-4-20250514-v1:0"
        assert call_kwargs["region_name"] == "us-east-1"

    @patch.dict(os.environ, {"AAA_LLM_PROVIDER": "anthropic"}, clear=True)
    @patch("langchain_anthropic.ChatAnthropic")
    def test_anthropic_provider(self, mock_cls):
        mock_cls.return_value = MagicMock()
        llm = get_llm()
        mock_cls.assert_called_once()
        call_kwargs = mock_cls.call_args.kwargs
        assert call_kwargs["model"] == "claude-sonnet-4-20250514"

    @patch.dict(os.environ, {"AAA_LLM_PROVIDER": "unknown"}, clear=True)
    def test_unknown_provider_raises(self):
        with pytest.raises(KeyError):
            get_llm()

    @patch.dict(
        os.environ,
        {"AAA_LLM_PROVIDER": "bedrock", "AAA_LLM_MODEL": "custom-model"},
        clear=True,
    )
    @patch("langchain_aws.ChatBedrockConverse")
    def test_custom_model(self, mock_cls):
        mock_cls.return_value = MagicMock()
        get_llm()
        assert mock_cls.call_args.kwargs["model"] == "custom-model"

    @patch.dict(
        os.environ,
        {"AAA_LLM_PROVIDER": "bedrock", "AWS_REGION": "us-west-2"},
        clear=True,
    )
    @patch("langchain_aws.ChatBedrockConverse")
    def test_aws_region(self, mock_cls):
        mock_cls.return_value = MagicMock()
        get_llm()
        assert mock_cls.call_args.kwargs["region_name"] == "us-west-2"
