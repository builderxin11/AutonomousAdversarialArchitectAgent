"""Centralized LLM factory for all AAA agent nodes.

All nodes call :func:`get_llm` instead of directly constructing a chat model.
This provides a single place to switch between Bedrock and Anthropic API.

Configuration is via environment variables:

- ``AAA_LLM_PROVIDER``: ``"bedrock"`` (default) or ``"anthropic"``
- ``AAA_LLM_MODEL``: model identifier (provider-specific, see defaults below)
- ``AWS_REGION`` / ``AWS_DEFAULT_REGION``: AWS region for Bedrock

Examples::

    # Bedrock (default)
    export AAA_LLM_PROVIDER=bedrock
    export AAA_LLM_MODEL=us.anthropic.claude-sonnet-4-20250514-v1:0
    export AWS_REGION=us-east-1

    # Anthropic API
    export AAA_LLM_PROVIDER=anthropic
    export AAA_LLM_MODEL=claude-sonnet-4-20250514
    export ANTHROPIC_API_KEY=sk-ant-...
"""

from __future__ import annotations

import os
from functools import lru_cache
from typing import Any

from langchain_core.language_models.chat_models import BaseChatModel

_DEFAULTS = {
    "bedrock": {
        "model": "us.anthropic.claude-sonnet-4-20250514-v1:0",
    },
    "anthropic": {
        "model": "claude-sonnet-4-20250514",
    },
}


def get_llm(*, max_tokens: int = 4096, **kwargs: Any) -> BaseChatModel:
    """Return a configured chat model based on environment variables.

    Parameters
    ----------
    max_tokens:
        Maximum tokens for the response.
    **kwargs:
        Extra keyword arguments forwarded to the underlying model constructor.
    """
    provider = os.environ.get("AAA_LLM_PROVIDER", "bedrock").lower()
    model_id = os.environ.get("AAA_LLM_MODEL", _DEFAULTS[provider]["model"])

    if provider == "bedrock":
        from langchain_aws import ChatBedrockConverse

        region = os.environ.get("AWS_REGION") or os.environ.get(
            "AWS_DEFAULT_REGION", "us-east-1"
        )
        return ChatBedrockConverse(
            model=model_id,
            region_name=region,
            max_tokens=max_tokens,
            **kwargs,
        )

    if provider == "anthropic":
        from langchain_anthropic import ChatAnthropic

        return ChatAnthropic(
            model=model_id,
            max_tokens=max_tokens,
            **kwargs,
        )

    raise ValueError(
        f"Unknown AAA_LLM_PROVIDER={provider!r}. Use 'bedrock' or 'anthropic'."
    )
