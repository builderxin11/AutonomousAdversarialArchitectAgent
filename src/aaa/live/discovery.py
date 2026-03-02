"""Victim module introspection for live agent testing.

Imports the victim module by file path and discovers its capabilities
by looking for naming conventions:

- ``build_victim_agent(model)`` — required agent factory
- ``reset()`` — optional state reset
- ``get_*()`` — state inspection functions
- ``inject_*()`` — chaos injection functions
- ``TOOLS`` — tool list
- ``SYSTEM_PROMPT`` — system prompt string
"""

from __future__ import annotations

import importlib.util
import inspect
from dataclasses import dataclass, field
from types import ModuleType
from typing import Any, Callable


@dataclass
class VictimCapabilities:
    """Discovered capabilities of a victim module."""

    module: ModuleType
    build_agent: Callable[..., Any]
    reset: Callable[[], None] | None = None
    state_getters: dict[str, Callable[[], Any]] = field(default_factory=dict)
    injectors: dict[str, Callable[..., None]] = field(default_factory=dict)
    tools: list[Any] | None = None
    system_prompt: str | None = None


def discover_victim(module_path: str) -> VictimCapabilities:
    """Import a victim module and discover its capabilities.

    Parameters
    ----------
    module_path:
        Absolute or relative path to a ``.py`` file that defines
        ``build_victim_agent(model)``.

    Returns
    -------
    VictimCapabilities:
        Discovered callables and constants from the module.

    Raises
    ------
    FileNotFoundError:
        If *module_path* does not exist.
    ValueError:
        If the module does not define ``build_victim_agent``.
    """
    import pathlib

    path = pathlib.Path(module_path).resolve()
    if not path.exists():
        raise FileNotFoundError(f"Victim module not found: {module_path}")

    spec = importlib.util.spec_from_file_location("_victim_module", str(path))
    if spec is None or spec.loader is None:
        raise ValueError(f"Cannot load module from: {module_path}")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    # Required: build_victim_agent
    build_agent = getattr(module, "build_victim_agent", None)
    if build_agent is None or not callable(build_agent):
        raise ValueError(
            f"Module {module_path} does not define build_victim_agent(). "
            "This function is required for live agent testing."
        )

    # Optional: reset()
    reset_fn = getattr(module, "reset", None)
    if reset_fn is not None and not callable(reset_fn):
        reset_fn = None

    # Discover get_* functions → state_getters
    state_getters: dict[str, Callable[[], Any]] = {}
    for name, obj in inspect.getmembers(module, inspect.isfunction):
        if name.startswith("get_") and not name.startswith("get_transaction_history"):
            # Strip "get_" prefix for the key
            key = name[4:]
            state_getters[key] = obj

    # Discover inject_* functions → injectors
    injectors: dict[str, Callable[..., None]] = {}
    for name, obj in inspect.getmembers(module, inspect.isfunction):
        if name.startswith("inject_"):
            key = name[7:]
            injectors[key] = obj

    # Optional constants
    tools = getattr(module, "TOOLS", None)
    if tools is not None and not isinstance(tools, list):
        tools = None

    system_prompt = getattr(module, "SYSTEM_PROMPT", None)
    if system_prompt is not None and not isinstance(system_prompt, str):
        system_prompt = None

    return VictimCapabilities(
        module=module,
        build_agent=build_agent,
        reset=reset_fn,
        state_getters=state_getters,
        injectors=injectors,
        tools=tools,
        system_prompt=system_prompt,
    )
