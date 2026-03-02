# Distributed Agent Testing — Design Notes

> **Status**: Not implemented. This document captures the architectural thinking for extending `aaa test` beyond in-process agents to support distributed / deployed agent systems.

## Current Limitation

`aaa test` (Phase 11) runs the victim agent **in the same Python process** as AAA. The entire attack works because injectors (`inject_*`), tools (`@tool` functions), and state getters (`get_*`) all operate on the same in-memory Python objects:

```
┌─ Single Python process ───────────────────────────────┐
│                                                        │
│  Module-level state (dicts, lists)                     │
│       ↑            ↑              ↑                    │
│   inject_*()    @tool funcs     get_*()                │
│   (AAA calls)   (agent calls)   (AAA calls)            │
│                                                        │
└────────────────────────────────────────────────────────┘
```

This means `aaa test` currently **cannot** test:

| Scenario | Why it fails |
|----------|-------------|
| Agent deployed as an HTTP service | Cannot `import` a running service |
| Agent with database-backed state | `inject_*()` / `get_*()` can't reach the DB |
| Agent calling external APIs (payment gateways, etc.) | Tools make network calls, not in-memory mutations |
| Agent running in a container / on a different machine | No shared memory between processes |
| Multi-service agent architectures | State is distributed across services |

The in-process approach is intentionally scoped for **development-time validation**: you write an agent, `aaa scan` finds flaws, `aaa test` confirms them before you deploy. Once the agent is deployed, a different architecture is needed.

## What Distributed Testing Requires

Testing a deployed agent means replacing the three in-process mechanisms (injection, interaction, observation) with network-based equivalents.

### 1. Injection — Network-based chaos

Instead of calling `inject_recovery_event()` to mutate a Python list, chaos must be introduced through the agent's actual dependencies:

**Option A: Mock Server as a programmable backend**

The Universal Mock Server (`src/aaa/env/mock_server.py`) already supports this. The idea is to point the victim agent's external service calls at the Mock Server, then use the chaos API to inject conditions:

```
Agent ──HTTP──→ Mock Server (pretending to be the real backend)
                    ↑
AAA ────HTTP──→ /_chaos/config    {"error_rate": 1.0}
AAA ────HTTP──→ /_chaos/store/inject  {"key": "audit_log", ...}
```

The Mock Server's chaos control endpoints (`PATCH /_chaos/config`, `POST /_chaos/store/inject`) are already designed for this — they just haven't been wired into the `aaa test` pipeline yet.

**Option B: Direct database manipulation**

For agents with database-backed state, inject conditions directly at the data layer:

```python
# Instead of: inject_recovery_event()
db.execute("INSERT INTO audit_log (message) VALUES ('RECOVERY: service restored')")
```

This requires knowing the agent's schema, which the Auditor could potentially extract from ORM models or migration files.

**Option C: Network-layer chaos (sidecar proxy)**

Tools like Toxiproxy, Istio fault injection, or Chaos Monkey can introduce network-level failures (latency, packet loss, connection resets) without modifying the agent or its dependencies:

```
Agent ──→ Toxiproxy ──→ Real Backend
              ↑
AAA ─────→ Toxiproxy API: add_toxic("latency", latency=5000)
```

### 2. Interaction — HTTP / WebSocket / MCP instead of `ainvoke()`

Instead of calling `agent.ainvoke({"messages": [...]})` in-process, send messages through the agent's actual interface:

```python
# In-process (current)
result = await agent.ainvoke({"messages": [("user", prompt)]})

# HTTP API
response = httpx.post("http://agent-host:8080/chat", json={"message": prompt})

# WebSocket
async with websockets.connect("ws://agent-host:8080/ws") as ws:
    await ws.send(json.dumps({"message": prompt}))
    response = await ws.recv()

# MCP protocol
async with mcp_client.connect("http://agent-host:8080/mcp") as client:
    result = await client.call_tool("chat", {"message": prompt})
```

The runner would need an abstraction layer — something like an `AgentTransport` interface — to support multiple interaction protocols.

### 3. Observation — External state queries

Instead of calling `get_accounts()` to read a Python dict, query the agent's actual state store:

```python
# Database query
rows = db.execute("SELECT * FROM accounts WHERE id = 'ACC-001'")

# Agent debug/health API
response = httpx.get("http://agent-host:8080/debug/state")

# Mock Server request log (if agent talks to Mock Server)
response = httpx.get("http://mock-server/_chaos/log")

# Read from message queue / event stream
events = kafka.consume("agent.state.changes")
```

## Proposed Architecture

```
┌─ AAA Process ──────────────────────────────────────────────┐
│                                                             │
│  Planner ──→ generates TestCases with network-level steps  │
│                                                             │
│  Runner ──→ AgentTransport (HTTP / WS / MCP)               │
│         ──→ ChaosTransport (Mock Server / DB / Toxiproxy)  │
│         ──→ StateTransport (DB query / API / Mock Server)  │
│                                                             │
│  Judge ──→ compares snapshots (same as today)              │
│                                                             │
└─────────────────────────────────────────────────────────────┘
         │              │              │
         ↓              ↓              ↓
   ┌──────────┐  ┌───────────┐  ┌──────────────┐
   │ Victim   │  │ Mock      │  │ State Store  │
   │ Agent    │  │ Server    │  │ (DB/Redis)   │
   │ (remote) │  │ (chaos)   │  │              │
   └──────────┘  └───────────┘  └──────────────┘
```

The key abstractions needed:

```python
class AgentTransport(Protocol):
    """How to send messages to the agent."""
    async def send(self, message: str) -> str: ...

class ChaosTransport(Protocol):
    """How to inject chaos conditions."""
    async def inject(self, target: str, args: dict) -> None: ...

class StateTransport(Protocol):
    """How to observe agent state."""
    async def snapshot(self) -> dict[str, Any]: ...
```

The current in-process approach would become one implementation of these interfaces (the simplest one). Distributed testing would provide HTTP-based implementations.

## Implementation Considerations

### Configuration

A distributed test would need a configuration file specifying how to reach the agent, where to inject chaos, and how to observe state:

```yaml
# aaa-test.yaml
agent:
  transport: http
  url: http://localhost:8080/chat

chaos:
  transport: mock_server
  url: http://localhost:9090
  api_key: ${CHAOS_API_KEY}

state:
  transport: database
  connection: postgresql://localhost:5432/agent_db
  queries:
    accounts: "SELECT * FROM accounts"
    audit_log: "SELECT * FROM audit_log ORDER BY created_at"
```

### Docker Compose integration

The existing `docker-compose.yml` already defines an AAA + Mock Server multi-service setup. Extending it with a victim agent container would enable end-to-end distributed testing:

```yaml
services:
  victim-agent:
    build: ./examples/deployed_agent
    environment:
      - BACKEND_URL=http://mock-server:8000
  mock-server:
    build: .
    command: uvicorn aaa.env.mock_server:app
  aaa:
    build: .
    command: aaa test --config aaa-test.yaml
    depends_on: [victim-agent, mock-server]
```

### What the Planner needs to change

The LLM Planner currently generates steps like `action: "inject", target: "recovery_event"` (referencing Python functions). For distributed testing, it would need to generate network-level steps:

```json
{
  "action": "inject",
  "target": "mock_server",
  "args": {
    "method": "PATCH",
    "path": "/_chaos/config",
    "body": {"error_rate": 1.0}
  }
}
```

The Executor node already generates exactly this kind of output (HTTP method + path + body for Mock Server chaos API). The gap is that the Executor currently only *proves* these are possible — it doesn't actually use them in a live test loop.

## Relationship to Existing Components

| Existing Component | Role in Distributed Testing |
|---|---|
| **Mock Server** (`env/mock_server.py`) | Becomes the actual chaos injection target (already has `/_chaos/*` endpoints) |
| **Executor** (`nodes/executor.py`) | Already generates the HTTP-level exploit proofs that the distributed runner would execute |
| **Prober** (`nodes/prober.py`) | Already generates the conversation prompts that would be sent via HTTP to the deployed agent |
| **Judge** (`nodes/judge.py`) | Evaluation logic stays the same — compare before/after state snapshots |

The pieces exist; they just need to be connected through network transports instead of in-process function calls.
