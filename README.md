# Project AAA: Autonomous Adversarial Architect

A multi-agent framework for grey-box red-teaming of AI agentic workflows.

AAA autonomously detects and exploits logical and systemic vulnerabilities in AI agents by combining **static source code analysis** with **dynamic chaos engineering**.

## Architecture

AAA operates as a coordinated red team via a cyclic LangGraph pipeline:

```
Auditor -> Strategist -> Executor -> Prober -> Judge -> Report
```

| Agent | Role |
|-------|------|
| **Auditor** | AST-based static analysis to identify logic flaws and trust boundary gaps |
| **Strategist** | Tree-of-Thought reasoning to prioritize flaws into multi-step attack strategies |
| **Executor** | Proves flaws are exploitable via Mock Server environment manipulation |
| **Prober** | Generates adversarial conversation prompts for prompt injection testing |
| **Judge** | Logical chain evaluation across both attack surfaces; renders final verdict |

## Quick Start

### Installation

```bash
# Clone and install
git clone https://github.com/builderxin11/AutonomousAdversarialArchitectAgent.git
cd AutonomousAdversarialArchitectAgent

pip install -e ".[test]"
```

### Configure LLM Backend

AAA supports **AWS Bedrock** (default) and **Anthropic API**:

```bash
# Option A: AWS Bedrock (default)
export AAA_LLM_PROVIDER=bedrock
export AWS_REGION=us-east-1
# Ensure AWS credentials are configured (aws configure / env vars / IAM role)

# Option B: Anthropic API
export AAA_LLM_PROVIDER=anthropic
export ANTHROPIC_API_KEY=sk-ant-...
```

### Run a Scan

```bash
# Text report to stdout
aaa scan examples/victim_service.py

# JSON report to file
aaa scan examples/victim_service.py --format json -o report.json
```

Exit codes: `0` = not compromised, `1` = compromised, `2` = input error.

### Run with Docker

```bash
# Build and run the Mock Server
docker compose up mock-server

# Or run a scan directly
docker compose run --rm aaa scan examples/victim_service.py
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AAA_LLM_PROVIDER` | `bedrock` | LLM provider: `bedrock` or `anthropic` |
| `AAA_LLM_MODEL` | *(provider default)* | Model identifier |
| `AWS_REGION` | `us-east-1` | AWS region for Bedrock |
| `ANTHROPIC_API_KEY` | *(none)* | API key for Anthropic provider |

## Development

```bash
# Install with test dependencies
pip install -e ".[test]"

# Run the full test suite
pytest tests/ -v

# Run a specific test file
pytest tests/test_strategist.py -v
```

### Project Layout

```
src/aaa/
  cli.py              # CLI entry point (aaa scan)
  graph.py            # LangGraph pipeline wiring
  llm.py              # Centralized LLM factory
  report.py           # JSON/text report generation
  state.py            # TripleAState shared schema
  env/
    mock_server.py    # FastAPI Universal Mock Server
  nodes/
    auditor.py        # Static analysis node
    strategist.py     # ToT attack planning node
    executor.py       # Exploit proof node
    prober.py         # Adversarial prompt generation node
    judge.py          # Logical chain evaluation node

tests/                # 93 tests (unit + integration)
examples/
  victim_service.py   # Deliberately flawed victim agent for testing
```

## License

See [LICENSE](LICENSE) for details.
