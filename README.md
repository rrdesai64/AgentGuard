# AgentGuard: Dual-Ring Runtime Firewall & Kernel Sandbox for Autonomous Agents

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Ring 1 Latency](https://img.shields.io/badge/Ring_1_Latency-%3C2.5ms-success.svg)]()
[![Ring 2 Sandbox](https://img.shields.io/badge/Ring_2_Isolation-unshare_%2B_strace-informational.svg)]()

![AgentGuard Live Console](docs/console_preview.png)

**AgentGuard** is an inline, low-latency runtime security firewall designed to protect autonomous AI agents (MCP tool-calling systems and DevOps/coding agents) from **Indirect Prompt Injection**, **Semantic Intent Drift**, and **Subprocess Kernel Breakouts**.

Rather than relying on probabilistic "LLM-as-a-Judge" text wrappers—which introduce 600ms+ of latency, double token expenditure, and remain susceptible to adversarial prompt encodings—AgentGuard treats the language model as an **untrusted user-space process**. It enforces deterministic security invariants across two architectural rings:

1. **Ring 1 (Layer 7 — Semantic MCP Interceptor):** Provenance taint tracking, deterministic policy gates, and sub-millisecond vector-hashing intent alignment for structured JSON-RPC tool invocations.
2. **Ring 2 (Layer 3/4 — OS Kernel & Syscall Guardian):** Linux namespace isolation (`unshare`) and real-time system call tracing (`openat`, `connect`, `execve`) to prevent authorized coding subshells or poisoned dependencies from reading sensitive host credentials (`~/.ssh`, `.aws`, `/etc/shadow`) or opening unauthorized outbound network sockets.

---

## System Architecture

                            [ Untrusted External Data / Repo / Inbox ]
                                                |
                                                v
                                      [ Autonomous Agent ]
                                                |
             +----------------------------------+----------------------------------+
             v (Structured Tool Call: MCP/JSON)                                    v (Code/Shell Execution: bash/pytest)
    +---------------------------------------------------+         +---------------------------------------------------+
    | RING 1: Layer 7 Semantic MCP Interceptor          |         | RING 2: Layer 3/4 OS Kernel & Syscall Guardian    |
    | ------------------------------------------------- |         | ------------------------------------------------- |
    | * Causal Taint Graph (Session Lineage Tracking)   |         | * Linux Namespaces (unshare network/fs isolation) |
    | * Deterministic Policy Gate (Taint x Privilege)   |         | * Syscall Guard (Blocks ~/.ssh, ~/.aws, /etc)     |
    | * Algebraic Vector Intent Alignment (<2.5ms)      |         | * Socket Guard (Blocks unauthorized outbound IPs) |
    +---------------------------------------------------+         +---------------------------------------------------+
             |                                                                     |
             +----------------------------------+----------------------------------+
                                                v
                         [ Unified Telemetry API & Live Verification Console ]

---

## Benchmark Comparison

| Metric | Probabilistic LLM Guardrail | AgentGuard Dual-Ring Engine |
| :--- | :--- | :--- |
| **Interception Latency (Ring 1)** | 600 ms - 1,500 ms | **less than 2.5 ms** |
| **Kernel Syscall Containment (Ring 2)** | No visibility into child processes | **less than 8.0 ms (`SIGKILL` / Block)** |
| **Additional Token Cost** | 2x API Token Spend | **0 Tokens (Local & Deterministic)** |
| **Indirect Prompt Injection Defense** | Heuristic / Bypassable via encoding | **Monotonic Causal Taint Graph** |
| **Supply-Chain / `bash_exec` Breakout** | None | **Syscall-level `openat` & `connect` interception** |

---

## Quickstart (Ubuntu / Linux)

### 1. Install Dependencies

    git clone https://github.com/rrdesai64/AgentGuard.git
    cd AgentGuard
    pip install -r requirements.txt

### 2. Run the CLI Verification Suite
Execute both Ring 1 (MCP Indirect Injection) and Ring 2 (Kernel SSH Key Exfiltration) test cases:

    python3 demo_runner.py

### 3. Launch the Telemetry Server & Test Console

    python3 server.py

Navigate to `http://localhost:8000` to evaluate live presets or inject custom payloads against both enforcement rings.

---

## Repository Layout

    AgentGuard/
    |-- config/
    |   `-- security_policy.yaml       # Unified Ring 1 (MCP) & Ring 2 (OS Syscall) policies
    |-- core/
    |   |-- __init__.py
    |   |-- schemas.py                 # Pydantic data contracts & telemetry models
    |   |-- taint_graph.py             # Causal lineage & provenance state tracker
    |   |-- ring1_interceptor.py       # Layer 7 JSON-RPC proxy & vector drift scorer
    |   `-- ring2_guardian.py          # Layer 3/4 Linux syscall & namespace supervisor
    |-- docs/
    |   `-- console_preview.png        # Live dual-ring verification console screenshot
    |-- demo_runner.py                 # Automated CLI verification suite
    |-- server.py                      # FastAPI backend + Verification Web Console
    `-- requirements.txt

---

## References
1. **Model Context Protocol (MCP) Specification:** [modelcontextprotocol.io](https://modelcontextprotocol.io/specification)
2. **Defending LLM Agents via Information Flow Control (CaMeL):** [arXiv:2503.18813](https://arxiv.org/abs/2503.18813)
3. **OWASP Top 10 for LLM Applications (LLM01 & LLM07):** [owasp.org](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
4. **Linux Kernel Namespaces & Syscall Tracing (`unshare` / `strace`):** [man7.org](https://man7.org/linux/man-pages/man2/unshare.2.html)
