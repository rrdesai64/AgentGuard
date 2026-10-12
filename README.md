# AgentGuard: Dual-Ring Runtime Firewall & Kernel Sandbox for Autonomous Agents

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Ring 1 Latency](https://img.shields.io/badge/Ring_1_Latency-%3C2.5ms-success.svg)]()
[![Ring 2 Sandbox](https://img.shields.io/badge/Ring_2_Isolation-unshare_%2B_strace-informational.svg)]()

**AgentGuard** is an inline, low-latency runtime security firewall designed to protect autonomous AI agents (MCP tool-calling systems and DevOps/coding agents) from **Indirect Prompt Injection**, **Semantic Intent Drift**, and **Subprocess Kernel Breakouts**.

Rather than relying on probabilistic "LLM-as-a-Judge" text wrappersâ€”which introduce 600ms+ of latency, double token expenditure, and remain susceptible to adversarial prompt encodingsâ€”AgentGuard treats the language model as an **untrusted user-space process**. It enforces deterministic security invariants across two architectural rings:

1. **Ring 1 (Layer 7 â€” Semantic MCP Interceptor):** Provenance taint tracking, deterministic policy gates, and sub-millisecond vector-hashing intent alignment for structured JSON-RPC tool invocations.
2. **Ring 2 (Layer 3/4 â€” OS Kernel & Syscall Guardian):** Linux namespace isolation ('unshare') and real-time system call tracing ('openat', 'connect', 'execve') to prevent authorized coding subshells or poisoned dependencies from reading sensitive host credentials ('~/.ssh', '.aws', '/etc/shadow') or opening unauthorized outbound network sockets.

---

## System Architecture


                        [ Untrusted External Data / Repo / Inbox ]
                                            â”‚
                                            â–¼
                                  [ Autonomous Agent ]
                                            â”‚
         â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
         â–¼ (Structured Tool Call: MCP/JSON)                                    â–¼ (Code/Shell Execution: bash/pytest)
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”         â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚ RING 1: Layer 7 Semantic MCP Interceptor          â”‚         â”‚ RING 2: Layer 3/4 OS Kernel & Syscall Guardian    â”‚
â”‚ ------------------------------------------------- â”‚         â”‚ ------------------------------------------------- â”‚
â”‚ * Causal Taint Graph (Session Lineage Tracking)   â”‚         â”‚ * Linux Namespaces (unshare network/fs isolation) â”‚
â”‚ * Deterministic Policy Gate (Taint x Privilege)   â”‚         â”‚ * Syscall Guard (Blocks ~/.ssh, ~/.aws, /etc)     â”‚
â”‚ * Algebraic Vector Intent Alignment (<2.5ms)      â”‚         â”‚ * Socket Guard (Blocks unauthorized outbound IPs) â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜         â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
         â”‚                                                                     â”‚
         â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                                            â–¼
                     [ Unified Telemetry API & Live Verification Console ]


---

## Benchmark Comparison

| Metric | Probabilistic LLM Guardrail | AgentGuard Dual-Ring Engine |
| :--- | :--- | :--- |
| **Interception Latency (Ring 1)** | 600 ms â€“ 1,500 ms | **< 2.5 ms** |
| **Kernel Syscall Containment (Ring 2)** | No visibility into child processes | **< 8.0 ms (SIGKILL / Block)** |
| **Additional Token Cost** | 2x API Token Spend | **0 Tokens (Local & Deterministic)** |
| **Indirect Prompt Injection Defense** | Heuristic / Bypassable via encoding | **Monotonic Causal Taint Graph** |
| **Supply-Chain / `bash_exec` Breakout** | None | **Syscall-level `openat` & `connect` interception** |

---

## Quickstart (Ubuntu / Linux)

### 1. Install Dependencies
bash
git clone [https://github.com/](https://github.com/)rrdesai64/agentguard.git
cd agentguard
pip install -r requirements.txt


### 2. Run the CLI Verification Suite
Execute both Ring 1 (MCP Indirect Injection) and Ring 2 (Kernel SSH Key Exfiltration) test cases:
bash
python3 demo_runner.py


### 3. Launch the Telemetry Server & Test Console
bash
python3 server.py

Navigate to http://localhost:8000 to evaluate live presets or inject custom payloads against both enforcement rings.

---

## Repository Layout


agentguard/
â”œâ”€â”€ config/
â”‚   â””â”€â”€ security_policy.yaml       # Unified Ring 1 (MCP) & Ring 2 (OS Syscall) policies
â”œâ”€â”€ core/
â”‚   â”œâ”€â”€ __init__.py
â”‚   â”œâ”€â”€ schemas.py                 # Pydantic data contracts & telemetry models
â”‚   â”œâ”€â”€ taint_graph.py             # Causal lineage & provenance state tracker
â”‚   â”œâ”€â”€ ring1_interceptor.py       # Layer 7 JSON-RPC proxy & vector drift scorer
â”‚   â””â”€â”€ ring2_guardian.py          # Layer 3/4 Linux syscall & namespace supervisor
â”œâ”€â”€ demo_runner.py                 # Automated CLI verification suite
â”œâ”€â”€ server.py                      # FastAPI backend + Verification Web Console
â””â”€â”€ requirements.txt


---

## References
1. **Model Context Protocol (MCP) Specification:** [modelcontextprotocol.io](https://modelcontextprotocol.io/specification)
2. **Defending LLM Agents via Information Flow Control (CaMeL):** [arXiv:2503.18813](https://arxiv.org/abs/2503.18813)
3. **OWASP Top 10 for LLM Applications (LLM01 & LLM07):** [owasp.org](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
4. **Linux Kernel Namespaces & Syscall Tracing (`unshare` / `strace`):** [man7.org](https://man7.org/linux/man-pages/man2/unshare.2.html)
