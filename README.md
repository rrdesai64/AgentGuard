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

```text
                        [ Untrusted External Data / Repo / Inbox ]
                                            │
                                            ▼
                                  [ Autonomous Agent ]
                                            │
         ┌──────────────────────────────────┴──────────────────────────────────┐
         ▼ (Structured Tool Call: MCP/JSON)                                    ▼ (Code/Shell Execution: bash/pytest)
┌───────────────────────────────────────────────────┐         ┌───────────────────────────────────────────────────┐
│ RING 1: Layer 7 Semantic MCP Interceptor          │         │ RING 2: Layer 3/4 OS Kernel & Syscall Guardian    │
│ ------------------------------------------------- │         │ ------------------------------------------------- │
│ * Causal Taint Graph (Session Lineage Tracking)   │         │ * Linux Namespaces (unshare network/fs isolation) │
│ * Deterministic Policy Gate (Taint x Privilege)   │         │ * Syscall Guard (Blocks ~/.ssh, ~/.aws, /etc)     │
│ * Algebraic Vector Intent Alignment (<2.5ms)      │         │ * Socket Guard (Blocks unauthorized outbound IPs) │
└───────────────────────────────────────────────────┘