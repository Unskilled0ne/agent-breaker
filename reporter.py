import json
import os
import time
from rich.console import Console
from rich.table import Table
from harness import CampaignReport

class BenchmarkReporter:
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)
        self.console = Console()

    def print_summary(self, report: CampaignReport):
        self.console.print("\n[bold cyan]════════════════════════════════════════════════════════════════════════════[/bold cyan]")
        self.console.print("[bold white]            AGENT BREAKER: AI AGENT EXPLOITATION BENCHMARK            [/bold white]")
        self.console.print("[bold cyan]════════════════════════════════════════════════════════════════════════════[/bold cyan]\n")

        summary_table = Table(title="🛡️ Defense Impact Summary", header_style="bold magenta")
        summary_table.add_column("Evaluation Tier", style="bold")
        summary_table.add_column("Total Probes", justify="center")
        summary_table.add_column("Exploited", justify="center")
        summary_table.add_column("Defended", justify="center")
        summary_table.add_column("Attack Success Rate (ASR)", justify="center", style="bold")

        unprot_defended = report.total_attacks - report.unprotected_successes
        hard_defended = report.total_attacks - report.hardened_successes

        summary_table.add_row(
            "[red]Unprotected Agent[/red]",
            str(report.total_attacks),
            str(report.unprotected_successes),
            str(unprot_defended),
            f"[red]{report.unprotected_asr}%[/red]"
        )
        summary_table.add_row(
            "[green]Hardened Agent (Mitigations Active)[/green]",
            str(report.total_attacks),
            str(report.hardened_successes),
            str(hard_defended),
            f"[green]{report.hardened_asr}%[/green]"
        )
        self.console.print(summary_table)

        detail_table = Table(title="🔍 Detailed Attack Vectors & Mitigation Status", header_style="bold blue")
        detail_table.add_column("ID", style="dim", width=8)
        detail_table.add_column("Attack Vector", style="bold")
        detail_table.add_column("Category", style="cyan")
        detail_table.add_column("Unprotected", justify="center")
        detail_table.add_column("Hardened", justify="center")
        detail_table.add_column("Mitigation Triggered", style="green")

        for u, h in zip(report.unprotected_results, report.hardened_results):
            u_status = "[red]EXPLOITED[/red]" if u.success else "[green]DEFENDED[/green]"
            h_status = "[red]EXPLOITED[/red]" if h.success else "[green]DEFENDED[/green]"
            detail_table.add_row(
                u.attack_id,
                u.name,
                u.category,
                u_status,
                h_status,
                h.blocked_by or "Policy Gating"
            )
        self.console.print(detail_table)
        self.console.print(f"\n[bold green]✔ Net Security Improvement: -{report.asr_reduction_pct}% Attack Surface Reduction[/bold green]\n")

    def generate_markdown(self, report: CampaignReport) -> str:
        md = f"""# Agent Breaker: Autonomous AI Agent Exploitation & Mitigation Report 💥🤖

**Evaluated on:** `{time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}`  
**Author:** Vasilis Tsiamouras

---

## 1. Executive Summary & Attack Success Rate (ASR)

| Evaluation Tier | Total Probes | Exploited Vulnerabilities | Neutralized Attacks | Attack Success Rate (ASR) |
| :--- | :---: | :---: | :---: | :---: |
| **Unprotected Agent** | {report.total_attacks} | {report.unprotected_successes} | {report.total_attacks - report.unprotected_successes} | **{report.unprotected_asr}%** |
| **Hardened Agent** | {report.total_attacks} | {report.hardened_successes} | {report.total_attacks - report.hardened_successes} | **{report.hardened_asr}%** |
| **Security Impact** | — | **-{report.unprotected_successes - report.hardened_successes} critical flaws** | **+{report.unprotected_successes - report.hardened_successes} mitigated** | **-{report.asr_reduction_pct}% Risk Reduction** |

---

## 2. Attack Vectors & Mitigations Matrix

| Attack ID | Vector Name | OWASP Category | MITRE ATLAS | Baseline (Zero Defenses) | Hardened Status | Defensive Mitigation |
| :--- | :--- | :--- | :--- | :---: | :---: | :--- |
"""
        for u, h in zip(report.unprotected_results, report.hardened_results):
            u_status = "🔴 VULNERABLE" if u.success else "🟢 DEFENDED"
            h_status = "🔴 VULNERABLE" if h.success else "🟢 DEFENDED"
            md += f"| `{u.attack_id}` | **{u.name}** | `{u.category}` | `{u.mitre_atlas_id}` | {u_status} | {h_status} | `{h.blocked_by or 'Policy Gating'}` |\n"

        md += """
---

## 3. Defense Architecture & Security Controls Implemented

1. **Context Boundary Boxing (`ContextBoundaryBoxer`):** Encapsulates external tool outputs (inbox messages, web scraping) into sandboxed XML structures, preventing the model from adopting untrusted content as system instructions.
2. **MCP Tool Description Sanitization (`ToolSchemaSanitizer`):** Scans tool descriptions and schemas for prompt injection keywords prior to injecting them into the agent system prompt.
3. **Role-Based Tool Execution (`AgentToolGuard`):** Restricts high-privilege operations (`execute_sql`, `read_file`) to verified `admin` roles, preventing confused deputy attacks.
4. **Human-In-The-Loop Approval Gate (`HumanApprovalGate`):** Destructive actions (`purge_records`, `drop_table`) pause agent execution and require cryptographic human sign-off.
5. **Output Sanitization (`OutputSanitizer`):** Strips markdown image tags (`![](...)`) to eliminate SSRF exfiltration vectors and inspects candidate outputs for internal canary tokens.
"""
        md_path = os.path.join(self.output_dir, "agent_breaker_report.md")
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(md)
        return md_path

    def generate_sarif(self, report: CampaignReport) -> str:
        results = []
        for r in report.hardened_results:
            if r.success:
                results.append({
                    "ruleId": f"{r.category} ({r.mitre_atlas_id})",
                    "level": "error",
                    "message": {"text": f"Agent vulnerability: {r.name}. Details: {r.details}"},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": "agent/agent.py"}}}]
                })
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "Agent Breaker Red-Teaming Harness", "version": "1.0"}},
                "results": results
            }]
        }
        sarif_path = os.path.join(self.output_dir, "agent_breaker.sarif")
        with open(sarif_path, "w", encoding="utf-8") as f:
            json.dump(sarif, f, indent=2)
        return sarif_path
