#!/usr/bin/env python3
import os
import sys
import argparse

venv_python = os.path.join(os.path.dirname(os.path.abspath(__file__)), "venv", "bin", "python")
if os.path.exists(venv_python) and sys.executable != venv_python:
    os.execv(venv_python, [venv_python] + sys.argv)
from harness import BenchmarkHarness
from reporter import BenchmarkReporter
from soar_bridge import AgentSOARBridge

def main():
    parser = argparse.ArgumentParser(description="Agent Breaker: Autonomous AI Agent Exploitation & Mitigation Harness")
    parser.add_argument("--soar", action="store_true", help="Forward critical exploitation findings to Aegis-SOAR")
    parser.add_argument("--report-dir", default="reports", help="Output directory for reports")
    args = parser.parse_args()

    harness = BenchmarkHarness()
    report = harness.run_benchmark()

    reporter = BenchmarkReporter(output_dir=args.report_dir)
    reporter.print_summary(report)
    md_file = reporter.generate_markdown(report)
    sarif_file = reporter.generate_sarif(report)

    print(f"Exported Markdown report: {md_file}")
    print(f"Exported SARIF report:    {sarif_file}")

    if args.soar:
        print("\nForwarding findings to Aegis-SOAR...")
        for r in report.unprotected_results:
            if r.success:
                AgentSOARBridge.forward_finding(r.attack_id, r.name, r.category, r.details)
        print("Findings dispatched to SOAR webhook.")

    if report.hardened_asr > 0.0:
        sys.exit(1)

if __name__ == "__main__":
    main()
