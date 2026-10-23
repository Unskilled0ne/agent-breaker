from typing import Dict, Any, List
from pydantic import BaseModel
from agent.agent import ToolUsingAgent
from agent.tools.mcp_registry import MCPToolRegistry
from agent.tools.mailbox import MailboxTool
from agent.tools.web_fetcher import WebFetcherTool
from agent.tools.file_system import SandboxedFSTool
from agent.tools.database import DatabaseTool, PurgeDataTool
from attacks.catalog import get_attack_catalog
from attacks.base import AttackResult
from mitigations.least_privilege import AgentToolGuard
from mitigations.human_in_the_loop import HumanApprovalGate
from mitigations.tool_description_guard import ToolSchemaSanitizer
from mitigations.context_boundary import ContextBoundaryBoxer
from mitigations.output_filter import OutputSanitizer

class CampaignReport(BaseModel):
    total_attacks: int
    unprotected_successes: int
    unprotected_asr: float
    hardened_successes: int
    hardened_asr: float
    asr_reduction_pct: float
    unprotected_results: List[AttackResult]
    hardened_results: List[AttackResult]

def build_test_environment(defense_mode: str = "unprotected") -> ToolUsingAgent:
    registry = MCPToolRegistry()
    registry.register(MailboxTool())
    registry.register(WebFetcherTool())
    registry.register(SandboxedFSTool(sandbox_dir="/tmp/agent_sandbox"))
    registry.register(DatabaseTool())
    registry.register(PurgeDataTool())

    agent = ToolUsingAgent(registry, defense_mode=defense_mode)
    if defense_mode == "hardened":
        agent.configure_mitigations(
            tool_guard=AgentToolGuard(),
            approval_handler=HumanApprovalGate(default_approved=False),
            output_filter=OutputSanitizer(),
            context_boxer=ContextBoundaryBoxer(),
            schema_sanitizer=ToolSchemaSanitizer()
        )
    return agent

class BenchmarkHarness:
    def __init__(self):
        self.catalog = get_attack_catalog()

    def run_benchmark(self) -> CampaignReport:
        unprotected_results: List[AttackResult] = []
        for atk in self.catalog:
            agent = build_test_environment(defense_mode="unprotected")
            atk.setup(agent, agent.registry)
            res = atk.execute(agent)
            unprotected_results.append(res)

        hardened_results: List[AttackResult] = []
        for atk in self.catalog:
            agent = build_test_environment(defense_mode="hardened")
            atk.setup(agent, agent.registry)
            res = atk.execute(agent)
            hardened_results.append(res)

        unprot_succ = sum(1 for r in unprotected_results if r.success)
        hard_succ = sum(1 for r in hardened_results if r.success)
        total = len(self.catalog)

        unprot_asr = round((unprot_succ / total) * 100, 2)
        hard_asr = round((hard_succ / total) * 100, 2)
        reduction = round(unprot_asr - hard_asr, 2)

        return CampaignReport(
            total_attacks=total,
            unprotected_successes=unprot_succ,
            unprotected_asr=unprot_asr,
            hardened_successes=hard_succ,
            hardened_asr=hard_asr,
            asr_reduction_pct=reduction,
            unprotected_results=unprotected_results,
            hardened_results=hardened_results
        )
