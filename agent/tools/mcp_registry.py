from typing import Dict, Any, List, Optional
from agent.tools.base import BaseTool, ToolDefinition

class MCPToolRegistry:
    def __init__(self):
        self._tools: Dict[str, BaseTool] = {}

    def register(self, tool: BaseTool):
        self._tools[tool.name] = tool

    def get_tool(self, name: str) -> Optional[BaseTool]:
        return self._tools.get(name)

    def list_tools(self) -> List[ToolDefinition]:
        return [t.definition for t in self._tools.values()]

    def export_schemas_for_prompt(self) -> str:
        lines = []
        for t in self._tools.values():
            lines.append(f"- Tool: `{t.name}`: {t.description}")
            if t.definition.parameters:
                lines.append(f"  Params: {list(t.definition.parameters.keys())}")
        return "\n".join(lines)
