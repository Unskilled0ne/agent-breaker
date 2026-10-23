from typing import Tuple, Optional
from agent.tools.base import ToolDefinition

class AgentToolGuard:
    @staticmethod
    def authorize(definition: ToolDefinition, caller_role: str = "guest") -> Tuple[bool, Optional[str]]:
        role = (caller_role or "guest").lower().strip()
        if definition.privileged:
            if role != "admin":
                return False, f"Unauthorized: Tool '{definition.name}' requires role 'admin'. Caller has role '{caller_role}'."
        return True, None
