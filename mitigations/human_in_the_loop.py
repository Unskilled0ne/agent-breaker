from typing import Tuple, Dict, Any

class HumanApprovalGate:
    def __init__(self, default_approved: bool = False):
        self.default_approved = default_approved

    def request_approval(self, tool_name: str, args: Dict[str, Any], caller_role: str) -> Tuple[bool, str]:
        if not self.default_approved:
            return False, f"Action Paused: Tool '{tool_name}' marked destructive. Explicit human security approval required."
        return True, "Approved by human operator."
