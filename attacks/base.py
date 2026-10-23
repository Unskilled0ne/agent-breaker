from typing import Dict, Any, Optional
from pydantic import BaseModel

class AttackResult(BaseModel):
    attack_id: str
    name: str
    category: str
    mitre_atlas_id: str
    success: bool
    details: str
    unauthorized_tool_called: Optional[str] = None
    data_leaked: Optional[str] = None
    blocked_by: Optional[str] = None

class BaseAttack:
    def __init__(self, attack_id: str, name: str, category: str, mitre_atlas_id: str):
        self.attack_id = attack_id
        self.name = name
        self.category = category
        self.mitre_atlas_id = mitre_atlas_id

    def setup(self, agent, registry):
        pass

    def execute(self, agent) -> AttackResult:
        raise NotImplementedError
