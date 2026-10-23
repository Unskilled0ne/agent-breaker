from typing import Dict, Any, Optional
from pydantic import BaseModel, Field

class ToolDefinition(BaseModel):
    name: str
    description: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    privileged: bool = False
    destructive: bool = False

class BaseTool:
    def __init__(self, definition: ToolDefinition):
        self.definition = definition

    @property
    def name(self) -> str:
        return self.definition.name

    @property
    def description(self) -> str:
        return self.definition.description

    def execute(self, **kwargs) -> Any:
        raise NotImplementedError
