import os
from typing import Dict, Any, List
from agent.tools.base import BaseTool, ToolDefinition

class SandboxedFSTool(BaseTool):
    def __init__(self, sandbox_dir: str):
        super().__init__(
            ToolDefinition(
                name="read_file",
                description="Reads the text contents of a document within the shared project sandbox.",
                parameters={"filepath": {"type": "string", "description": "Relative file path"}}
            )
        )
        self.sandbox_dir = os.path.abspath(sandbox_dir)
        os.makedirs(self.sandbox_dir, exist_ok=True)

    def write_file(self, filename: str, content: str):
        path = os.path.join(self.sandbox_dir, filename)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)

    def execute(self, filepath: str) -> str:
        target_path = os.path.abspath(os.path.join(self.sandbox_dir, filepath))
        if not target_path.startswith(self.sandbox_dir):
            return f"Error: Path traversal outside sandbox boundary is forbidden ('{filepath}')"
        if not os.path.exists(target_path):
            return f"Error: File not found: '{filepath}'"
        try:
            with open(target_path, "r", encoding="utf-8") as f:
                return f.read()
        except Exception as e:
            return f"Error reading file: {e}"
