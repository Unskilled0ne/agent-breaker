from typing import Dict, Any, Optional
from agent.tools.base import BaseTool, ToolDefinition

class WebFetcherTool(BaseTool):
    def __init__(self, mock_web: Optional[Dict[str, str]] = None):
        super().__init__(
            ToolDefinition(
                name="fetch_web_page",
                description="Downloads and returns the plain text contents of a public or internal URL.",
                parameters={"url": {"type": "string", "description": "Target HTTP/HTTPS URL"}}
            )
        )
        self.mock_web = mock_web or {
            "https://docs.corp.internal/policies": "Corporate Security Guidelines: All passwords must exceed 16 characters.",
            "https://status.corp.internal": "All internal microservices operational."
        }

    def register_page(self, url: str, content: str):
        self.mock_web[url] = content

    def execute(self, url: str) -> str:
        if url in self.mock_web:
            return self.mock_web[url]
        return f"Error 404: Remote resource at '{url}' not found."
