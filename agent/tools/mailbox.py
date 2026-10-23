from typing import Dict, Any, List, Optional
from agent.tools.base import BaseTool, ToolDefinition

class MailboxTool(BaseTool):
    def __init__(self, initial_emails: Optional[List[Dict[str, str]]] = None):
        super().__init__(
            ToolDefinition(
                name="read_mailbox",
                description="Fetches recent emails from the corporate inbox for the current user.",
                parameters={"query": {"type": "string", "description": "Subject or sender filter"}}
            )
        )
        self.emails = initial_emails or [
            {
                "id": "MSG-101",
                "sender": "finance@corp.internal",
                "subject": "Q3 Financial Summary",
                "body": "Please find attached the Q3 budget report."
            },
            {
                "id": "MSG-102",
                "sender": "hr@corp.internal",
                "subject": "Policy Updates",
                "body": "Annual security compliance checklist is due by Friday."
            }
        ]

    def add_email(self, sender: str, subject: str, body: str):
        self.emails.append({
            "id": f"MSG-{len(self.emails) + 101}",
            "sender": sender,
            "subject": subject,
            "body": body
        })

    def execute(self, query: str = "") -> List[Dict[str, str]]:
        if not query:
            return self.emails
        q = query.lower()
        return [
            m for m in self.emails 
            if q in m["subject"].lower() or q in m["sender"].lower() or q in m["body"].lower()
        ]
