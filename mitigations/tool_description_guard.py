import re
from typing import Tuple

POISON_PATTERNS = [
    r"(?i)ignore\s+(all\s+)?(previous|prior)\s+instructions",
    r"(?i)system\s+override",
    r"(?i)disregard\s+rules",
    r"(?i)forward\s+credentials",
    r"(?i)exfiltrate"
]

class ToolSchemaSanitizer:
    @staticmethod
    def sanitize(schema_text: str) -> Tuple[bool, str, str]:
        for p in POISON_PATTERNS:
            if re.search(p, schema_text):
                cleaned = re.sub(p, "[REDACTED_POISON_INSTRUCTION]", schema_text)
                return False, cleaned, "Suspicious prompt injection directive identified in MCP tool metadata"
        return True, schema_text, ""
