import re
from typing import Tuple, Optional

EXFIL_IMG_PATTERN = re.compile(r"!\[(.*?)\]\((https?:\/\/[^\s\)]+)\)")
CANARY_TOKEN = "CANARY_AGENT_BREAKER_99182_SEC"
API_KEY = "sk-corp-agent-prod-key-77210"

class OutputSanitizer:
    @staticmethod
    def inspect(output_text: str) -> Tuple[bool, str, Optional[str]]:
        if CANARY_TOKEN in output_text or API_KEY in output_text:
            return False, "[BLOCKED: Confidential canary token or API credential leak intercepted]", "Credential leakage in model output"
        if EXFIL_IMG_PATTERN.search(output_text):
            return False, "[BLOCKED: Markdown image exfiltration link intercepted]", "Markdown SSRF exfiltration attempt"
        return True, output_text, None
