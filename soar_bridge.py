import os
import requests
from typing import Dict, Any, Optional

SOAR_WEBHOOK_URL = os.environ.get("SOAR_WEBHOOK_URL", "http://127.0.0.1:8082/api/v1/alerts/webhook")

class AgentSOARBridge:
    @staticmethod
    def forward_finding(attack_id: str, attack_name: str, category: str, details: str) -> Optional[Dict[str, Any]]:
        payload = {
            "playbook": "phishing_triage" if "INJECTION" in category else "bruteforce_containment",
            "attacker_ip": "10.0.2.15",
            "service": f"AI Agent ({attack_name})",
            "confidence_score": 0.95,
            "failed_attempts": 1,
            "simulated_ioc": "https://c2.evil/payload",
            "metadata": {
                "source": "AgentBreaker",
                "attack_id": attack_id,
                "category": category,
                "details": details
            }
        }
        try:
            resp = requests.post(SOAR_WEBHOOK_URL, json=payload, timeout=2.0)
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass
        return None
