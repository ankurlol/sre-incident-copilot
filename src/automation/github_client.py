import os
import httpx
import logging
from typing import Dict, Any
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

class GitHubRollbackClient:
    def __init__(self):
        self.reload_config()

    def reload_config(self):
        load_dotenv()
        self.token = os.getenv("GITHUB_TOKEN")
        self.owner = os.getenv("GITHUB_REPO_OWNER", "ankurlol")
        self.repo = os.getenv("GITHUB_REPO_NAME", "sample-payment-api")
        self.workflow_id = os.getenv("GITHUB_WORKFLOW_ID", "deploy.yml")
        simulate_val = os.getenv("SIMULATE_GITHUB_ACTIONS", "false").lower()
        self.simulate = simulate_val == "true" or not bool(self.token)

    async def trigger_rollback(self, target_sha: str, reason: str) -> Dict[str, Any]:
        self.reload_config()

        if self.simulate:
            logger.info(f"[SIMULATION] Dispatched GitHub Actions rollback to SHA {target_sha} for {self.owner}/{self.repo}")
            return {
                "status": "success",
                "simulated": True,
                "target_sha": target_sha,
                "repository": f"{self.owner}/{self.repo}",
                "workflow": self.workflow_id,
                "action": "workflow_dispatch",
                "inputs": {
                    "rollback_sha": target_sha,
                    "reason": reason
                },
                "message": f"[SIMULATION] Triggered deployment workflow for commit {target_sha[:7]}."
            }

        url = f"https://api.github.com/repos/{self.owner}/{self.repo}/actions/workflows/{self.workflow_id}/dispatches"
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "SRE-Incident-Copilot"
        }
        payload = {
            "ref": "main",
            "inputs": {
                "rollback_sha": target_sha,
                "reason": reason
            }
        }

        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(url, json=payload, headers=headers, timeout=10.0)
                if response.status_code in [200, 204]:
                    return {
                        "status": "success",
                        "simulated": False,
                        "target_sha": target_sha,
                        "status_code": response.status_code,
                        "message": f"Live GitHub Actions workflow triggered for commit {target_sha[:7]}."
                    }
                else:
                    return {
                        "status": "error",
                        "simulated": False,
                        "status_code": response.status_code,
                        "error": response.text
                    }
            except Exception as e:
                return {
                    "status": "error",
                    "simulated": False,
                    "error": str(e)
                }
