import os
import httpx
import logging
from typing import Dict, Any, Optional
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

    async def trigger_rollback(
        self,
        target_sha: str,
        reason: str,
        token: Optional[str] = None,
        owner: Optional[str] = None,
        repo: Optional[str] = None,
        workflow_id: Optional[str] = None
    ) -> Dict[str, Any]:
        self.reload_config()

        # Allow per-user overrides, fallback to system config
        active_token = token or self.token
        active_owner = owner or self.owner
        active_repo = repo or self.repo
        active_workflow = workflow_id or self.workflow_id

        simulate_mode = self.simulate if not token else False

        if simulate_mode or not active_token:
            logger.info(f"[SIMULATION] Dispatched GitHub Actions rollback to SHA {target_sha} for {active_owner}/{active_repo}")
            return {
                "status": "success",
                "simulated": True,
                "target_sha": target_sha,
                "repository": f"{active_owner}/{active_repo}",
                "workflow": active_workflow,
                "action": "workflow_dispatch",
                "inputs": {
                    "rollback_sha": target_sha,
                    "reason": reason
                },
                "message": f"[SIMULATION] Triggered deployment workflow for commit {target_sha[:7]}."
            }

        url = f"https://api.github.com/repos/{active_owner}/{active_repo}/actions/workflows/{active_workflow}/dispatches"
        headers = {
            "Authorization": f"Bearer {active_token}",
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
                        "repository": f"{active_owner}/{active_repo}",
                        "workflow": active_workflow,
                        "status_code": response.status_code,
                        "message": f"Live GitHub Actions workflow triggered for commit {target_sha[:7]}."
                    }
                else:
                    return {
                        "status": "error",
                        "simulated": False,
                        "target_sha": target_sha,
                        "repository": f"{active_owner}/{active_repo}",
                        "status_code": response.status_code,
                        "error": response.text,
                        "message": f"GitHub API error {response.status_code}"
                    }
            except Exception as e:
                return {
                    "status": "error",
                    "simulated": False,
                    "target_sha": target_sha,
                    "repository": f"{active_owner}/{active_repo}",
                    "error": str(e),
                    "message": f"Failed to dispatch GitHub workflow: {str(e)}"
                }

    async def test_connection(self, token: str, owner: str, repo: str) -> Dict[str, Any]:
        if not token or not owner or not repo:
            return {"success": False, "error": "Token, Owner, and Repository Name are all required."}

        url = f"https://api.github.com/repos/{owner}/{repo}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "SRE-Incident-Copilot"
        }

        async with httpx.AsyncClient() as client:
            try:
                resp = await client.get(url, headers=headers, timeout=10.0)
                if resp.status_code == 200:
                    data = resp.json()
                    return {
                        "success": True,
                        "repository": data.get("full_name"),
                        "description": data.get("description") or "No description",
                        "default_branch": data.get("default_branch", "main"),
                        "private": data.get("private", False),
                        "stars": data.get("stargazers_count", 0)
                    }
                elif resp.status_code == 401:
                    return {"success": False, "error": "Authentication failed: Invalid GitHub Token."}
                elif resp.status_code == 404:
                    return {"success": False, "error": f"Repository '{owner}/{repo}' not found or token lacks permission to view it."}
                else:
                    return {"success": False, "error": f"GitHub API error {resp.status_code}: {resp.text}"}
            except Exception as e:
                return {"success": False, "error": f"Connection error: {str(e)}"}
