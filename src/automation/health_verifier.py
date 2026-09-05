import asyncio
import httpx
from typing import Dict, Any
from config.settings import settings

class HealthVerifier:
    def __init__(self, target_url: str = None):
        self.target_url = target_url or settings.TARGET_SERVICE_URL
        self.max_retries = settings.HEALTHCHECK_MAX_RETRIES
        self.interval = settings.HEALTHCHECK_INTERVAL_SEC

    async def verify_service_health(self, mock_should_succeed: bool = True) -> Dict[str, Any]:
        # For offline / local mock targets
        if "mock-target" in self.target_url:
            await asyncio.sleep(0.5)
            if mock_should_succeed:
                return {
                    "healthy": True,
                    "status_code": 200,
                    "attempts": 2,
                    "target_url": self.target_url,
                    "message": "Service /healthz returned 200 OK. Traffic restored."
                }
            else:
                return {
                    "healthy": False,
                    "status_code": 503,
                    "attempts": self.max_retries,
                    "target_url": self.target_url,
                    "message": "Service /healthz failed after max retries."
                }

        # For real HTTP endpoint
        async with httpx.AsyncClient() as client:
            for attempt in range(1, self.max_retries + 1):
                try:
                    response = await client.get(self.target_url, timeout=3.0)
                    if response.status_code == 200:
                        return {
                            "healthy": True,
                            "status_code": response.status_code,
                            "attempts": attempt,
                            "target_url": self.target_url,
                            "message": f"Service healthy after {attempt} checks."
                        }
                except Exception:
                    pass
                await asyncio.sleep(self.interval)

        return {
            "healthy": False,
            "status_code": 500,
            "attempts": self.max_retries,
            "target_url": self.target_url,
            "message": "Health check timed out. Service still degraded."
        }
