import time
from typing import Dict, Any, Tuple, Optional
from pydantic import BaseModel
from config.settings import settings
from src.automation.git_tracker import GitCommit

class GuardrailCheckResult(BaseModel):
    passed: bool
    blocked_reason: Optional[str] = None
    warning: Optional[str] = None
    details: Dict[str, Any] = {}

class SafetyGuardrails:
    def __init__(self):
        self.last_rollback_timestamp: Optional[float] = None
        self.rollback_history = []

    def evaluate_rollback_safety(
        self,
        commit: GitCommit,
        llm_confidence: float,
        recommended_action: str
    ) -> GuardrailCheckResult:
        # 1. Global Killswitch Check
        if not settings.AUTO_ROLLBACK_ENABLED:
            return GuardrailCheckResult(
                passed=False,
                blocked_reason="Auto-rollback is globally disabled via configuration killswitch."
            )

        # 2. Database Migration Guardrail (Critical Safety Rule)
        if settings.BLOCK_ON_DB_MIGRATION and commit.has_db_migrations:
            return GuardrailCheckResult(
                passed=False,
                blocked_reason=(
                    "CRITICAL SAFETY GUARD TRIGGERED: Commit includes database schema migrations "
                    f"(changed files: {commit.changed_files}). Automated rollback blocked to prevent data corruption. "
                    "Manual DBA review required."
                ),
                details={"risk_level": "CRITICAL_DATA_LOSS_RISK", "changed_files": commit.changed_files}
            )

        # 3. LLM Confidence Guardrail
        if llm_confidence < settings.MIN_CONFIDENCE_THRESHOLD:
            return GuardrailCheckResult(
                passed=False,
                blocked_reason=(
                    f"RCA Confidence ({llm_confidence:.0%}) is below the required safety threshold "
                    f"({settings.MIN_CONFIDENCE_THRESHOLD:.0%}). Manual triage required."
                ),
                details={"confidence": llm_confidence, "threshold": settings.MIN_CONFIDENCE_THRESHOLD}
            )

        # 4. Anti-Flapping / Rate Limiting
        current_time = time.time()
        window_seconds = settings.ROLLBACK_WINDOW_MINUTES * 60
        if self.last_rollback_timestamp is not None:
            time_since_last = current_time - self.last_rollback_timestamp
            if time_since_last < window_seconds:
                return GuardrailCheckResult(
                    passed=False,
                    blocked_reason=(
                        f"Anti-Flapping Rate Limit: A rollback occurred {int(time_since_last / 60)} minutes ago. "
                        f"Window limit is {settings.ROLLBACK_WINDOW_MINUTES} minutes."
                    ),
                    details={"time_since_last_sec": time_since_last}
                )

        # 5. Recommendation Check
        if recommended_action.upper() not in ["ROLLBACK_NOW", "AUTO_ROLLBACK"]:
            return GuardrailCheckResult(
                passed=False,
                blocked_reason=f"LLM diagnostic did not recommend automatic rollback (Recommendation: {recommended_action})."
            )

        return GuardrailCheckResult(
            passed=True,
            details={"approved_target_sha": commit.previous_sha}
        )

    def record_rollback(self, target_sha: str):
        self.last_rollback_timestamp = time.time()
        self.rollback_history.append({
            "timestamp": self.last_rollback_timestamp,
            "target_sha": target_sha
        })
