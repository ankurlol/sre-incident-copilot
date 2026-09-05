from typing import Dict, Any, Optional
from src.rag.rca_engine import RCAReport
from src.automation.guardrails import GuardrailCheckResult

class IncidentReporter:
    def format_slack_message(
        self,
        rca: RCAReport,
        guardrail: GuardrailCheckResult,
        rollback_result: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        status_emoji = "??" if rca.severity == "P1" else "??"
        if guardrail.passed and rollback_result and rollback_result.get("status") == "success":
            target = rollback_result.get("target_sha", "prev")[:7]
            action_text = f"? Auto-Rollback Executed to {rca.breaking_commit_sha[:7]} ? {target}"
        else:
            action_text = f"?? Auto-Rollback Blocked: {guardrail.blocked_reason}"

        return {
            "incident_id": rca.incident_id,
            "title": f"{status_emoji} [{rca.severity}] Outage Detected in {rca.service_name}",
            "summary": rca.root_cause_summary,
            "breaking_author": rca.breaking_author,
            "breaking_commit": rca.breaking_commit_sha[:7],
            "breaking_file": rca.breaking_file,
            "confidence": f"{rca.confidence_score:.0%}",
            "action_status": action_text,
            "mitigation_steps": rca.mitigation_steps,
            "matched_runbooks": [rb["title"] for rb in rca.matched_runbooks[:2]]
        }

    def format_markdown_summary(
        self,
        rca: RCAReport,
        guardrail: GuardrailCheckResult,
        rollback_result: Optional[Dict[str, Any]] = None
    ) -> str:
        lines = [
            f"# Incident Report: {rca.incident_id}",
            f"**Service:** {rca.service_name} | **Severity:** {rca.severity} | **Confidence:** {rca.confidence_score:.0%}",
            "",
            "## ?? Root Cause Analysis",
            rca.root_cause_summary,
            "",
            f"- **Breaking Commit:** `{rca.breaking_commit_sha[:7]}` by {rca.breaking_author}",
            f"- **Affected File:** `{rca.breaking_file}`",
            "",
            "## ??? Guardrails & Remediation Status",
        ]
        if guardrail.passed:
            lines.append("? **Safety Guardrails Passed:** Safe for automated remediation.")
            if rollback_result:
                lines.append(f"?? **GitHub Rollback:** {rollback_result.get('message', 'Completed')}")
        else:
            lines.append(f"?? **Auto-Rollback Blocked:** {guardrail.blocked_reason}")

        lines.extend([
            "",
            "## ?? Matched Runbooks & Mitigation Steps",
        ])
        for step in rca.mitigation_steps:
            lines.append(f"1. {step}")

        return "\n".join(lines)
