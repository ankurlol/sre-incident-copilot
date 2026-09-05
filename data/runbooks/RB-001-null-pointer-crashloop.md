# Runbook: RB-001 - Null Pointer / Unhandled Exception CrashLoopBackOff

## Metadata
- **Service:** Core API / Backend Services
- **Severity:** P1 / P2
- **Keywords:** AttributeError, NullPointerException, KeyError, CrashLoopBackOff, 500 Internal Server Error

## Symptoms
- Kubernetes pods failing with CrashLoopBackOff or rapid process restarts.
- Sudden spike in 5xx HTTP response codes (>5% error rate).
- Stack trace showing unhandled NoneType or missing dictionary keys during request handling.

## Diagnostic Steps
1. Inspect the last 100 log lines from failing pods: kubectl logs deployment/<service-name> --tail=100.
2. Check if a new deployment or commit occurred within the last 30 minutes.
3. Compare the current commit SHA with the previous stable release.
4. Check if the error originates in newly modified business logic.

## Remediation Strategy
1. **If caused by a recent code release:**
   - Immediately initiate a rollback to the previous stable Git SHA.
   - Verify health endpoint /healthz returns HTTP 200 after rollback.
2. **If caused by external upstream payload changes:**
   - Apply hotfix to wrap accessing fields in safe .get() or null-coalescing operators.
