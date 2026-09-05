# Runbook: RB-002 - Database Connection Pool Exhaustion

## Metadata
- **Service:** Payment API / Order Processing / Relational Database
- **Severity:** P1
- **Keywords:** OperationalError, connection pool exhausted, too many connections, timeout waiting for connection

## Symptoms
- API latency spikes > 5000ms followed by HTTP 504 Gateway Timeouts.
- Logs show sqlalchemy.exc.TimeoutError: QueuePool limit of size 20 overflow 10 reached.
- Database CPU is low, but active connection count is at max limit.

## Diagnostic Steps
1. Query active DB connections: SELECT count(*), state FROM pg_stat_activity GROUP BY state;.
2. Check if unclosed DB sessions or leaked transactions exist in recent PRs.
3. Inspect POOL_SIZE and MAX_OVERFLOW settings in database configuration.

## Remediation Strategy
1. Restart application instances to purge leaked connections.
2. If temporary traffic surge: Scale up connection pool size by 50% via environment variables.
3. If new query missing context manager (with db.session()): Hotfix or rollback to last stable release.
