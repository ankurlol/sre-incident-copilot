# Runbook: RB-004 - Database Schema Migration Failure Guard

## Metadata
- **Service:** All services using Alembic / Prisma / Flyway
- **Severity:** P0 / P1
- **Keywords:** migration failed, column does not exist, alembic, table locked, foreign key constraint

## CRITICAL SAFETY RULE: DO NOT AUTO-ROLLBACK
- **Warning:** If a failed release contains irreversible database migrations (e.g. dropped columns, renamed tables), **AUTOMATED CODE ROLLBACK CAN CAUSE MASSIVE DATA CORRUPTION**.
- **Action:**
  1. Hold automated code rollbacks immediately.
  2. Require manual DBA / Tech Lead intervention.
  3. Verify whether down-migration script exists and is safe to execute.
