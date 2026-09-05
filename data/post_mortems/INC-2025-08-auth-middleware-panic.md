# Post-Mortem: INC-2025-08 - Auth Middleware Panic on Missing Header

- **Date:** 2025-08-14
- **Duration:** 18 minutes
- **Impact:** 12,000 checkout requests failed with HTTP 500
- **Root Cause:** Commit 491c2a deployed a new authorization header parser that assumed X-User-Role was always present. When guest visitors accessed the site, it threw an unhandled KeyError: 'X-User-Role'.
- **Resolution:** Rolled back deployment to previous SHA e381b90. Later released a hotfix using .get('X-User-Role', 'guest').
- **Lessons Learned:** Always verify optional request headers. Ensure automated rollback can trigger within 2 minutes of CrashLoopBackOff detection.
