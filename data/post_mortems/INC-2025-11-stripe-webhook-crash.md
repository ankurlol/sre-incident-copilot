# Post-Mortem: INC-2025-11 - Stripe Webhook Signature Verification Crash

- **Date:** 2025-11-03
- **Duration:** 24 minutes
- **Impact:** Payment webhooks returned 500, causing delayed order fulfillments.
- **Root Cause:** Updated Stripe SDK library in commit 8b2a19c changed the signature verification signature from erify_header(payload, sig, secret) to erify_header(payload=..., sig_header=..., secret=...).
- **Resolution:** Automated rollback triggered after 3 crash alerts. Production restored in 90 seconds.
