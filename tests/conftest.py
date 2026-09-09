import os
import pytest

# Configure isolated SQLite database for all test runs
# This prevents automated test suites from ever touching the live production Neon PostgreSQL database.
os.environ["DATABASE_URL"] = "sqlite:///./test_runner.db"
os.environ["ADMIN_EMAIL"] = "ci.admin@test.local"
os.environ["ADMIN_KEY"] = "ci_secret_key"
os.environ["SIMULATE_GITHUB_ACTIONS"] = "true"
os.environ["EXPOSE_DEV_OTP"] = "true"

