import re
from typing import Dict, Any, Tuple

class LogSanitizer:
    """Production PII and Secret Redactor to prevent data leaks to LLMs."""

    PATTERNS = [
        # GitHub tokens
        (r'ghp_[a-zA-Z0-9]{36}', '[REDACTED_GITHUB_TOKEN]'),
        (r'github_pat_[a-zA-Z0-9_]{82}', '[REDACTED_GITHUB_FINE_GRAINED_TOKEN]'),
        # AWS Access Keys
        (r'AKIA[0-9A-Z]{16}', '[REDACTED_AWS_ACCESS_KEY]'),
        # Bearer / JWT tokens
        (r'Bearer\s+ey[a-zA-Z0-9_\-\.]+', 'Bearer [REDACTED_JWT]'),
        # Database passwords in URIs (e.g. postgres://user:password@host)
        (r'(://[^:]+:)([^@]+)(@)', r'\1[REDACTED_DB_PASSWORD]\3'),
        # Passwords / Secrets in JSON or logs
        (r'(?i)(password|secret|api_key|token)["'']?\s*[:=]\s*["'']?([^"''\s,;]+)', r'\1: [REDACTED_SECRET]'),
        # Credit Card Numbers (13-16 digits with optional dashes)
        (r'\b(?:\d{4}[ -]?){3}(?:\d{4}|\d{1,4})\b', '[REDACTED_CREDIT_CARD]'),
        # Private SSH / RSA Keys
        (r'-----BEGIN [A-Z ]+ PRIVATE KEY-----[^-]+-----END [A-Z ]+ PRIVATE KEY-----', '[REDACTED_PRIVATE_KEY]')
    ]

    @classmethod
    def sanitize(cls, text: str) -> Tuple[str, int]:
        """Sanitizes sensitive information from stack traces and logs. Returns (clean_text, redaction_count)."""
        if not text:
            return "", 0

        clean_text = text
        redactions = 0

        for pattern, replacement in cls.PATTERNS:
            matches = len(re.findall(pattern, clean_text))
            if matches > 0:
                clean_text = re.sub(pattern, replacement, clean_text)
                redactions += matches

        return clean_text, redactions
