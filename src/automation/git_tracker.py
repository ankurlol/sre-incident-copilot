import os
import re
from typing import List, Dict, Any, Optional
from pydantic import BaseModel

class GitCommit(BaseModel):
    sha: str
    previous_sha: str
    author: str
    message: str
    timestamp: str
    changed_files: List[str]
    diff_snippet: str
    has_db_migrations: bool = False

class GitTracker:
    def __init__(self):
        pass

    def detect_db_migrations(self, changed_files: List[str]) -> bool:
        migration_patterns = [
            r'migrations/',
            r'alembic/versions/',
            r'prisma/schema\.prisma',
            r'prisma/migrations/',
            r'flyway/sql/',
            r'db/migrate/',
            r'schema\.sql',
            r'\.sql$'
        ]
        for file in changed_files:
            for pattern in migration_patterns:
                if re.search(pattern, file, re.IGNORECASE):
                    return True
        return False

    def parse_commit_payload(
        self,
        sha: str,
        previous_sha: str,
        author: str,
        message: str,
        changed_files: List[str],
        diff_snippet: str,
        timestamp: Optional[str] = None
    ) -> GitCommit:
        has_migrations = self.detect_db_migrations(changed_files)
        return GitCommit(
            sha=sha,
            previous_sha=previous_sha,
            author=author,
            message=message,
            timestamp=timestamp or "Just now",
            changed_files=changed_files,
            diff_snippet=diff_snippet,
            has_db_migrations=has_migrations
        )
