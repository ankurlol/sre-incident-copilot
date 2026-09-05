import os
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field
from typing import Optional

class Settings(BaseSettings):
    # App config
    APP_NAME: str = "Self-Healing SRE Incident Copilot"
    APP_ENV: str = "development"
    PORT: int = 8000
    HOST: str = "0.0.0.0"
    
    # LLM & Embeddings
    LLM_PROVIDER: str = Field(default="gemini", description="gemini, openai, or mock")
    GEMINI_API_KEY: Optional[str] = None
    OPENAI_API_KEY: Optional[str] = None
    OPENAI_MODEL: str = "gpt-4o-mini"
    GEMINI_MODEL: str = "gemini-1.5-flash"
    
    # GitHub Integration
    GITHUB_TOKEN: Optional[str] = None
    GITHUB_REPO_OWNER: str = "ankurlol"
    GITHUB_REPO_NAME: str = "sample-payment-api"
    GITHUB_WORKFLOW_ID: str = "deploy.yml"
    SIMULATE_GITHUB_ACTIONS: bool = True
    
    # Target Service Health Check
    TARGET_SERVICE_URL: str = "http://localhost:8000/mock-target/healthz"
    HEALTHCHECK_MAX_RETRIES: int = 5
    HEALTHCHECK_INTERVAL_SEC: float = 2.0
    
    # Safety Guardrails
    AUTO_ROLLBACK_ENABLED: bool = True
    MIN_CONFIDENCE_THRESHOLD: float = 0.75
    MAX_ROLLBACKS_PER_WINDOW: int = 1
    ROLLBACK_WINDOW_MINUTES: int = 0
    BLOCK_ON_DB_MIGRATION: bool = True
    
    # Paths
    RUNBOOKS_DIR: str = "data/runbooks"
    POST_MORTEMS_DIR: str = "data/post_mortems"
    
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()
