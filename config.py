"""
Application configuration: environment variables, secrets, and the
Settings object. Extracted from app.py (Stage 1 refactor) so that
config lives in one place instead of being mixed in with routes.

Nothing in this file should depend on FastAPI routes or the database
connection itself — it should be importable on its own.
"""
import asyncio
import logging
import os
from pathlib import Path

import resend
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logger = logging.getLogger("swiftslot")
logging.basicConfig(level=logging.INFO)
log = logger

# ---------------------------------------------------------------------------
# Third-party service setup
# ---------------------------------------------------------------------------
SMTP_SEMAPHORE = asyncio.Semaphore(5)
resend.api_key = os.getenv("RESEND_API_KEY")

# ---------------------------------------------------------------------------
# Secrets
# ---------------------------------------------------------------------------
TOKEN_SECRET = os.getenv("TOKEN_SECRET", "")
if not TOKEN_SECRET:
    TOKEN_SECRET = "dev-token-secret-change-this"
SECRET_KEY = TOKEN_SECRET.encode("utf-8")

SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "true").lower() == "true"
SESSION_SECRET = os.getenv("SESSION_SECRET", "dev-secret-change-this")


# ---------------------------------------------------------------------------
# Settings (env-driven, validated at startup)
# ---------------------------------------------------------------------------
class Settings(BaseSettings):
    database_url: str = Field(default="", alias="DATABASE_URL")
    render_external_url: str = Field(default="", alias="RENDER_EXTERNAL_URL")
    db_min_size: int = Field(default=1, alias="DB_POOL_MIN_SIZE")
    db_max_size: int = Field(default=10, alias="DB_POOL_MAX_SIZE")
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")

    model_config = SettingsConfigDict(
        env_file=str(Path(__file__).resolve().parent / ".env"),
        extra="ignore"
    )

    def assert_startup_ready(self) -> None:
        if not self.database_url:
            raise RuntimeError("DATABASE_URL must be set to a Neon PostgreSQL connection string.")

        external_url = self.render_external_url.strip().rstrip("/")
        if not external_url:
            raise RuntimeError(
                "RENDER_EXTERNAL_URL must be set. "
                "For local development use: RENDER_EXTERNAL_URL=http://localhost:8000"
            )
        self.render_external_url = external_url


settings = Settings()
logging.getLogger("swiftslot").setLevel(settings.log_level.upper())
