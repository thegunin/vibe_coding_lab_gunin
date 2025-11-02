"""Application configuration helpers."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


@dataclass(frozen=True)
class Settings:
    """Strongly typed container for environment-driven settings."""

    bot_token: str
    password_salt: str
    database_path: Path
    log_level: str = "INFO"


def load_settings(env_file: str | None = None) -> Settings:
    """Load settings from .env file and environment variables."""

    load_dotenv(dotenv_path=env_file)

    bot_token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    password_salt = os.getenv("PASSWORD_SALT", "").strip()
    database_path = os.getenv("DATABASE_PATH", "feedback_bot.db").strip()
    log_level = os.getenv("LOG_LEVEL", "INFO").strip().upper()

    if not bot_token:
        raise RuntimeError("TELEGRAM_BOT_TOKEN is required but missing.")
    if not password_salt:
        raise RuntimeError("PASSWORD_SALT is required but missing.")

    resolved_db_path = Path(database_path).expanduser().resolve()

    return Settings(
        bot_token=bot_token,
        password_salt=password_salt,
        database_path=resolved_db_path,
        log_level=log_level,
    )
