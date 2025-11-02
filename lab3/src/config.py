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
    run_mode: str = "polling"
    webhook_url: str | None = None
    webhook_path: str = "webhook"
    webapp_host: str = "0.0.0.0"
    webapp_port: int = 8000


def load_settings(env_file: str | None = None) -> Settings:
    """Load settings from .env file and environment variables."""

    load_dotenv(dotenv_path=env_file)

    bot_token = os.getenv("BOT_TOKEN", os.getenv("TELEGRAM_BOT_TOKEN", "")).strip()
    password_salt = os.getenv("PASSWORD_SALT", "").strip()
    database_path = os.getenv("DATABASE_PATH", "feedback_bot.db").strip()
    log_level = os.getenv("LOG_LEVEL", "INFO").strip().upper()
    run_mode = os.getenv("RUN_MODE", "polling").strip().lower() or "polling"
    webhook_url_raw = os.getenv("WEBHOOK_URL", "").strip()
    webhook_path_raw = os.getenv("WEBHOOK_PATH", "webhook").strip().lstrip("/")
    webapp_host = os.getenv("WEBAPP_HOST", "0.0.0.0").strip() or "0.0.0.0"
    webapp_port_raw = os.getenv("WEBAPP_PORT", "8000").strip()

    if not bot_token:
        raise RuntimeError("BOT_TOKEN is required but missing.")
    if not password_salt:
        raise RuntimeError("PASSWORD_SALT is required but missing.")

    resolved_db_path = Path(database_path).expanduser().resolve()
    webhook_path = webhook_path_raw or "webhook"
    webhook_url = webhook_url_raw or None

    try:
        webapp_port = int(webapp_port_raw)
    except ValueError as exc:
        raise RuntimeError("WEBAPP_PORT must be a valid integer.") from exc
    if webapp_port <= 0:
        raise RuntimeError("WEBAPP_PORT must be a positive integer.")

    return Settings(
        bot_token=bot_token,
        password_salt=password_salt,
        database_path=resolved_db_path,
        log_level=log_level,
        run_mode=run_mode,
        webhook_url=webhook_url,
        webhook_path=webhook_path,
        webapp_host=webapp_host,
        webapp_port=webapp_port,
    )
