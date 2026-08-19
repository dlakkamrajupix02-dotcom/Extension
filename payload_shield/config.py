"""
Configuration Settings for Payload Shield.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    redis_url: str = "redis://localhost:6379/0"
    session_key_ttl_seconds: int = 3600  # 1 hour default
    header_name: str = "X-Payload-Shield-Session"

    model_config = SettingsConfigDict(env_prefix="PAYLOAD_SHIELD_")


settings = Settings()

