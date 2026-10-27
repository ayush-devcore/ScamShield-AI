from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "ScamShield AI"
    environment: str = "development"
    debug: bool = False

    database_url: str
    redis_url: str

    jwt_secret_key: str
    jwt_algorithm: str = "HS256"

    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7

    frontend_origin: str = "http://localhost:5173"

    max_upload_size_mb: int = 8
    mfa_encryption_key: str | None = None
    mfa_challenge_expire_minutes: int = 5
    session_idle_timeout_minutes: int = 30

    sandbox_runtime_enabled: bool = False
    sandbox_network_verified: bool = False
    sandbox_worker_image: str = "scamshield-playwright-worker:1.64.1"
    sandbox_internal_network: str = "scamshield-sandbox-internal"
    sandbox_egress_network: str = "scamshield-sandbox-egress-net"
    sandbox_proxy_container: str = "scamshield-sandbox-egress"
    sandbox_encryption_key: str | None = None
    sandbox_job_timeout_seconds: int = 90

    safe_browsing_api_key: str | None = None
    phishtank_app_key: str | None = None

    log_level: str = "INFO"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
