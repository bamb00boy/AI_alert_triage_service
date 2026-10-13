"""Runtime configuration. Every value can be overridden with a TRIAGE_* environment variable."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="TRIAGE_", env_file=".env", extra="ignore")

    # --- infrastructure -------------------------------------------------------
    database_url: str = "postgresql://triage_app:triage_app@localhost:5432/triage"
    migrate_database_url: str = "postgresql://triage_owner:triage_owner@localhost:5432/triage"
    amqp_url: str = "amqp://triage:triage@localhost:5672/"
    otlp_endpoint: str | None = "http://localhost:4318"
    log_level: str = "INFO"

    # --- ingest ---------------------------------------------------------------
    # Comma-separated list so keys can be rotated: sign with the first, accept any.
    hmac_secrets: SecretStr = SecretStr("dev-only-change-me")
    hmac_max_skew_seconds: int = 300
    max_body_bytes: int = 256_000

    # --- worker ---------------------------------------------------------------
    prefetch: int = 1
    delivery_limit: int = 5
    retry_delays_seconds: tuple[int, ...] = (2, 8, 32, 128)
    lease_seconds: int = 30
    demo_delay_seconds: float = 0.0  # artificial per-message delay for the kill-a-worker demo

    # --- threat intel / connectors --------------------------------------------
    ti_url: str = "http://localhost:8001"
    connector_mode: Literal["fixtures", "live"] = "fixtures"
    connectors: tuple[str, ...] = ("local_ti", "virustotal", "abuseipdb")
    fixtures_dir: str = "fixtures/connectors"
    virustotal_api_key: SecretStr | None = None
    abuseipdb_api_key: SecretStr | None = None
    ti_data_dir: str = "data/ti"

    # --- LLM ------------------------------------------------------------------
    llm_primary: str = "ollama"
    llm_secondary: str | None = "llamacpp"
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "qwen3:4b-instruct"
    llamacpp_url: str = "http://localhost:8081"
    llamacpp_model: str = "llama-3.2-3b-instruct"
    llm_timeout_seconds: float = 90.0
    llm_num_ctx: int = 8192
    replay_cassette: str = "local/eval/cassette.jsonl"

    # --- retrieval ------------------------------------------------------------
    embed_model: str = "BAAI/bge-small-en-v1.5"
    embed_cache_dir: str = "local/models/fastembed"
    retrieval_k: int = 8
    attack_techniques_file: str = "data/attack/techniques.jsonl"

    # --- safety ---------------------------------------------------------------
    auto_close_min_confidence: float = 0.85

    # --- approval UI ----------------------------------------------------------
    session_secret: SecretStr = SecretStr("dev-only-session-secret")
    oidc_discovery_url: str = "http://localhost:8080/realms/triage/.well-known/openid-configuration"
    oidc_client_id: str = "approval-ui"
    oidc_client_secret: SecretStr = SecretStr("approval-ui-dev-secret")
    ui_base_url: str = "http://localhost:8002"
    analyst_role: str = "analyst"
    viewer_role: str = "viewer"

    def hmac_secret_list(self) -> list[bytes]:
        return [s.strip().encode() for s in self.hmac_secrets.get_secret_value().split(",") if s.strip()]



@lru_cache
def get_settings() -> Settings:
    return Settings()
