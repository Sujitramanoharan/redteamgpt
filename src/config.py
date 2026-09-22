"""Central configuration. Every deployment knob is an environment variable so the
same image runs unchanged on a free Space and on a paid cluster."""
from functools import lru_cache
from pathlib import Path
from typing import Annotated, List

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

ROOT = Path(__file__).parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=ROOT / ".env", env_file_encoding="utf-8", extra="ignore"
    )

    app_name: str = "RedTeamGPT Security Intelligence API"
    version: str = "3.0.0"
    environment: str = Field(default="development")
    port: int = 7860

    # --- Auth -------------------------------------------------------------
    # Comma-separated keys. Empty list leaves the API open, which is what a
    # public demo Space needs; set REQUIRE_AUTH=true the moment it matters.
    # NoDecode stops pydantic-settings from JSON-parsing these, so the
    # validator below can accept plain comma-separated env values.
    api_keys: Annotated[List[str], NoDecode] = Field(default_factory=list)
    require_auth: bool = False

    # --- CORS -------------------------------------------------------------
    cors_origins: Annotated[List[str], NoDecode] = Field(default_factory=lambda: ["*"])

    # --- Abuse controls ---------------------------------------------------
    rate_limit_per_minute: int = 60
    max_prompt_chars: int = 20_000
    max_batch_size: int = 50
    max_upload_bytes: int = 5 * 1024 * 1024

    # --- Model ------------------------------------------------------------
    # Local dir wins when present; otherwise the Hub id is pulled at boot so a
    # clean clone (models/ is gitignored) can still start.
    model_dir: Path = ROOT / "models" / "detector"
    model_hub_id: str = ""
    max_sequence_length: int = 256
    chunk_stride: int = 64
    decision_threshold: float = 0.5

    # --- Assistant LLM ----------------------------------------------------
    # gemini | groq | openai | anthropic | none. Without a key the firewall
    # still works; only answer generation is unavailable.
    llm_provider: str = "none"
    llm_api_key: str = ""
    # Floating alias rather than a pinned version: Google retires specific
    # model ids, and a stale default breaks generation with a 404.
    llm_model: str = "gemini-flash-latest"
    llm_history_turns: int = 6
    # Scan the model's reply too, not just the user's prompt.
    scan_output: bool = True

    # --- Storage ----------------------------------------------------------
    # sqlite:// for free tier, postgresql:// later. Empty disables persistence.
    database_path: Path = ROOT / "data" / "audit.db"
    audit_retention_days: int = 30

    # --- Observability ----------------------------------------------------
    log_level: str = "INFO"
    log_json: bool = True
    enable_metrics: bool = True

    @field_validator("api_keys", "cors_origins", mode="before")
    @classmethod
    def _split_csv(cls, v):
        if isinstance(v, str):
            return [item.strip() for item in v.split(",") if item.strip()]
        return v

    @property
    def is_production(self) -> bool:
        return self.environment.lower() in ("production", "prod")

    @property
    def auth_enforced(self) -> bool:
        return self.require_auth and bool(self.api_keys)


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
