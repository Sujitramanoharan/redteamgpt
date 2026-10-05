"""Central configuration. Every deployment knob is an environment variable so the
same image runs unchanged on a free Space and on a paid cluster."""
import os
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

    # Public URL of the app. Links in emails point here, and in production it
    # must be https so session cookies can be marked Secure. Render sets
    # RENDER_EXTERNAL_URL, so a Render deploy works without setting this.
    app_base_url: str = Field(
        default_factory=lambda: os.environ.get("RENDER_EXTERNAL_URL", "http://localhost:5174"))

    # --- Accounts and sessions ---------------------------------------------
    # Every caller is an organisation: dashboard users sign in with a session
    # cookie, integrations send an API key created in the dashboard.
    signup_enabled: bool = True
    email_verification_required: bool = True
    session_ttl_hours: int = 24 * 14
    login_max_failures: int = 10
    login_lockout_minutes: int = 15
    # Per-IP ceiling on sign-in, sign-up and password-reset requests.
    auth_rate_limit_per_minute: int = 10
    # Encrypts secrets customers store with us (their upstream LLM keys).
    # Any long random string; a Fernet key is derived from it.
    encryption_key: str = ""

    # --- Email (any SMTP provider: Resend, Brevo, SendGrid, Postmark...) ---
    # Unset in development: emails are written to the log instead of sent.
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from: str = "RedTeamGPT <no-reply@localhost>"
    smtp_starttls: bool = True

    # --- CORS -------------------------------------------------------------
    # The SPA is served from the same origin as the API, so production needs no
    # cross-origin access at all. NoDecode stops pydantic-settings from
    # JSON-parsing this, so the validator below accepts comma-separated values.
    cors_origins: Annotated[List[str], NoDecode] = Field(default_factory=list)

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
    # Pin an exact Hub commit so a deploy always serves the model that passed
    # evaluation, not whatever was pushed to the repo last.
    model_hub_revision: str = ""
    hf_token: str = ""
    max_sequence_length: int = 256
    chunk_stride: int = 64
    decision_threshold: float = 0.5
    # "torch" or "onnx" (from src/export_onnx.py, which checks verdict parity).
    inference_backend: str = "torch"
    # Intra-op threads per inference. 0 means half the cores. Under concurrent
    # load a lower value usually wins, because requests already run in
    # parallel and per-inference threads then compete for the same cores.
    torch_threads: int = 0

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

    # --- Human review -----------------------------------------------------
    # Decisions inside this probability band are where the model is least
    # reliable, so they are queued for a person to confirm.
    review_enabled: bool = True
    review_band_low: float = 0.25
    review_band_high: float = 0.75
    review_queue_max: int = 500

    # --- Storage ----------------------------------------------------------
    # postgresql://... in production (Render provides DATABASE_URL). Empty
    # falls back to a local SQLite file for development and tests.
    database_url: str = ""
    database_path: Path = ROOT / "data" / "app.db"
    # Run migrations at startup. Production runs them from the container
    # entrypoint instead, before any worker starts.
    auto_migrate: bool = True
    # Default for new organisations; each org can change its own.
    audit_retention_days: int = 30
    max_retention_days: int = 365

    # --- Assistant limits -------------------------------------------------
    # The Assistant tab answers with the platform's own LLM key, so each
    # organisation gets a daily message allowance.
    default_chat_daily_cap: int = 50

    # --- Scaling ----------------------------------------------------------
    # Set to share rate-limit state across instances; in-process otherwise.
    redis_url: str = ""

    # --- Observability ----------------------------------------------------
    log_level: str = "INFO"
    log_json: bool = True
    enable_metrics: bool = True
    # Prometheus /metrics requires "Authorization: Bearer <token>" when set.
    metrics_token: str = ""
    sentry_dsn: str = ""

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _split_csv(cls, v):
        if isinstance(v, str):
            return [item.strip() for item in v.split(",") if item.strip()]
        return v

    @property
    def is_production(self) -> bool:
        return self.environment.lower() in ("production", "prod")

    @property
    def effective_database_url(self) -> str:
        url = self.database_url.strip()
        if not url:
            return f"sqlite:///{self.database_path.as_posix()}"
        # Render and Heroku hand out postgres:// URLs; SQLAlchemy needs the
        # driver named explicitly.
        for prefix in ("postgres://", "postgresql://"):
            if url.startswith(prefix):
                return "postgresql+psycopg://" + url[len(prefix):]
        return url

    @property
    def email_configured(self) -> bool:
        return bool(self.smtp_host)

    def production_problems(self) -> list[str]:
        """Misconfigurations that must stop a production boot.

        Each of these has shipped to production somewhere: an open CORS policy,
        a SQLite file on an ephemeral disk, cookies sent over plain http.
        Failing at startup is cheaper than finding out from an incident.
        """
        if not self.is_production:
            return []
        problems = []
        if len(self.encryption_key) < 32:
            problems.append("ENCRYPTION_KEY must be set to a random string of 32+ characters")
        if self.effective_database_url.startswith("sqlite"):
            problems.append("DATABASE_URL must point at Postgres; SQLite on a container disk is lost on redeploy")
        if "*" in self.cors_origins:
            problems.append("CORS_ORIGINS must not be '*'")
        if not self.app_base_url.startswith("https://"):
            problems.append("APP_BASE_URL must be an https:// URL")
        if self.email_verification_required and not self.email_configured:
            problems.append("SMTP_HOST is required to send verification emails "
                            "(or set EMAIL_VERIFICATION_REQUIRED=false)")
        return problems


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
