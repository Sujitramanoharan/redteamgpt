"""Production must refuse to boot with an unsafe configuration."""
from config import Settings

SAFE = dict(
    environment="production",
    encryption_key="x" * 40,
    database_url="postgres://u:p@db.example.com:5432/app",
    app_base_url="https://redteamgpt.example.com",
    smtp_host="smtp.example.com",
    cors_origins=[],
)


def _problems(**overrides):
    return Settings(**(SAFE | overrides)).production_problems()


def test_safe_production_config_passes():
    assert _problems() == []


def test_each_unsafe_setting_is_caught():
    assert _problems(encryption_key="short")
    assert _problems(database_url="")  # falls back to SQLite
    assert _problems(cors_origins=["*"])
    assert _problems(app_base_url="http://redteamgpt.example.com")
    assert _problems(smtp_host="")


def test_development_is_not_policed():
    assert Settings(environment="development").production_problems() == []


def test_render_postgres_url_gets_a_driver():
    s = Settings(database_url="postgres://u:p@host/db")
    assert s.effective_database_url.startswith("postgresql+psycopg://")
