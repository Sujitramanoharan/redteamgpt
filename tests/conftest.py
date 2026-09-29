import os
import uuid
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "backend"))

# Settings are read once at import time, so the environment has to be chosen
# before anything imports config. conftest loads before test modules, so here.
_TMP = Path(tempfile.mkdtemp(prefix="redteamgpt-test-"))
os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL") or f"sqlite:///{(_TMP / 'app.db').as_posix()}"
os.environ["LOG_JSON"] = "false"
os.environ["RATE_LIMIT_PER_MINUTE"] = "10000"
os.environ["AUTH_RATE_LIMIT_PER_MINUTE"] = "10000"
os.environ["EMAIL_VERIFICATION_REQUIRED"] = "true"
os.environ["SMTP_HOST"] = ""
os.environ["REDIS_URL"] = ""
os.environ["ENVIRONMENT"] = "development"
os.environ["APP_BASE_URL"] = "http://testserver"
# Hermetic: never call a real LLM provider from the test suite.
os.environ["LLM_PROVIDER"] = "none"
os.environ["LLM_API_KEY"] = ""

import pytest
from fastapi.testclient import TestClient

PASSWORD = "correct-horse-battery-9"


def unique_email(tag: str = "user") -> str:
    # Random rather than a counter: pytest can import this module twice.
    return f"{tag}-{uuid.uuid4().hex[:10]}@example.com"


def last_link_token(to: str) -> str:
    """The token from the most recent email sent to `to`."""
    import emailer

    for msg in reversed(emailer.outbox):
        if msg["to"] == to:
            return msg["body"].split("token=")[1].split()[0]
    raise AssertionError(f"No email was sent to {to}")


def signed_in_client(app, email: str | None = None, org: str = "Acme") -> TestClient:
    """A client with its own cookie jar, signed up, verified and signed in."""
    c = TestClient(app)
    email = email or unique_email()
    r = c.post("/api/auth/signup", json={"email": email, "password": PASSWORD, "org_name": org})
    assert r.status_code == 200, r.text
    r = c.post("/api/auth/verify-email", json={"token": last_link_token(email)})
    assert r.status_code == 200, r.text
    c.headers["X-CSRF-Token"] = r.json()["csrf_token"]
    c.email = email
    c.me = r.json()
    return c


@pytest.fixture(scope="session")
def app():
    from main import app as fastapi_app

    # Entering the context runs startup once: migrations, model load, warmup.
    with TestClient(fastapi_app):
        yield fastapi_app


@pytest.fixture(scope="session")
def client(app):
    """An organisation owner signed in to the dashboard."""
    return signed_in_client(app, org="Primary Org")


@pytest.fixture(scope="session")
def api_key(client):
    return client.post("/api/keys", json={"name": "test key"}).json()["key"]


@pytest.fixture(scope="session")
def api_client(app, api_key):
    """An integration calling with an API key and no cookies."""
    c = TestClient(app)
    c.headers["X-API-Key"] = api_key
    return c


@pytest.fixture
def anon(app):
    return TestClient(app)
