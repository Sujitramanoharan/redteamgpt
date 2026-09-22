import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "backend"))

# Settings are read once at import time, so the test database has to be chosen
# before anything imports config. conftest loads before test modules, so here.
_TMP_DB = Path(tempfile.mkdtemp(prefix="redteamgpt-test-")) / "audit.db"
os.environ["DATABASE_PATH"] = str(_TMP_DB)
os.environ["REQUIRE_AUTH"] = "false"
os.environ["LOG_JSON"] = "false"
os.environ["RATE_LIMIT_PER_MINUTE"] = "10000"

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="session")
def client():
    from main import app

    with TestClient(app) as c:
        yield c
