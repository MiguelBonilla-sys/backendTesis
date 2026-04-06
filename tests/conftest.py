import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from main import app


@pytest_asyncio.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as ac:
        yield ac


@pytest.fixture
def phishing_url() -> str:
    """Domain using Cyrillic 'а' (U+0430) instead of Latin 'a'."""
    return "https://xn--pple-43d.com/login"


@pytest.fixture
def safe_url() -> str:
    return "https://apple.com/login"


@pytest.fixture
def mock_ti_all_phishing() -> dict:
    return {"virustotal": 1.0, "urlscan": 1.0, "google_safe_browsing": 1.0}


@pytest.fixture
def mock_ti_all_safe() -> dict:
    return {"virustotal": 0.0, "urlscan": 0.0, "google_safe_browsing": 0.0}
