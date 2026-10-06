from core.config import settings


def test_api_docs_follow_flag(monkeypatch):
    import main

    monkeypatch.setattr(settings, "API_DOCS_ENABLED", True)
    assert main._docs_urls() == {"docs_url": "/docs", "redoc_url": "/redoc",
                                 "openapi_url": "/openapi.json"}
    monkeypatch.setattr(settings, "API_DOCS_ENABLED", False)
    assert set(main._docs_urls().values()) == {None}
