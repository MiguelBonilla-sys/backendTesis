"""Tests for the Ollama-backed EmbeddingFunction in models/chromadb_client.py."""
from unittest.mock import MagicMock, patch

import httpx
import pytest


@pytest.fixture(autouse=True)
def _reset_embed_cache():
    import models.chromadb_client as m

    m._embed_fn = None
    m._embed_fn_resolved = False
    yield
    m._embed_fn = None
    m._embed_fn_resolved = False


def _mk_resp(json_body: dict, status: int = 200) -> MagicMock:
    r = MagicMock(spec=httpx.Response)
    r.status_code = status
    r.json.return_value = json_body
    r.raise_for_status.return_value = None
    return r


class TestOllamaEmbedder:
    def test_call_posts_to_ollama_and_returns_embeddings(self):
        from models.chromadb_client import _OllamaEmbedder

        ef = _OllamaEmbedder("http://x:11434", "embeddinggemma")
        resp = _mk_resp({"embeddings": [[0.1, 0.2], [0.3, 0.4]]})
        with patch("httpx.post", return_value=resp) as p:
            out = ef(["a", "b"])
        assert out == [[0.1, 0.2], [0.3, 0.4]]
        call = p.call_args
        assert call.args[0] == "http://x:11434/api/embed"
        assert call.kwargs["json"] == {"model": "embeddinggemma", "input": ["a", "b"]}

    def test_embed_query_and_documents_alias_call(self):
        from models.chromadb_client import _OllamaEmbedder

        ef = _OllamaEmbedder("http://x:11434", "m")
        with patch("httpx.post", return_value=_mk_resp({"embeddings": [[1.0]]})):
            assert ef.embed_query(["q"]) == [[1.0]]
            assert ef.embed_documents(["d"]) == [[1.0]]

    def test_config_roundtrip(self):
        from models.chromadb_client import _OllamaEmbedder

        cfg = _OllamaEmbedder("http://h:1", "mod").get_config()
        rebuilt = _OllamaEmbedder.build_from_config(cfg)
        assert rebuilt.get_config() == cfg
        assert _OllamaEmbedder.name() == "ollama"

    def test_trailing_slash_stripped(self):
        from models.chromadb_client import _OllamaEmbedder

        ef = _OllamaEmbedder("http://x:11434/", "m")
        with patch("httpx.post", return_value=_mk_resp({"embeddings": [[0.0]]})) as p:
            ef(["x"])
        assert p.call_args.args[0] == "http://x:11434/api/embed"


class TestEmbeddingFunctionResolver:
    def test_chroma_provider_returns_none(self, monkeypatch):
        import models.chromadb_client as m

        monkeypatch.setattr("models.chromadb_client.settings.EMBED_PROVIDER", "chroma")
        assert m._embedding_function() is None

    def test_ollama_provider_reachable(self, monkeypatch):
        import models.chromadb_client as m
        from models.chromadb_client import _OllamaEmbedder

        monkeypatch.setattr("models.chromadb_client.settings.EMBED_PROVIDER", "ollama")
        monkeypatch.setattr("models.chromadb_client.settings.EMBED_MODEL", "embeddinggemma")
        with patch("httpx.get", return_value=_mk_resp({"models": []})):
            ef = m._embedding_function()
        assert isinstance(ef, _OllamaEmbedder)

    def test_ollama_unreachable_does_not_switch_embedding_space(self, monkeypatch):
        import models.chromadb_client as m

        monkeypatch.setattr("models.chromadb_client.settings.EMBED_PROVIDER", "ollama")
        with patch("httpx.get", side_effect=httpx.ConnectError("no route")):
            assert isinstance(m._embedding_function(), m._OllamaEmbedder)

    def test_result_is_cached(self, monkeypatch):
        import models.chromadb_client as m

        monkeypatch.setattr("models.chromadb_client.settings.EMBED_PROVIDER", "ollama")
        with patch("httpx.get", return_value=_mk_resp({"models": []})) as g:
            m._embedding_function()
            m._embedding_function()
        g.assert_not_called()  # resolve configuration without network I/O
