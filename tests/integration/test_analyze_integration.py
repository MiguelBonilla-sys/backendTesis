import pytest
from httpx import AsyncClient, ASGITransport
from main import app
from core.config import settings
from unittest.mock import AsyncMock, patch

@pytest.fixture
def anyio_backend():
    return "asyncio"

@pytest.mark.asyncio
async def test_analyze_pipeline_integration_mocked_llm():
    """
    Integration test that runs the full pipeline. 
    We mock the external TI and LLM calls to isolate the local orchestration.
    """
    payload = {
        "url": "https://xn--pple-43d.com/login",
        "email_body": "Please login to your account.",
        "email_id": "test-msg-123"
    }
    
    # We mock TI and LLM to avoid external dependencies or large model loading
    # But we let IDN and Fusion run real logic
    with patch("data_pipeline.threat_intel.ThreatIntelService.fetch_all", new_callable=AsyncMock) as mock_ti:
        mock_ti.return_value = {
            "virustotal": 1.0,
            "urlscan": 1.0,
            "google_safe_browsing": 1.0
        }
        
        with patch("agents.llm_agent.LLMAgent.analyze", new_callable=AsyncMock) as mock_llm:
            mock_llm.return_value = {
                "s_llm": 0.9,
                "reasoning": "Mocked phishing reason",
                "tokens_used": 100,
                "rag_context": []
            }
            
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                # Add dummy token if auth is required
                headers = {"Authorization": "Bearer test-token"}
                with patch("auth.auth.decode_token", return_value={"sub": "testuser", "role": "admin"}):
                    response = await ac.post("/api/v1/analyze", json=payload, headers=headers)
                    
                    assert response.status_code == 200
                    data = response.json()
                    assert data["verdict"] == "PHISHING"
                    assert "trace_id" in data
                    assert "idn_result" in data
                    assert "fusion_result" in data
                    assert data["fusion_result"]["s_risk"] > 0.8
