"""Tests for data_pipeline/knowledge_updater.py — ChromaDB ingestion and feedback loop."""
from __future__ import annotations

from unittest.mock import AsyncMock, call, patch

import pytest

from core.constants import COLLECTION_EMAIL, COLLECTION_IDN, COLLECTION_TI
from data_pipeline.knowledge_updater import (
    AUTO_INGEST_THRESHOLD,
    KnowledgeUpdaterService,
    context_header,
)


class TestContextHeader:
    def test_basic(self):
        h = context_header(verdict="PHISHING", domain="paypa1.com")
        assert h == "[ctx verdict=PHISHING domain=paypa1.com]"

    def test_decoded_and_impersonates_and_source(self):
        h = context_header(
            verdict="PHISHING", domain="xn--pypal-4ve.com",
            domain_unicode="pаypal.com", impersonates="paypal.com",
            source="seed_corpus",
        )
        assert h == (
            "[ctx verdict=PHISHING domain=pаypal.com "
            "impersonates=paypal.com source=seed_corpus]"
        )

    def test_impersonates_equal_to_domain_is_omitted(self):
        h = context_header(
            verdict="LEGITIMATE", domain="usbbog.edu.co",
            impersonates="usbbog.edu.co", source="institutional_baseline",
        )
        assert "impersonates=" not in h
        assert h == "[ctx verdict=LEGITIMATE domain=usbbog.edu.co source=institutional_baseline]"

_BASE_ANALYSIS = dict(
    url="https://paypa1.com/login",
    domain="paypa1.com",
    verdict="PHISHING",
    s_risk=0.95,
    s_idn_local=0.88,
    s_ti=0.72,
    s_llm=0.91,
    confusable_chars=["р", "а"],
    domain_unicode="paypa1.com",
    homograph_ratio=0.40,
    visual_similarity=0.97,
    is_mixed_script=True,
    reasons=["Cyrillic homograph detected", "High VirusTotal score"],
    llm_reason="Domain uses Cyrillic chars to impersonate paypal.com",
    s_vt=0.80,
    s_urlscan=0.65,
    s_gsb=0.50,
)

# Same as _BASE_ANALYSIS but without 'verdict' — ingest_confirmed_feedback
# takes 'confirmed_verdict' as a separate parameter instead.
_FEEDBACK_ANALYSIS = {k: v for k, v in _BASE_ANALYSIS.items() if k != "verdict"}


# ---------------------------------------------------------------------------
# ingest_from_analysis()
# ---------------------------------------------------------------------------

class TestIngestFromAnalysis:
    @pytest.mark.asyncio
    async def test_upserts_all_three_collections(self):
        svc = KnowledgeUpdaterService()
        with patch(
            "data_pipeline.knowledge_updater.upsert_documents",
            new_callable=AsyncMock,
        ) as mock_upsert:
            await svc.ingest_from_analysis(**_BASE_ANALYSIS)

        assert mock_upsert.call_count == 3
        collections_used = {c.args[0] for c in mock_upsert.call_args_list}
        assert collections_used == {COLLECTION_EMAIL, COLLECTION_IDN, COLLECTION_TI}
        # cada doc arranca con el header de contexto (contextual retrieval)
        for c in mock_upsert.call_args_list:
            assert c.kwargs["documents"][0].startswith("[ctx verdict=PHISHING")

    @pytest.mark.asyncio
    async def test_doc_ids_use_incident_id_when_provided(self):
        svc = KnowledgeUpdaterService()
        with patch(
            "data_pipeline.knowledge_updater.upsert_documents",
            new_callable=AsyncMock,
        ) as mock_upsert:
            await svc.ingest_from_analysis(**_BASE_ANALYSIS, incident_id="abc123")

        all_ids = [c.kwargs["ids"][0] for c in mock_upsert.call_args_list]
        assert all("abc123" in id_ for id_ in all_ids)

    @pytest.mark.asyncio
    async def test_source_auto_ingest_when_flag_true(self):
        svc = KnowledgeUpdaterService()
        with patch(
            "data_pipeline.knowledge_updater.upsert_documents",
            new_callable=AsyncMock,
        ) as mock_upsert:
            await svc.ingest_from_analysis(**_BASE_ANALYSIS, auto_ingested=True)

        for c in mock_upsert.call_args_list:
            metadata = c.kwargs["metadatas"][0]
            assert metadata["source"] == "auto_ingest"

    @pytest.mark.asyncio
    async def test_source_admin_confirmed_when_flag_false(self):
        svc = KnowledgeUpdaterService()
        with patch(
            "data_pipeline.knowledge_updater.upsert_documents",
            new_callable=AsyncMock,
        ) as mock_upsert:
            await svc.ingest_from_analysis(**_BASE_ANALYSIS, auto_ingested=False)

        for c in mock_upsert.call_args_list:
            metadata = c.kwargs["metadatas"][0]
            assert metadata["source"] == "admin_confirmed"

    @pytest.mark.asyncio
    async def test_upsert_failure_silent_no_raise(self):
        svc = KnowledgeUpdaterService()
        with patch(
            "data_pipeline.knowledge_updater.upsert_documents",
            new_callable=AsyncMock,
            side_effect=RuntimeError("chromadb unavailable"),
        ):
            # Must not raise — graceful degradation
            await svc.ingest_from_analysis(**_BASE_ANALYSIS)

    @pytest.mark.asyncio
    async def test_verdict_in_document_text(self):
        svc = KnowledgeUpdaterService()
        captured_docs: list[str] = []

        async def _capture_upsert(collection, *, ids, documents, metadatas=None):
            captured_docs.extend(documents)

        with patch("data_pipeline.knowledge_updater.upsert_documents", side_effect=_capture_upsert):
            await svc.ingest_from_analysis(**_BASE_ANALYSIS)

        assert any("PHISHING" in doc for doc in captured_docs)


# ---------------------------------------------------------------------------
# AUTO_INGEST_THRESHOLD constant
# ---------------------------------------------------------------------------

class TestAutoIngestThreshold:
    def test_threshold_value(self):
        assert AUTO_INGEST_THRESHOLD == 0.90


# ---------------------------------------------------------------------------
# ingest_confirmed_feedback()
# ---------------------------------------------------------------------------

class TestIngestConfirmedFeedback:
    async def test_failed_upsert_leaves_feedback_pending(self):
        with patch("data_pipeline.knowledge_updater.upsert_documents",
                   side_effect=RuntimeError("storage down")), \
             patch("data_pipeline.knowledge_updater.execute", new_callable=AsyncMock) as execute:
            with pytest.raises(RuntimeError, match="storage down"):
                await KnowledgeUpdaterService().ingest_confirmed_feedback(
                    feedback_id="fb", incident_id="inc", confirmed_verdict="PHISHING",
                    note=None, **_FEEDBACK_ANALYSIS,
                )
        execute.assert_not_awaited()

    async def test_legitimate_retry_purges_without_reintroducing_phishing_docs(self):
        with patch("data_pipeline.knowledge_updater.delete_document", new_callable=AsyncMock) as delete, \
             patch("data_pipeline.knowledge_updater.upsert_documents", new_callable=AsyncMock) as upsert, \
             patch("data_pipeline.knowledge_updater.execute", new_callable=AsyncMock) as execute:
            await KnowledgeUpdaterService().ingest_confirmed_feedback(
                feedback_id="fb", incident_id="inc", confirmed_verdict="LEGITIMATE",
                note=None, **_FEEDBACK_ANALYSIS,
            )
        assert delete.await_count == 3
        upsert.assert_not_awaited()
        execute.assert_awaited_once()

    async def test_failed_purge_leaves_feedback_pending(self):
        with patch("data_pipeline.knowledge_updater.delete_document",
                   side_effect=RuntimeError("storage down")), \
             patch("data_pipeline.knowledge_updater.execute", new_callable=AsyncMock) as execute:
            with pytest.raises(RuntimeError):
                await KnowledgeUpdaterService().ingest_confirmed_feedback(
                    feedback_id="fb", incident_id="inc", confirmed_verdict="LEGITIMATE",
                    note=None, **_FEEDBACK_ANALYSIS,
                )
        execute.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_calls_ingest_from_analysis_and_marks_ingested(self):
        svc = KnowledgeUpdaterService()
        with (
            patch(
                "data_pipeline.knowledge_updater.upsert_documents",
                new_callable=AsyncMock,
            ),
            patch(
                "data_pipeline.knowledge_updater.execute",
                new_callable=AsyncMock,
            ) as mock_execute,
        ):
            await svc.ingest_confirmed_feedback(
                feedback_id="fb-001",
                incident_id="inc-001",
                confirmed_verdict="PHISHING",
                note="Admin confirmed",
                **_FEEDBACK_ANALYSIS,
            )

        mock_execute.assert_called_once()
        sql_arg = mock_execute.call_args.args[0]
        assert "feedback" in sql_arg.lower()
        assert "ingested" in sql_arg.lower()

    @pytest.mark.asyncio
    async def test_feedback_id_passed_to_execute(self):
        svc = KnowledgeUpdaterService()
        with (
            patch("data_pipeline.knowledge_updater.upsert_documents", new_callable=AsyncMock),
            patch(
                "data_pipeline.knowledge_updater.execute",
                new_callable=AsyncMock,
            ) as mock_execute,
        ):
            await svc.ingest_confirmed_feedback(
                feedback_id="fb-xyz",
                incident_id="inc-001",
                confirmed_verdict="PHISHING",
                note=None,
                **_FEEDBACK_ANALYSIS,
            )

        positional_args = mock_execute.call_args.args
        assert "fb-xyz" in positional_args


# ---------------------------------------------------------------------------
# process_feedback_queue()
# ---------------------------------------------------------------------------

class TestProcessFeedbackQueue:
    def _make_row(self, idx: int = 0) -> dict:
        return {
            "id": f"fb-{idx:03d}",
            "incident_id": f"inc-{idx:03d}",
            "confirmed_verdict": "PHISHING",
            "note": None,
            "url": "https://paypa1.com/login",
            "domain": "paypa1.com",
            "s_risk": 0.95,
            "s_idn": 0.88,
            "s_llm": 0.91,
            "s_ti": 0.72,
            "llm_reason": "Cyrillic homograph",
            "reasons": ["Cyrillic homograph detected"],
        }

    @pytest.mark.asyncio
    async def test_returns_count_of_processed_rows(self):
        svc = KnowledgeUpdaterService()
        rows = [self._make_row(i) for i in range(2)]

        with (
            patch("data_pipeline.knowledge_updater.fetch", new_callable=AsyncMock, return_value=rows),
            patch("data_pipeline.knowledge_updater.upsert_documents", new_callable=AsyncMock),
            patch("data_pipeline.knowledge_updater.execute", new_callable=AsyncMock),
        ):
            count = await svc.process_feedback_queue()

        assert count == 2

    @pytest.mark.asyncio
    async def test_empty_queue_returns_zero(self):
        svc = KnowledgeUpdaterService()

        with (
            patch("data_pipeline.knowledge_updater.fetch", new_callable=AsyncMock, return_value=[]),
            patch("data_pipeline.knowledge_updater.upsert_documents", new_callable=AsyncMock) as mock_upsert,
        ):
            count = await svc.process_feedback_queue()

        assert count == 0
        mock_upsert.assert_not_called()

    @pytest.mark.asyncio
    async def test_batch_size_passed_to_fetch(self):
        svc = KnowledgeUpdaterService()

        with patch(
            "data_pipeline.knowledge_updater.fetch",
            new_callable=AsyncMock,
            return_value=[],
        ) as mock_fetch:
            await svc.process_feedback_queue(batch_size=25)

        args = mock_fetch.call_args.args
        assert 25 in args

    @pytest.mark.asyncio
    async def test_one_row_fails_continues_rest(self):
        svc = KnowledgeUpdaterService()
        rows = [self._make_row(0), self._make_row(1)]
        execute_call_count = 0

        async def _execute_side_effect(*args, **kwargs):
            nonlocal execute_call_count
            execute_call_count += 1
            if execute_call_count == 1:
                # Fail the DB update for the first row — propagates out of
                # ingest_confirmed_feedback so process_feedback_queue catches it
                raise RuntimeError("DB update fails for first row")

        with (
            patch("data_pipeline.knowledge_updater.fetch", new_callable=AsyncMock, return_value=rows),
            patch("data_pipeline.knowledge_updater.upsert_documents", new_callable=AsyncMock),
            patch("data_pipeline.knowledge_updater.execute", side_effect=_execute_side_effect),
        ):
            count = await svc.process_feedback_queue()

        # First row failed → only second processed
        assert count == 1


# ---------------------------------------------------------------------------
# purge_incident_documents (T11 — anti-envenenamiento)
# ---------------------------------------------------------------------------

class TestPurgeIncidentDocuments:
    @pytest.mark.asyncio
    async def test_purges_all_three_collections(self):
        from unittest.mock import AsyncMock, call, patch

        from core.constants import COLLECTION_EMAIL, COLLECTION_IDN, COLLECTION_TI
        from data_pipeline.knowledge_updater import KnowledgeUpdaterService

        service = KnowledgeUpdaterService()
        with patch(
            "data_pipeline.knowledge_updater.delete_document",
            new_callable=AsyncMock,
        ) as mock_delete:
            await service.purge_incident_documents("abc-123")

        assert mock_delete.await_count == 3
        mock_delete.assert_has_awaits(
            [
                call(COLLECTION_EMAIL, "email_abc-123"),
                call(COLLECTION_IDN, "idn_abc-123"),
                call(COLLECTION_TI, "ti_abc-123"),
            ]
        )
