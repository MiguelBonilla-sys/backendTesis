"""Ingestion must be traceable, replayable and fail before corrupting knowledge."""
import json
from unittest.mock import AsyncMock, patch

import pytest

from data_pipeline.reference_ingest import (
    PIPELINE,
    canonical_source_url,
    ingest_references,
    prepare_references,
    select_content,
    snapshot_page,
    split_chunks,
)

URL = "https://www.unicode.org/reports/tr39/"
TEXT = "# Intro\n\n" + "Confusables require careful domain analysis. " * 100


@pytest.fixture
def source(tmp_path):
    (tmp_path / "page.json").write_text(json.dumps({"data": {"web": [{
        "url": URL, "title": "Unicode", "markdown": TEXT,
    }]}}))
    return {"url": URL, "snapshot": "page.json", "publisher": "Unicode", "topic": "IDN"}


def test_prepare_replay_ids_hashes_and_source_without_phishing_verdict(source, tmp_path):
    first, manifest = prepare_references([source], tmp_path, "2026-09-05")
    replay, _ = prepare_references([source], tmp_path, "2026-09-06")
    assert [r["id"] for r in first] == [r["id"] for r in replay]
    assert len(first) > 1
    assert len({r["id"] for r in first}) == len(first)
    assert manifest[0]["markdown"] == TEXT.strip()
    for record in first:
        meta = record["metadata"]
        assert meta["source_url"] == URL and len(meta["chunk_sha256"]) == 64
        assert meta["ingestion_pipeline"] == PIPELINE
        assert "verdict" not in meta


@pytest.mark.parametrize("url", [
    "http://www.unicode.org/reports/tr39/", "https://localhost/",
    "https://unicode.org.evil.example/", "https://user:pass@www.unicode.org/",
    "https://www.unicode.org:8000/",
])
def test_only_reviewed_public_https_sources(url):
    with pytest.raises(ValueError):
        canonical_source_url(url)


def test_url_normalization_removes_fragment():
    assert canonical_source_url(URL + "#section") == URL


@pytest.mark.parametrize("host", ["www.microsoft.com", "www.malwarebytes.com", "www.dian.gov.co"])
def test_reviewed_incident_publishers(host):
    assert canonical_source_url(f"https://{host}/report") == f"https://{host}/report"
    with pytest.raises(ValueError):
        canonical_source_url(f"https://{host}.evil.example/report")


def case_source(source):
    return {**source, "document_type": "case_report", "case_id": "CASE-01",
            "published_at": "2023-10-18", "observed_period": "October 2023",
            "evidence_type": "observed_campaign",
            "curated_text": ("# Reviewed public case\n\n"
                             + "Historical evidence, not a verdict. " * 12)}


def test_curated_case_keeps_original_provenance_without_incident_label(source, tmp_path):
    from data_pipeline.reference_ingest import digest

    case = case_source(source)
    records, manifest = prepare_references([case], tmp_path, "2026-09-05")
    assert manifest[0]["markdown"] == case["curated_text"].strip()
    for record in records:
        meta = record["metadata"]
        assert meta["document_type"] == "case_report"
        assert meta["content_kind"] == "reviewed_summary"
        assert meta["published_at"] == "2023-10-18"
        assert meta["source_content_sha256"] == digest(TEXT.strip())
        assert meta["snapshot_sha256"] == digest(TEXT)
        assert meta["content_sha256"] == digest(case["curated_text"].strip())
        assert "verdict" not in meta
        assert "Historical evidence" in record["document"]
        assert "Confusables require" not in record["document"]
    assert prepare_references([case], tmp_path, "2026-09-06")[0] == [
        {**r, "metadata": {**r["metadata"], "retrieved_at": "2026-09-06"}} for r in records
    ]


@pytest.mark.parametrize("override", [
    {"case_id": ""}, {"published_at": "2023-02-30"}, {"observed_period": None},
    {"evidence_type": "proof_of_concept"}, {"curated_text": "Too short"},
    {"curated_text": None}, {"document_type": "security_reference"},
    {"document_type": "PHISHING"},
])
def test_unreviewed_or_invalid_cases_fail_closed(source, tmp_path, override):
    with pytest.raises(ValueError):
        prepare_references([{**case_source(source), **override}], tmp_path, "2026-09-05")


def test_snapshot_path_cannot_escape(source, tmp_path):
    with pytest.raises(ValueError, match="escapes"):
        prepare_references([{**source, "snapshot": "../secret.json"}], tmp_path, "today")


def test_duplicate_source_rejected(source, tmp_path):
    with pytest.raises(ValueError, match="Duplicate"):
        prepare_references([source, source], tmp_path, "today")


def test_scrape_and_mcp_data_envelopes():
    page = {"markdown": TEXT, "metadata": {"sourceURL": URL, "statusCode": 200}}
    assert snapshot_page({"data": page}, URL) == page
    assert snapshot_page(page, URL) == page


def test_failed_or_missing_scrape_rejected():
    with pytest.raises(ValueError, match="missing"):
        snapshot_page({"data": {"web": []}}, URL)
    with pytest.raises(ValueError, match="Failed"):
        snapshot_page({"markdown": "Forbidden", "metadata": {
            "sourceURL": URL, "statusCode": 403,
        }}, URL)


def test_section_selection_ignores_toc_and_preserves_paragraphs():
    content = "nav\n[Security](#Security)\n# Intro\nintro\n## Security\n" + "safe data " * 40
    content += "\n## Footer\nignore me"
    selected = select_content(content, {
        "url": URL, "start_heading": "^## Security", "stop_heading": "^## Footer",
    })
    assert selected.startswith("## Security")
    assert "safe data" in selected and "ignore me" not in selected and "nav" not in selected


def test_bad_section_and_empty_page_fail_closed():
    with pytest.raises(ValueError, match="Missing start_heading"):
        select_content(TEXT, {"url": URL, "start_heading": "No such section"})
    with pytest.raises(ValueError, match="Insufficient"):
        select_content("Unavailable", {"url": URL})


def test_no_title_rejected(source, tmp_path):
    (tmp_path / "page.json").write_text(json.dumps({"markdown": TEXT,
        "metadata": {"sourceURL": URL}}))
    with pytest.raises(ValueError, match="Missing source title"):
        prepare_references([source], tmp_path, "today")


def test_chunks_bound_length_overlap_and_keep_tail():
    text = ("a" * 350 + "\n\n" + "b" * 350 + "\n\n") * 4 + "FINAL_END"
    chunks = split_chunks(text, size=500, overlap=80)
    assert max(map(len, chunks)) <= 500
    assert chunks[-1].endswith("FINAL_END")
    for left, right in zip(chunks, chunks[1:], strict=False):
        assert left[-80:] in right
    assert split_chunks("") == []


@pytest.mark.parametrize("size,overlap", [(100, 0), (400, -1), (400, 200)])
def test_bad_chunk_parameters(size, overlap):
    with pytest.raises(ValueError):
        split_chunks(TEXT, size, overlap)


async def test_reingest_prunes_only_owned_source_after_all_writes(source, tmp_path):
    records, _ = prepare_references([source], tmp_path, "today")
    collection = AsyncMock()
    collection.get.return_value = {"ids": [records[0]["id"], "ref_stale"]}
    with patch("models.chromadb_client.get_or_create_collection", return_value=collection), \
         patch("models.chromadb_client.upsert_documents", new_callable=AsyncMock) as upsert:
        result = await ingest_references(records, batch_size=1)
    assert upsert.await_count == len(records)
    assert result["removed_stale"] == 1
    collection.delete.assert_awaited_once_with(ids=["ref_stale"])
    assert {"ingestion_pipeline": PIPELINE} in collection.get.call_args.kwargs["where"]["$and"]


async def test_failed_write_never_prunes_or_reports_success(source, tmp_path):
    records, _ = prepare_references([source], tmp_path, "today")
    with patch("models.chromadb_client.upsert_documents", side_effect=RuntimeError("down")), \
         patch("models.chromadb_client.get_or_create_collection") as get_collection:
        with pytest.raises(RuntimeError):
            await ingest_references(records)
    get_collection.assert_not_called()


async def test_empty_ingest_and_bad_batch():
    assert await ingest_references([]) == {"upserted": 0, "removed_stale": 0}
    with pytest.raises(ValueError):
        await ingest_references([], batch_size=0)
