"""Mirror real Chroma in a disposable local container, without model downloads."""

import asyncio
import shutil
import time
import uuid

import chromadb
import httpx
import pytest
from chromadb.config import Settings

from scripts.sync_chroma_standby import _sync_collection
from tests.support.local_process import check_output, run

SPACE = "fixture-model-v1:2d"


class AsyncCollection:
    def __init__(self, collection):
        self.collection = collection
        self.metadata = collection.metadata

    def __getattr__(self, name):
        async def call(*args, **kwargs):
            return await asyncio.to_thread(getattr(self.collection, name), *args, **kwargs)

        return call


class AsyncClient:
    def __init__(self, client, namespace):
        self.client = client
        self.namespace = namespace

    async def get_collection(self, name):
        return AsyncCollection(
            await asyncio.to_thread(self.client.get_collection, self.namespace + name)
        )

    async def get_or_create_collection(self, name, **kwargs):
        return AsyncCollection(
            await asyncio.to_thread(
                self.client.get_or_create_collection, self.namespace + name, **kwargs
            )
        )


@pytest.fixture(scope="module")
def chroma_server():
    engine = shutil.which("podman") or shutil.which("docker")
    if not engine:
        pytest.skip("Local container engine required for isolated Chroma integration")
    image = "docker.io/chromadb/chroma:latest"
    check = run([engine, "image", "inspect", image], capture_output=True, timeout=10)
    if check.returncode:
        pytest.skip("Cached Chroma image required; tests do not pull images")
    name = "tesis-review-chroma-" + uuid.uuid4().hex[:10]
    run(
        [
            engine,
            "run",
            "-d",
            "--name",
            name,
            "--pull=never",
            "-p",
            "127.0.0.1::8000",
            "-e",
            "ANONYMIZED_TELEMETRY=False",
            image,
        ],
        check=True,
        capture_output=True,
        timeout=20,
    )
    try:
        port = int(
            check_output([engine, "port", name, "8000/tcp"], timeout=5)
            .decode()
            .strip()
            .rsplit(":", 1)[1]
        )
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            try:
                if httpx.get(f"http://127.0.0.1:{port}/api/v2/heartbeat", timeout=1).is_success:
                    break
            except httpx.HTTPError:
                pass
            time.sleep(0.1)
        else:
            pytest.fail("Disposable Chroma did not become ready")
        yield chromadb.HttpClient(
            host="127.0.0.1", port=port, settings=Settings(anonymized_telemetry=False)
        )
    finally:
        run([engine, "rm", "-f", name], check=True, capture_output=True, timeout=10)


@pytest.fixture
def replicas(chroma_server):
    names = ["source_" + uuid.uuid4().hex + "_", "replica_" + uuid.uuid4().hex + "_"]
    clients = [AsyncClient(chroma_server, name) for name in names]
    collections = [
        chroma_server.get_or_create_collection(
            name + "sync_test", metadata={"embedding_space": SPACE}
        )
        for name in names
    ]
    try:
        yield clients, collections
    finally:
        for name in names:
            chroma_server.delete_collection(name + "sync_test")


async def mirror(clients, **kwargs):
    return await _sync_collection(
        "sync_test",
        *clients,
        batch=2,
        prune=True,
        dest_embed=None,
        source_space=SPACE,
        destination_space=SPACE,
        **kwargs,
    )


async def test_updates_replace_stale_metadata_and_deletions_stay_deleted(replicas):
    clients, (source, replica) = replicas
    source.upsert(
        ids=["keep"],
        documents=["confirmed"],
        embeddings=[[1.0, 0.0]],
        metadatas=[{"source": "admin_confirmed", "verdict": "PHISHING"}],
    )
    replica.upsert(
        ids=["keep", "purged"],
        documents=["old", "false positive"],
        embeddings=[[1.0, 0.0], [0.0, 1.0]],
        metadatas=[{"source": "auto_high", "expires_at": "2000-01-01"}, {"source": "auto_high"}],
    )
    assert await mirror(clients) == (1, 1)
    metadata = replica.get(ids=["keep"])["metadatas"][0]
    assert metadata == {"source": "admin_confirmed", "verdict": "PHISHING"}
    assert await mirror(clients) == (0, 0)
    assert replica.get()["ids"] == ["keep"]
    source.delete(ids=["keep"])
    assert await mirror(clients) == (0, 1)
    assert replica.count() == 0


async def test_unknown_space_is_rejected_before_mutation(replicas):
    clients, (source, replica) = replicas
    replica.upsert(ids=["keep"], documents=["keep"], embeddings=[[1.0, 0.0]])
    source.modify(metadata={"embedding_space": "another-model:2d"})
    with pytest.raises(RuntimeError, match="source embedding space"):
        await mirror(clients)
    assert replica.count() == 1


async def test_dimension_mismatch_cannot_purge_destination(replicas):
    clients, (source, replica) = replicas
    source.upsert(ids=["new"], documents=["new"], embeddings=[[1.0, 0.0, 0.0]])
    replica.upsert(ids=["keep"], documents=["keep"], embeddings=[[1.0, 0.0]])
    with pytest.raises(RuntimeError, match="dimensions"):
        await mirror(clients)
    assert replica.get()["ids"] == ["keep"]
