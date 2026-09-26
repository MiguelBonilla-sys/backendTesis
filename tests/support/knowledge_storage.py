"""Small in-memory doubles for the admission/serialization contract."""

import asyncio
from contextlib import asynccontextmanager

from data_pipeline.knowledge_admission import AUTO_SOURCES


class MemoryCollection:
    def __init__(self, rows=None):
        self.rows = dict(rows or {})
        self.deleted = []

    async def get(self, *, ids=None, where=None, include=None, limit=300, offset=0):
        values = list(self.rows.items())
        if ids is not None:
            values = [(did, row) for did, row in values if did in ids]
        if where:
            values = [(did, row) for did, row in values if row.get("source") in AUTO_SOURCES]
        values = values[offset : offset + limit]
        return {"ids": [did for did, _ in values], "metadatas": [dict(row) for _, row in values]}

    async def count(self):
        return len(self.rows)

    async def delete(self, *, ids):
        for did in ids:
            self.rows.pop(did, None)
            self.deleted.append(did)


class MemoryKnowledgePool:
    def __init__(self):
        self.lock = asyncio.Lock()
        self.blocked = False
        self.persisted = True
        self.url = None
        self.incident_ids = []
        self.calls = []

    @asynccontextmanager
    async def acquire(self):
        yield self

    @asynccontextmanager
    async def transaction(self):
        try:
            yield self
        finally:
            if self.lock.locked():
                self.lock.release()

    async def execute(self, query, *args):
        self.calls.append((query, args))
        if "pg_advisory_xact_lock" in query:
            await self.lock.acquire()

    async def fetchval(self, query, *args):
        self.calls.append((query, args))
        if "confirmed_verdict" in query:
            return self.blocked
        if "EXISTS" in query:
            return self.persisted
        return self.url

    async def fetch(self, query, *args):
        self.calls.append((query, args))
        return [{"id": value} for value in self.incident_ids]
