"""Redis cache manager for TI scores (key = ti:<domain>, TTL = 3600s)."""

import json

from core.config import settings
from core.logger import logger
from models.redis_client import get_redis


class CacheManager:
    @staticmethod
    def _key(domain: str) -> str:
        return f"ti:{domain}"

    async def get_ti_scores(self, domain: str) -> dict | None:
        try:
            raw = await get_redis().get(self._key(domain))
            if raw:
                logger.info(f"Cache HIT: {domain}")
                return json.loads(raw)
            logger.info(f"Cache MISS: {domain}")
            return None
        except Exception as exc:
            logger.warning(f"Cache read error for {domain!r}: {exc}")
            return None

    async def set_ti_scores(self, domain: str, scores: dict) -> None:
        try:
            await get_redis().setex(self._key(domain), settings.REDIS_TTL, json.dumps(scores))
        except Exception as exc:
            logger.warning(f"Cache write error for {domain!r}: {exc}")

    async def get_or_fetch_ti(self, domain: str, ti_service) -> dict:
        cached = await self.get_ti_scores(domain)
        if cached is not None:
            return cached
        scores = await ti_service.fetch_all(domain)
        await self.set_ti_scores(domain, scores)
        return scores
