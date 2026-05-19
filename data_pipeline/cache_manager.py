"""
Redis cache manager para resultados de Threat Intelligence e IDN.
Key format: ti:{domain_2ld} | idn:{domain_2ld}
TTL default: 3600s
"""
from __future__ import annotations

import json

from core.constants import IDN_CACHE_PREFIX, TI_CACHE_PREFIX
from core.logger import get_logger
from models.redis_client import cache_delete, cache_get, cache_set

logger = get_logger(__name__)


async def get_ti_cache(domain_2ld: str) -> dict | None:
    """
    Recupera resultado TI cacheado para un dominio 2LD.

    Returns:
        dict con scores si existe en cache, None si miss o entry corrupta.
    """
    key = f"{TI_CACHE_PREFIX}{domain_2ld}"
    raw = await cache_get(key)
    if raw is None:
        logger.debug("ti_cache_miss", domain=domain_2ld)
        return None
    try:
        data = json.loads(raw)
        logger.debug("ti_cache_hit", domain=domain_2ld)
        return data
    except json.JSONDecodeError:
        logger.warning("ti_cache_corrupt", domain=domain_2ld)
        await cache_delete(key)
        return None


async def set_ti_cache(domain_2ld: str, data: dict, ttl: int = 3600) -> None:
    """
    Guarda resultado TI en cache con TTL dado.

    Args:
        domain_2ld: Dominio de segundo nivel (ej. "paypal").
        data:       Dict serializable con scores TI.
        ttl:        Tiempo de vida en segundos (default 3600).
    """
    key = f"{TI_CACHE_PREFIX}{domain_2ld}"
    await cache_set(key, json.dumps(data), ttl=ttl)
    logger.debug("ti_cache_set", domain=domain_2ld, ttl=ttl)


async def get_idn_cache(domain_2ld: str) -> dict | None:
    """
    Recupera resultado IDN cacheado para un dominio 2LD.

    Returns:
        dict con scores IDN si existe en cache, None si miss o entry corrupta.
    """
    key = f"{IDN_CACHE_PREFIX}{domain_2ld}"
    raw = await cache_get(key)
    if raw is None:
        logger.debug("idn_cache_miss", domain=domain_2ld)
        return None
    try:
        data = json.loads(raw)
        logger.debug("idn_cache_hit", domain=domain_2ld)
        return data
    except json.JSONDecodeError:
        logger.warning("idn_cache_corrupt", domain=domain_2ld)
        await cache_delete(key)
        return None


async def set_idn_cache(domain_2ld: str, data: dict, ttl: int = 3600) -> None:
    """
    Guarda resultado IDN en cache con TTL dado.

    Args:
        domain_2ld: Dominio de segundo nivel.
        data:       Dict serializable con scores IDN.
        ttl:        Tiempo de vida en segundos (default 3600).
    """
    key = f"{IDN_CACHE_PREFIX}{domain_2ld}"
    await cache_set(key, json.dumps(data), ttl=ttl)
    logger.debug("idn_cache_set", domain=domain_2ld, ttl=ttl)


async def invalidate_domain(domain_2ld: str) -> None:
    """
    Invalida ambas entradas de cache (TI e IDN) para el dominio dado.

    Útil para forzar re-análisis tras una actualización de TI feeds.

    Args:
        domain_2ld: Dominio de segundo nivel a invalidar.
    """
    await cache_delete(f"{TI_CACHE_PREFIX}{domain_2ld}")
    await cache_delete(f"{IDN_CACHE_PREFIX}{domain_2ld}")
    logger.info("domain_cache_invalidated", domain=domain_2ld)
