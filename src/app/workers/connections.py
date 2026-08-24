"""Shared connection factories for worker processes."""

import redis

from app.config import Settings


def create_redis(settings: Settings) -> redis.Redis:
    return redis.Redis.from_url(
        settings.redis_url,
        decode_responses=True,
        socket_connect_timeout=2,
        socket_timeout=10,
    )
