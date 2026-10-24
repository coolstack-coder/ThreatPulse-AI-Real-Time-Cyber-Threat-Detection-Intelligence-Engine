"""In-process publish/subscribe event bus.

Each subscriber gets its own bounded queue. A slow consumer, such as a dashboard tab on a
bad connection, loses its *oldest* events instead of slowing down the detection pipeline.
The interface (topic + JSON payload) maps one-to-one onto Kafka or Redis Streams if the
engine is ever split into separate services.
"""

from __future__ import annotations

import asyncio
from typing import Any


class EventBus:
    def __init__(self, maxsize: int = 2000):
        self.maxsize = maxsize
        self._subs: set[asyncio.Queue] = set()
        self.published = 0
        self.dropped = 0

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=self.maxsize)
        self._subs.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subs.discard(q)

    @property
    def subscribers(self) -> int:
        return len(self._subs)

    def publish(self, topic: str, payload: Any) -> None:
        self.published += 1
        msg = {"type": topic, "data": payload}
        for q in self._subs:
            if q.full():
                try:
                    q.get_nowait()
                    self.dropped += 1
                except asyncio.QueueEmpty:
                    pass
            q.put_nowait(msg)
