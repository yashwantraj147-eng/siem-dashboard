import asyncio
import json
import logging
from typing import Set

logger = logging.getLogger(__name__)


class SSEBroadcaster:
    """
    In-memory async pub-sub hub for Server-Sent Events (SSE),
    enabling sub-second real-time telemetry streaming to SOC analyst dashboards.
    """
    def __init__(self):
        self.listeners: Set[asyncio.Queue] = set()

    async def subscribe(self) -> asyncio.Queue:
        queue = asyncio.Queue(maxsize=100)
        self.listeners.add(queue)
        logger.debug(f"New SSE client connected. Total listeners: {len(self.listeners)}")
        return queue

    def unsubscribe(self, queue: asyncio.Queue):
        self.listeners.discard(queue)
        logger.debug(f"SSE client disconnected. Total listeners: {len(self.listeners)}")

    def broadcast_sync(self, event_type: str, payload: dict):
        """Thread-safe event broadcast to all active SSE queues."""
        if not self.listeners:
            return

        message = json.dumps({"type": event_type, "payload": payload})
        for queue in list(self.listeners):
            try:
                queue.put_nowait(message)
            except (asyncio.QueueFull, Exception):
                pass


# Global singleton instance
broadcaster = SSEBroadcaster()
