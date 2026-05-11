"""
Redis Pub/Sub subscriber that runs in a background thread.

When a message is published to a Redis channel (from any instance),
this subscriber picks it up and fans it out to local SSE clients
on this instance.

This enables horizontal scaling: multiple Render instances each
run this subscriber, so an event from instance A reaches users
connected to instance B.
"""
import json
import threading
import time
import logging

from cache.redis_client import get_pubsub

logger = logging.getLogger(__name__)

_subscriber_thread = None
_running = False


def _on_global_message(message):
    """Handle messages from the sse:global channel."""
    from sse.sse_manager import broadcast_local
    try:
        data = json.loads(message["data"])
        event_name = data.get("event", "update")
        event_data = data.get("data", {})
        broadcast_local(event_name, event_data)
    except Exception as e:
        logger.error(f"Error handling global SSE message: {e}")


def _on_forum_message(message):
    """Handle messages from sse:forum:* channels."""
    from sse.sse_manager import broadcast_forum_local
    try:
        channel = message["channel"]
        # channel format: "sse:forum:{forum_id}:message"
        parts = channel.split(":")
        if len(parts) >= 3:
            forum_id = int(parts[2])
            data = json.loads(message["data"])
            broadcast_forum_local(forum_id, "new_forum_message", data)
    except Exception as e:
        logger.error(f"Error handling forum SSE message: {e}")


def _subscriber_loop():
    """Main subscriber loop — reconnects on failure."""
    global _running
    _running = True

    while _running:
        try:
            pubsub = get_pubsub()
            if pubsub is None:
                logger.info("Redis not available for Pub/Sub, retrying in 10s…")
                time.sleep(10)
                continue

            # Subscribe to channels
            pubsub.subscribe(**{"sse:global": _on_global_message})
            pubsub.psubscribe(**{"sse:forum:*:message": _on_forum_message})

            logger.info("✅ Redis Pub/Sub subscriber started")

            # Listen for messages (blocking with timeout for clean shutdown)
            while _running:
                message = pubsub.get_message(timeout=1.0)
                if message and message["type"] in ("message", "pmessage"):
                    if message.get("channel") == "sse:global":
                        _on_global_message(message)
                    elif message.get("channel", "").startswith("sse:forum:"):
                        _on_forum_message(message)

        except Exception as e:
            logger.error(f"Pub/Sub subscriber error: {e}, reconnecting in 5s…")
            time.sleep(5)


def start_subscriber():
    """Start the Pub/Sub subscriber in a daemon background thread."""
    global _subscriber_thread
    if _subscriber_thread is not None and _subscriber_thread.is_alive():
        return

    _subscriber_thread = threading.Thread(
        target=_subscriber_loop,
        daemon=True,
        name="redis-pubsub-subscriber",
    )
    _subscriber_thread.start()
    logger.info("🔄 Pub/Sub subscriber thread launched")


def stop_subscriber():
    """Signal the subscriber to stop."""
    global _running
    _running = False
