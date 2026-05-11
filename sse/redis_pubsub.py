"""
Redis Pub/Sub subscriber that runs in a background thread.

When a message is published to a Redis channel (from any instance),
this subscriber picks it up and fans it out to local SSE clients
on this instance.

FIX: Removed duplicate message handling. We now use ONLY the manual
dispatch in the loop (not callback handlers), which avoids double-delivery.
"""
import json
import threading
import time
import logging

from cache.redis_client import get_pubsub

logger = logging.getLogger(__name__)

_subscriber_thread = None
_running = False


def _handle_global_message(raw_data):
    """Handle messages from the sse:global channel."""
    from sse.sse_manager import broadcast_local
    try:
        data = json.loads(raw_data)
        event_name = data.get("event", "update")
        event_data = data.get("data", {})
        logger.info(f"PubSub received global event: {event_name}")
        broadcast_local(event_name, event_data)
    except Exception as e:
        logger.error(f"Error handling global SSE message: {e}")


def _handle_forum_message(channel, raw_data):
    """Handle messages from sse:forum:*:message channels."""
    from sse.sse_manager import broadcast_forum_local
    try:
        # channel format: "sse:forum:{forum_id}:message"
        parts = channel.split(":")
        if len(parts) >= 3:
            forum_id = int(parts[2])
            data = json.loads(raw_data)
            event_name = data.get("event", "new_forum_message")
            event_data = data.get("data", data)
            logger.info(f"PubSub received forum event: forum={forum_id} event={event_name}")
            broadcast_forum_local(forum_id, event_name, event_data)
    except Exception as e:
        logger.error(f"Error handling forum SSE message: {e}")


def _subscriber_loop():
    """Main subscriber loop — reconnects on failure."""
    global _running
    _running = True

    while _running:
        pubsub = None
        try:
            pubsub = get_pubsub()
            if pubsub is None:
                logger.info("Redis not available for Pub/Sub, retrying in 10s...")
                time.sleep(10)
                continue

            # Subscribe WITHOUT callback handlers — we dispatch manually below
            # This prevents the double-handling bug
            pubsub.subscribe("sse:global")
            pubsub.psubscribe("sse:forum:*:message")

            logger.info("Redis Pub/Sub subscriber active — listening for events")

            while _running:
                message = pubsub.get_message(timeout=1.0)
                if message is None:
                    continue

                msg_type = message.get("type", "")

                # Regular channel message (sse:global)
                if msg_type == "message":
                    channel = message.get("channel", "")
                    raw_data = message.get("data", "")

                    if channel == "sse:global" and isinstance(raw_data, str):
                        _handle_global_message(raw_data)

                # Pattern-matched message (sse:forum:*:message)
                elif msg_type == "pmessage":
                    channel = message.get("channel", "")
                    raw_data = message.get("data", "")

                    if channel.startswith("sse:forum:") and isinstance(raw_data, str):
                        _handle_forum_message(channel, raw_data)

        except Exception as e:
            logger.error(f"Pub/Sub subscriber error: {e}, reconnecting in 5s...")
            time.sleep(5)
        finally:
            # Clean up pubsub connection on error
            if pubsub is not None:
                try:
                    pubsub.close()
                except Exception:
                    pass


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
    logger.info("Pub/Sub subscriber thread launched")


def stop_subscriber():
    """Signal the subscriber to stop."""
    global _running
    _running = False
