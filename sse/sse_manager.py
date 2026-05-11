"""
SSE (Server-Sent Events) connection manager.

Manages local SSE client queues and provides broadcast functions.
For multi-instance scaling, `broadcast_global()` publishes through
Redis Pub/Sub so all instances receive the event.

FIX: broadcast_global() no longer double-broadcasts. It publishes
to Redis ONLY — the Pub/Sub subscriber handles local fan-out.
If Redis is unavailable, it falls back to local-only broadcast.
"""
import json
import queue
import threading
import logging
from flask import Response

from cache.redis_client import publish, redis_available

logger = logging.getLogger(__name__)

# ── Local SSE client storage ─────────────────────────────
_sse_clients = []          # list of queue.Queue()
_sse_lock = threading.Lock()

# Forum-specific SSE clients: {forum_id: [queue.Queue(), ...]}
_forum_sse_clients = {}
_forum_sse_lock = threading.Lock()


# ── Broadcast functions ──────────────────────────────────

def broadcast_local(event_name: str, data: dict):
    """Push SSE event to all clients connected to THIS instance only."""
    msg = f"event: {event_name}\ndata: {json.dumps(data, default=str)}\n\n"
    with _sse_lock:
        dead = []
        for q in _sse_clients:
            try:
                q.put_nowait(msg)
            except queue.Full:
                dead.append(q)
        for q in dead:
            _sse_clients.remove(q)
    client_count = len(_sse_clients)
    logger.info(f"SSE broadcast_local: event={event_name} → {client_count} clients")


def broadcast_global(event_name: str, data: dict):
    """
    Publish SSE event to Redis Pub/Sub → all instances (including this one)
    receive it via the subscriber thread and fan out to their local SSE clients.

    IMPORTANT: We do NOT call broadcast_local() here anymore.
    The Pub/Sub subscriber thread handles local delivery after receiving
    the message from Redis. This prevents double-broadcasting.

    If Redis is unavailable, we fall back to local-only broadcast.
    """
    if redis_available():
        payload = {"event": event_name, "data": data}
        publish("sse:global", payload)
        logger.info(f"SSE broadcast_global: published {event_name} to Redis")
    else:
        # Fallback: no Redis, broadcast locally only
        logger.warning(f"SSE broadcast_global: Redis unavailable, falling back to local")
        broadcast_local(event_name, data)


def broadcast_forum_local(forum_id, event_name: str, data: dict):
    """Push SSE event to clients listening to a specific forum."""
    msg = f"event: {event_name}\ndata: {json.dumps(data, default=str)}\n\n"
    with _forum_sse_lock:
        clients = _forum_sse_clients.get(forum_id, [])
        dead = []
        for q in clients:
            try:
                q.put_nowait(msg)
            except queue.Full:
                dead.append(q)
        for q in dead:
            clients.remove(q)
    client_count = len(_forum_sse_clients.get(forum_id, []))
    logger.info(f"SSE forum broadcast: forum={forum_id} event={event_name} → {client_count} clients")


def broadcast_forum_global(forum_id, event_name: str, data: dict):
    """
    Publish forum event to Redis Pub/Sub → all instances fan out to
    their local forum SSE clients. Falls back to local if Redis is down.
    """
    if redis_available():
        payload = {"event": event_name, "data": data}
        publish(f"sse:forum:{forum_id}:message", payload)
        logger.info(f"SSE forum broadcast_global: forum={forum_id} event={event_name} to Redis")
    else:
        broadcast_forum_local(forum_id, event_name, data)


def get_client_count() -> dict:
    """Return current SSE connection counts (for health/debug)."""
    with _sse_lock:
        global_count = len(_sse_clients)
    with _forum_sse_lock:
        forum_count = sum(len(clients) for clients in _forum_sse_clients.values())
    return {"global_sse_clients": global_count, "forum_sse_clients": forum_count}


# ── SSE stream generators ────────────────────────────────

def _sse_stream(client_queue: queue.Queue):
    """Generator that yields SSE events from the queue with heartbeats."""
    try:
        while True:
            try:
                msg = client_queue.get(timeout=15)
                yield msg
            except queue.Empty:
                # Send heartbeat to keep connection alive
                # (prevents proxies/Render from killing the connection)
                yield ": heartbeat\n\n"
    except GeneratorExit:
        logger.debug("SSE client disconnected (GeneratorExit)")


def create_sse_response():
    """
    Create a new SSE connection for the global feed.
    Returns a Flask Response with the event stream.
    """
    client_queue = queue.Queue(maxsize=100)

    with _sse_lock:
        _sse_clients.append(client_queue)

    logger.info(f"SSE global client connected (total: {len(_sse_clients)})")

    # Send an initial connection confirmation event
    try:
        client_queue.put_nowait("event: connected\ndata: {\"status\": \"ok\"}\n\n")
    except queue.Full:
        pass

    def on_close():
        with _sse_lock:
            if client_queue in _sse_clients:
                _sse_clients.remove(client_queue)
        logger.info(f"SSE global client disconnected (remaining: {len(_sse_clients)})")

    response = Response(
        _sse_stream(client_queue),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
            "Access-Control-Allow-Origin": "*",
        },
    )
    response.call_on_close(on_close)
    return response


def create_forum_sse_response(forum_id):
    """
    Create a new SSE connection for a specific forum's messages.
    Returns a Flask Response with the event stream.
    """
    client_queue = queue.Queue(maxsize=100)

    with _forum_sse_lock:
        if forum_id not in _forum_sse_clients:
            _forum_sse_clients[forum_id] = []
        _forum_sse_clients[forum_id].append(client_queue)

    logger.info(f"SSE forum client connected: forum={forum_id} (total: {len(_forum_sse_clients[forum_id])})")

    # Send connection confirmation
    try:
        client_queue.put_nowait(f"event: connected\ndata: {{\"forum_id\": {forum_id}, \"status\": \"ok\"}}\n\n")
    except queue.Full:
        pass

    def on_close():
        with _forum_sse_lock:
            clients = _forum_sse_clients.get(forum_id, [])
            if client_queue in clients:
                clients.remove(client_queue)
        logger.info(f"SSE forum client disconnected: forum={forum_id}")

    response = Response(
        _sse_stream(client_queue),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
            "Access-Control-Allow-Origin": "*",
        },
    )
    response.call_on_close(on_close)
    return response
