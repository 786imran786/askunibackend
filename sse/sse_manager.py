"""
SSE (Server-Sent Events) connection manager.

Manages local SSE client queues and provides broadcast functions.
For multi-instance scaling, use `broadcast_global()` which goes through
Redis Pub/Sub so all instances receive the event.
"""
import json
import queue
import threading
import time
import logging
from flask import Response

from cache.redis_client import publish

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


def broadcast_global(event_name: str, data: dict):
    """
    Publish SSE event to Redis Pub/Sub → all instances receive it
    and fan out to their local SSE clients.
    Falls back to local broadcast if Redis is unavailable.
    """
    payload = {"event": event_name, "data": data}
    publish("sse:global", payload)
    # Also broadcast locally in case Redis isn't set up
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
                yield ": heartbeat\n\n"
    except GeneratorExit:
        pass


def create_sse_response():
    """
    Create a new SSE connection for the global feed.
    Returns a Flask Response with the event stream.
    """
    client_queue = queue.Queue(maxsize=50)

    with _sse_lock:
        _sse_clients.append(client_queue)

    def on_close():
        with _sse_lock:
            if client_queue in _sse_clients:
                _sse_clients.remove(client_queue)

    response = Response(
        _sse_stream(client_queue),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )
    response.call_on_close(on_close)
    return response


def create_forum_sse_response(forum_id):
    """
    Create a new SSE connection for a specific forum's messages.
    Returns a Flask Response with the event stream.
    """
    client_queue = queue.Queue(maxsize=50)

    with _forum_sse_lock:
        if forum_id not in _forum_sse_clients:
            _forum_sse_clients[forum_id] = []
        _forum_sse_clients[forum_id].append(client_queue)

    def on_close():
        with _forum_sse_lock:
            clients = _forum_sse_clients.get(forum_id, [])
            if client_queue in clients:
                clients.remove(client_queue)

    response = Response(
        _sse_stream(client_queue),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )
    response.call_on_close(on_close)
    return response
