"""
core/event_bus.py — Async publish/subscribe event bus for the AI Red Team
Framework.

Decouples inter-module communication so that modules never import each
other directly.  Handlers can be synchronous *or* ``async`` callables;
the bus normalises them transparently.

Usage::

    from core.event_bus import bus, Event

    async def on_scan_complete(event: Event) -> None:
        ports = event.payload["open_ports"]
        ...

    bus.subscribe("scan.complete", on_scan_complete)
    await bus.publish_async(Event("scan.complete", {"open_ports": [22, 80]}))

Predefined event types (conventions, not enforced)::

    recon.complete          recon.subdomains_found   recon.dns_records_found
    scan.complete           scan.ports_open          scan.services_identified
    analysis.complete       analysis.decisions_ready
    exploit.complete        exploit.credentials_found  exploit.rce_gained
    post_exploit.complete   privesc.success          persistence.installed
    report.complete
    phase.transition        phase.error              phase.skipped
"""

from __future__ import annotations

import asyncio
import inspect
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Awaitable, Callable, Union

logger = logging.getLogger(__name__)

# Handler type: sync or async callable accepting an Event
Handler = Callable[["Event"], Union[None, Awaitable[None]]]


# ---------------------------------------------------------------------------
# 1. Event data-class
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Event:
    """Immutable event payload published on the bus."""

    event_type: str
    payload: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    source: str = ""

    def __str__(self) -> str:  # pragma: no cover
        return f"Event({self.event_type}, source={self.source!r})"


# ---------------------------------------------------------------------------
# 2. EventBus
# ---------------------------------------------------------------------------

class EventBus:
    """Simple in-process pub/sub with support for both sync and async handlers.

    * ``subscribe(event_type, handler)`` — register a handler.
    * ``unsubscribe(event_type, handler)`` — remove a handler.
    * ``publish(event)`` — fire-and-forget (sync context).
    * ``publish_async(event)`` — ``await``-able; runs all handlers
      concurrently via ``asyncio.gather``.
    * ``publish_sync(event)`` — blocking call safe for non-async code;
      creates an event-loop if needed.
    """

    def __init__(self) -> None:
        self._subscribers: dict[str, list[Handler]] = {}
        self._history: list[Event] = []

    # ------------------------------------------------------------------
    # Subscribe / unsubscribe
    # ------------------------------------------------------------------

    def subscribe(self, event_type: str, handler: Handler) -> None:
        """Register *handler* for *event_type*."""
        self._subscribers.setdefault(event_type, []).append(handler)

    def unsubscribe(self, event_type: str, handler: Handler) -> None:
        """Remove a previously registered *handler*."""
        handlers = self._subscribers.get(event_type, [])
        try:
            handlers.remove(handler)
        except ValueError:
            pass

    def clear(self) -> None:
        """Remove **all** subscriptions (useful in tests)."""
        self._subscribers.clear()
        self._history.clear()

    # ------------------------------------------------------------------
    # Publish (async)
    # ------------------------------------------------------------------

    async def publish_async(self, event: Event) -> None:
        """Publish *event* and ``await`` all handlers concurrently.

        If an individual handler raises an exception it is logged but
        does **not** prevent other handlers from executing.
        """
        self._history.append(event)
        handlers = self._get_handlers(event.event_type)
        if not handlers:
            return

        tasks = [self._invoke(h, event) for h in handlers]
        await asyncio.gather(*tasks)

    # ------------------------------------------------------------------
    # Publish (sync convenience)
    # ------------------------------------------------------------------

    def publish_sync(self, event: Event) -> None:
        """Blocking publish for non-async callers.

        If a running event-loop exists (e.g. inside ``asyncio.run``),
        a new thread-based loop is created so this never deadlocks.
        """
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop is not None and loop.is_running():
            # We're inside an async context — schedule and wait via a
            # background thread to avoid blocking the loop.
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                pool.submit(asyncio.run, self.publish_async(event)).result()
        else:
            asyncio.run(self.publish_async(event))

    # Alias kept so old code using ``publish()`` still works.
    publish = publish_sync

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    @property
    def history(self) -> list[Event]:
        """Return the list of all events published so far."""
        return list(self._history)

    def handlers_for(self, event_type: str) -> list[Handler]:
        """Return a *copy* of the handler list for *event_type*."""
        return list(self._subscribers.get(event_type, []))

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_handlers(self, event_type: str) -> list[Handler]:
        """Return handlers for *event_type* plus any wildcard (``*``) handlers."""
        specific = self._subscribers.get(event_type, [])
        wildcard = self._subscribers.get("*", [])
        return specific + wildcard

    @staticmethod
    async def _invoke(handler: Handler, event: Event) -> None:
        """Call *handler* safely, adapting sync → async if needed."""
        try:
            result = handler(event)
            if inspect.isawaitable(result):
                await result
        except Exception:
            logger.exception("Event handler %r failed for %s", handler, event)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

bus: EventBus = EventBus()
