from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class WorkflowEvent:
    name: str
    payload: dict[str, Any]


Subscriber = Callable[[WorkflowEvent], None]


class EventBus:
    """Small synchronous publisher for workflow lifecycle events."""

    def __init__(self) -> None:
        self._subscribers: dict[str, list[Subscriber]] = defaultdict(list)

    def subscribe(self, event_name: str, subscriber: Subscriber) -> None:
        self._subscribers[event_name].append(subscriber)

    def publish(self, event: WorkflowEvent) -> None:
        for subscriber in tuple(self._subscribers[event.name]):
            subscriber(event)
