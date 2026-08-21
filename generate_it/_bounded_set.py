"""A memory-bounded set that evicts the oldest entry when full."""

from __future__ import annotations

from collections import OrderedDict
from typing import Generic, Hashable, Iterator, TypeVar

_T = TypeVar("_T", bound=Hashable)


class BoundedSet(Generic[_T]):
    """An insertion-ordered set with a hard upper bound on element count.

    When :attr:`max_size` is exceeded, the oldest entry is silently evicted.
    Re-adding an already-present element is a no-op — it does NOT refresh
    its position.
    """

    __slots__ = ("_data", "max_size")

    def __init__(self, max_size: int = 10_000) -> None:
        self._data: OrderedDict[_T, None] = OrderedDict()
        self.max_size = max_size

    def add(self, item: _T) -> None:
        if item in self._data:
            return
        self._data[item] = None
        if len(self._data) > self.max_size:
            self._data.popitem(last=False)

    def __contains__(self, item: object) -> bool:
        return item in self._data

    def __len__(self) -> int:
        return len(self._data)

    def __iter__(self) -> Iterator[_T]:
        return iter(self._data)
