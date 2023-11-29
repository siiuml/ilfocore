# Copyright (c) 2022-2023 SiumLhahah
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
ilfocore.utils.multithread

Multi-threading utilities.

"""

from collections.abc import Callable
from functools import wraps
from queue import Queue
from typing import Any
from threading import _RLock


def call_forever(queue: Queue):
    """Run in another thread to call functions.

    Use queue.put(None) to cancel the thread.

    """
    while (item := queue.get()) is not None:
        func, args, kwargs = item
        func(*args, **kwargs)


def in_queue(queue: Queue | str) -> Callable[
        [Callable[..., Any]], Callable[..., None]]:
    """Put function and arguments in queue."""
    def in_queue_[**P](func: Callable[P, Any]) -> Callable[P, None]:
        """Function and its arguments will be put in queue.

        If queue is instance of str,
        then the item will be put in vars(self)[queue].

        """
        if isinstance(queue, str):
            attrs = queue.split('.')
            self = None

            @wraps(func)
            def decorated(*args: P.args, **kwargs: P.kwargs) -> None:
                """Method called in another thread."""
                nonlocal attrs, queue, self
                if self is not args[0]:
                    self = queue = args[0]
                    for name in attrs:
                        queue = getattr(queue, name)
                queue.put((func, args, kwargs))
        else:
            @wraps(func)
            def decorated(*args: P.args, **kwargs: P.kwargs) -> None:
                """Function called in another thread."""
                queue.put((func, args, kwargs))
        return decorated
    return in_queue_


class ReadLock:

    """Simple read lock class."""

    def __init__(self, wlock: _RLock):
        self._cnt = 0
        self._wlock = wlock
        self._block = wlock._block

    def acquire(self, blocking=True, timeout=-1) -> int:
        """Acquire the lock."""
        no_rlock_acquired = not self._cnt
        self._cnt += 1
        if no_rlock_acquired or self._wlock._owner:
            return self._block.acquire(blocking, timeout)
        return 1

    __enter__ = acquire

    def release(self):
        """Release the lock."""
        self._cnt = cnt = self._cnt - 1 if self._cnt else 0
        if not cnt:
            self._block.release()

    def __exit__(self, *args):
        self.release()


class ReadWriteLock:

    """Simple read-write lock class."""

    def __init__(self):
        self._wlock = wlock = _RLock()
        self._rlock = ReadLock(wlock)

    @property
    def rlock(self) -> ReadLock:
        """Return the read lock."""
        return self._rlock

    @property
    def wlock(self) -> _RLock:
        """Return the write lock."""
        return self._wlock
