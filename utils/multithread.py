# Copyright (c) 2022-2023 SiumLhahah
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
ilfocore.utils.multithread

Multi-threading utilities.

"""

from functools import wraps
from queue import Queue
from typing import Callable

do_nothing = lambda *args, **kwargs: None


def call_forever(queue: Queue):
    """Run in another thread to call functions.

    Use queue.put(None) to cancel the thread.

    """
    while (item := queue.get()) is not None:
        func, args, kwargs = item
        func(*args, **kwargs)


def in_queue(queue: Queue | str):
    """Put function and arguments in queue."""
    def in_queue_(func: Callable):
        """Function and its arguments will be put in queue.

        If queue is instance of str,
        then the item will be put in vars(self)[queue].

        """
        if isinstance(queue, str):
            attrs = queue.split('.')
            self = None

            @wraps(func)
            def decorated(*args, **kwargs):
                """Method called in another thread."""
                nonlocal attrs, queue, self
                if self is not args[0]:
                    queue = (self := args[0])
                    for name in attrs:
                        queue = getattr(queue, name)
                queue.put((func, args, kwargs))
        else:
            @wraps(func)
            def decorated(*args, **kwargs):
                """Function called in another thread."""
                queue.put((func, args, kwargs))
        return decorated
    return in_queue_
