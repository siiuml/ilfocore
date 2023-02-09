# !/usr/bin/python
# -*- coding: utf-8 -*-

"""

===============


"""

__author__ = 'Bob K Harris'
def calling_thread(queue: Queue):
    """Call function in the thread.

    Use queue.put(None) to cancel the thread.

    """
    while (item := queue.get()) is not None:
        func, args, kwargs = item
        func(*args, **kwargs)


def in_queue(queue: Queue | str):
    """Put function and arguments in queue."""
    def _in_queue(func: Callable):
        """Function and its arguments will be put in queue.

        If queue is instance of str,
        then the item will be put in vars(self)[queue].

        """
        def decorated(*args, **kwargs):
            """Called in another thread."""
            nonlocal queue
            if isinstance(queue, str):
                queue = vars(self := args[0]).get(name := queue)
                if queue is None:
                    raise AttributeError(f"{self.__class__.__name__} object "
                                          f"has no attribute {name}")
            queue.put((func, args, kwargs))
        if func.__doc__ is not None:
            decorated.__doc__ += '\n\n' + func.__doc__
        return decorated
    return _in_queue