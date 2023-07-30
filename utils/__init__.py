# Copyright (c) 2022-2023 SiumLhahah
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.


"""
ilfocore.utils

Ilfocore utilities.

"""

from io import BufferedIOBase

do_nothing = lambda *args, **kwargs: None


def write_integral(num: int, buf: BufferedIOBase, byteorder='big') -> int:
    """Write an integral into buffer.

    Returns the number of bytes written.

    """
    if num < 128:
        return buf.write(num.to_bytes())
    for size in range(1, 256):
        if num < 1 << size * 8:
            break
    else:
        raise AssertionError
    return (buf.write((size + 128).to_bytes())
            + buf.write(num.to_bytes(size, byteorder)))


def read_integral(buf: BufferedIOBase, byteorder='big') -> int:
    """Read an integral from buffer."""
    size = int.from_bytes(buf.read(1))
    if size < 128:
        return size
    return int.from_bytes(buf.read(size - 128), byteorder)
