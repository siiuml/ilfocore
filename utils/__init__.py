# Copyright (c) 2022-2023 SiumLhahah
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
ilfocore.utils

Ilfocore utilities.

"""

from io import BufferedIOBase
from math import ceil

do_nothing = lambda *args, **kwargs: None


def pack_integral(num: int | None, byteorder='big') -> bytes:
    """Pack an integral into bytes."""
    if num is None:
        return b'\xff'
    if num < 0b10000000:
        return num.to_bytes()
    return (((size := ceil(num.bit_length() / 8)) + 0b10000000).to_bytes()
            + num.to_bytes(size, byteorder))


def write_integral(num: int | None, buf: BufferedIOBase, byteorder='big'
                   ) -> int:
    """Write an integral into buffer.

    Returns the number of bytes written.

    """
    return buf.write(pack_integral(num, byteorder))


def read_integral(buf: BufferedIOBase, byteorder='big', *, not_none=True
                  ) -> int | None:
    """Read an integral from buffer."""
    if size_bytes := buf.read(1):
        size = size_bytes[0]
    else:
        raise ValueError
    if size < 0x80:
        return size
    if not_none or size < 0xff:
        return int.from_bytes(buf.read(size - 128), byteorder)
    return None


def pack_with_size(data: bytes | None, byteorder='big') -> bytes:
    """Pack data with its size."""
    if data is None:
        return b'\xff'
    return pack_integral(len(data), byteorder) + data


def write_with_size(data: bytes | None, buf: BufferedIOBase, byteorder='big'
                    ) -> int:
    """Write data size and data into buffer.

    Returns the number of bytes written.

    """
    return buf.write(pack_with_size(data, byteorder))


def read_by_size(buf: BufferedIOBase, byteorder='big', *, not_none=True
                 ) -> bytes | None:
    """Read data from buffer by its size indicated in the buffer."""
    size = read_integral(buf, byteorder)
    if not_none or size is not None:
        return buf.read(size)
    return None
