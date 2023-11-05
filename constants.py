# Copyright (c) 2022-2023 SiumLhahah
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
ilfocore.constants

Constants for ilfocore.

"""

from collections import namedtuple
from enum import Enum

# Request type size
TYPE_SIZE = 1

# The size of a 2-byte integer
# which determines the size of
# the maximum node packet size
# that not greater than 65535
PACKET_SIZE_LEN = 2

# Encoding and byteorder
ENCODING = 'utf-8'
BYTEORDER = 'big'


class ReqType(bytes, Enum):

    """Request types."""

    EOT = b'\x04'
    ENQ = b'\x05'
    ACK = b'\x06'
    NAK = b'\x15'
    SYN = b'\x16'


Address = namedtuple('Address', ['host', 'port'])
Address.host: str
Address.host.__doc__ = """Host."""
Address.port: int
Address.port.__doc__ = """Port."""


class Key(namedtuple('Key', ['algorithm', 'key'])):

    __slots__ = ()

    def __new__(cls, algorithm: str, key: bytes):
        return super(Key, cls).__new__(cls, algorithm.lower(), key)


Key.algorithm.__doc__ = """Algorithm of the key."""
Key.key.__doc__ = """Key bytes."""
