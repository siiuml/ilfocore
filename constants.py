# Copyright (c) 2022 SiumLhahah
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
ilfocore.constants

Constants for ilfocore.

"""

from enum import Enum

# Request type size
TYPE_SIZE = 1

# The size of a 1-byte integer
# which determines the size of
# a algorithm name that not
# greater than 255
ALG_SIZE_LEN = 1

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


# Types
Address = tuple[str, int]
Real = int | float
