#!/usr/bin/python

"""
ilfocore.lib.bytesenum
===============

Enums
"""

from enum import Enum


class Chr(bytes, Enum):
    """Control characters."""

    EMPTY = b''
    NUT = b'\x00'
    SOH = b'\x01'
    STX = b'\x02'
    ETX = b'\x03'
    EOT = b'\x04'
    ENQ = b'\x05'
    ACK = b'\x06'
    BELL = b'\x07'
    BS = b'\x08'
    HT = b'\x09'
    LF = b'\x0a'
    VT = b'\x0b'
    FF = b'\x0c'
    CR = b'\x0d'
    SO = b'\x0e'
    SI = b'\x0f'
    DLE = b'\x10'
    DC1 = b'\x11'
    DC2 = b'\x12'
    DC3 = b'\x13'
    DC4 = b'\x14'
    NAK = b'\x15'
    SYN = b'\x16'
    ETB = b'\x17'
    CAN = b'\x18'
    EM = b'\x19'
    SUB = b'\x1a'
    ESC = b'\x1b'
    FS = b'\x1c'
    GS = b'\x1d'
    RS = b'\x1e'
    US = b'\x1f'
    SPACE = b'\x20'


class NAKStatus(bytes, Enum):
    """NAK states."""

    FIN = b'0'
    NOT_AUTH_SIG = b'1'
    SIZE_EXCEED = b'2'
    UNK_FORMAT = b'3'
    UNK_FORMAT_C2 = b'4'
    UNK_FORMAT_S2 = b'5'
    UNK_HEADER = b'6'
    UNS_ASYM_ALG = b'7'
    UNS_SIG_ALG = b'8'
    UNS_SYM_ALG = b'9'
    UNS_PACK_SIZE = b'10'
