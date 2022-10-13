#!/usr/bin/python
# Copyright (c) 2022 SiumLhahah
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
ilfocore.contact
===============

Contacts
"""

__author__ = 'SiumLhahah'

from collections import deque, namedtuple
from secrets import randbelow
from sys import byteorder
from typing import Union
from .lib import generating

SEQ_BYTES = 4
MIN_ORIGIN_SEQ = 256
MAX_ORIGIN_SEQ = 1024
MAX_SEQ = 256 ** SEQ_BYTES
MY_UID = 0
DICT_KEYS_TYPE = type({}.keys())
DICT_VALUES_TYPE = type({}.values())

UID = Union[int, bytes]
Addr = tuple[str, int]
Keys = namedtuple('Keys', ['algorithm', 'pk', 'sk'])


def rand_seq() -> int:
    """Generate an initial sequence number."""
    return randbelow(MAX_ORIGIN_SEQ - MIN_ORIGIN_SEQ) + MIN_ORIGIN_SEQ


def get_seq(seq: int) -> bytes:
    """Get sequence number in bytes."""
    return seq.to_bytes(SEQ_BYTES, byteorder)


class BaseContact:
    """Base of all types of contacts.

    Some attributes of a BaseContact object:
       - addr: Addr, current address if online
       - addrs: deque[Addr], possible addresses
       - uid: UID, contact uid, uid == 0 if is instance of Me
    """

    def __init__(self, uid: UID, addrs: list[Addr]):
        self._uid = uid
        self._addrs = deque(addrs)
        self._addr = None
        self.online = False

    @property
    def uid(self) -> UID:
        """UID of contact."""
        return self._uid

    @property
    def address(self) -> Addr:
        """Current address."""
        return self._addr

    @property
    def addresses(self) -> deque[Addr]:
        """Addresses which was logined by."""
        return self._addrs


class Contact(BaseContact):
    """Other contact."""

    def __init__(self, uid: UID,
                 sig_keys: Keys,
                 addrs: list[Addr]):
        BaseContact.__init__(self, uid, addrs)
        self.seq = rand_seq()
        self._addrs = deque(addrs)
        self._sig_keys = sig_keys
        self._sym_key = Keys(None, None, None)

    def connected(self, addr: Addr, sym_key: Keys):
        """Contact connected."""
        self.online = True
        self._sym_key = sym_key
        self._addr = addr
        self.update_addrs(addr)

    def closed(self):
        """Contact closed."""
        self.online = False
        self._sym_key = Keys(None, None, None)

    def update_addrs(self, addr: Addr):
        """Update addresses.

        May be overriden.
        """
        if addr in set(self._addrs):
            self._addrs.remove(addr)
        self._addrs.appendleft(addr)

    def new_seq(self) -> bytes:
        """Get a new sequence number."""
        self.seq += 1
        if self.seq > MAX_SEQ:
            self.seq = rand_seq()
        return get_seq(self.seq)

    @property
    def sig_keys(self) -> Keys:
        """Keys for signature."""
        return self._sig_keys

    @property
    def sym_key(self) -> Keys:
        """Symmetric key for main transmission."""
        return self._sym_key


class Contacts(dict):
    """Dict of contacts."""

    def __init__(self, contacts: dict[UID, Contact], uid_type='INTEGER'):
        dict.__init__(self, contacts)
        self._uid_type = uid_type
        self.max_uid = 0 if uid_type == 'INTEGER' else None

    def new_contact(self, pub_key: Keys, addrs: list[Addr]) -> UID:
        """Add a new contact."""
        if __debug__:
            print("ilfocore.contact.Contact.new_contact")
        # Get UID
        if self._uid_type == 'INTEGER':
            uid = generating.uid.gen_id('INTEGER', pre=self.max_uid)
            self.max_uid = uid
        else:
            uid = generating.uid.gen_id(self._uid_type, pre=self.get_uids())

        self[uid] = Contact(uid, pub_key, addrs)
        return uid

    def get_uids(self) -> DICT_KEYS_TYPE:
        """Return UIDs."""
        return self.keys()

    def get_contacts(self) -> DICT_VALUES_TYPE:
        """Return contacts."""
        return self.values()

    def get_uid_from_key(self, key: Keys) -> UID:
        """Get contact uid from its public key."""
        for uid, contact in self.items():
            if contact.sig_keys == key:
                return uid
        return None

    @property
    def uid_type(self) -> str:
        """Type of contacts' UIDs."""
        return self._uid_type


class Me(BaseContact):
    """Node itself, with (MY_UID := 0) as its UID."""

    def __init__(self, addr: Addr):
        BaseContact.__init__(self, MY_UID, [addr])
        self._addr = addr

    def connected(self):
        """Login."""
        self.online = True

    def logout(self):
        """Logout."""
        self.online = False
