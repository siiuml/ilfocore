# Copyright (c) 2022-2024 SiumLhahah
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
ilfocore.ilfonode

Safe node of ilfocore, providing authentic transmission support.

"""

from collections import defaultdict
from io import BufferedReader, BytesIO
from typing import Iterable
from . import udpnode as udpnode
from .constants import ENCODING, Address, Key
from .lib.signature import PrivateKey, PublicKey, get_sign, get_verify
from .utils import write_with_size


class BaseSession(udpnode.BaseSession):

    """Basic safe session class.
    Authentic session to the target node.

    Methods for the caller:

    - start()
    - close()
    - send(data: bytes | Iterable[bytes]) -> last_seq

    Methods that may be overridden:

    - setup_common()

    # if not multi-threaded for sessions
    - start()
    - process_noblock(request)
    - stop()

    - send_nak()
    - close()
    - process_capture(req_type: bytes, buf: BytesIO)
    - process_request(req_type: bytes, buf: BytesIO)

    See udpnode.BaseSession.__doc__ for more information.

    """

    pub_key: Key        # The identity of target
    sig_key: PublicKey  # The PublicKey object of target's public key

    def __init__(self, conn):
        self.pub_key: Key = None
        self.sig_key: PublicKey = None
        super().__init__(conn)

    @udpnode.in_queue
    def setup(self):
        """Setup to send signature.

        May be overriden.

        """
        sig_key = self.node.sig_key
        buf = BytesIO()
        secret, send_key, _ = self.asym_keys
        alg = secret.name
        buf.write(self.recv_conn_id)
        write_with_size(bytes(alg, ENCODING), buf)
        buf.write(send_key)
        self.send((bytes(sig_key.name, ENCODING),
                   sig_key.public_key.to_bytes(),
                   sig_key.sign(buf.getvalue())))

    def handle_sig_alg(self, buf: BufferedReader):
        """Handle signature algorithm."""
        alg = buf.read()
        try:
            self.pub_key = Key(str(alg, ENCODING), None)
        except UnicodeDecodeError:
            # Close the session
            self.close()
            return
        self.handle = self.handle_sig_key

    handle = handle_sig_alg

    def handle_sig_key(self, buf: BufferedReader):
        """Handle public key for signature."""
        key = buf.read()
        alg = self.pub_key.algorithm
        try:
            self.sig_key = self.node.get_verify(alg).from_bytes(key)
            alg = self.sig_key.name
            self.pub_key = Key(alg, key)
        except ValueError:
            # Close the session
            self.close()
            return
        self.handle = self.handle_sig

    def handle_sig(self, buf: BufferedReader):
        """Handle the signature."""
        sig = buf.read()
        buf = BytesIO()
        secret, _, recv_key = self.asym_keys
        alg = secret.name
        buf.write(self.send_conn_id)
        try:
            write_with_size(bytes(alg, ENCODING), buf)
            buf.write(recv_key)
            self.sig_key.verify(sig, buf.getvalue())
        except ValueError:
            # Close the session
            self.close()
            return
        self.handle = super().handle
        self.node.session_groups[self.pub_key][self.address] = self
        self.setup_common()

    def setup_common(self):
        """Start to handle common messages.

        Should be overriden like this:

            ...
            self.handle = self.handle_common_method
            ...

        """

    def close(self):
        """Close session, interrupt thread if multi-threaded."""
        if self.sig_key in self.node.session_groups:
            group = self.node.session_groups[self.pub_key]
            if self.address in group:
                del group[self.address]
                if not group:
                    del self.node.session_groups[self.pub_key]
        super().close()


class Node(udpnode.Node):

    """Ilfocore node class.

    Methods for the caller:

    - __init__(sig_key, server_address, SessionClass)
    - serve_forever(poll_interval=0.5)
    - close()
    - sendto(data: bytes | Iterable[bytes], target_pub_key: Key
             ) -> dict[BaseSession, last_seq: int]

    See udpnode.Node.__doc__ for more information.

    """

    version = b'node2ilfo2'

    # Instance variables:

    pub_key: Key        # The identity of local node
    sig_key: PrivateKey  # The PrivateKey object.

    session_groups: defaultdict[Key, dict[Address, BaseSession]]

    def __init__(
        self,
        signature_key: PrivateKey,
        server_address: Address,
        SessionClass: type[BaseSession],
        bind_and_activate=True
    ):
        super().__init__(server_address, SessionClass, bind_and_activate)
        self.sig_key = signature_key
        self.pub_key = Key(self.sig_key.name,
                           self.sig_key.public_key.to_bytes())
        self.session_groups = defaultdict(dict)

    def sendto(self, data: bytes | Iterable[bytes],
               target_pub_key: Key) -> dict[BaseSession, int]:
        """Send package or packages to target nodes."""
        with self.group_lock:
            cons = self.session_groups.get(target_pub_key)
            if cons is None:
                return None
            cons = list(cons.values())
        return {con: con.send(data) for con in cons}

    get_sign = staticmethod(get_sign)
    get_verify = staticmethod(get_verify)
