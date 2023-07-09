# Copyright (c) 2022-2023 SiumLhahah
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
ilfocore.ilfonode

Safe node of ilfocore, providing authentic transmission support.

"""

from collections import defaultdict
from io import BufferedIOBase
from typing import Iterable
from . import udpnode
from .constants import Address, ENCODING
from .lib import signature
from .utils.multithread import in_queue


class BaseSession(udpnode.BaseSession):

    """Base safe session class.
    Authentic session to the other node.

    Methods for the caller:

    - start()
    - close()
    - send(package: bytes) -> last_seq
    - send_packages(packages: typing.Iterable[bytes]) -> last_seq

    Methods that may be overridden:

    - setup_common()

    # if not multi-threaded for sessions
    - start()
    - process_noblock(request)
    - stop()

    - send_nak()
    - close()
    - process_capture(req_type: bytes, buf: io.BytesIO)
    - process_request(req_type: bytes, buf: io.BytesIO)

    Instance variables:

    - pub_key : tuple[str, bytes]
        The identity of other node.
    - sig_key : signature.PublicKey
        The PublicKey object.
    - ...

    See udpnode.BaseSession.__doc__ for more information.

    """

    def __init__(self, conn):
        self.pub_key: tuple[str, bytes] = None
        self.sig_key: signature.PublicKey = None
        super().__init__(conn)

    @in_queue('_queue')
    def setup(self):
        """Setup to send signature.

        May be overriden.

        """
        sig_key = self.node.sig_key
        secret, send_key, _ = self.asym_keys
        alg = secret.name
        alg = len(alg).to_bytes() + bytes(alg, ENCODING)
        self.send_packages((bytes(sig_key.name, ENCODING),
                            sig_key.public_key.to_bytes(),
                            sig_key.sign(self.recv_conn_id + alg + send_key)))

    def handle_sig_alg(self, buf: BufferedIOBase):
        """Handle signature algorithm."""
        self.handle = self.handle_sig_key
        alg = buf.read()
        try:
            self.pub_key = (str(alg, ENCODING), None)
        except UnicodeDecodeError:
            # Close the session
            self.close()
            return

    handle = handle_sig_alg

    def handle_sig_key(self, buf: BufferedIOBase):
        """Handle public key for signature."""
        self.handle = self.handle_sig
        key = buf.read()
        try:
            alg, _ = self.pub_key
            self.sig_key = self.node.get_verify(alg).from_bytes(key)
            alg = self.sig_key.name
            self.pub_key = (alg, key)
        except ValueError:
            # Close the session
            self.close()
            return

    def handle_sig(self, buf: BufferedIOBase):
        """Handle the signature."""
        self.handle = super().handle
        sig = buf.read()
        try:
            secret, _, recv_key = self.asym_keys
            alg = secret.name
            alg = len(alg).to_bytes() + bytes(alg, ENCODING)
            self.sig_key.verify(sig, self.send_conn_id + alg + recv_key)
        except ValueError:
            # Close the session
            self.close()
            return
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
    - send_packages_to(packages: typing.Iterable[bytes],
                       target_sig_key: tuple[str, bytes]
                       ) -> dict[BaseSession, last_seq: int]
    - sendto(package: bytes, target_sig_key: tuple[str, bytes]
             ) -> dict[BaseSession, last_seq: int]

    Instance variables:

    - sig_key : signature.PrivateKey
        The identity of a node of ilfocore.
    - ...

    See udpnode.Node.__doc__ for more information.

    """

    version = b'node2ilfo2'

    def __init__(
        self,
        sig_key: signature.PrivateKey,
        server_address: Address,
        SessionClass: type[BaseSession],
        bind_and_activate=True
    ):
        self.sig_key = sig_key
        self.pub_key = (self.sig_key.name,
                        self.sig_key.public_key.to_bytes())
        self.session_groups: defaultdict[
            tuple[str, bytes], dict[Address, SessionClass]
        ] = defaultdict(dict)
        super().__init__(server_address, SessionClass, bind_and_activate)

    def send_packages_to(
            self, packages: Iterable[bytes], target_sig_key: tuple[str, bytes]
    ) -> dict[BaseSession, int]:
        """Send packages to target nodes."""
        with self.group_lock:
            cons = self.session_groups.get(target_sig_key)
            if cons is None:
                return None
            cons = list(cons.values())
        return {con: con.send_packages(packages) for con in cons}

    def sendto(
            self, package: bytes, target_sig_key: tuple[str, bytes]
    ) -> dict[BaseSession, int]:
        """Send package to target nodes."""
        return self.send_packages_to((package,), target_sig_key)

    get_sign = staticmethod(signature.get_sign)
    get_verify = staticmethod(signature.get_verify)
