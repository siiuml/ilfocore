# Copyright (c) 2022 SiumLhahah
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
ilfocore.udpnode

Node based on UDP.

"""

from abc import ABCMeta, abstractmethod
from collections import deque, namedtuple
from hmac import compare_digest
from io import BytesIO
from queue import Queue
from secrets import randbelow, token_bytes
from socketserver import UDPServer
from threading import Lock, Thread
from time import monotonic as time
from types import MethodType
from typing import Iterable, Self
from .constants import (
    ALG_SIZE_LEN,
    BYTEORDER,
    ENCODING,
    PACKET_SIZE_LEN,
    TYPE_SIZE,
    Address,
    Real,
    ReqType
)
from .lib import asymmetric, authentication, cipher, kdf
from .utils.multithread import call_forever, do_nothing, in_queue


Packet = namedtuple('Packet', ['seq', 'data'])
Packet.__doc__ = """Datagram packet with its sequence number.

seq : bytes
data : bytes

"""


class Connection(metaclass=ABCMeta):

    """Base class for connection classes.

    Methods for the caller:

    - __init__(address: Address, node: Node)
    - process(request: bytes)
    - retransmit()
    - send(package: bytes)
    - send_packages(packages: typing.Iterable[bytes])

    Methods that may be overridden:

    - handle(data: bytes)
    - process_request(req_type: bytes, request: bytes)
    - process_capture(req_type: bytes, request: bytes)
    - send_nak()
    - finish()
    - close()
    - update_deadline()

    Class variables:

    - multithreaded : bool

    Instance variables:

    - self.address : Address
    - self.node : Node
    - self._recv_buf : io.BytesIO
    - self.__not_packing : bool
    - self.__size_left : int
    - self.is_finished : bool
    - self._send_buf : deque[Packet]
    - self._send_buf_lock : threading.Lock
    - self.deadline : Real
    - self._retries : int

    - self.version: bytes
    - self.max_packet_size : int

    - self.conn_id_size : int
    - self.recv_conn_id : bytes
    - self.send_conn_id : bytes

    - self.seq_size : int
    - self._recv_seq : int
    - self._max_seq_number : int
    - self._send_seq : int

    - self.mac_key : authentication.Digest
    - self.digest_key : authentication.Digest
    - self.asym_keys : tuple[asymmetric.AsymmetricSecret, bytes, bytes]
    - self.kdf : kdf.KDF
    - self.cipher_key : cipher.SymmetricKey

    """

    multithreaded = False

    def __init__(self, address, node):
        self.address = address
        self.node = node

        # For parsing
        # Buffer for packing node packages
        self._recv_buf = BytesIO()
        # If not packing a node package
        self.__not_packing = True
        # The size of the rest of a node package
        self.__size_left = 0
        # If the connection is finished, then it won't handle any packages
        self.is_finished = False

        # For sending
        # Datagram packets for retransmission
        self._send_buf: deque[Packet] = deque()
        # Deadline to retransmit datagram packet
        self.deadline: Real = 0
        # Retransmission times counting
        self._retries = 0
        # Lock
        self._send_buf_lock = Lock()

    def start(self):
        """Call setup().

        Overriden by SessionClass.

        """
        # Call to setup
        self.setup()

    def setup(self):
        """Setup, called by start().

        Overriden by ClientClass.

        """

    def handle(self, data: bytes):
        """Handle a package.

        Overriden by ClientClass, ServerClass and SessionClass.

        """

    def finish(self):
        """Finish the connection completely, called by close().
        Send EOT message to inform the other node.

        Overriden by ClientClass and ServerClass.

        """
        self.is_finished = True
        data = ReqType.EOT + self.send_conn_id
        data = data + self.mac_key.digest(data)
        self.node.socket.sendto(data, self.address)

    def stop(self):
        """Called by close().

        Overriden by SessionClass.

        """

    def close(self):
        """Close the connection.
        Call finish() and stop()
        and pop self from dicts of node.

        Overriden by ClientClass, ServerClass and BaseSessionClass.
        Lock acquiring or releasing will be in the overriden close().

        """
        if self in self.node.retrans_cons:
            self.node.retrans_cons.remove(self)
        self.finish()
        self.stop()

    def parse(self, buf: BytesIO) -> bytes | None:
        """Parse node packages which may be like these:

            p1 = b'\x02abc'
            l1, d1 = b'\x02', b'ab'
            p1 == l1 + d1

            p2 = b'\x82\x00\x80'
            l2, d2 = b'\x82\x00\x80', b'a' * 128
            p2 == l2 + d2

        And the result parsed:

            conn.parse(BytesIO(p1)) == b'abc'
            conn.parse(BytesIO(p2)) == b'a' * 128

        l1 and l2 determines the length of data,
        similar to the one in DER format.
        - l1

                int.from_bytes(l1) == 0b00000010
                0b00000010 == len(d1)

        - l2
                size_len, size = l2[0], l2[1:]
                int.from_bytes(size_len) == 0b10000010
                0b10000010 - 0b10000000 == 0b00000010
                0b00000010 == len(size)
                int.from_bytes(size, 'big') == 128
                128 == len(d2)

        Return the next package from self._recv_buf and buf.

            buf == BytesIO(packet)

        """
        if self.__not_packing:
            # Not packing a package
            # May be packing size of a package
            is_packing_size = True
            if not (size_len := self.__size_left):
                # Not packing the size
                # Brand new package
                size_len = buf.read(1)[0]
                if size_len < 128:
                    self.__size_left = size_len
                    is_packing_size = False
                else:
                    size_len -= 128
                    is_packing_size = bool(size_len)
            if is_packing_size:
                # Try to get the size from bytes
                size = buf.read(size_len)
                if len(size) >= size_len:
                    # Got all bytes in need
                    self.__size_left = int.from_bytes(
                        self._recv_buf.getvalue() + size, BYTEORDER)
                    self._recv_buf.__init__()
                    # Start to pack the package
                    self.__not_packing = False
                else:
                    # Continue to pack the size
                    self.__size_left = (size_len -
                                        self._recv_buf.write(size))
                    return None
            else:
                # Start to pack the package
                self.__not_packing = False

        self.__size_left -= len(part := buf.read(self.__size_left))
        if not self.__size_left:
            package = self._recv_buf.getvalue() + part
            # Reset status
            self.__not_packing = True
            self._recv_buf.__init__()
            # Return the full package
            return package
        self._recv_buf.write(part)

    def verify_mac(self, request: bytes) -> bytes | None:
        """Verify MAC, return the message."""
        index = -self.mac_key.digest_size
        msg, mac = request[:index], request[index:]
        if compare_digest(mac, self.mac_key.digest(msg)):
            return msg

    def process_enq(self, request: bytes):
        """Called by process_request() to process ENQ message."""
        if not (msg := self.verify_mac(request)):
            seq = request[TYPE_SIZE: TYPE_SIZE + self.seq_size]
            # Prompt other node to retransmit
            self.node.socket.sendto(ReqType.NAK + seq, self.address)
            return
        buf = BytesIO(msg)
        buf.seek(TYPE_SIZE)
        seq_bytes = buf.read(self.seq_size)
        seq = int.from_bytes(seq_bytes, BYTEORDER)
        if seq > self._recv_seq:
            # Acknowledge
            # Target not received the acknowledge
            # have to retransmit the datagram packet
            ack = ReqType.ACK + seq_bytes
            self.node.socket.sendto(ack + self.mac_key.digest(ack),
                                    self.address)
            # Update latest sequence number
            self._recv_seq = seq
            # Parse packets into packages
            size = len(buf.getvalue())
            while (buf.tell() < size and
                   (package := self.parse(buf)) is not None):
                # Decrypt package
                try:
                    package = self.cipher_key.decrypt(package)
                except ValueError:
                    return
                # Handle package
                self.handle(package)
                if self.is_finished:
                    break

    def process_ack(self, request: bytes):
        """Called by process_request() to process ACK message.

        Overriden by ClientClass.

        """
        # Data packet was sent successfully
        if not (request := self.verify_mac(request)):
            return
        buf = BytesIO(request)
        buf.seek(TYPE_SIZE)
        seq = buf.read(self.seq_size)
        # Ignore data left in request buffer
        with self._send_buf_lock:
            if (buf := self._send_buf) and seq == buf[0].seq:
                # Pop packet in send_buf
                buf.popleft()
                # Reset deadline
                self.update_deadline()
                # Send next packet
                if buf:
                    self.node.socket.sendto(buf[0].data,
                                            self.address)
                    return
                with self.node.group_lock:
                    if self in self.node.retrans_cons:
                        self.node.retrans_cons.remove(self)

    def process_nak(self, request: bytes):
        """Called by process_request() to process NAK message."""
        with self._send_buf_lock:
            if self._send_buf and request[TYPE_SIZE:] == self._send_buf[0].seq:
                self.retransmit()

    def process_syn(self, request: bytes):
        """Called by process_request() to process SYN message.

        Overriden by ServerClass.

        """
        if request[TYPE_SIZE: TYPE_SIZE + self.conn_id_size
                   ] != self.recv_conn_id:
            # New connection
            self.is_finished = True
            self.finish = do_nothing
            self.close()
            self.node.establish_conn_to_client(request, self.address)

    def process_eot(self, request: bytes):
        """Called by process_request() to process EOT message."""
        if (self.verify_mac(request) and
            request[TYPE_SIZE: TYPE_SIZE + self.conn_id_size
                    ] == self.recv_conn_id):
            self.close()

    def process_capture(self, req_type: bytes, request: bytes):
        """Called by process_request() to process
        request with an unknown request type.

        May be overriden.

        """

    def process_request(self, req_type: bytes, request: bytes):
        """Process request, parsing the datagram packet.

        May be overriden for other request types.

        """
        match req_type:
            case ReqType.ENQ:
                self.process_enq(request)
            case ReqType.ACK:
                self.process_ack(request)
            case ReqType.NAK:
                self.process_nak(request)
            case ReqType.SYN:
                self.process_syn(request)
            case ReqType.EOT:
                self.process_eot(request)
            case _:
                self.process_capture(req_type, request)

    def process(self, request: bytes):
        """Split the request type."""
        self.process_request(request[:TYPE_SIZE], request)

    def send_packages(self, packages: Iterable[bytes]):
        """Send a list of node packages.

        Encrypt the packages, split the encrypted
        packages into at least one node packets.
        The size of a node packet is not greater
        than the max_packet_size of target node.

        """
        buf = BytesIO()
        for package in packages:
            # Encrypt data
            package = self.cipher_key.encrypt(package)
            size = len(package)
            if size < 128:
                size = size.to_bytes()
            else:
                for size_len in range(1, 256):
                    if size < 1 << size_len * 8:
                        break
                else:
                    raise AssertionError
                size = size.to_bytes(size_len, BYTEORDER)
                size_len = (size_len + 128).to_bytes()
                size = size_len + size
            buf.write(size + package)
        buf.seek(0)
        size = self.max_packet_size
        with self._send_buf_lock:
            is_latest = not bool(self._send_buf)
            while packet := buf.read(size):
                self._send_seq += 1
                if (seq := self._send_seq) < self._max_seq_number:
                    seq = seq.to_bytes(self.seq_size, BYTEORDER)
                else:
                    raise NotImplementedError("No sequence number available")
                packet = ReqType.ENQ + seq + packet
                packet += self.mac_key.digest(packet)
                self._send_buf.append(Packet(seq, packet))
            if not self._send_buf:
                return
            if is_latest:
                # No previous packets to send
                self.update_deadline()
                packet = self._send_buf[0].data
                self.node.socket.sendto(packet, self.address)
                with self.node.group_lock:
                    self.node.retrans_cons.add(self)

    def send(self, package: bytes):
        """Send a node package."""
        self.send_packages((package,))

    def update_deadline(self):
        """Reset deadline from current time.

        May be overriden.

        """
        self.deadline = time() + self.node.timeout * 2 ** self._retries

    def retransmit(self):
        """Retransmit the latest packet sent.

        If self._retries == self.node.retries,
        then close the connection.

        """
        if self._retries < self.node.retries:
            with self._send_buf_lock:
                if self._send_buf:
                    _, packet = self._send_buf[0]
            self.node.socket.sendto(packet, self.address)
            self._retries += 1
            self.update_deadline()
        else:
            self.close()


class HalfConnection(Connection):

    """Unestablished session."""

    multithreaded = True

    def __init__(self, address, node):
        super().__init__(address, node)
        self._recv_seq = 0
        self.recv_conn_id: bytes = None
        self.max_packet_size: int = None
        self.mac_key = authentication.NoDigest.generate()
        self.digest_key: authentication.Digest = None
        self.asym_keys: tuple[
            asymmetric.AsymmetricSecret, bytes, bytes] = None
        self.kdf: kdf.KDF = None
        self.cipher_key = cipher.NoCipher.generate()
        self._alg_buf: deque[str] = deque()
        self._session: BaseSession = None

    @property
    def recv_seq(self) -> int:
        """Sequence number received."""
        return self._recv_seq

    @property
    def max_seq_number(self) -> int:
        """Maximum sequence number to send."""
        return self._max_seq_number

    @property
    def send_seq(self) -> int:
        """Sequence number sent."""
        return self._send_seq

    def setup(self):
        """Setup, called by start();

        Overriden by ServerClass.

        """
        self.handle = self.handle_alg

    retransmit = in_queue('_queue')(Connection.retransmit)

    def finish(self):
        """Do nothing if the first message have not been accepted."""
        self.is_finished = True

    def check_version(self):
        """Check protocol version of client.

        Raise ValueError to close the connection.

        """
        if not self.version.startswith(self.node.version):
            raise ValueError("Protocol version not supported")

    def handle_alg(self, data: bytes):
        """Handle algorithm package."""
        try:
            self._alg_buf.append(str(data, ENCODING))
        except UnicodeDecodeError:
            self.close()
            return
        self.handle = self._handlers.popleft()

    def handle_in_session(self, data: bytes):
        """Handle package in session."""
        if self._session is not None:
            self._session.handle(data)

    @staticmethod
    def get_init_seq(max_seq_number: int) -> int:
        """Generate initial sequence number."""
        return randbelow(max_seq_number // 2) + 1

    random_bytes = staticmethod(token_bytes)
    random_bytes.__doc__ = """Generate random bytes."""

    get_digest = staticmethod(authentication.get_digest)
    get_digest.__doc__ = """Get digest class.

    May be overriden like this to support other digest methods:

    @staticmethod
    def get_digest(alg):
        match alg:
            case 'digestalg1':
                return DigestAlgClass1
            case 'digestalg2':
                return DigestAlgClass2
        return super().get_digest(alg)

    """

    @staticmethod
    @abstractmethod
    def get_exchange(alg: str) -> type[asymmetric.AsymmetricSecret]:
        """Get asymmetric key for key exchange."""

    get_cipher = staticmethod(cipher.get_cipher)
    get_cipher.__doc__ = """Get symmetric encryptor class.

    May be overriden for other symmetric encryption algorithms.

    """

    get_mac = staticmethod(authentication.get_mac)
    get_mac.__doc__ = """Get message authenticator class.

    May be overriden for other message authentication algorithms.

    """

    get_kdf = staticmethod(kdf.get_kdf)
    get_mac.__doc__ = """Get key derivation class.

    May be overriden for other key derivation functions.

    """


class ConnectionToClient(HalfConnection):

    """Unestablished session to server node."""

    seq_size = 4

    def __init__(self, address: Address, node):
        super().__init__(address, node)
        self._max_seq_number = 1 << self.seq_size * 8
        self._send_seq = self.get_init_seq(self._max_seq_number)
        self.conn_id_size = 0
        self.send_conn_id = b''
        self._handlers = deque([self.handle_asym,
                                self.handle_mac])
        if self.multithreaded:
            self._queue: Queue[bytes | None] = node.client_request_queue

    def process_init(self, request: bytes):
        """Process initial message."""
        self.process_syn = do_nothing
        self.process = MethodType(
            in_queue('_queue')(Connection.process), self)
        self.process_hello(request)

    process = process_init

    @in_queue('_queue')
    def process_hello(self, request: bytes):
        """Process SYN message.

        request == (
            syn +               # SYN request type
            conn_id +           # connection ID
            ver_size + ver +    # version
            alg_size + alg +    # hash algorithm with its size
            max_packet_size +   # max node packet size
            reservation +       # compatible with extra bytes
            mac                 # MAC
            )

        """
        buf = BytesIO(request)
        buf.seek(TYPE_SIZE)
        try:
            # Connection ID
            size = buf.read(1)
            self.conn_id_size = size[0] + 1
            self.recv_conn_id = size + buf.read(size[0])
            # Check protocol version
            size = int.from_bytes(buf.read(ALG_SIZE_LEN), BYTEORDER)
            self.version = buf.read(size)
            self.check_version()
            # Verify MAC
            size = int.from_bytes(buf.read(ALG_SIZE_LEN), BYTEORDER)
            alg = str(buf.read(size), ENCODING)
            mac_key = self.get_digest(alg).generate()
            index = -mac_key.digest_size
            data, mac = request[:index], request[index:]
            dig = mac_key.digest(data)
            self.mac_key = mac_key
            self.digest_key = mac_key
            if not compare_digest(mac, dig):
                raise ValueError("Request not authentic")
            # Max node packet size
            max_size = buf.read(PACKET_SIZE_LEN)
            max_size = (int.from_bytes(max_size, BYTEORDER)
                        - TYPE_SIZE - self.seq_size - mac_key.digest_size)
            if max_size <= 0:
                raise ValueError("Invalid node packet size")
            self.max_packet_size = max_size
        except ValueError:
            # Close the connection
            self.close()
            return
        self.process_syn = super().process_syn
        # Acknowledge
        self.send_ack()
        self.finish = MethodType(Connection.finish, self)

    def send_ack(self):
        """Called by process_syn to send ACK for SYN.

        datagram_packet == (
            ack +               # ACK request type
            conn_id +           # connection ID
            ver_size + ver +    # version
            seq_size +          # sequence number size
            max_packet_size +   # max node packet size
            mac                 # MAC
            )

        """
        buf = BytesIO()
        # ReqType
        buf.write(ReqType.ACK)
        # Connection ID
        self.send_conn_id = ((self.conn_id_size - 1).to_bytes() +
                             self.random_bytes(self.conn_id_size - 1))
        buf.write(self.send_conn_id)
        # Protocol version
        ver = self.node.version
        buf.write(len(ver).to_bytes(ALG_SIZE_LEN, BYTEORDER))
        buf.write(ver)
        # Sequence number size
        buf.write(self.seq_size.to_bytes())
        # Max UDP packet size
        buf.write(self.node.max_packet_size.to_bytes(
            PACKET_SIZE_LEN, BYTEORDER))
        # Check packet size
        data = buf.getvalue()
        if len(data) > TYPE_SIZE + self.seq_size + self.max_packet_size:
            # Packet size exceeds
            self.close()
            return
        # MAC
        buf.write(self.mac_key.digest(data))
        # Send ACK message
        self.node.socket.sendto(buf.getvalue(), self.address)

    get_exchange = staticmethod(asymmetric.get_server_exchange)

    def handle_asym(self, recv_key: bytes):
        """Handle recv_key and send algorithms and send_key for key exchange.

        packages == (kdf_alg, cipher_alg, send_key)

        """
        self.handle = self.handle_alg
        try:
            # Key exchange
            asym_alg = self._alg_buf.popleft()
            secret = self.get_exchange(asym_alg).generate()
            shared_key, send_key = secret.exchange(recv_key)
            self.asym_keys = (secret, send_key, recv_key)
            # Key derivation function
            kdf_alg = self.node.kdf_alg
            self.kdf = self.get_kdf(kdf_alg).generate()
            # Symmetric key
            cipher_alg = self.node.cipher_alg
            cipher = self.get_cipher(cipher_alg)
            cipher_key = cipher.from_bytes(
                self.kdf.derive(shared_key, cipher.key_size))

        except (IndexError, ValueError):
            # Close the connection
            self.close()
            return

        # Send package without cipher
        kdf_alg = bytes(kdf_alg, ENCODING)
        cipher_alg = bytes(cipher_alg, ENCODING)
        self.send_packages((kdf_alg, cipher_alg, send_key))
        self.cipher_key = cipher_key

    def handle_mac(self, key: bytes):
        """Handle key for message authentication."""
        self.handle = self.handle_in_session
        try:
            self.mac_key = self.get_mac(
                self._alg_buf.popleft()).from_bytes(key)
        except (IndexError, ValueError):
            # Close the connection
            self.close()
            return
        self.max_packet_size += (self.digest_key.digest_size -
                                 self.mac_key.digest_size)

        # Establish the session
        self._session = self.node.establish_session(self)
        # Close but not finish the connection
        self.finish = do_nothing
        self.close()

    def close(self):
        """Close the connection."""
        with self.node.group_lock:
            if self.address in self.node.clients:
                del self.node.clients[self.address]
            super().close()


class ConnectionToServer(HalfConnection):

    """Unestablished session to server node."""

    conn_id_size = 16

    def __init__(self, address: Address, node):
        super().__init__(address, node)
        self._max_seq_number: int = None
        self._send_seq: int = None
        self.send_conn_id = ((self.conn_id_size - 1).to_bytes() +
                             self.random_bytes(self.conn_id_size - 1))
        self._temp_key = None
        self._handlers = deque([self.handle_alg,
                                self.handle_asym])
        if self.multithreaded:
            self._queue: Queue[bytes | None] = node.server_request_queue

    @in_queue('_queue')
    def setup(self):
        """Send SYN message at first to start the connection.

        datagram_packet == (
            syn +               # SYN request type
            conn_id +           # connection ID
            ver_size + ver +    # version
            alg_size + alg +    # hash algorithm with its size
            max_packet_size +   # max node packet size
            mac                 # MAC
        )

        """
        super().setup()
        buf = BytesIO()
        # ReqType
        buf.write(ReqType.SYN)
        # Connection ID
        buf.write(self.send_conn_id)
        # Protocol version
        ver = self.node.version
        buf.write(len(ver).to_bytes(ALG_SIZE_LEN, BYTEORDER))
        buf.write(ver)
        # Hash algorithm
        alg = self.node.digest_alg
        self.mac_key = self.get_digest(alg).generate()
        self.digest_key = self.mac_key
        alg = bytes(alg, ENCODING)
        buf.write(len(alg).to_bytes(ALG_SIZE_LEN, BYTEORDER))
        buf.write(alg)
        # Max datagram packet size
        buf.write(self.node.max_packet_size.to_bytes(PACKET_SIZE_LEN,
                                                     BYTEORDER))
        # MAC
        mac = self.mac_key.digest(buf.getvalue())
        buf.write(mac)
        # Send SYN message
        packet = buf.getvalue()
        # No send() calling during this period, so no lock acquiring now
        self._send_buf.appendleft(Packet(None, packet))
        self.node.socket.sendto(packet, self.address)
        self.update_deadline()
        with self.node.group_lock:
            self.node.retrans_cons.add(self)

    def process_init(self, request: bytes):
        """Process initial message."""
        self.process_ack = do_nothing
        self.process = MethodType(
            in_queue('_queue')(Connection.process), self)
        self.process_hello(request)

    process = process_init

    @in_queue('_queue')
    def process_hello(self, request: bytes):
        """Process ACK message.

        request == (
            ack +               # ACK request type
            conn_id +           # connection ID
            ver_size + ver +    # version
            seq_size +          # sequence number size
            max_packet_size +   # max node packet size
            reservation +       # compatible with extra bytes
            mac                 # MAC
        )

        """
        try:
            # Check request type
            if (req_type := request[:TYPE_SIZE]) != ReqType.ACK:
                if req_type == ReqType.SYN:
                    # Identify the SYN message of session
                    buf = BytesIO(request)
                    buf.seek(TYPE_SIZE)
                    recv = int.from_bytes(buf.read(buf.read(1)[0]),
                                          BYTEORDER, signed=True)
                    send = int.from_bytes(self.send_conn_id[1:],
                                          BYTEORDER, signed=True)
                    # If (recv < 0) != (send < 0),
                    # then accept received SYN if recv >= send
                    # If (recv < 0) == (send < 0),
                    # then accept received SYN if recv < send
                    recv_is_less = recv < send
                    send_is_neg = send < 0
                    if (send_is_neg and recv_is_less
                        if recv < 0 else
                        send_is_neg or recv_is_less):
                        self.close()
                        self.node.establish_conn_to_client(request,
                                                           self.address)
                raise ValueError("Invaild request type")
            # Verify MAC
            mac_key = self.mac_key
            index = -mac_key.digest_size
            msg, mac = request[:index], request[index:]
            dig = mac_key.digest(msg)
            if not compare_digest(mac, dig):
                raise ValueError("Request not authentic")
            buf = BytesIO(msg)
            buf.seek(TYPE_SIZE)
            # Connection ID
            size = buf.read(1)
            self.recv_conn_id = size + buf.read(size[0])
            # Check protocol version
            size = int.from_bytes(buf.read(ALG_SIZE_LEN), BYTEORDER)
            self.version = buf.read(size)
            self.check_version()
            # Sequence number size
            self.seq_size = buf.read(1)[0]
            # Max node packet size
            max_size = buf.read(PACKET_SIZE_LEN)
            max_size = (int.from_bytes(max_size, BYTEORDER)
                        - TYPE_SIZE - self.seq_size - mac_key.digest_size)
            if max_size <= 0:
                raise ValueError("Invalid node packet size")
        except ValueError:
            self.process = self.process_init
            return
        self._send_buf.clear()
        self._max_seq_number = 1 << self.seq_size * 8
        self._send_seq = self.get_init_seq(self._max_seq_number)
        self.max_packet_size = max_size
        # Key exchange
        self.process_ack = super().process_ack
        self.send_asym()
        self.finish = MethodType(Connection.finish, self)

    get_exchange = staticmethod(asymmetric.get_client_exchange)

    def send_asym(self):
        """Send asymmetric key for key exchange.

        packages == (alg, send_key)

        """
        # Generate key pair
        alg = self.node.key_exchange_alg
        secret = self.get_exchange(alg).generate()
        send_key = secret.public_bytes()
        self.asym_keys = (secret, send_key, None)
        # Reset sending buffer
        self._send_buf.clear()
        alg = bytes(alg, ENCODING)
        # Send packages
        self.send_packages((alg, send_key))

    def handle_asym(self, recv_key: bytes):
        """Handle asymmetric key for key exchange."""
        self.handle = self.handle_in_session
        self.process_ack = self.process_mac_ack
        try:
            # Key derivation function
            self.kdf = self.get_kdf(self._alg_buf.popleft()).generate()
            # Cipher algorithm
            cipher = self.get_cipher(self._alg_buf.popleft())
            # Key exchange
            secret, send_key, _ = self.asym_keys
            shared_key = secret.exchange(recv_key)
            self.cipher_key = cipher.from_bytes(
                self.kdf.derive(shared_key, cipher.key_size))
        except (IndexError, ValueError):
            # Close the connection
            self.close()
            return
        self.asym_keys = (secret, send_key, recv_key)
        # Send MAC package
        self.send_mac()

    def send_mac(self):
        """Send key for message authentication.

        packages == (alg, key)  # key will be encrypted in send_packages()

        """
        # Algorithm
        alg = self.node.mac_alg
        self._temp_key = self.get_mac(alg).generate()
        alg = bytes(alg, ENCODING)
        # Send package
        self.send_packages((alg, self._temp_key.to_bytes()))

    def process_mac_ack(self, request: bytes):
        """Process ACK message for MAC key."""
        super().process_ack(request)
        if not self._send_buf:
            # MAC key was sent successfully
            self.process_ack = super().process_ack
            self.mac_key = self._temp_key
            self.max_packet_size += (self.digest_key.digest_size -
                                     self.mac_key.digest_size)
            # Establish the session
            self._session = self.node.establish_session(self)
            # Close but not finish the connection
            self.finish = do_nothing
            self.close()

    def close(self):
        """Close the connection."""
        with self.node.group_lock:
            if self.address in self.node.servers:
                del self.node.servers[self.address]
            super().close()


class BaseSession(Connection):

    """Base session class.
    Established session to the other node.

    Methods for the caller:

    - from_connection(conn: HalfConnection)
    - process(request: bytes)
    - start()
    - finish()
    - stop()
    - close()
    - send(package: bytes)
    - send_packages(packages: typing.Iterable[bytes])

    Methods that should be overriden:
    - handle(data: bytes)

    Methods that may be overridden:

    - setup()
    - finish()

    # if not multi-threaded for sessions
    - start()
    - setup()
    - process()
    - stop()

    - close()
    - process_capture(req_type: bytes, buf: io.BytesIO)
    - process_request(req_type: bytes, buf: io.BytesIO)

    Class variables:
    - multithreaded : bool
        If multithread to process requests.

    Instance variables:

    - address : Address
        Target address.
    - node : Node
        Node reflection.

    - version : bytes
        Protocol version of target node.
    - recv_conn_id : bytes
        Session ID received.
    - send_conn_id : bytes
        Session ID sent.
    - max_packet_size : int
        max_packet_size == (max_udp_packet_size - TYPE_SIZE
           - self.seq_size - self.mac_key.digest_size)
        Maximum available size for a node packet to send.
    - seq_size : int
        Byte length of sequence numbers receving.

    - asym_keys : tuple[asymmetric.AsymmetricSecret, bytes, bytes]
        Secret key, public key sent and public key received.
    - cipher_key : cipher.SymmetricKey
        Symmetric encryptor.
    - digest_key : authentication.MACKey
        Message authenticator not used.
    - mac_key : authentication.MACKey
        Message authenticator.

    - _queue : Queue
        Queue of requests to process.

    """

    multithreaded = True

    def __init__(self, conn: HalfConnection):
        """Constructor.

        Establish a session.

        """
        super().__init__(conn.address, conn.node)
        # Session info
        self.version = conn.version
        self.conn_id_size = conn.conn_id_size
        self.recv_conn_id = conn.recv_conn_id
        self.send_conn_id = conn.send_conn_id
        # Transmission
        self.max_packet_size = conn.max_packet_size
        self.seq_size = conn.seq_size
        self._recv_seq = conn.recv_seq
        self._max_seq_number = conn.max_seq_number
        self._send_seq = conn.send_seq
        # Security
        self.asym_keys = conn.asym_keys
        self.cipher_key = conn.cipher_key
        self.digest_key = conn.digest_key
        self.mac_key = conn.mac_key
        # Multi-threading
        if self.multithreaded:
            self._queue: Queue[bytes | None] = Queue()
            self.thread = Thread(target=call_forever,
                                 args=(self._queue,))

    @classmethod
    def from_connection(cls, conn: HalfConnection) -> Self:
        """Establish a session from a connection."""
        return cls(conn)

    def start(self):
        """Start the session thread after instance initialized.

        May be overriden for single-threading.

        """
        if self.multithreaded:
            self.thread.start()
        super().start()

    process = in_queue('_queue')(Connection.process)

    def stop(self):
        """Stop the session thread, called by close().

        May be overriden.

        """
        if self.multithreaded:
            self._queue.put_nowait(None)

    def close(self):
        """Close session, interrupt thread if multi-threaded."""
        with self.node.group_lock:
            if self.address in self.node.sessions:
                del self.node.sessions[self.address]
            super().close()


class Node(UDPServer):

    """Base class for node classes.

    Methods for the caller:

    - __init__(server_address, SessionClass)
    - serve_forever(poll_interval=0.5)
    - close()

    Methods that may be overridden:

    - handle_timeout()
    - verify_request(request, client_address) -> bool
    - shutdown_request(request)
    - close_request(request)
    - handle_error()

    Class variables:
    - version : bytes
    - max_packet_size : int
    - ClientClass = ConnectionToClient
    - ServerClass = ConnectionToServer
    - has_thread_as_client : bool
    - has_thread_as_server : bool
    - keepalive_interval : Real
    - keepalive_timeout : Real
    - timeout : Real
    - retries : int
    - digest_alg : str
    - key_exchange_alg : str
    - cipher_alg : str
    - mac_alg : str
    - kdf_alg : str

    Instance variables:

    - sessions : dict[Address, BaseSession]
        Information of established sessions.
    - clients : dict[Address, ConnectionToClient]
        Information of connections,
        target nodes as clients, self as server.
    - servers : dict[Address, ConnectionToServer]
        Information of connections,
        target nodes as servers, self as client.

    - dead_cons : set[Connection]
        Dead connections not having sent any message.
    - retrans_cons: set[Connection]
        Connections that need retransmission.

    - group_lock : threading.Lock
        To lock groups, such as sessions and dead_cons.

    - __keepalive_send_time : Real
        Time to send keepalive packets.
    - __keepalive_deadline : Real
        Deadline for others to send keepalive packest.

    - client_request_queue : Queue[tuple[bytes, ConnectionToClient]]
    - server_request_queue : Queue[tuple[bytes, ConnectionToServer]]
    - threads : list[threading.Threads]

    """
    # Infomation in connection
    version = b'node2'  # version of protocol, for others to identify it
    max_packet_size = 512
    # Classes
    ClientClass = ConnectionToClient
    ServerClass = ConnectionToServer
    # Multi-threading
    has_queue_to_server = True
    has_queue_to_client = True
    # Keepalive
    keepalive_interval: Real = 15
    keepalive_timeout: Real = 30
    # Retransmission
    timeout: Real = 1
    retries = 6
    # Algorithms
    digest_alg = 'sha256'
    key_exchange_alg = 'x25519'
    cipher_alg = 'aes256'
    mac_alg = 'hmac-sha256'
    kdf_alg = 'hkdf_extract-md5'

    def __init__(
        self,
        server_address: Address,
        SessionClass: type[BaseSession],
        bind_and_activate=True
    ):

        self.SessionClass = SessionClass
        self.sessions: dict[Address, BaseSession] = {}
        self.clients: dict[Address, ConnectionToClient] = {}
        self.servers: dict[Address, ConnectionToServer] = {}
        self.retrans_cons: set[Connection] = set()
        self.dead_cons: set[Connection] = set()
        self.group_lock = Lock()

        self.__keepalive_send_time = time() + self.keepalive_interval
        self.__keepalive_deadline = time() + self.keepalive_timeout

        # Multi-thread
        # As client
        if self.has_queue_to_server:
            self.server_request_queue: Queue[
                tuple[bytes, ConnectionToServer] | None
            ] = Queue()
            self.server_request_thread = Thread(
                target=call_forever, args=(self.server_request_queue,))
        # As server
        if self.has_queue_to_client:
            self.client_request_queue: Queue[
                tuple[bytes, ConnectionToClient] | None
            ] = Queue()
            self.client_request_thread = Thread(
                target=call_forever, args=(self.client_request_queue,))

        super().__init__(server_address, SessionClass, bind_and_activate)

    def server_activate(self):
        """Start the threads."""
        if self.has_queue_to_server:
            self.server_request_thread.start()
        if self.has_queue_to_client:
            self.client_request_thread.start()

    def service_actions(self):
        """Keepalive and retransmission."""
        now = time()
        with self.group_lock:
            if now >= self.__keepalive_send_time:
                if now >= self.__keepalive_deadline:
                    # Close all dead connections
                    for con in self.dead_cons:
                        con.close()
                    # Reset status
                    self.dead_cons = set(
                        (self.sessions |
                         self.servers |
                         self.clients).values())
                    # Reset deadline
                    self.__keepalive_deadline = time(
                    ) + self.keepalive_timeout
                # Send keepalive packets
                # To established sessions only
                for con in self.sessions.values():
                    self.socket.sendto(b'', con.address)
                # Reset time to send keepalive packet
                self.__keepalive_send_time = now + self.keepalive_interval

            # Retransmission
            for con in self.retrans_cons:
                if now >= con.deadline:
                    con.retransmit()

    def get_request(self):
        """Get the request from the socket"""
        request, client_addr = self.socket.recvfrom(self.max_packet_size)
        return request, client_addr[: 2]

    def process_request(self, request: bytes, target_address: Address):
        """Process one request."""
        with self.group_lock:
            for group in (self.sessions, self.servers, self.clients):
                if con := group.get(target_address):
                    if con in self.dead_cons:
                        # Connection alive
                        self.dead_cons.remove(con)
                    if request:
                        con.process(request)
                    return
        if request and request[:TYPE_SIZE] == ReqType.SYN:
            # New connection
            self.establish_conn_to_client(request, target_address)

    def connect(self, address: Address) -> ConnectionToClient:
        """New connection to server."""
        conn = self.ServerClass(address, self)
        with self.group_lock:
            self.servers[address] = conn
        conn.start()
        return conn

    def establish_conn_to_client(
            self, request: bytes, addr: Address) -> ConnectionToClient:
        """New connection from client, called by process_request()."""
        conn = self.ClientClass(addr, self)
        # Lock acquired by caller process_request()
        self.clients[addr] = conn
        conn.start()
        conn.process(request)
        return conn

    def establish_session(self, conn: HalfConnection) -> BaseSession:
        """Establish a new session, called by HalfConnection methods."""
        con = self.SessionClass.from_connection(conn)
        with self.group_lock:
            self.sessions[conn.address] = con
        con.start()
        return con

    def close(self):
        """Shutdown and clean up."""
        self.shutdown()
        self.server_close()

    def server_close(self):
        """Called to clean up the node."""
        if self.has_queue_to_client:
            self.client_request_queue.put(None)
            self.client_request_thread.join()
        if self.has_queue_to_server:
            self.server_request_queue.put(None)
            self.server_request_thread.join()

        for cls, group in ((self.SessionClass, self.sessions),
                           (self.ServerClass, self.servers),
                           (self.ClientClass, self.clients)):
            if cls.multithreaded:
                for con in group.values():
                    con.finish()
                    con.stop()
                    con.thread.join()

    def handle_request(self, *args):
        """Use module self.SessionClass.handle instead."""
        raise

    def finish_request(self, *args):
        """Use module self.SessionClass.handle instead."""
        raise
