# Copyright (c) 2022-2024 SiumLhahah
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
ilfocore.udpnode

Node based on UDP.

"""

from abc import ABCMeta, abstractmethod
from collections import deque
from collections.abc import Callable, Iterable
from functools import wraps
from hmac import compare_digest
from io import BufferedReader, BytesIO
from queue import Queue
from secrets import randbelow, token_bytes
from socket import SOCK_DGRAM, getaddrinfo
from socketserver import UDPServer
from threading import RLock, Thread
from time import monotonic as time
from types import MethodType
from typing import Self

from .constants import (
    BYTEORDER,
    ENCODING,
    PACKET_SIZE_LEN,
    TYPE_SIZE,
    Address,
    ReqType
)
from .lib import asymmetric, authentication, cipher, kdf
from .utils import (
    do_nothing,
    read_by_size,
    read_integral,
    write_integral,
    write_with_size
)
from .utils.multithread import call_forever, in_queue


class Connection(metaclass=ABCMeta):

    """Base class for connection classes.

    Methods for the caller:

    - __init__(address: Address, node: Node)
    - process(buf: BytesIO)
    - retransmit(now : int)
    - send(data: bytes | Iterable[bytes]) -> last_seq

    Methods that may be overridden:

    - handle(buf: BytesIO)
    - process_request(req_type: bytes, buf: BytesIO)
    - process_capture(req_type: bytes, buf: BytesIO)
    - finish()
    - close()
    - update_deadline()

    """

    # Class variables:
    multithreaded = False   # If multithread to process requests

    # Instance variables:
    # Basic connection properties
    address: Address   # Target address
    node: 'Node'       # Node reflection.

    data: object       # Stable data of unestablished connections to server

    # For sending
    _send_pkts: list[bytes]     # Datagram packets for retransmission
    _deadline: float            # Deadline to retransmit datagram packet
    _retries: int               # Retransmission times counting
    # For receiving
    _recv_pkts: list[BytesIO]   # Datagram packets received but not parsed

    # For parsing
    _recv_buf: BytesIO     # Buffer for packing node packages
    __not_packing: bool    # If not packing a node package
    __size_left: int       # The size of the rest of a node package
    is_finished: bool      # If the connection is finished
    #                        then it won't handle any packages

    # Multi-threading
    _send_lock: RLock           # Lock of sending process
    _queue: Queue[bytes | None]  # Queue of requests to handle

    # Basic connection information
    version: bytes          # Protocol version of target node
    max_packet_size: int    # Maximum available size for a node packet to send
    # max_packet_size ==
    # max_udp_packet_size - TYPE_SIZE - _recv_seq_size - mac_key.digest_size
    conn_id_size: int       # Size of connection ID
    recv_conn_id: bytes     # Connection ID received
    send_conn_id: bytes     # Connection ID sent

    # Basic transmissino information
    send_seq_size: int      # Byte length of sequence numbers sending
    _send_seq: int          # Sequnce number of _send_pkts[0]
    _max_seq_number: int
    _recv_seq_size: int
    _recv_seq: int          # Sequnce number of _recv_pkts[0]

    # Security
    mac_key: authentication.Digest     # Message authenticator
    digest_key: authentication.Digest  # Temporary message authenticator
    asym_keys: tuple[asymmetric.AsymmetricSecret, bytes, bytes]
    # Secret key, public key sent and public key received
    kdf: kdf.KDF                       # Key derivation function
    cipher_key: cipher.SymmetricKey    # Symmetric encryptor

    def __init__(self, address: Address, node: 'Node', data=None):
        self.address = address
        self.node = node
        self.data = data

        self._send_pkts = []
        self._deadline = 0
        self._retries = 0

        self._recv_pkts = []

        self._recv_buf = BytesIO()
        self.__not_packing = True
        self.__size_left = 0
        self.is_finished = False

        self._send_lock = RLock()

    @classmethod
    def from_connection(cls, conn: Self) -> Self:
        """Establish a connection from another one."""
        self = cls(conn.address, conn.node, conn.data)
        return self

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

    def handle(self, buf: BufferedReader):
        """Handle a package buffer.

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

    def _parse(self, buf: BytesIO) -> BufferedReader | None:
        """Parse node packages which may be like these:

            p1 = b'\x02abc'
            l1, d1 = b'\x02', b'ab'
            p1 == l1 + d1

            p2 = b'\x82\x00\x80'
            l2, d2 = b'\x82\x00\x80', b'a' * 128
            p2 == l2 + d2

        And the result parsed:

            conn._parse(BytesIO(p1)) == b'abc'
            conn._parse(BytesIO(p2)) == b'a' * 128

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

        """
        recv_buf = self._recv_buf
        if self.__not_packing:
            # Not packing a package
            # May be packing size of a package
            is_packing_size = True
            if not (size_len := self.__size_left):
                # Not packing the size
                # Brand new package
                size_len = int.from_bytes(buf.read(1))
                if size_len < 128:
                    self.__size_left = size_len
                    is_packing_size = False
                else:
                    size_len -= 128
                    is_packing_size = bool(size_len)
            if is_packing_size:
                # Try to get the size from bytes
                size = buf.read(size_len)
                written = recv_buf.write(size)
                if written >= size_len:
                    # Got all bytes in need
                    recv_buf.seek(0)
                    self.__size_left = int.from_bytes(
                        recv_buf.read(), BYTEORDER)
                    # Start to pack the package
                    recv_buf.seek(0)
                    recv_buf.truncate()
                    self.__not_packing = False
                else:
                    # Continue to pack the size
                    self.__size_left = size_len - written
                    return None
            else:
                # Start to pack the package
                self.__not_packing = False

        self.__size_left -= len(part := buf.read(self.__size_left))
        recv_buf.write(part)
        if not self.__size_left:
            # Reset status
            self.__not_packing = True
            self._recv_buf = BytesIO()
            # Return the full package buffer
            recv_buf.seek(0)
            return BufferedReader(recv_buf)
        return None

    def verify_mac(self, buf: BytesIO) -> bool:
        """Verify MAC."""
        req = buf.getvalue()
        if dig_size := self.mac_key.digest_size:
            index = -dig_size
            msg, mac = req[:index], req[index:]
            buf.truncate(len(msg))
        else:
            msg, mac = req, b''
        return compare_digest(mac, self.mac_key.digest(msg))

    def acknowledge(self):
        """Send ACK message to target."""
        ack = ReqType.ACK + (
            self._recv_seq - 1).to_bytes(self._recv_seq_size, BYTEORDER)
        self.node.socket.sendto(ack + self.mac_key.digest(ack), self.address)

    def process_enq(self, buf: BytesIO):
        """Called by process_request() to process ENQ message."""
        auth = self.verify_mac(buf)
        seq_bytes = buf.read(self._recv_seq_size)
        if not auth:
            # Prompt other node to retransmit
            self.node.socket.sendto(ReqType.NAK + seq_bytes, self.address)
            return
        seq = int.from_bytes(seq_bytes, BYTEORDER)
        if self._recv_seq is None:
            # For compatibility
            self._recv_seq = seq

        if (index := seq - self._recv_seq) < 0:
            return
        pad_size = index - len(recv_pkts := self._recv_pkts)
        if pad_size >= 0:
            recv_pkts += [None] * pad_size
            recv_pkts.append(buf)
        else:
            recv_pkts[index] = buf
        if index:
            return

        end = recv_pkts.index(None) if None in recv_pkts else len(recv_pkts)
        self._recv_pkts = recv_pkts[end:]
        self._recv_seq += end
        # Acknowledge
        # Target not received the acknowledge
        # have to retransmit the datagram packet
        self.acknowledge()
        # Parse packets into packages
        for buf in recv_pkts[:end]:
            size = len(buf.getvalue())
            while buf.tell() < size:
                try:
                    pkg_buf = self._parse(buf)
                except OverflowError:
                    self.close()
                    return
                if pkg_buf is None:
                    break
                # Decrypt package
                try:
                    pkg_buf = BufferedReader(BytesIO(
                        self.cipher_key.decrypt(pkg_buf.read())))
                except ValueError:
                    return
                if self.is_finished:
                    break
                # Handle package
                self.handle(pkg_buf)

    def acknowledged(self, seq: int):
        """Received ACK message from target."""

    def process_ack(self, buf: BytesIO):
        """Called by process_request() to process ACK message.

        Overriden by ClientClass.

        """
        if not self.verify_mac(buf):
            return
        # Data packet was sent successfully
        seq = int.from_bytes(buf.read(self.send_seq_size), BYTEORDER)
        next_seq = seq + 1
        # Ignore data left in request buffer
        with self._send_lock:
            index = next_seq - self._send_seq
            if (pkts := self._send_pkts) and 0 < index <= len(pkts):
                # Remove packets in send_pkts
                self._send_seq = next_seq
                del pkts[: index]
                # Reset deadline
                self._retries = 0
                self.update_deadline()
                if not pkts:
                    with self.node.group_lock:
                        if self in self.node.retrans_cons:
                            self.node.retrans_cons.remove(self)
                self.acknowledged(seq)

    def process_nak(self, buf: BytesIO):
        """Called by process_request() to process NAK message."""
        with self._send_lock:
            pkts = self._send_pkts
            if pkts:
                index = (int.from_bytes(buf.read(self.send_seq_size),
                                        BYTEORDER)
                         - self._send_seq)
                if 0 <= index < len(pkts):
                    if self._retries >= self.node.retries:
                        self.close()
                        return
                    self.node.socket.sendto(pkts[index], self.address)
                    self._retries += 1
                    self.update_deadline()

    def process_syn(self, buf: BytesIO):
        """Called by process_request() to process SYN message.

        Overriden by ServerClass.

        """
        pos = buf.tell()
        is_same = buf.read(self.conn_id_size) == self.recv_conn_id
        buf.seek(pos)
        if not is_same:
            # New connection
            self.is_finished = True
            self.finish = do_nothing
            self.close()
            self.node.establish_conn_to_client(buf, self.address)

    def process_eot(self, buf: BytesIO):
        """Called by process_request() to process EOT message."""
        if (self.verify_mac(buf) and
                buf.read(self.conn_id_size) == self.recv_conn_id):
            self.close()

    def process_capture(self, req_type: bytes, buf: BytesIO):
        """Called by process_request() to process
        request with an unknown request type.

        May be overriden.

        """

    def process_request(self, req_type: bytes, buf: BytesIO):
        """Process request, parsing the datagram packet.

        May be overriden for other request types.

        """
        match req_type:
            case ReqType.ENQ:
                self.process_enq(buf)
            case ReqType.ACK:
                self.process_ack(buf)
            case ReqType.NAK:
                self.process_nak(buf)
            case ReqType.SYN:
                self.process_syn(buf)
            case ReqType.EOT:
                self.process_eot(buf)
            case _:
                self.process_capture(req_type, buf)

    def process(self, buf: BytesIO):
        """Read the request type."""
        if self.is_finished:
            # Do not process request
            return
        self.process_request(buf.read(TYPE_SIZE), buf)

    def send(self, data: bytes | Iterable[bytes]) -> int:
        """Send a node package or a list of node packages.

        Encrypt the packages, split the encrypted
        packages into at least one node packets.
        The size of a node packet is not greater
        than the max_packet_size of target node.

        Return the sequence number of the last
        node packet sent.

        """
        # Encrypt data
        pkg_buf = BytesIO()
        if isinstance(data, bytes):
            write_with_size(self.cipher_key.encrypt(data), pkg_buf)
        else:
            for pkg in data:
                write_with_size(self.cipher_key.encrypt(pkg), pkg_buf)
        pkg_buf.seek(0)
        pkt_buf = BytesIO(ReqType.ENQ)
        size = self.max_packet_size
        max_seq = self._max_seq_number
        mac_key = self.mac_key
        seq = None
        with self._send_lock:
            while data := pkg_buf.read(size):
                pkt_buf.seek(1)
                if self.is_finished:
                    return
                seq = self._send_seq + len(self._send_pkts)
                if seq < max_seq:
                    seq_bytes = seq.to_bytes(self.send_seq_size, BYTEORDER)
                else:
                    self.close()
                    self.node.connect(self.address)
                    return
                pkt_buf.write(seq_bytes)
                pkt_buf.write(data)
                pkt_buf.truncate()
                pkt_buf.write(mac_key.digest(pkt_buf.getvalue()))
                self._send_pkts.append(data := pkt_buf.getvalue())
                self.node.socket.sendto(data, self.address)
        self.update_deadline()
        with self.node.group_lock:
            self.node.retrans_cons.add(self)
        return seq

    send_packages = send

    def update_deadline(self):
        """Reset deadline from current time.

        May be overriden.

        """
        self._deadline = time() + self.node.timeout * 2 ** self._retries

    def retransmit(self, now: float):
        """Retransmit the latest packet sent.

        If self._retries == self.node.retries,
        then close the connection.

        Return the number of retransmitted packets.

        """
        if now < self._deadline or not self._send_pkts:
            return 0
        if self._retries >= self.node.retries:
            self.close()
            return 0
        with self._send_lock:
            cnt = len(pkts := self._send_pkts)
            for data in pkts:
                self.node.socket.sendto(data, self.address)
        self._retries += 1
        self.update_deadline()
        return cnt

    def __repr__(self) -> str:
        return f"Connection to {self.address}"


class HalfConnection(Connection):

    """Unestablished session."""

    multithreaded = True
    send_seq_size = 4

    _handlers: deque[Callable[[BufferedReader], None]]
    _alg_buf: deque[str]
    _session: 'BaseSession'

    def __init__(self, address, node, data=None):
        super().__init__(address, node, data)
        self._max_seq_number = 1 << self.send_seq_size * 8
        self._send_seq = self.get_init_seq(self._max_seq_number)
        self._recv_size = None
        self._recv_seq = None
        self._recv_pkts = []
        self.version = None
        self.recv_conn_id = None
        self.max_packet_size = None
        self.mac_key = authentication.NoDigest.generate()
        self.digest_key = None
        self.asym_keys = None
        self.kdf = None
        self.cipher_key = cipher.NoCipher.generate()

        self._alg_buf = deque()
        self._session = None

    @property
    def recv_seq_size(self) -> int:
        """Length of recv_seq in bytes."""
        return self._recv_seq_size

    @property
    def recv_seq(self) -> int:
        """Sequence number of the first packet in recv_pkts."""
        return self._recv_seq

    @property
    def send_seq(self) -> int:
        """Sequence number of the first packet in send_pkts."""
        return self._send_seq

    @property
    def max_seq_number(self) -> int:
        """Maximum sequence number can be sent."""
        return self._max_seq_number

    def setup(self):
        """Setup, called by start();

        Overriden by ServerClass.

        """
        self.handle = self.handle_alg

    def finish(self):
        """Do nothing if the first message have not been accepted."""
        self.is_finished = True

    def check_version(self):
        """Check protocol version of client.

        Raise ValueError to close the connection.

        """
        if not self.version.startswith(self.node.version):
            raise ValueError("Protocol version not supported")

    def handle_alg(self, buf: BufferedReader):
        """Handle algorithm package."""
        try:
            self._alg_buf.append(str(buf.read(), ENCODING))
        except UnicodeDecodeError:
            self.close()
            return
        self.handle = self._handlers.popleft()

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

    """Unestablished session to client node."""

    def __init__(self, address, node, data=None):
        super().__init__(address, node, data=None)
        self.conn_id_size = 0
        self.send_conn_id = b''
        self._handlers = deque([self.handle_asym,
                                self.handle_mac])
        if self.multithreaded:
            self._queue = queue = node.client_request_queue
            in_my_queue = in_queue(queue)
            self.retransmit = in_my_queue(self.retransmit)
            self.process_hello = in_my_queue(self.process_hello)

    def process_init(self, buf: BytesIO):
        """Process initial message."""
        self.process_syn = do_nothing
        self.process = in_queue(self._queue)(super().process)
        self.process_hello(buf)

    process = process_init

    def process_hello(self, buf: BytesIO):
        """Process SYN message.

        request == (
            syn +               # SYN request type
            conn_id +           # connection ID
            ver_size + ver +    # version
            alg_size + alg +    # hash algorithm with its size
            max_packet_size +   # max node packet size
            seq_size +          # sequence number size
            init_seq +          # initial sequence number
            reservation +       # compatible with extra bytes
            mac                 # MAC
        )

        """
        try:
            # Connection ID
            size = buf.read(1)
            self.conn_id_size = size[0] + 1
            self.recv_conn_id = size + buf.read(size[0])
            # Check protocol version
            self.version = read_by_size(buf)
            self.check_version()
            # Verify MAC
            alg = str(read_by_size(buf), ENCODING)
            mac_key = self.get_digest(alg).generate()
            self.mac_key = mac_key
            self.digest_key = mac_key
            if not self.verify_mac(buf):
                raise ValueError("Request not authentic")
            # Max node packet size
            max_size = buf.read(PACKET_SIZE_LEN)
            max_size = (int.from_bytes(max_size, BYTEORDER) - TYPE_SIZE
                        - self.send_seq_size - mac_key.digest_size)
            if max_size <= 0:
                raise ValueError("Invalid node packet size")
            self.max_packet_size = max_size
            # Initial sequence number and its size
            size = buf.read(1)
            if size:
                size = size[0]
                self._recv_seq_size = size
                self._recv_seq = int.from_bytes(buf.read(size), BYTEORDER)
            else:
                # For compatibility
                self._recv_seq_size = self.send_seq_size
        except (IndexError, ValueError):
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
            init_seq +          # initial sequence number
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
        write_with_size(self.node.version, buf)
        # Sequence number size
        write_integral(self.send_seq_size, buf)
        # Max UDP packet size
        buf.write(self.node.max_packet_size.to_bytes(
            PACKET_SIZE_LEN, BYTEORDER))
        # Initial sequence number
        buf.write(self._send_seq.to_bytes(self.send_seq_size, BYTEORDER))
        # Check packet size
        data = buf.getvalue()
        if len(data) > (TYPE_SIZE + self._recv_seq_size
                        + self.max_packet_size):
            # Packet size exceeds
            self.close()
            return
        # MAC
        buf.write(self.mac_key.digest(data))
        # Send ACK message
        self.node.socket.sendto(buf.getvalue(), self.address)

    get_exchange = staticmethod(asymmetric.get_server_exchange)

    def handle_asym(self, buf: BufferedReader):
        """Handle recv_key and send algorithms and send_key for key exchange.

        packages == (kdf_alg, cipher_alg, send_key)

        """
        self.handle = self.handle_alg
        recv_key = buf.read()
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
        self.send((kdf_alg, cipher_alg, send_key))
        self.cipher_key = cipher_key

    def handle_mac(self, buf: BufferedReader):
        """Handle key for message authentication."""
        self.handle = do_nothing
        key = buf.read()
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
        # Close but do not send EOT message
        self.finish = super().finish
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
    _temp_key: authentication.MACKey
    _mac_seq: int

    def __init__(self, address, node, data=None):
        super().__init__(address, node, data)
        self.send_conn_id = ((self.conn_id_size - 1).to_bytes() +
                             self.random_bytes(self.conn_id_size - 1))
        self._temp_key = None
        self._mac_seq = None
        self._handlers = deque([self.handle_alg,
                                self.handle_asym])
        if self.multithreaded:
            self._queue = queue = node.server_request_queue
            in_my_queue = in_queue(queue)
            self.retransmit = in_my_queue(self.retransmit)
            self.setup = in_my_queue(self.setup)
            self.process_hello = in_my_queue(self.process_hello)

    def setup(self):
        """Send SYN message at first to start the connection.

        datagram_packet == (
            syn +               # SYN request type
            conn_id +           # connection ID
            ver_size + ver +    # version
            alg_size + alg +    # hash algorithm with its size
            max_packet_size +   # max node packet size
            seq_size +          # sequence number size
            init_seq +          # initial sequence number
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
        write_with_size(self.node.version, buf)
        # Hash algorithm
        alg = self.node.digest_alg
        self.mac_key = self.get_digest(alg).generate()
        self.digest_key = self.mac_key
        write_with_size(bytes(alg, ENCODING), buf)
        # Max datagram packet size
        buf.write(self.node.max_packet_size.to_bytes(PACKET_SIZE_LEN,
                                                     BYTEORDER))
        # Initial sequence number and its size
        buf.write(self.send_seq_size.to_bytes())
        buf.write(self._send_seq.to_bytes(self.send_seq_size, BYTEORDER))
        # MAC
        mac = self.mac_key.digest(buf.getvalue())
        buf.write(mac)
        # Send SYN message
        packet = buf.getvalue()
        # No send() calling during this period, so no lock acquiring now
        self._send_pkts.append(packet)
        self.node.socket.sendto(packet, self.address)
        self.update_deadline()
        with self.node.group_lock:
            self.node.retrans_cons.add(self)

    def process_init(self, buf: BytesIO):
        """Process initial message."""
        self.process_ack = do_nothing
        self.process = in_queue(self._queue)(super().process)
        self.process_hello(buf)

    process = process_init

    def process_hello(self, buf: BytesIO):
        """Process ACK message.

        request == (
            ack +               # ACK request type
            conn_id +           # connection ID
            ver_size + ver +    # version
            seq_size +          # sequence number size
            max_packet_size +   # max node packet size
            init_seq +          # initial sequence number
            reservation +       # compatible with extra bytes
            mac                 # MAC
        )

        """
        try:
            # Check request type
            if (req_type := buf.read(TYPE_SIZE)) != ReqType.ACK:
                if req_type == ReqType.SYN:
                    # Identify the SYN message of session
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
                        buf.seek(TYPE_SIZE)
                        conn = self.node.establish_conn_to_client(
                            buf, self.address)
                        conn.data = self.data
                raise ValueError("Invaild request type")
            # Verify MAC
            if not self.verify_mac(buf):
                raise ValueError("Request not authentic")
            # Connection ID
            size = buf.read(1)
            self.recv_conn_id = size + buf.read(size[0])
            # Check protocol version
            self.version = read_by_size(buf)
            self.check_version()
            # Sequence number size
            size = read_integral(buf)
            self._recv_seq_size = size
            # Max node packet size
            max_size = buf.read(PACKET_SIZE_LEN)
            max_size = (int.from_bytes(max_size, BYTEORDER) - TYPE_SIZE
                        - size - self.mac_key.digest_size)
            if max_size <= 0:
                raise ValueError("Invalid node packet size")
            # Initial sequence number
            init_seq = buf.read(size)
            if init_seq:  # For compatibility
                self._recv_seq = int.from_bytes(init_seq, BYTEORDER)
        except (IndexError, ValueError):
            self.process = self.process_init
            return
        self._send_pkts.clear()
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
        # Reset sending packets buffer
        self._send_pkts.clear()
        alg = bytes(alg, ENCODING)
        # Send packages
        self.send((alg, send_key))

    def handle_asym(self, buf: BufferedReader):
        """Handle asymmetric key for key exchange."""
        self.handle = do_nothing
        recv_key = buf.read()
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

        packages == (alg, key)  # key will be encrypted in send()

        """
        # Algorithm
        alg = self.node.mac_alg
        self._temp_key = self.get_mac(alg).generate()
        alg = bytes(alg, ENCODING)
        # Send package
        self._mac_seq = self.send((alg, self._temp_key.to_bytes()))
        self.acknowledged = self.acknowledged_mac

    def acknowledged_mac(self, seq: int):
        """Try to confirm that target have received MAC key."""
        if seq >= self._mac_seq:
            # MAC key was sent successfully
            self.acknowledged = super().acknowledged
            self.mac_key = self._temp_key
            self.max_packet_size += (self.digest_key.digest_size -
                                     self.mac_key.digest_size)
            # Establish the session
            self._session = self.node.establish_session(self)
            # Close but do not send EOT message
            self.finish = super().finish
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
    - process(request: BytesIO)
    - start()
    - finish()
    - stop()
    - close()
    - send(data: bytes | Iterable[bytes]) -> last_seq

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
    - process_capture(req_type: bytes, buf: BytesIO)
    - process_request(req_type: bytes, buf: BytesIO)

    """

    multithreaded = True

    _recv_raw_pkt_cnt: int
    _was_recving: bool

    _ack_req: bool

    def __init__(self, conn: HalfConnection):
        """Constructor.

        Establish a session.

        """
        super().__init__(conn.address, conn.node, conn.data)

        self.version = conn.version
        self.conn_id_size = conn.conn_id_size
        self.recv_conn_id = conn.recv_conn_id
        self.send_conn_id = conn.send_conn_id

        self.max_packet_size = conn.max_packet_size
        self._recv_seq_size = conn._recv_seq_size
        self._recv_seq = conn._recv_seq
        self.send_seq_size = conn.send_seq_size
        self._max_seq_number = conn.max_seq_number
        self._send_seq = conn.send_seq

        self.asym_keys = conn.asym_keys
        self.cipher_key = conn.cipher_key
        self.digest_key = conn.digest_key
        self.mac_key = conn.mac_key

        self.data = conn.data

        if self.multithreaded:
            self._queue = queue = Queue()
            self.thread = Thread(
                target=self._sensitive_calling,
                args=(queue,)
            )
            self._recv_raw_pkt_cnt = 0
            self._was_recving = False
            self.process = self._get_cnting_process(queue, self.process)

            self._ack_req = False
        else:
            self.acknowledge = super().acknowledge

    def _get_cnting_process[**P](
        self, queue: Queue, process: Callable[P, None]
    ) -> Callable[P, None]:
        """Return a process function counting packets it receives."""
        @wraps(process)
        def cnting_process_outer(*args: P.args, **kwargs: P.kwargs):
            @in_queue(self._queue)
            def cnting_process_inner(*args: P.args, **kwargs: P.kwargs):
                try:
                    self._was_recving = True
                    process(*args, **kwargs)
                finally:
                    self._recv_raw_pkt_cnt -= 1

            self._recv_raw_pkt_cnt += 1
            cnting_process_inner(*args, **kwargs)
        return cnting_process_outer

    def _sensitive_calling(self, queue):
        """Call on_quiet()
        when all packets recently received have been processed."""
        while (item := queue.get()) is not None:
            func, args, kwargs = item
            func(*args, **kwargs)
            if self._was_recving and not self._recv_raw_pkt_cnt:
                self._was_recving = False
                self.on_quiet()

    def on_quiet(self):
        """Called when all packets recently received have been processed."""
        if self._ack_req:
            self._ack_req = False
            super().acknowledge()

    def acknowledge(self):
        """Instead of sending ACK instantly,
        this method requests on_quiet() to send ACK,
        which can reduce redundant ACKs."""
        self._ack_req = True

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

    def stop(self):
        """Stop the session thread, called by close().

        May be overriden.

        """
        if self.multithreaded:
            self._queue.put_nowait(None)

    def close(self):
        """Close session, interrupt thread if multi-threaded."""
        with self.node.group_lock:
            addr = self.address
            if addr in self.node.sessions:
                del self.node.sessions[addr]
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

    """
    # Class variables:
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
    keepalive_interval: float = 15
    keepalive_timeout: float = 30
    # Retransmission
    timeout: float = 1
    retries = 6
    # Algorithms
    digest_alg = 'sha256'
    key_exchange_alg = 'x25519'
    cipher_alg = 'aes256'
    mac_alg = 'hmac-sha256'
    kdf_alg = 'hkdf_extract-md5'

    # Instance variables:
    # All connections
    sessions: dict[Address, BaseSession]        # Established sessions
    clients: dict[Address, ConnectionToClient]  # target nodes as clients
    # while self as server
    servers: dict[Address, ConnectionToClient]  # target nodes as servers
    # while self as client

    # Marked connections
    retrans_cons: set[Connection]   # Dead connections having sent no data
    dead_cons: set[Connection]      # Connections that need retransmission

    # Keepalive
    __keepalive_send_time: float   # Time to send keepalive packets
    __keepalive_deadline: float    # Deadline for others to send data

    # Multi-threading
    client_request_queue: Queue[tuple[bytes, ConnectionToClient] | None]
    server_request_queue: Queue[tuple[bytes, ConnectionToServer] | None]
    threads: list[Thread]
    group_lock: RLock  # To lock groups, such as sessions and dead_cons

    def __init__(
        self,
        server_address: Address,
        SessionClass: type[BaseSession],
        bind_and_activate=True
    ):

        self.SessionClass = SessionClass
        self.sessions = {}
        self.clients = {}
        self.servers = {}
        self.retrans_cons = set()
        self.dead_cons = set()
        self.group_lock = RLock()

        self.__keepalive_send_time = time() + self.keepalive_interval
        self.__keepalive_deadline = time() + self.keepalive_timeout

        # As client
        if self.has_queue_to_server:
            self.server_request_queue = queue = Queue()
            self.server_request_thread = Thread(
                target=call_forever, args=(queue,))
        # As server
        if self.has_queue_to_client:
            self.client_request_queue = queue = Queue()
            self.client_request_thread = Thread(
                target=call_forever, args=(queue,))

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
        if now >= self.__keepalive_send_time:
            if now >= self.__keepalive_deadline:
                with self.group_lock:
                    # Close all dead connections
                    for con in self.dead_cons:
                        con.close()
                    # Reset status
                    self.dead_cons = set((self.sessions
                                          | self.servers
                                          | self.clients).values())
                # Reset deadline
                self.__keepalive_deadline = time() + self.keepalive_timeout
            # Send keepalive packets
            # To established sessions only
            with self.group_lock:
                for con in self.sessions.values():
                    self.socket.sendto(b'', con.address)
            # Reset time to send keepalive packet
            self.__keepalive_send_time = now + self.keepalive_interval
        with self.group_lock:
            # Retransmission
            for con in self.retrans_cons.copy():
                con.retransmit(now)

    def get_request(self) -> tuple[bytes, Address]:
        """Get the request from the socket."""
        request, client_addr = self.socket.recvfrom(self.max_packet_size)
        return request, Address(*client_addr[: 2])

    def process_request(self, request: bytes, target_address: Address):
        """Process one request."""
        buf = BytesIO(request)
        with self.group_lock:
            for group in self.sessions, self.servers, self.clients:
                if con := group.get(target_address):
                    if con in self.dead_cons:
                        # Connection alive
                        self.dead_cons.remove(con)
                    if request:
                        con.process(buf)
                    return
            if request and buf.read(TYPE_SIZE) == ReqType.SYN:
                # New connection
                self.establish_conn_to_client(buf, target_address)

    def connect(self, address: Address) -> list[ConnectionToClient]:
        """New connection to server."""
        conns = []
        for _, _, _, _, addr in getaddrinfo(
                *address, family=self.address_family, type=SOCK_DGRAM):
            if len(addr) > 2:
                addr = addr[:2]
            conns.append(conn := self.ServerClass(addr, self))
            with self.group_lock:
                self.servers[addr] = conn
            conn.start()
        return conns

    def establish_conn_to_client(
        self, buf: BytesIO, origin: Address | ConnectionToServer
    ) -> ConnectionToClient:
        """New connection from client, called by process_request()."""
        client_cls = self.ClientClass
        conn = (client_cls.from_connection(origin)
                if isinstance(origin, ConnectionToServer)
                else client_cls(origin, self))
        # Lock acquired by caller process_request()
        self.clients[conn.address] = conn
        conn.start()
        conn.process(buf)
        return conn

    def establish_session(self, conn: HalfConnection) -> BaseSession:
        """Establish a new session, called by HalfConnection methods."""
        con = self.SessionClass.from_connection(conn)
        with self.group_lock:
            self.sessions[con.address] = con
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
            with self.group_lock:
                if cls.multithreaded:
                    for con in group.values():
                        con.finish()
                        con.stop()
                group.clear()

    def handle_request(self, *args, **kwargs):
        """Use module ilfocore.udpnode.Node.SessionClass.handle instead."""
        raise NotImplementedError(
            "Use module ilfocore.udpnode.Node.SessionClass.handle instead.")

    finish_request = handle_request
