#!/usr/bin/python
# Copyright (c) 2022 SiumLhahah
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
ilfocore.node
===============

Node of ilfocore

Base64 encodes in transmission:
   - Signatures
   - Symmetric keys
   - Encrypted messages

No base64 encoding in transmission for:
   - Algorithms
   - Public keys (must be in PEM format)
   - Verification code (Already encoded in base64)
"""

__author__ = 'SiumLhahah'

import socket
import socketserver
from base64 import b64decode, b64encode
from collections import defaultdict, deque, namedtuple
from enum import IntEnum
from ipaddress import ip_address
from secrets import token_bytes as random
from time import monotonic as time
from typing import Union
from .contact import get_seq, Addr, Contacts, Keys, SEQ_BYTES, UID
from .lib import generating, signature
from .lib.bytesenum import Chr, NAKStatus
from .lib.encryption import asymmetric, symmetric
from .lib.exceptions import (
    AlgorithmError,
    ContactOfflineError,
    PacketSizeError
)

MAX_CODE_LEN = 1024
INIT_SEQ = get_seq(1)

HEAD_BYTES = 1
PACK_SIZE_BYTES = 2
BYTEORDER = 'little'

Real = Union[int, float]

Deadline = namedtuple('Deadline', ['deadline', 'retries'])
Deadline.__doc__ = """Dealine with count of retries.
deadline : Real
retries : int
"""

Packet = namedtuple('Packet', ['seq', 'data'])
Packet.__doc__ = """Sequence number and data.
seq : bytes
data : bytes
"""


class Status(IntEnum):
    """TCP states."""

    CLOSED = 0
    SYN_SENT = 2
    ESTABLISHED = 4
    LISTEN = 1
    SYN_REVD = 3

    FIN_WAIT_1 = 5
    FIN_WAIT_2 = 8
    TIME_WAIT = 9
    CLOSE_WAIT = 6
    LAST_ACK = 7
    CLOSING = 10


class Node(socketserver.UDPServer):
    """UDP node class.

    Some attributes of a Node object:

       - Node.alive : dict[UID, bool]
         To make sure connection alive

       - Node.blacklist : set(Addr)
         Blacklist of addresses.

       - Node.buffer : dict[UID, deque[Packet]]
         Data packets to resend if timeout.

       - Node.client_time : float
         Time to exit client mode.

       - Node.deadlines : defaultdict[UID, Deadline]
         Deadlines to get response from contact.

       - Node.established : dict[Addr, UID]
         UIDs of addresses of established connections.

       - Node.keepalive_interval : int
         Interval to send keepalive packet.

       - Node.keepalive_timeout : int
         Time for contacts to send keepalive packet.

       - Node.recv_seq : dict[UID, bytes]
         Lastest sequence numbers from contacts.

       - Node.states : dict[Addr, State]
         States of connections.

       - Node.pack_sizes : dict[Addr, int]
         Max packet size of connections.

       - Node._client_buffer : dict[Addr, bytes]
         Data packets to resend if client send the same request.
         No sequence number.

       - Node._client_deadlines : defaultdict[Addr, Deadline]
         Deadlines to get response from server.

       - Node._client_mode : bool
         Return bool(Node._client_buffer).

       - Node._dotimeout : bool
         Return bool(Node._timeout).

       - Node._server_buffer : dict[Addr, bytes]
         Data packets to resend if client send the same request.

       - Node._timeout : Real
         Time for a packet to be timeout.

       - Node.__nbytes : int
         Length of random bytes in verification code.

       - Node.__keepalive_time : int
         Time to send keepalive packet.

       - Node.__keepalive_deadline : int
         Deadline for contacts to send keepalive packet.
    """

    def __init__(
        self,
        server_address: Addr,
        sig_keys: Keys,
        asym_keys: Keys,
        sym_algorithm: str,
        contacts: Contacts,
        *,
        nbytes: int = 32
    ):
        """
        String sym_algorithm will be used to
        encrypt, decrypt, and generate key.
        """

        self._sig_keys = sig_keys
        self._asym_keys = asym_keys
        self._sym_algorithm = sym_algorithm
        self.__nbytes = nbytes
        self._client_mode = False
        self._client_buffer = {}
        self._client_deadlines = defaultdict(self.__get_deadline)
        self._server_buffer = {}

        self.server_address = server_address
        self.contacts = contacts
        self.blacklist = set()
        self.states = {}
        self.pack_sizes = {}
        self.established = {}
        self.buffer = defaultdict(deque)
        self.deadlines = defaultdict(self.__get_deadline)
        self.alive = {}
        self.recv_seq = {}

        self._timeout = None
        self._dotimeout = None
        self.retries = None
        self.keepalive_interval = None
        self.keepalive_timeout = None
        self.__keepalive_time = None
        self.__keepalive_deadline = None

    def get_verification_code(self, addr: Addr) -> bytes:
        """Generate verification code from an address."""
        return b64encode(random(self.__nbytes) +
                         bytes(f'[{addr[0]}]:{addr[1]}', 'ascii'))

    def __get_deadline(self, retries: int = 0) -> Deadline:
        """Return deadline from current time.

        May be overriden.
        """
        deadline = time() + self._timeout * 2 ** retries
        return Deadline(deadline, retries)

    def connectall(
        self,
        keepalive_interval: int = 30,
        keepalive_timeout: int = 256,
        *,
        retries: int = 6,
        timeout: Real = 1
    ):
        """Starting connection."""

        # Initialize
        self._timeout = timeout
        self._dotimeout = bool(timeout)
        self.retries = retries
        self.keepalive_interval = keepalive_interval
        self.keepalive_timeout = keepalive_timeout
        self.__keepalive_time = int(time()) + keepalive_interval
        self.__keepalive_deadline = int(time()) + keepalive_timeout
        if __debug__:
            print(f"{self.server_address}: Connection start.")
        if ip_address(self.server_address[0]).version == 6:
            self.address_family = socket.AF_INET6
        else:
            # version == 4
            self.address_family = socket.AF_INET
        socketserver.UDPServer.__init__(self, self.server_address, None)
        del self.RequestHandlerClass

        for contact in self.contacts.get_contacts():
            for addr in contact.addresses:
                self.connect(addr)

    def connect(self, addr: Addr):
        """Connect to address."""
        # Client 1, starting a connection
        if __debug__:
            print(f"{self.server_address}: Client 1 to {addr}.")
        self.socket.connect(addr)
        # Max packet size
        size = self.max_packet_size.to_bytes(
            PACK_SIZE_BYTES, BYTEORDER)
        # Pack data
        data = Chr.SYN + size + self.get_verification_code(addr)
        # Send
        self.socket.sendto(data, addr)
        if __debug__:
            print(f"{self.server_address}: Send {data} to {addr}.")
        # Set state
        self.states[addr] = Status.SYN_SENT
        # Set timeout
        if self._dotimeout:
            self._client_buffer[addr] = data

        # Enter client mode
        if self._dotimeout:
            self._client_mode = True

    def release_connection(self, addr: Addr):
        """Close an connection.

        May be overriden.
        """
        if self._dotimeout:
            if addr in self._server_buffer:
                del self._server_buffer[addr]
            if addr in self._client_buffer:
                del self._client_buffer[addr]
                if addr in self._client_deadlines:
                    del self._client_deadlines[addr]
                self._client_mode = bool(self._client_buffer)
        for _dict in [self.established,
                      self.pack_sizes,
                      self.states]:
            if addr in _dict:
                del _dict[addr]
        if __debug__:
            print(f"{self.server_address}: Release connection to {addr}.")

    def close_connection(self, uid: UID):
        """Close an established connection of a contact.

        May be overriden.
        """
        if uid not in self.alive:
            if __debug__:
                print(f"Connection to {UID} is not established.")
            return
        self.handle_fail(uid)
        for _dict in [self.recv_seq,
                      self.alive,
                      self.deadlines,
                      self.buffer]:
            if uid in _dict:
                del _dict[uid]
        self.release_connection(self.contacts[uid].address)
        self.contacts[uid].closed()
        if __debug__:
            print(f"{self.server_address}: Closed connection to {uid}.")

    def sendto(self, data: bytes, uid: UID):
        """Send data to contact.

        May be overriden.
        """
        if uid not in self.alive:
            if __debug__:
                print(f"Connection to {UID} is not established.")
            raise ContactOfflineError(f"Contact {UID} is not online.")
        # Get contact
        contact = self.contacts[uid]
        addr = contact.address
        if __debug__:
            print("=======================================")
            print(f"Run sendto UID {uid}.")
            print(f"Symmetric key: {contact.sym_key.sk}.")
            print(f"Algorithm: {contact.sym_key.algorithm}.")
        # Encrypt data
        try:
            data = symmetric.encrypt(
                contact.sym_key.algorithm,
                data,
                contact.sym_key.sk)
        except AlgorithmError:
            self.handle_nak(NAKStatus.UNS_SYM_ALG, addr)
            self.close_connection(uid)
            return
        except:
            self.handle_nak(NAKStatus.UNK_FORMAT_S2, addr)
            self.close_connection(uid)
            return
        else:
            # Add header and sequence number
            seq = contact.new_seq()
            if HEAD_BYTES + SEQ_BYTES + len(data) > self.pack_sizes[addr]:
                raise PacketSizeError(
                    f"Packet size exceeds {self.pack_sizes[addr]} bytes")
            if __debug__:
                print("Packet size: "
                      f"{HEAD_BYTES + SEQ_BYTES + len(data)}.")
            # First message
            if not (self._dotimeout and self.buffer[uid]):
                if __debug__:
                    print(f"{self.server_address}: "
                          f"Sent {Chr.ENQ + seq + data} "
                          f"to {contact.address}.")
                # Send
                self.socket.sendto(Chr.ENQ + seq + data, addr)
            if self._dotimeout:
                # Send to buffer
                if __debug__:
                    print(f"{self.server_address}: "
                          f"Added {data} to buffer, "
                          f"{seq} as sequence number.")
                self.buffer[uid].append(Packet(seq, data))
        if __debug__:
            print("=======================================")

    def handle_fail(self, uid: UID):
        """Handle fail in transmission.

        May be overriden.
        """
        pass

    def handle_nak(self, status: NAKStatus, addr: Addr):
        """Send NAK message.

        May be overriden.
        """
        if __debug__:
            print("Send NAK message: ", end='')
            match status:
                case NAKStatus.FIN:
                    print("Finish connection.")
                case NAKStatus.NOT_AUTH_SIG:
                    print("Not authentic signature.")
                case NAKStatus.SIZE_EXCEED:
                    print("Packet size exceeds.")
                case NAKStatus.UNK_FORMAT_C2:
                    print("Client 2 Unknown format.")
                case NAKStatus.UNK_FORMAT_S2:
                    print("Server 2 Unknown format.")
                case NAKStatus.UNK_HEADER:
                    print("Unknown header.")
                case NAKStatus.UNS_ASYM_ALG:
                    print("Unsupported asymmetric encryption algorithm.")
                case NAKStatus.UNS_SIG_ALG:
                    print("Unsupported signature algorithm.")
                case NAKStatus.UNS_SYM_ALG:
                    print("Unsupported symmetric encryption algorithm.")
                case status:
                    print(f"{status}.")
            print(f"(to {addr}).")

        if status in NAKStatus.__dict__.values():
            # Release
            self.release_connection(addr)
        self.socket.sendto(Chr.NAK + status, addr)

    def process_nak(
        self,
        status: NAKStatus,
        target: Union[UID, Addr]
    ) -> bool:
        """Process received NAK.

        May be overriden.
        """
        if isinstance(target, tuple):
            if __debug__:
                print(f"Received NAK from {target}:  {status}.")
            return False
        if status == NAKStatus.FIN:
            self.close_connection(target)
        return True

    def setup(self, uid: UID):
        """Called when a contact has been connected.

        May be overriden.
        """
        pass

    def process_recv(self, data: bytes, uid: UID):
        """Process received data.

        May be overriden.
        """
        pass

    def service_actions(self):
        """Resend data packets if timeout."""
        if __debug__:
            print('.', end='')
        # Keepalive
        if time() > self.__keepalive_time:
            for uid in self.alive:
                # Send keepalive packet
                if __debug__:
                    print(f"{self.server_address}: "
                          f"Keepalive to {self.contacts[uid].address}.")
                self.socket.sendto(Chr.EMPTY, self.contacts[uid].address)
            # Reset
            self.__keepalive_time = int(time()) + self.keepalive_interval
        if time() > self.__keepalive_deadline:
            if __debug__:
                print("Keepalive timeout")
            for uid, alive in list(self.alive.items()):
                if alive:
                    if __debug__:
                        print(f"{self.server_address}: "
                              f"Connection {uid} alive.")
                    # Reset status
                    self.alive[uid] = False
                    continue
                if __debug__:
                    print(f"{self.server_address}: Connection {uid} dead.")
                # Close
                self.close_connection(uid)
            # Reset deadline
            self.__keepalive_deadline = time() + self.keepalive_timeout

        # Retransmission
        if self._dotimeout:
            # Established
            for uid, packets in self.buffer.items():
                if packets:
                    # If timeout
                    if time() > self.deadlines[uid].deadline:
                        retries = self.deadlines[uid].retries
                        if retries >= self.retries:
                            # Transmission failed
                            if __debug__:
                                print(f"Retries over {self.retries}.")
                            # Close
                            self.close_connection(uid)
                            continue
                        # Resend data
                        if __debug__:
                            print(f"Resend data: {packets[0].data}")
                        self.socket.sendto(
                            Chr.ENQ + packets[0].seq + packets[0].data,
                            self.contacts[uid].address
                        )
                        # Reset deadline
                        self.deadlines[uid] = self.__get_deadline(retries + 1)
                        if __debug__:
                            print(f"{self.server_address}: "
                                  f"Sent {packets[0].data} to "
                                  f"{self.contacts[uid].address}, "
                                  "deadline reset.")
            # As client
            if self._client_mode:
                for addr, data in list(self._client_buffer.items()):
                    # If timeout
                    if time() > self._client_deadlines[addr].deadline:
                        retries = self._client_deadlines[addr].retries
                        if __debug__:
                            print(f"{self.server_address}: Client mode to "
                                  f"{addr}, {retries} retries.")
                        if retries >= self.retries:
                            if __debug__:
                                print(f"{self.server_address}: "
                                      f"Release client mode to {addr}")
                            # Release connection
                            self.release_connection(addr)
                            continue
                        # Resend data
                        if __debug__:
                            print(f"Resend C1 data: {data}")
                        self.socket.sendto(data, addr)
                        # Reset deadline
                        self._client_deadlines[addr] = self.__get_deadline(
                            retries + 1)
                        if __debug__:
                            print(f"{self.server_address}: "
                                  f"Client mode sent {data} to {addr}."
                                  "deadline reset.")

    def server_close(self):
        """Called to clean up the node."""
        super().server_close()
        Node.__init__(
            self,
            self.server_address,
            self._sig_keys,
            self._asym_keys,
            self._sym_algorithm,
            self.contacts,
            nbytes=self.__nbytes
        )

    def verify_request(self, request, client_address) -> bool:
        """Verify the request."""
        return (request is not None and
                client_address not in self.blacklist)

    def process_request(self, request, client_address):
        """Process one request."""
        request = request[0]
        client_address = client_address[: 2]
        if __debug__:
            if request:
                print("\n=======================================")
                print(f"{self.server_address}: Received raw data packet "
                      f"{request} from {client_address}.")
                print("\n=======================================")
            else:
                # Keepalive packet
                print("!", end='')
        header, body = request[: HEAD_BYTES], request[HEAD_BYTES:]
        del request
        if __debug__ and header:
            print(f"{self.server_address}: Header as {header}.")
        status = self.states.get(client_address, Status.LISTEN)
        match status:
            # Established, from Client 2 or Server 2
            case Status.ESTABLISHED:
                seq, body = body[: SEQ_BYTES], body[SEQ_BYTES:]
                uid = self.established[client_address]
                match header:
                    case Chr.ENQ:
                        if __debug__:
                            print(f"RECV SEQ: {seq}")
                            print(f"CON  SEQ: {self.recv_seq[uid]}")
                        if seq != self.recv_seq[uid]:
                            self.recv_seq[uid] = seq
                            contact = self.contacts[uid]
                            try:
                                body = symmetric.decrypt(
                                    contact.sym_key.algorithm,
                                    body,
                                    contact.sym_key.sk)
                            except:
                                # Decrypt failed
                                self.handle_nak(
                                    NAKStatus.UNK_FORMAT, client_address)
                                return
                            # Process
                            self.process_recv(body, uid)

                        # Acknowledge
                        self.socket.sendto(Chr.ACK + seq, client_address)

                    case Chr.ACK:
                        # Data packet was sent successfully
                        if packets := self.buffer[uid]:
                            if seq == packets[0].seq:
                                # Pop packet in buffer
                                packets.popleft()
                                if uid in self.deadlines:
                                    del self.deadlines[uid]
                                # Send next packet
                                if packets := self.buffer[uid]:
                                    self.socket.sendto(
                                        Chr.ENQ +
                                        packets[0].seq +
                                        packets[0].data,
                                        self.contacts[uid].address
                                    )

                    case Chr.EMPTY:
                        # Keep alive
                        pass

                    case Chr.NAK:
                        self.process_nak(seq + body, uid)

                    case Chr.SYN:
                        # Release
                        self.close_connection(uid)
                        # Execute Server 1 as server
                        self.states[client_address] = Status.LISTEN
                        return self.process_request(
                            (header + seq + body, None), client_address)

                    case _:
                        self.handle_nak(NAKStatus.UNK_HEADER, client_address)

                # Keep connection alive
                self.alive[uid] = True

            # Server 2, received from Client 2 and
            # send ACK with seq to established client
            case Status.SYN_REVD:
                if __debug__:
                    print(f"{self.server_address}: Server 2 to {client_address}.")
                if header == Chr.ENQ:
                    # Parse data
                    seq, body = body[: SEQ_BYTES], body[SEQ_BYTES:]
                    asym_algorithm, asym_sk = (
                        self._asym_keys.algorithm, self._asym_keys.sk)
                    try:
                        # Split group
                        sig, sym_key = body.split(Chr.GS, 1)
                        # Split signature information
                        sig_algorithm, sig_pk, sig = sig.split(Chr.US, 2)
                        sig_algorithm = str(sig_algorithm, 'utf-8')
                        sig = b64decode(sig)
                        # Split symmetric key
                        sym_algorithm, sym_key = map(
                            b64decode, sym_key.split(Chr.US, 1))
                        sym_algorithm = asymmetric.decrypt(
                            asym_algorithm, sym_algorithm, asym_sk)
                        sym_algorithm = str(sym_algorithm, 'utf-8')
                        sym_key = asymmetric.decrypt(
                            asym_algorithm, sym_key, asym_sk)
                    except AlgorithmError:
                        # Unsupported algorithm
                        self.handle_nak(
                            NAKStatus.UNS_ASYM_ALG, client_address)
                        return
                    except:
                        # Unknown format or decrypt failed
                        self.handle_nak(
                            NAKStatus.UNK_FORMAT_S2, client_address)
                        return

                    # Load client verification code, from Server 1
                    randaddr = self._server_buffer[client_address]
                    randaddr = randaddr[
                        HEAD_BYTES + PACK_SIZE_BYTES:].split(Chr.GS, 1)[0]
                    # Verify signature
                    try:
                        signature.verify(sig_algorithm, randaddr, sig_pk, sig)
                    except AlgorithmError:
                        # Unsupported signature algorithm
                        self.handle_nak(
                            NAKStatus.UNS_SIG_ALG, client_address)
                        return
                    except ValueError:
                        # Not authentic
                        self.handle_nak(
                            NAKStatus.NOT_AUTH_SIG, client_address)
                        return

                    sig_pk = Keys(sig_algorithm, sig_pk, None)
                    uid = self.contacts.get_uid_from_key(sig_pk)
                    if not uid:
                        uid = self.handle_new(self, sig_pk, client_address)
                        if not uid:
                            # NAK
                            self.handle_nak(NAKStatus.FIN, client_address)
                            return
                    # Establish
                    sym_key = Keys(sym_algorithm, None, sym_key)
                    # Release server buffer, save max pack size
                    if client_address in self._server_buffer:
                        del self._server_buffer[client_address]
                    self.states[client_address] = Status.ESTABLISHED
                    self.established[client_address] = uid
                    self.contacts[uid].connected(client_address, sym_key)
                    self.recv_seq[uid] = seq
                    self.alive[uid] = True
                    # ACK will be processed as established
                    self.socket.sendto(Chr.ACK + seq, client_address)
                    if __debug__:
                        print(
                            f"{self.server_address}: Send S2 packet "
                            f"{Chr.ACK + seq} to {client_address}.")
                    self.setup(uid)

                elif header == Chr.SYN:
                    # Resend the same message
                    self.socket.sendto(
                        self._server_buffer[client_address], client_address)

                elif header == Chr.NAK:
                    self.process_nak(body, client_address)

            # Server 1, recveied from client 1, send to Client 2
            case Status.LISTEN:
                if __debug__:
                    print(f"{self.server_address}: "
                          f"Server 1 to {client_address}.")
                if header == Chr.SYN:
                    # Parse data
                    packsize, randaddr = (
                        body[: PACK_SIZE_BYTES], body[PACK_SIZE_BYTES:])
                    if len(randaddr) > MAX_CODE_LEN:
                        # Proctect
                        self.blacklist.add(client_address)
                        return
                    self.pack_sizes[client_address] = int.from_bytes(
                        packsize, BYTEORDER)
                    # Request body should be base64 encoded
                    # server verification code (random bytes
                    # with address) received from client.
                    #
                    # To client:
                    #   - Max packet size
                    #   - Random bytes with client address
                    #   - Public key of server and
                    #     signature of server verification code
                    #   - Public key for asymmetric encryption

                    # Max packet size
                    packsize = self.max_packet_size.to_bytes(
                        PACK_SIZE_BYTES, BYTEORDER)

                    # Sign server verification code
                    # Variable body is verificaition code from client,
                    # so there's no UNK_FORMAT_S1
                    sig = signature.sign(self._sig_keys.algorithm,
                                         randaddr,
                                         self._sig_keys.sk)
                    sig = Chr.US.join([
                        bytes(self._sig_keys.algorithm, 'utf-8'),
                        self._sig_keys.pk,
                        b64encode(sig)])

                    # Client verification code
                    randaddr = self.get_verification_code(client_address)
                    randaddr = b64encode(randaddr)

                    # Public key
                    asym = Chr.US.join([
                        bytes(self._asym_keys.algorithm, 'utf-8'),
                        self._asym_keys.pk])

                    # Pack data
                    data = Chr.ACK + packsize + Chr.GS.join(
                        [randaddr, sig, asym])
                    if len(data) <= self.pack_sizes[client_address]:
                        # Send
                        self.socket.sendto(data, client_address)
                        if __debug__:
                            print(f"{self.server_address}: "
                                  f"Send S1 packet {data} to "
                                  f"{client_address}.")
                        self.states[client_address] = Status.SYN_REVD
                        self._server_buffer[client_address] = data
                    else:
                        # Max packet size no enough
                        self.handle_nak(
                            NAKStatus.UNS_PACK_SIZE, client_address)

                # Ignore any other header

            # Client 2, received from Server 1
            # Variable client_address is the server address actually
            case Status.SYN_SENT:
                if __debug__:
                    print(f"{self.server_address}: Client 2 to {client_address}")
                if header == Chr.ACK:
                    if __debug__:
                        print(f"{self.server_address}: Client 2 ACK")
                    # To server:
                    #   - Sequence number
                    #   - Public key of client and
                    #     signature of client verification code
                    #   - Encrypted symmetric key

                    # Parse data
                    packsize, body = (
                        body[: PACK_SIZE_BYTES], body[PACK_SIZE_BYTES:])
                    self.pack_sizes[client_address] = int.from_bytes(
                        packsize, BYTEORDER)
                    try:
                        # Split group
                        randaddr, sig, asym_pk = body.split(Chr.GS, 2)
                        # Split signature information
                        sig_algorithm, sig_pk, sig = sig.split(Chr.US, 2)
                        sig_algorithm = str(sig_algorithm, 'utf-8')
                        sig = b64decode(sig)
                        # Split asymmetric public key
                        asym_algorithm, asym_pk = asym_pk.split(Chr.US, 1)
                        asym_algorithm = str(asym_algorithm, 'utf-8')
                    except:
                        # Unknown format
                        self.handle_nak(
                            NAKStatus.UNK_FORMAT_C2, client_address)
                        return
                    # Load server verification code, from Client 1
                    server_randaddr = self._client_buffer[client_address][
                        HEAD_BYTES + PACK_SIZE_BYTES:]
                    # Verify signature
                    try:
                        signature.verify(
                            sig_algorithm,
                            server_randaddr,
                            sig_pk,
                            sig
                        )
                    except AlgorithmError:
                        # Unsupported signature algorithm
                        self.handle_nak(
                            NAKStatus.UNS_SIG_ALG, client_address)
                        return
                    except ValueError:
                        # Not authentic
                        self.handle_nak(
                            NAKStatus.NOT_AUTH_SIG, client_address)
                        return
                    # Sign client verification code
                    sig = signature.sign(self._sig_keys.algorithm,
                                         randaddr,
                                         self._sig_keys.sk)
                    sig = Chr.US.join([
                        bytes(self._sig_keys.algorithm, 'utf-8'),
                        self._sig_keys.pk,
                        b64encode(sig)])
                    # Generate key for symmetric encryption
                    sym_algorithm = self._sym_algorithm
                    sym_key = generating.keys.genkeys(sym_algorithm)[1]
                    # Symmetric key
                    # Symmetric key and algorithm will be encrypted
                    try:
                        e_sym_algorithm = asymmetric.encrypt(
                            asym_algorithm,
                            bytes(sym_algorithm, 'utf-8'),
                            asym_pk)
                        e_sym_key = asymmetric.encrypt(
                            asym_algorithm,
                            sym_key,
                            asym_pk)
                    except AlgorithmError:
                        self.handle_nak(
                            NAKStatus.UNS_ASYM_ALG, client_address)
                        return
                    except:
                        self.handle_nak(
                            NAKStatus.UNK_FORMAT_C2, client_address)
                        return
                    e_sym_key = Chr.US.join(map(
                        b64encode, [e_sym_algorithm, e_sym_key]))
                    # Pack data
                    seq = INIT_SEQ
                    data = Chr.GS.join([sig, e_sym_key])
                    # Check packet size
                    if (HEAD_BYTES + SEQ_BYTES + len(data)
                        > self.pack_sizes[client_address]):
                        # Max packet size no enough
                        self.handle_nak(
                            NAKStatus.UNS_PACK_SIZE, client_address)
                        return
                    # Send
                    self.socket.sendto(Chr.ENQ + seq + data, client_address)
                    if __debug__:
                        print(f"{self.server_address}: "
                              f"Send C2 packet {data} to "
                              f"{client_address}.")
                    # Connected to server
                    for uid, contact in self.contacts.items():
                        addrs = contact.addresses
                        # Selected contact by current address
                        if client_address in addrs:
                            # Release other connections
                            for addr in addrs:
                                # Release buffer as client
                                if (self._dotimeout and
                                        addr in self._client_buffer):
                                    del self._client_buffer[addr]
                                    if (addr in
                                            self._client_deadlines[addr]):
                                        del self._client_deadlines[addr]
                            self._client_mode = bool(self._client_buffer)
                            break
                    else:
                        # New address
                        uid = self.handle_new(
                            self,
                            Keys(sig_algorithm, sig_pk, None),
                            client_address
                        )
                        if not uid:
                            # NAK
                            self.handle_nak(NAKStatus.FIN, client_address)
                            return
                    # Update status
                    self.states[client_address] = Status.ESTABLISHED
                    self.established[client_address] = uid
                    self.recv_seq[uid] = seq
                    self.alive[uid] = True
                    self.contacts[uid].connected(
                        client_address, Keys(sym_algorithm, None, sym_key))
                    # Set timeout
                    if self._dotimeout:
                        self.buffer[uid].append(Packet(seq, data))
                    self.setup(uid)

                elif header == Chr.SYN:
                    # Release
                    self.release_connection(client_address)
                    # Execute Server 1 as server
                    self.states[client_address] = Status.LISTEN
                    return self.process_request((header + body, None),
                                                client_address)
                elif header == Chr.NAK:
                    # Release
                    self.release_connection(client_address)
                    self.process_nak(body, client_address)

        # No more states

    finish_request = process_request

    @staticmethod
    def handle_new(self, pub_key: Keys, addr: Addr) -> UID:
        """New contact.

        May be overriden.
        """
        uid = self.contacts.new_contact(
            pub_key, [addr])
        return uid

    @property
    def sig_keys(self) -> Keys:
        """Signagture alogorithm, public key and private key."""
        return self._sig_keys

    @property
    def asym_keys(self) -> Keys:
        """Asymmetric encryption alogorithm, public key and private key."""
        return self._asym_keys

    @property
    def sym_algorithm(self) -> str:
        """Symmetric encryption algorithm."""
        return self._asym_keys

    @property
    def dotimeout(self) -> bool:
        """If will handle timeout data packet."""
        return self._dotimeout

    @property
    def timeout(self) -> float:
        """Timeout."""
        return self._timeout

    @timeout.setter
    def timeout(self, timeout):
        """Set timeout."""
        self._timeout = timeout
        self._dotimeout = bool(timeout)
