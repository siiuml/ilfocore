"""
Simple usage example.
"""

from threading import Thread
from time import sleep
from ilfocore.constants import Address
from ilfocore.ilfonode import BaseSession, Node
from ilfocore.lib import signature

# May use IPv6
# import socket
# Node.address_family = socket.AF_INET6


class MySession(BaseSession):
    def setup_common(self):
        self.handle = self.handle_common

    def handle_common(self, buf):
        # Print the data received
        data = buf.read()
        print(f"{self.node.server_address}: Recv {data}")


if __name__ == "__main__":
    # Generate identities of nodes
    alg = 'ed25519'
    key1 = signature.get_sign(alg).generate()
    key2 = signature.get_sign(alg).generate()
    # Initialize nodes
    addr1 = Address('localhost', 9999)
    addr2 = Address('localhost', 9998)
    node1 = Node(key1, addr1, MySession)
    node2 = Node(key2, addr2, MySession)
    # Start threads
    t1 = Thread(target=node1.serve_forever)
    t2 = Thread(target=node2.serve_forever)
    t1.start()
    t2.start()
    # Let nodes connect to each other
    node1.connect(addr2)
    node2.connect(addr1)
    # Wait for the session to get established
    sleep(5)
    # Send message to node2
    node1.sendto(b'hello', node2.pub_key)
    # Out: ('127.0.0.1', 9998): Recv b'hello'
    # Close nodes
    node1.close()
    node2.close()
