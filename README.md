**This README file and the comments in python files are not yet completed.**

The ilfocore package
===================

```
Language: Python (>= 3.11)
```

The ilfocore package provides basic, stable and authentic transmission support
for the ilafalseone package, a instant messenger package in development. The
ilafalseone package will be completed in a few weeks.

Required site-package:
[cryptography](https://github.com/pyca/cryptography)
Install from from pip:
```
$ pip install cryptography
```

Example
-------

```
from threading import Thread
from time import sleep
from ilfocore import BaseSession, Node, signature


class MySession(BaseSession):
    def handle_common(self, data):
        # Print the data received
        print(f"{self.node.server_address}: Recv {data}")


if __name__ == "__main__":
    # Generate identities of nodes
    alg = 'ed25519'
    key1 = signature.get_sign(alg).generate()
    key2 = signature.get_sign(alg).generate()
    # Initialize nodes
    addr1 = ('127.0.0.1', 9999)
    addr2 = ('127.0.0.1', 9998)
    node1 = Node(key1, addr1, MySession)
    node2 = Node(key2, addr2, MySession)
    # Start threads
    t1 = Thread(target=node1.serve_forever)
    t2 = Thread(target=node2.serve_forever)
    t1.start()
    t2.start()
    # Let node1 connect to node2
    node1.connect(addr2)
    # Wait for the session to get established
    sleep(1)
    # Get the session and send message to node2
    con = node1.sessions[addr2]
    con.send(b'hello')  # Out: ('127.0.0.1', 9998): Recv b'hello'
    # Close nodes
    node1.close()
    node2.close()
```
