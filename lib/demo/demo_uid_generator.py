# /usr/bin/python

"""
ilfocore.lib.demo.demo_uid_generator
===============

Demostration of uid generator
"""

import random


def new():
    return random.randbytes(16)
