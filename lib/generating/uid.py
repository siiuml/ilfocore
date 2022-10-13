#!/usr/bin/python

"""
ilfocore.lib.generating.uid
===============

Generate an UID
"""

import uuid
from typing import Union
from ..exceptions import AlgorithmError, DemoError
from ..demo import demo_uid_generator


def gen_uuid(pre: set = set()) -> bytes:
    """Generate an UUID"""
    while (uid := uuid.uuid4().bytes) in pre:
        pass
    return uid


def gen_demo() -> bytes:
    """Generate an demo-type random ID"""
    raise DemoError("demo cannot be used.")

    return demo_uid_generator.new()


ID_GENERATORS = {
    'UUID': gen_uuid
    # 'demo': gen_demo
}

TYPES = ('INTEGER',) + tuple(ID_GENERATORS.keys())


def gen_id(type='INTEGER', **kwargs) -> Union[int, bytes]:
    """Generate an ID
       kwargs:
           pre: str
    """
    if type == 'INTEGER':
        # Int-type generator
        return kwargs['pre'] + 1
    if gen_method := ID_GENERATORS.get(type):
        return gen_method(**kwargs)
    raise AlgorithmError("Unsupported ID type")
