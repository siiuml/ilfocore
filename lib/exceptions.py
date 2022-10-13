#!/usr/bin/python

""""
ilfocore.lib.exceptions
===============

Errors
"""


class ErrorMetaclass(type):
    """Error Metaclass"""

    def __new__(cls, name, base=Exception, attrs={}):
        def init(self, msg=None):
            base.__init__(self, msg)
            self.msg = msg
        attrs['__init__'] = init
        attrs['__str__'] = lambda self: str(self.msg)
        return type.__new__(cls, name, (base,), attrs)

    def __init__(cls, name, base=Exception, attrs={}):
        super().__init__(name, (base,), attrs)


AlgorithmError = ErrorMetaclass('AlgorithmError', NotImplementedError)
ContactOfflineError = ErrorMetaclass('ContactOfflineError', ValueError)
DemoError = ErrorMetaclass('DemoError', NotImplementedError)
KeyFormatError = ErrorMetaclass('KeyFormatError', ValueError)
PacketSizeError = ErrorMetaclass('PacketSizeError', ValueError)
