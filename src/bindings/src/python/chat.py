"""
Object oriented wrapper for the CVC_CHAT structure and related methods from
OpenPACE

@author: Dominik Oepen
@date: 04.12.2011
@license: GPL
"""

import pace

class CHATException(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return self.value

class CHAT(object):
    def __init__(self, asn1_string):
        self.asn1_string = asn1_string
        self.chat = pace.d2i_CVC_CHAT(asn1_string)
        if (self.chat is None):
            raise CHATException("Failed to parse ASN1 representation")

    def __del__(self):
        pace.CVC_CHAT_free(self.chat)

    def __str__(self):
        ret = pace.get_chat_repr(self.chat)

        if ret is None:
            raise ChatException("Failed to parse CHAT")

        return ret

    def get_role(self):
        ret = pace.get_chat_role(self.chat)

        if ret is None:
            raise ChatException("Failed to retrieve terminal role from CHAT")

        return ret

    def get_terminal_type(self):
        ret = pace.get_chat_terminal_type(self.chat)

        if ret is None:
            raise ChatException("Failed to retrieve terminal type from CHAT")

        return ret

    def get_relative_authorizations(self):
        ret = pace.get_chat_rel_auth(self.chat)

        if ret is None:
            raise ChatException("Failed to retrieve relative authorization from CHAT")

        return ret
