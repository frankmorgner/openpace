#
# Copyright (c) 2010-2012 Dominik Oepen
#
# This file is part of OpenPACE.
#
# OpenPACE is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option)
# any later version.
#
# OpenPACE is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License along with
# OpenPACE.  If not, see <http://www.gnu.org/licenses/>.
#

"""
Object oriented wrapper for the CVC_CHAT structure and related methods from
OpenPACE

@author: Dominik Oepen
@date: 04.12.2011
@license: GPL
"""

import pace
from binascii import b2a_hex

class CHATException(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return self.value

class CHAT(object):
    def __init__(self, chat):
        if (type(chat) == str):
            self.asn1_string = chat
            self.chat = pace.d2i_CVC_CHAT(chat)
        elif (type(chat).__name__ == 'SwigPyObject'):
            self.asn1_string = pace.i2d_CVC_CHAT(chat)
            self.chat = chat
        if (self.chat is None or self.asn1_string is None):
            raise CHATException("Failed to parse CHAT")

    def __del__(self):
        pass
        # Freeing the underlying C structure can result in double frees if there
        # are other references to this CHAT (e.g. in an associated CVC object
        # pace.CVC_CHAT_free(self.chat)

    def __str__(self):
        ret = pace.get_chat_repr(self.chat)

        if ret is None:
            raise CHATException("Failed to parse CHAT")

        return ret

    def get_role(self):
        ret = pace.get_chat_role(self.chat)

        if ret is None:
            raise CHATException("Failed to retrieve terminal role from CHAT")

        return ret

    def get_terminal_type(self):
        ret = pace.get_chat_terminal_type(self.chat)

        if ret is None:
            raise CHATException("Failed to retrieve terminal type from CHAT")

        return ret

    def get_relative_authorizations(self):
        ret = pace.get_chat_rel_auth(self.chat)

        if ret is None:
            raise CHATException("Failed to retrieve relative authorization from CHAT")

        return ret


class CVC(object):
    def __init__(self, asn1_string):
        self.asn1_string = asn1_string
        self.cvc = pace.CVC_d2i_CVC_CERT(asn1_string)
        if not self.cvc:
            raise TypeError("Failed to parse certificate")
        self.chat = CHAT(pace.cvc_get_chat(self.cvc))

    def __del__(self):
        pace.CVC_CERT_free(self.cvc)

    def __str__(self):
        print self.chat
