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
