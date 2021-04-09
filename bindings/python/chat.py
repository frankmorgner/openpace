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
# Additional permission under GNU GPL version 3 section 7
#
# If you modify this Program, or any covered work, by linking or combining it
# with OpenSSL (or a modified version of that library), containing
# parts covered by the terms of OpenSSL's license, the licensors of
# this Program grant you additional permission to convey the resulting work.
# Corresponding Source for a non-source form of such a combination shall include
# the source code for the parts of OpenSSL used as well as that of the
# covered work.
#
# If you modify this Program, or any covered work, by linking or combining it
# with OpenSC (or a modified version of that library), containing
# parts covered by the terms of OpenSC's license, the licensors of
# this Program grant you additional permission to convey the resulting work. 
# Corresponding Source for a non-source form of such a combination shall include
# the source code for the parts of OpenSC used as well as that of the
# covered work.
#

"""
Object oriented wrapper for the CVC_CHAT structure and related methods from
OpenPACE

:Author: Dominik Oepen
:Date: 04.12.2011
:License: GPL
"""

import eac

class OpenPACEException(Exception):
    def __init__(self, value):
        self.value = eac.print_ossl_err() + value

    def __str__(self):
        return self.value

class CHAT(object):
    def __init__(self, chat):
        if (type(chat) == bytes):
            self.asn1_string = chat
            self.chat = eac.d2i_CVC_CHAT(chat)
        elif (type(chat).__name__ == 'SwigPyObject'):
            self.asn1_string = eac.i2d_CVC_CHAT(chat)
            self.chat = eac.CVC_CHAT_dup(chat)
        if (self.chat is None or self.asn1_string is None):
            raise OpenPACEException("Failed to parse CHAT")

    def __del__(self):
        eac.CVC_CHAT_free(self.chat)

    def __str__(self):
        ret = eac.get_chat_repr(self.chat).decode("utf-8")

        if ret is None:
            raise OpenPACEException("Failed to parse CHAT")

        return ret

    def get_role(self):
        ret = eac.get_chat_role(self.chat)

        if ret is None:
            raise OpenPACEException("Failed to retrieve terminal role from CHAT")

        return ret

    def get_terminal_type(self):
        ret = eac.get_chat_terminal_type(self.chat)

        if ret is None:
            raise OpenPACEException("Failed to retrieve terminal type from CHAT")

        return ret

    def get_relative_authorizations(self):
        ret = eac.get_chat_rel_auth(self.chat)

        if ret is None:
            raise OpenPACEException("Failed to retrieve relative authorization from CHAT")

        return ret


class CVC(object):
    def __init__(self, asn1_string):
        self.asn1_string = asn1_string
        self.cvc = eac.CVC_d2i_CVC_CERT(asn1_string)
        if not self.cvc:
            raise TypeError("Failed to parse certificate")
        self.chat = CHAT(eac.cvc_get_chat(self.cvc))

    def __del__(self):
        eac.CVC_CERT_free(self.cvc)

    def __str__(self):
        ret = eac.get_cvc_repr(self.cvc).decode("utf-8")

        if ret is None:
            raise OpenPACEException("Failed to parse CV certificate")

        return ret

    def get_car(self):
        ret = eac.CVC_get_car(self.cvc).decode("utf-8")

        if ret is None:
            raise OpenPACEException("Failed to extract CAR")

        return ret

    def get_chr(self):
        ret = eac.CVC_get_chr(self.cvc).decode("utf-8")

        if ret is None:
            raise OpenPACEException("Failed to extract CHR")

        return ret

    def get_effective_date(self):
        ret = eac.CVC_get_effective_date(self.cvc)

        if ret is None:
            raise OpenPACEException("Failed to extract effective date")

        return ret

    def get_expiration_date(self):
        ret = eac.CVC_get_expiration_date(self.cvc)

        if ret is None:
            raise OpenPACEException("Failed to extract expiration date")

        return ret

    def get_profile_identifier(self):
        profile_id = eac.CVC_get_profile_identifier(self.cvc)
        return profile_id


class EAC_CTX(object):
    def __init__(self):
        self.ctx = eac.EAC_CTX_new()
        if not self.ctx:
            raise TypeError("Failed to create context")

    def __del__(self):
        eac.EAC_CTX_clear_free(self.ctx)

    def __str__(self):
        ret = eac.EAC_CTX_print_private(self.ctx)

        if ret is None:
            raise OpenPACEException("Failed to print EAC_CTX")

        return ret


class PACE_SEC(object):
    def __init__(self, secret, secret_type):
        self.sec = eac.PACE_SEC_new(secret, secret_type)
        if not self.sec:
            raise TypeError("Failed to create context")

    def __del__(self):
        eac.PACE_SEC_clear_free(self.sec)

    def __str__(self):
        ret = eac.PACE_SEC_print_private(self.sec)

        if ret is None:
            raise OpenPACEException("Failed to print PACE_SEC")

        return ret
