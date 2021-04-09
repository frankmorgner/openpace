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
Object oriented wrapper for PACE entities, the PICC and the PCD structure
and related methods from OpenPACE

:Author: Dominik Oepen
:Date: 23.02.2012
:License: GPL
"""

import eac
import string, binascii

EF_CARD_ACCESS = b"\x31\x81\x82\x30\x0D\x06\x08\x04\x00\x7F\x00\x07\x02\x02\x02\x02\x01\x02\x30\x12\x06\x0A\x04\x00\x7F\x00\x07\x02\x02\x03\x02\x02\x02\x01\x02\x02\x01\x41\x30\x12\x06\x0A\x04\x00\x7F\x00\x07\x02\x02\x04\x02\x02\x02\x01\x02\x02\x01\x0D\x30\x1C\x06\x09\x04\x00\x7F\x00\x07\x02\x02\x03\x02\x30\x0C\x06\x07\x04\x00\x7F\x00\x07\x01\x02\x02\x01\x0D\x02\x01\x41\x30\x2B\x06\x08\x04\x00\x7F\x00\x07\x02\x02\x06\x16\x1F\x65\x50\x41\x20\x2D\x20\x42\x44\x72\x20\x47\x6D\x62\x48\x20\x2D\x20\x54\x65\x73\x74\x6B\x61\x72\x74\x65\x20\x76\x32\x2E\x30\x04\x49\x17\x15\x41\x19\x28\x80\x0A\x01\xB4\x21\xFA\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\x10\x10\x29\x10\x10"

_myprintable = " " + string.ascii_letters + string.digits + string.punctuation
def hexdump(data, indent = 0, short = False, linelen = 16, offset = 0):
    """Generates a nice hexdump of data and returns it. Consecutive lines will
    be indented with indent spaces. When short is true, will instead generate
    hexdump without adresses and on one line.

    Examples:
    hexdump('\x00\x41') -> \
    '0000:  00 41                                             .A              '
    hexdump('\x00\x41', short=True) -> '00 41 (.A)'"""

    def hexable(data):
        return " ".join([binascii.b2a_hex(a) for a in data])

    def printable(data):
        return "".join([e in _myprintable and e or "." for e in data])

    if short:
        return "%s (%s)" % (hexable(data), printable(data))

    FORMATSTRING = "%04x:  %-"+ str(linelen*3) +"s  %-"+ str(linelen) +"s"
    result = ""
    (head, tail) = (data[:linelen], data[linelen:])
    pos = 0
    while len(head) > 0:
        if pos > 0:
            result = result + "\n%s" % (' ' * indent)
        result = result + FORMATSTRING % (pos+offset, hexable(head), printable(head))
        pos = pos + len(head)
        (head, tail) = (tail[:linelen], tail[linelen:])
    return result

class PACEException(Exception):
    def __init__(self, reason, protocol_step = None, role = None):
        self.reason = reason
        self.protocol_step = protocol_step
        self.role = role

    def __str__(self):
        eac.print_ossl_err()
        print

        ret_str = "Error "
        if (self.protocol_step is not None):
            ret_str += "during " + self.protocol_step + " "
        if (self.role is not None):
            ret_str += "at the " + self.role + " side:\n\t"
        return ret_str + self.reason

class PACEEntity(object):
    """Base class for all class implementing the PACE protocol"""

    def __init__(self, pin):
        """
        Keyword arguments:
        pin -- the (low entropy) shared secret for the PACE protocol
        """
        self.pin = pin
        self.ctx = eac.EAC_CTX_new()
        self.sec = eac.PACE_SEC_new(self.pin, eac.PACE_PIN)
        eac.EAC_CTX_init_ef_cardaccess(EF_CARD_ACCESS, self.ctx)
        self._enc_nonce = ""
        self._ephemeral_pubkey = ""
        self._opp_pubkey = ""

    def __del__(self):
        if (self.ctx):
            eac.EAC_CTX_clear_free(self.ctx)
        if (self.sec):
            eac.PACE_SEC_clear_free(self.sec)

    def __str__(self):
        ret_string = eac.EAC_CTX_print_private(self.ctx, 0)
        return ret_string

    def get_static_pubkey(self):
        self._static_pubkey = eac.PACE_STEP3A_generate_mapping_data(self.ctx)
        return self._static_pubkey

    def perform_mapping(self, pubkey):
        eac.PACE_STEP3A_map_generator(self.ctx, pubkey)

    def generate_ephemeral_pubkey(self):
        self._ephemeral_pubkey = eac.PACE_STEP3B_generate_ephemeral_key(self.ctx)
        return self._ephemeral_pubkey

    def compute_shared_secret(self, pubkey):
        self._opp_pubkey = pubkey
        if (not eac.PACE_STEP3B_compute_shared_secret(self.ctx, pubkey)):
            raise PACEException("Failed to compute shared secret", "Step 3B")

    def derive_keys(self):
        if (not eac.PACE_STEP3C_derive_keys(self.ctx)):
            raise PACEException("Failed to derive keys", "Step 3C")

    def encrypt(self, data):
        """Encrypt a block of data using the secret established by the PACE
        protocol. This method can only be used after a successful run of eac.
        """
        enc = eac.EAC_encrypt(self.ctx, data)
        if not enc or not eac.EAC_increment_ssc(self.ctx):
            raise PACEException("Failed to encrypt the following data: " + data.decode("utf-8"))
        return enc

    def decrypt(self, data):
        """Decrypt a block of data using the secret established by the PACE
        protocol. This method can only be used after a successful run of eac.
        """
        dec = eac.EAC_decrypt(self.ctx, data)
        if not dec or not eac.EAC_increment_ssc(self.ctx):
            raise PACEException("Failed to decrypt the following data: " + data.decode("utf-8"))
        return dec

    def authenticate(self, data):
        """Compute a MAC for block of data using the secret established by the
        PACE protocol. This method can only be used after a successful run of
        eac.
        """
        auth = eac.EAC_authenticate(self.ctx, data)
        if not auth or not eac.EAC_increment_ssc(self.ctx):
            raise PACEException("Failed to compute MAC for: " + data.decode("utf-8"))
        return auth

    def EAC_CTX_set_encryption_ctx(self):
        eac.EAC_CTX_set_encryption_ctx(self.ctx, eac.EAC_ID_PACE)

    def EAC_Comp(self):
        return eac.EAC_Comp(self.ctx, eac.EAC_ID_PACE, self._ephemeral_pubkey)

class PICC(PACEEntity):
    """
    This class implements the PACE protocol stepts that are only needed for
    the Proximity integrated circuit card
    """

    def __init__(self, pin):
        super(PICC, self).__init__(pin)

    def __str__(self):
        return "PICC:\n" + super(PICC, self).__str__().decode("utf-8")

    def generate_nonce(self):
        self._enc_nonce = eac.PACE_STEP1_enc_nonce(self.ctx, self.sec)
        if not self._enc_nonce:
            raise PACEException("Could not generate nonce", "Step 1", "PICC")
        return self._enc_nonce

    def verify_authentication_token(self, token):
        ret = eac.PACE_STEP3D_verify_authentication_token(self.ctx, token)
        if (not ret):
            raise PACEException("Failed to verify authentication token")
        if (eac.EAC_CTX_set_encryption_ctx(self.ctx, eac.EAC_ID_PACE) == 0):
            raise PACEException("Failed to initialize Secure Messaging context")
        # PICC starts with ssc = 1
        if not eac.EAC_increment_ssc(self.ctx):
            raise PACEException("Failed to incremement ssc")
        return ret

class PCD(PACEEntity):
    """Proximity coupling device"""

    def __init__(self, pin):
        super(PCD, self).__init__(pin)

    def __str__(self):
        return "PCD:\n" + super(PCD, self).__str__().decode("utf-8")

    def decrypt_nonce(self, enc_nonce):
        self._enc_nonce = enc_nonce
        if (not eac.PACE_STEP2_dec_nonce(self.ctx, self.sec, enc_nonce)):
            raise PACEException("Could not decrypt nonce", "Step 2", "PCD")

    def get_authentication_token(self):
        ret = eac.PACE_STEP3D_compute_authentication_token(self.ctx, self._opp_pubkey)
        if (not ret):
            raise PACEException("Failed to compute authentication token")
        if (eac.EAC_CTX_set_encryption_ctx(self.ctx, eac.EAC_ID_PACE) == 0):
            raise PACEException("Failed to initialize Secure Messaging context")
        return ret
