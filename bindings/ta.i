/*
 * Copyright (c) 2010-2012 Dominik Oepen
 *
 * This file is part of OpenPACE.
 *
 * OpenPACE is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * OpenPACE is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * OpenPACE.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @date 2011-01-03
 * @version 0.2
 * @author Dominik Oepen <oepen@informatik.hu-berlin.de>
 */

%{
#include <eac/ta.h>
#include <openssl/buffer.h>
#include <stdlib.h>
#include <string.h>
%}

void
TA_disable_checks(EAC_CTX *ctx);

int
TA_STEP2_import_certificate(const EAC_CTX *ctx, const unsigned char *in,
        size_t in_len);
%rename(TA_STEP2_import_certificate) import_certificate;
%inline %{
    static int import_certificate(const EAC_CTX *ctx, char *in, int in_len) {
        if (in_len < 0)
            return 0;
        else
            return TA_STEP2_import_certificate(ctx, (unsigned char*) in, (size_t) in_len);
    }
%}

#ifdef SWIGPYTHON
%rename(TA_STEP3_generate_ephemeral_key) generate_ephemeral_ta_key;
%inline %{
    static void generate_ephemeral_ta_key(char **out, int *out_len, const EAC_CTX *ctx) {
        BUF_MEM *out_buf = NULL;

        out_buf = TA_STEP3_generate_ephemeral_key(ctx);
        buf2string(out_buf, out, out_len);

        if (out_buf)
            BUF_MEM_free(out_buf);
    }
%}

%rename(TA_STEP4_get_nonce) get_nonce;
%inline %{
    static void get_nonce(char **out, int *out_len, const EAC_CTX *ctx) {
        BUF_MEM *out_buf = NULL;

        out_buf = TA_STEP4_get_nonce(ctx);
        buf2string(out_buf, out, out_len);

        if (out_buf)
            BUF_MEM_free(out_buf);
    }
%}
#else

BUF_MEM *
TA_STEP3_generate_ephemeral_key(const EAC_CTX *ctx);

BUF_MEM *
TA_STEP4_get_nonce(const EAC_CTX *ctx);

#endif

BUF_MEM *
TA_STEP5_sign(const EAC_CTX *ctx, const BUF_MEM *my_ta_eph_pubkey,
           const BUF_MEM *opp_pace_eph_pubkey, const BUF_MEM *auxdata);

int
TA_STEP4_set_nonce(const EAC_CTX *ctx, const BUF_MEM *nonce);

int
TA_STEP6_verify(const EAC_CTX *ctx, const BUF_MEM *opp_ta_comp_pubkey,
        const BUF_MEM *my_pace_comp_eph_pubkey, const BUF_MEM *auxdata,
        const BUF_MEM *signature);
