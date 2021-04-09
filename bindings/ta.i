/*
 * Copyright (c) 2010-2012 Dominik Oepen
 * Copyright (c) 2013      Frank Morgner
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
 *
 * Additional permission under GNU GPL version 3 section 7
 *
 * If you modify this Program, or any covered work, by linking or combining it
 * with OpenSSL (or a modified version of that library), containing
 * parts covered by the terms of OpenSSL's license, the licensors of
 * this Program grant you additional permission to convey the resulting work.
 * Corresponding Source for a non-source form of such a combination shall include
 * the source code for the parts of OpenSSL used as well as that of the
 * covered work.
 *
 * If you modify this Program, or any covered work, by linking or combining it
 * with OpenSC (or a modified version of that library), containing
 * parts covered by the terms of OpenSC's license, the licensors of
 * this Program grant you additional permission to convey the resulting work. 
 * Corresponding Source for a non-source form of such a combination shall include
 * the source code for the parts of OpenSC used as well as that of the
 * covered work.
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

#if !defined(SWIG_CSTRING_UNIMPL)

%rename(TA_STEP2_import_certificate) ta_step2_import_certificate;
%inline %{
    static int ta_step2_import_certificate(const EAC_CTX *ctx, char *in, size_t in_len) {
            return TA_STEP2_import_certificate(ctx, (unsigned char*) in, in_len);
    }
%}

%rename(TA_STEP3_generate_ephemeral_key) ta_step3_generate_ephemeral_ta_key;
%inline %{
    static void ta_step3_generate_ephemeral_ta_key(char **out, size_t *out_len, const EAC_CTX *ctx) {
        BUF_MEM *out_buf = NULL;

        out_buf = TA_STEP3_generate_ephemeral_key(ctx);
        buf2string(out_buf, out, out_len);

        if (out_buf)
            BUF_MEM_free(out_buf);
    }
%}

%rename(TA_STEP4_get_nonce) ta_step4_get_nonce;
%inline %{
    static void ta_step4_get_nonce(char **out, size_t *out_len, const EAC_CTX *ctx) {
        BUF_MEM *out_buf = NULL;

        out_buf = TA_STEP4_get_nonce(ctx);
        buf2string(out_buf, out, out_len);

        if (out_buf)
            BUF_MEM_free(out_buf);
    }
%}

%rename(TA_STEP4_set_nonce) ta_step4_set_nonce;
%inline %{
    static int ta_step4_set_nonce(const EAC_CTX *ctx, char *in, size_t in_len) {
        BUF_MEM *in_buf = NULL;
        int ret = 0;

        in_buf = get_buf(in, in_len);
        if (!in_buf)
            return 0;

        ret = TA_STEP4_set_nonce(ctx, in_buf);
        BUF_MEM_free(in_buf);
        return ret;
    }
%}

%rename(TA_STEP5_sign) ta_step5_sign;
%inline %{
    static void ta_step5_sign(char **out, size_t *out_len, const EAC_CTX *ctx,
            char *my_ta_eph_pubkey, size_t my_ta_eph_pubkey_len,
            char *opp_pace_eph_pubkey, size_t opp_pace_eph_pubkey_len,
            char *auxdata, size_t auxdata_len) {
        BUF_MEM *my_ta_eph_pubkey_buf = NULL, *opp_pace_eph_pubkey_buf = NULL, *auxdata_buf = NULL, *out_buf = NULL;

        my_ta_eph_pubkey_buf = get_buf(my_ta_eph_pubkey, my_ta_eph_pubkey_len);
        opp_pace_eph_pubkey_buf = get_buf(opp_pace_eph_pubkey, opp_pace_eph_pubkey_len);
        auxdata_buf = get_buf(auxdata, auxdata_len);
        if (!my_ta_eph_pubkey_buf || !opp_pace_eph_pubkey_buf || !auxdata_buf)
            goto err;

        out_buf = TA_STEP5_sign(ctx, my_ta_eph_pubkey_buf, opp_pace_eph_pubkey_buf, auxdata_buf);

err:
        buf2string(out_buf, out, out_len);
        if (my_ta_eph_pubkey_buf)
            BUF_MEM_free(my_ta_eph_pubkey_buf);
        if (opp_pace_eph_pubkey_buf)
            BUF_MEM_free(opp_pace_eph_pubkey_buf);
        if (auxdata_buf)
            BUF_MEM_free(auxdata_buf);
        if (out_buf)
            BUF_MEM_free(out_buf);
    }
%}

%rename(TA_STEP6_verify) ta_step6_verify;
%inline %{
    static int ta_step6_verify(const EAC_CTX *ctx,
            char *opp_ta_comp_pubkey, size_t opp_ta_comp_pubkey_len,
            char *my_pace_comp_eph_pubkey, size_t my_pace_comp_eph_pubkey_len,
            char *auxdata, size_t auxdata_len,
            char *signature, size_t signature_len) {
        BUF_MEM *opp_ta_comp_pubkey_buf = NULL, *my_pace_comp_eph_pubkey_buf = NULL, *auxdata_buf = NULL, *signature_buf = NULL;
        int r = 0;

        opp_ta_comp_pubkey_buf = get_buf(opp_ta_comp_pubkey, opp_ta_comp_pubkey_len);
        my_pace_comp_eph_pubkey_buf = get_buf(my_pace_comp_eph_pubkey, my_pace_comp_eph_pubkey_len);
        auxdata_buf = get_buf(auxdata, auxdata_len);
        signature_buf = get_buf(signature, signature_len);
        if (!opp_ta_comp_pubkey_buf || !my_pace_comp_eph_pubkey_buf || !signature_buf)
            goto err;

        r = TA_STEP6_verify(ctx, opp_ta_comp_pubkey_buf, my_pace_comp_eph_pubkey_buf, auxdata_buf, signature_buf);

err:
        if (opp_ta_comp_pubkey_buf)
            BUF_MEM_free(opp_ta_comp_pubkey_buf);
        if (my_pace_comp_eph_pubkey_buf)
            BUF_MEM_free(my_pace_comp_eph_pubkey_buf);
        if (auxdata_buf)
            BUF_MEM_free(auxdata_buf);
        if (signature_buf)
            BUF_MEM_free(signature_buf);

        return r;
    }
%}

#else

int
TA_STEP2_import_certificate(const EAC_CTX *ctx, const unsigned char *in,
        size_t in_len);

%newobject TA_STEP3_generate_ephemeral_key;
BUF_MEM *
TA_STEP3_generate_ephemeral_key(const EAC_CTX *ctx);

%newobject TA_STEP4_get_nonce;
BUF_MEM *
TA_STEP4_get_nonce(const EAC_CTX *ctx);

int
TA_STEP4_set_nonce(const EAC_CTX *ctx, const BUF_MEM *nonce);

%newobject TA_STEP5_sign;
BUF_MEM *
TA_STEP5_sign(const EAC_CTX *ctx, const BUF_MEM *my_ta_eph_pubkey,
           const BUF_MEM *opp_pace_eph_pubkey, const BUF_MEM *auxdata);

int
TA_STEP6_verify(const EAC_CTX *ctx, const BUF_MEM *opp_ta_comp_pubkey,
        const BUF_MEM *my_pace_comp_eph_pubkey, const BUF_MEM *auxdata,
        const BUF_MEM *signature);

#endif
