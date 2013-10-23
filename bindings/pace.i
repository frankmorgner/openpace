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
 */

/**
 * @date 2010-01-07
 * @version 0.2
 * @author Dominik Oepen <oepen@informatik.hu-berlin.de>
 */
%module pace

%include "cstring.i"

%{
#include <eac/pace.h>
#include <openssl/buffer.h>
#include <stdlib.h>
#include <string.h>
%}

typedef unsigned short uint16_t;

enum s_type {
    PACE_MRZ = 1,
    PACE_CAN,
    PACE_PIN,
    PACE_PUK,
    PACE_RAW,
    PACE_SEC_UNDEF,
};

#define PACE_TR_VERSION_2_01 1
#define PACE_TR_VERSION_2_02 2

/**
 * @defgroup typemaps              Typemaps
 * @{ ************************************************************************/

#ifdef SWIGJAVA

/* Typemap to convert byte arrays to character pointer + length */
%typemap(in)     (char * BYTE, int LENGTH) {
    /* Functions from jni.h */
    $1 = (char *) JCALL2(GetByteArrayElements, jenv, $input, 0);
    $2 = (int)    JCALL1(GetArrayLength,       jenv, $input);
}
%typemap(jni)    (char *BYTE, int LENGTH) "jbyteArray"
%typemap(jtype)  (char *BYTE, int LENGTH) "byte[]"
%typemap(jstype) (char *BYTE, int LENGTH) "byte[]"
%typemap(javain) (char *BYTE, int LENGTH) "$javainput"

%apply (char *BYTE, int LENGTH) {(char *in, int in_len)};
%apply (char *BYTE, int LENGTH) {(char *privkey, int privkey_len)};
%apply (char *BYTE, int LENGTH) {(char *cert, int cert_len)};
%apply (char *BYTE, int LENGTH) {(char *car, int car_len)};
%apply (char *BYTE, int LENGTH) {(char *comp_pubkey, int comp_pubkey_len)};
%apply (char *BYTE, int LENGTH) {(char *pubkey, int pubkey_len)};
%apply (char *BYTE, int LENGTH) {(char *my_ta_eph_pubkey, int my_ta_eph_pubkey_len)};
%apply (char *BYTE, int LENGTH) {(char *opp_pace_eph_pubkey, int opp_pace_eph_pubkey_len)};
%apply (char *BYTE, int LENGTH) {(char *auxdata, int auxdata_len)};
%apply (char *BYTE, int LENGTH) {(char *opp_ta_comp_pubkey, int opp_ta_comp_pubkey_len)};
%apply (char *BYTE, int LENGTH) {(char *my_pace_comp_eph_pubkey, int my_pace_comp_eph_pubkey_len)};
%apply (char *BYTE, int LENGTH) {(char *signature, int signature_len)};

#endif

#ifndef SWIG_CSTRING_UNIMPL

%apply (char *STRING, int LENGTH) {(char *in, int in_len)};
%apply (char *STRING, int LENGTH) {(char *privkey, int privkey_len)};
%apply (char *STRING, int LENGTH) {(char *cert, int cert_len)};
%apply (char *STRING, int LENGTH) {(char *car, int car_len)};
%apply (char *STRING, int LENGTH) {(char *comp_pubkey, int comp_pubkey_len)};
%apply (char *STRING, int LENGTH) {(char *pubkey, int pubkey_len)};
%apply (char *STRING, int LENGTH) {(char *my_ta_eph_pubkey, int my_ta_eph_pubkey_len)};
%apply (char *STRING, int LENGTH) {(char *opp_pace_eph_pubkey, int opp_pace_eph_pubkey_len)};
%apply (char *STRING, int LENGTH) {(char *auxdata, int auxdata_len)};
%apply (char *STRING, int LENGTH) {(char *opp_ta_comp_pubkey, int opp_ta_comp_pubkey_len)};
%apply (char *STRING, int LENGTH) {(char *my_pace_comp_eph_pubkey, int my_pace_comp_eph_pubkey_len)};
%apply (char *STRING, int LENGTH) {(char *signature, int signature_len)};

%cstring_output_allocate_size(char **out, int *out_len, free(*$1));

#endif

/** @} ***********************************************************************/

%include "util.i"
%include "eac.i"
%include "ta.i"
%include "ca.i"
%include "cvc.i"
%include "objects.i"

/**
 * @defgroup manage              Data Managment
 * @{ ************************************************************************/

PACE_SEC *
PACE_SEC_new(char *in, int in_len, enum s_type type); /* typemap applied */

void
PACE_SEC_clear_free(PACE_SEC *s);
/** @} ***********************************************************************/

/**
 * @defgroup protocol              Protocol steps
 * @{ ************************************************************************/

#if !defined(SWIG_CSTRING_UNIMPL)

%rename(PACE_STEP1_enc_nonce) pace_step1_enc_nonce;
%inline %{
    static void pace_step1_enc_nonce(char **out, int *out_len, const EAC_CTX *ctx, const PACE_SEC *pi) {
        BUF_MEM *enc_nonce = PACE_STEP1_enc_nonce(ctx, pi);
        if (!enc_nonce) {
            *out_len = 0;
            *out = NULL;
        } else {
            buf2string(enc_nonce, out, out_len);
            BUF_MEM_free(enc_nonce);
        }
    }
%}

%rename(PACE_STEP2_dec_nonce) pace_step2_dec_nonce;
%inline %{
    static int pace_step2_dec_nonce(const EAC_CTX *ctx, const PACE_SEC *pi, char *in, int in_len) {
        BUF_MEM *in_buf = NULL;
        int ret = 0;

        in_buf = get_buf(in, in_len);
        if (!in_buf)
            return 0;

        ret = PACE_STEP2_dec_nonce(ctx, pi, in_buf);
        BUF_MEM_free(in_buf);
        return ret;
    }
%}

%rename(PACE_STEP3A_generate_mapping_data) pace_step3a_generate_mapping_data;
%inline %{
    static void pace_step3a_generate_mapping_data(char **out, int *out_len, const EAC_CTX *ctx) {
        BUF_MEM *out_buf = NULL;

        out_buf = PACE_STEP3A_generate_mapping_data(ctx);
        buf2string(out_buf, out, out_len);

        BUF_MEM_free(out_buf);
    }
%}

%rename(PACE_STEP3B_compute_shared_secret) pace_step3b_compute_shared_secret;
%inline %{
    static int pace_step3b_compute_shared_secret(const EAC_CTX *ctx, char *in, int in_len) {
        BUF_MEM *in_buf = NULL;
        int ret = 0;

        in_buf = get_buf(in, in_len);
        if (!in_buf)
            return 0;

        ret = PACE_STEP3B_compute_shared_secret(ctx, in_buf);
        BUF_MEM_free(in_buf);
        return ret;
    }
%}

%rename(PACE_STEP3A_map_generator) pace_step3a_map_generator;
%inline %{
    static int pace_step3a_map_generator(const EAC_CTX *ctx, char *in, int in_len) {
        BUF_MEM *in_buf = NULL;
        int ret = 0;

        in_buf = get_buf(in, in_len);
        if (!in)
            goto err;

        ret = PACE_STEP3A_map_generator(ctx, in_buf);

    err:
        if(in_buf)
            BUF_MEM_free(in_buf);
        return ret;
    }
%}

%rename(PACE_STEP3B_generate_ephemeral_key) pace_step3b_generate_ephemeral_pace_key;
%inline %{
    static void pace_step3b_generate_ephemeral_pace_key(char **out, int *out_len, EAC_CTX *ctx) {
        BUF_MEM *out_buf = NULL;

        out_buf = PACE_STEP3B_generate_ephemeral_key(ctx);
        buf2string(out_buf, out, out_len);

        if(out_buf)
            BUF_MEM_free(out_buf);
    }
%}

%rename(PACE_STEP3D_compute_authentication_token) pace_step3d_compute_authentication_token;
%inline %{
    static void pace_step3d_compute_authentication_token(char **out, int *out_len,
            const EAC_CTX *ctx, char *in, int in_len) {
        BUF_MEM *in_buf = NULL, *out_buf = NULL;

        in_buf = get_buf(in, in_len);
        out_buf = PACE_STEP3D_compute_authentication_token(ctx, in_buf);
        buf2string(out_buf, out, out_len);

        if (in_buf)
            BUF_MEM_free(in_buf);
        if (out_buf)
            BUF_MEM_free(out_buf);
    }
%}

%rename(PACE_STEP3D_verify_authentication_token) pace_step3d_verify_authentication_token;
%inline %{
    static int pace_step3d_verify_authentication_token(const EAC_CTX *ctx, char *in, int in_len) {
        BUF_MEM *in_buf = NULL;
        int ret = 0;

        in_buf = get_buf(in, in_len);
        if (!in_buf)
            return 0;

        ret = PACE_STEP3D_verify_authentication_token(ctx, in_buf);
        BUF_MEM_free(in_buf);
        return ret;
    }
%}

#else

BUF_MEM *
PACE_STEP1_enc_nonce(const EAC_CTX * ctx, const PACE_SEC * pi);

int
PACE_STEP2_dec_nonce(const EAC_CTX *ctx, const PACE_SEC *pi,
        const BUF_MEM *enc_nonce);

BUF_MEM *
PACE_STEP3A_generate_mapping_data(const EAC_CTX *ctx);

int
PACE_STEP3A_map_generator(const EAC_CTX *ctx, const BUF_MEM *in);

BUF_MEM *
PACE_STEP3B_generate_ephemeral_key(EAC_CTX *ctx);

int
PACE_STEP3B_compute_shared_secret(const EAC_CTX *ctx, const BUF_MEM *in);

BUF_MEM *
PACE_STEP3D_compute_authentication_token(const EAC_CTX *ctx, BUF_MEM *pub);

int
PACE_STEP3D_verify_authentication_token(const EAC_CTX *ctx, const BUF_MEM *token);

#endif

int
PACE_STEP3C_derive_keys(const EAC_CTX *ctx);

/** @} ***********************************************************************/
