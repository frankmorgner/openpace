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
 * @date 2010-01-07
 * @version 0.2
 * @author Dominik Oepen <oepen@informatik.hu-berlin.de>
 */
%module pace

%{
#include <eac/pace.h>
#include <openssl/buffer.h>
%}

enum s_type {
    PACE_MRZ = 1,
    PACE_CAN,
    PACE_PIN,
    PACE_PUK,
    PACE_RAW,
    PACE_SEC_UNDEF,
};

/**
 * @defgroup manage              Data Managment
 * @{ ************************************************************************/

%begin %{
#define SWIG_PYTHON_STRICT_BYTE_CHAR
%}

%newobject PACE_SEC_new;
PACE_SEC *
PACE_SEC_new(char *in, size_t in_len, enum s_type type); /* typemap applied */

%delobject PACE_SEC_clear_free;
void
PACE_SEC_clear_free(PACE_SEC *s);

#if !defined(SWIG_CSTRING_UNIMPL)

%begin %{
#define SWIG_PYTHON_STRICT_BYTE_CHAR
%}

%rename (PACE_SEC_print_private) pace_sec_print_private;
%inline %{
    static void pace_sec_print_private(char **out, size_t *out_len, PACE_SEC *sec, int indent) {
        long tmp;
        BIO *bio = BIO_new(BIO_s_mem());
        if (!bio)
            goto err;

        PACE_SEC_print_private(bio, sec, indent);

        tmp = BIO_get_mem_data(bio, NULL);
        if (tmp < 0)
            goto err;
        *out = (char *) malloc(tmp);
        if (!*out)
            goto err;
        *out_len = tmp;

        if (BIO_read(bio, (void*) *out, *out_len) <= 0)
            goto err;

        BIO_free_all(bio);
        return;

err:
        *out_len = 0;
        if (*out)
            free(*out);
        if (bio)
            BIO_free_all(bio);
    }
%}

#endif
/** @} ***********************************************************************/

/**
 * @defgroup protocol              Protocol steps
 * @{ ************************************************************************/

#if !defined(SWIG_CSTRING_UNIMPL)

%begin %{
#define SWIG_PYTHON_STRICT_BYTE_CHAR
%}

%rename(PACE_STEP1_enc_nonce) pace_step1_enc_nonce;
%inline %{
    static void pace_step1_enc_nonce(char **out, size_t *out_len, const EAC_CTX *ctx, const PACE_SEC *pi) {
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
    static int pace_step2_dec_nonce(const EAC_CTX *ctx, const PACE_SEC *pi, char *in, size_t in_len) {
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
    static void pace_step3a_generate_mapping_data(char **out, size_t *out_len, const EAC_CTX *ctx) {
        BUF_MEM *out_buf = NULL;

        out_buf = PACE_STEP3A_generate_mapping_data(ctx);
        buf2string(out_buf, out, out_len);

        BUF_MEM_free(out_buf);
    }
%}

%rename(PACE_STEP3B_compute_shared_secret) pace_step3b_compute_shared_secret;
%inline %{
    static int pace_step3b_compute_shared_secret(const EAC_CTX *ctx, char *in, size_t in_len) {
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
    static int pace_step3a_map_generator(const EAC_CTX *ctx, char *in, size_t in_len) {
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
    static void pace_step3b_generate_ephemeral_pace_key(char **out, size_t *out_len, EAC_CTX *ctx) {
        BUF_MEM *out_buf = NULL;

        out_buf = PACE_STEP3B_generate_ephemeral_key(ctx);
        buf2string(out_buf, out, out_len);

        if(out_buf)
            BUF_MEM_free(out_buf);
    }
%}

%rename(PACE_STEP3D_compute_authentication_token) pace_step3d_compute_authentication_token;
%inline %{
    static void pace_step3d_compute_authentication_token(char **out, size_t *out_len,
            const EAC_CTX *ctx, char *in, size_t in_len) {
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
    static int pace_step3d_verify_authentication_token(const EAC_CTX *ctx, char *in, size_t in_len) {
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

%begin %{
#define SWIG_PYTHON_STRICT_BYTE_CHAR
%}

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

%begin %{
#define SWIG_PYTHON_STRICT_BYTE_CHAR
%}

int
PACE_STEP3C_derive_keys(const EAC_CTX *ctx);

/** @} ***********************************************************************/
