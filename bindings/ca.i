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
 * @date 2012-01-04
 * @version 0.2
 * @author Dominik Oepen <oepen@informatik.hu-berlin.de>
 */

%{
#include <eac/ca.h>
#include <eac/cv_cert.h>
#include <stdlib.h>
#include <string.h>

/* included in OpenPACE, but not propagated */
extern void BUF_MEM_clear_free(BUF_MEM *b);
%}

void
CA_disable_passive_authentication(EAC_CTX *ctx);

/* FIXME: Manual NIDs are bad because they will probably change in the next
 * version of OpenSSL */
#define id_CA_DH_3DES_CBC_CBC 953
#define id_CA_DH_AES_CBC_CMAC_128 954
#define id_CA_DH_AES_CBC_CMAC_192 955
#define id_CA_DH_AES_CBC_CMAC_256 956
#define id_CA_ECDH_3DES_CBC_CBC 958
#define id_CA_ECDH_AES_CBC_CMAC_128 959
#define id_CA_ECDH_AES_CBC_CMAC_192 960
#define id_CA_ECDH_AES_CBC_CMAC_256 961

int
CA_STEP6_derive_keys(EAC_CTX *ctx, const BUF_MEM *nonce, const BUF_MEM *token);

#ifdef SWIGPYTHON

%rename(CA_STEP1_get_pubkey) ca_step1_get_pubkey;
%inline %{
    static void ca_step1_get_pubkey(char **out, int *out_len, const EAC_CTX *ctx) {
        BUF_MEM *out_buf = CA_STEP1_get_pubkey(ctx);
        buf2string(out_buf, out, out_len);
        BUF_MEM_clear_free(out_buf);
        return;
    }
%}

%rename(CA_STEP2_get_eph_pubkey) ca_step2_get_eph_pubkey;
%inline %{
    static void ca_step2_get_eph_pubkey(char **out, int *out_len, const EAC_CTX *ctx) {
        BUF_MEM *out_buf = CA_STEP2_get_eph_pubkey(ctx);
        buf2string(out_buf, out, out_len);
        BUF_MEM_clear_free(out_buf);
        return;
    }
%}

#else

BUF_MEM *
CA_STEP1_get_pubkey(const EAC_CTX *ctx);


BUF_MEM *
CA_STEP2_get_eph_pubkey(const EAC_CTX *ctx);

#endif

int
CA_STEP3_check_pcd_pubkey(const EAC_CTX *ctx,
        const BUF_MEM *comp_pubkey, const BUF_MEM *pubkey);
%rename(CA_STEP3_check_pcd_pubkey) ca_step3_check_pcd_pubkey;
%inline %{
    static int ca_step3_check_pcd_pubkey (const EAC_CTX *ctx,
            char *comp_pubkey, int comp_pubkey_len, /* typemap applied */
            char *pubkey, int pubkey_len) /* typemap applied */ {
        BUF_MEM *comp_pubkey_buf = NULL, *pubkey_buf = NULL;
        int ret = -1;

        comp_pubkey_buf = get_buf(comp_pubkey, comp_pubkey_len);
        pubkey_buf = get_buf(pubkey, pubkey_len);
        if (!comp_pubkey_buf || !pubkey_buf)
            goto err;

        ret = CA_STEP3_check_pcd_pubkey(ctx, comp_pubkey_buf, pubkey_buf);

err:
        if (comp_pubkey_buf)
            BUF_MEM_clear_free(comp_pubkey_buf);
        if (pubkey_buf)
            BUF_MEM_clear_free(pubkey_buf);
        return ret;
    }
%}

int
CA_STEP4_compute_shared_secret(const EAC_CTX *ctx, const BUF_MEM *pubkey);
%rename(CA_STEP4_compute_shared_secret) ca_step4_compute_shared_secret;
%inline %{
    static int ca_step4_compute_shared_secret (const EAC_CTX *ctx,
            char *pubkey, int pubkey_len) /* typemap applied */ {
        BUF_MEM *pubkey_buf = NULL;
        int ret = -1;

        pubkey_buf = get_buf(pubkey, pubkey_len);
        if (!pubkey_buf)
            goto err;

        ret = CA_STEP4_compute_shared_secret(ctx, pubkey_buf);

err:
        if (pubkey_buf)
            BUF_MEM_clear_free(pubkey_buf);
        return ret;
    }
%}

int
CA_STEP5_derive_keys(const EAC_CTX *ctx, const BUF_MEM *pub,
                   BUF_MEM **nonce, BUF_MEM **token);
#ifdef SWIGPYTHON
%rename(CA_STEP5_derive_keys) ca_step5_derive_keys;
%inline %{
    static PyObject* ca_step5_derive_keys (const EAC_CTX *ctx,
            char *pubkey, int pubkey_len) /* typemap applied */ {
        BUF_MEM *pubkey_buf = NULL, *nonce = NULL, *token = NULL;
        PyObject *out = NULL, *nonce_str = NULL, *token_str = NULL;

        out = PyTuple_New(2);
        if (!out)
            goto err;

        pubkey_buf = get_buf(pubkey, pubkey_len);
        if (!pubkey_buf)
            goto err;

        if (!CA_STEP5_derive_keys(ctx, pubkey_buf, &nonce, &token))
            goto err;

        /* In python3 the following functions must be replace with their
           PyBytes counterparts. */
        nonce_str = PyString_FromStringAndSize(nonce->data, nonce->length);
        token_str = PyString_FromStringAndSize(token->data, token->length);
        if (!nonce_str || !token_str)
            goto err;

        /* TODO: Error checking */
        PyTuple_SetItem(out, 0, nonce_str);
        PyTuple_SetItem(out, 1, token_str);

err:
        if (pubkey_buf)
            BUF_MEM_clear_free(pubkey_buf);
        if (nonce)
            BUF_MEM_clear_free(nonce);
        if (token)
            BUF_MEM_clear_free(token);
        /* Do we have to free nonce_str and token_str ? */
        return out;
    }
%}
#endif

BUF_MEM*
CA_get_pubkey(const EAC_CTX *ctx, const unsigned char *in, size_t in_len);
%rename(CA_get_pubkey) ca_get_pubkey;
%inline %{
    static void ca_get_pubkey (const EAC_CTX *ctx, char **out, int *out_len, char *in, int
            in_len) /* typemap applied */ {
        BUF_MEM *pubkey;

        if (in_len > 0) {
            pubkey = CA_get_pubkey(ctx, (unsigned char*) in, (size_t) in_len);
            buf2string(pubkey, out, out_len);
            BUF_MEM_clear_free(pubkey);
        } else {
            *out_len = 0;
            *out = NULL;
        }
        return;
    }
%}
