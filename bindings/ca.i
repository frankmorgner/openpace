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
 * @date 2012-01-04
 * @version 0.2
 * @author Dominik Oepen <oepen@informatik.hu-berlin.de>
 */

%{
#include <eac/ca.h>
#include <eac/cv_cert.h>
#include <eac/objects.h>
#include <stdlib.h>
#include <string.h>

/* included in OpenPACE, but not propagated */
extern void BUF_MEM_clear_free(BUF_MEM *b);
%}

void
CA_disable_passive_authentication(EAC_CTX *ctx);

#if !defined(SWIG_CSTRING_UNIMPL)

%rename(CA_get_pubkey) ca_get_pubkey;
%inline %{
    static void ca_get_pubkey (const EAC_CTX *ctx, char **out, size_t *out_len, char *in, size_t
            in_len) /* typemap applied */ {
        BUF_MEM *out_buf = CA_get_pubkey(ctx, (unsigned char*) in, in_len);
        buf2string(out_buf, out, out_len);
        BUF_MEM_clear_free(out_buf);
        return;
    }
%}

%rename(CA_STEP1_get_pubkey) ca_step1_get_pubkey;
%inline %{
    static void ca_step1_get_pubkey(char **out, size_t *out_len, const EAC_CTX *ctx) {
        BUF_MEM *out_buf = CA_STEP1_get_pubkey(ctx);
        buf2string(out_buf, out, out_len);
        BUF_MEM_clear_free(out_buf);
        return;
    }
%}

%rename(CA_STEP2_get_eph_pubkey) ca_step2_get_eph_pubkey;
%inline %{
    static void ca_step2_get_eph_pubkey(char **out, size_t *out_len, const EAC_CTX *ctx) {
        BUF_MEM *out_buf = CA_STEP2_get_eph_pubkey(ctx);
        buf2string(out_buf, out, out_len);
        BUF_MEM_clear_free(out_buf);
        return;
    }
%}

%rename(CA_STEP3_check_pcd_pubkey) ca_step3_check_pcd_pubkey;
%inline %{
    static int ca_step3_check_pcd_pubkey (const EAC_CTX *ctx,
            char *comp_pubkey, size_t comp_pubkey_len, /* typemap applied */
            char *pubkey, size_t pubkey_len) /* typemap applied */ {
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

%rename(CA_STEP4_compute_shared_secret) ca_step4_compute_shared_secret;
%inline %{
    static int ca_step4_compute_shared_secret (const EAC_CTX *ctx,
            char *pubkey, size_t pubkey_len) /* typemap applied */ {
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

#else

%newobject CA_get_pubkey;
BUF_MEM*
CA_get_pubkey(const EAC_CTX *ctx, const unsigned char *in, size_t in_len);

%newobject CA_STEP1_get_pubkey;
BUF_MEM *
CA_STEP1_get_pubkey(const EAC_CTX *ctx);

%newobject CA_STEP2_get_eph_pubkey;
BUF_MEM *
CA_STEP2_get_eph_pubkey(const EAC_CTX *ctx);

int
CA_STEP3_check_pcd_pubkey(const EAC_CTX *ctx,
        const BUF_MEM *comp_pubkey, const BUF_MEM *pubkey);

int
CA_STEP4_compute_shared_secret(const EAC_CTX *ctx, const BUF_MEM *pubkey);

int
CA_STEP6_derive_keys(EAC_CTX *ctx, const BUF_MEM *nonce, const BUF_MEM *token);

#endif

%rename(CA_set_key) ca_set_key;
%inline %{
    int
    ca_set_key(const EAC_CTX *ctx,
            char *privkey, size_t privkey_len,
            char *pubkey, size_t pubkey_len)
    {
        return CA_set_key(ctx,
            (unsigned char *) privkey, privkey_len,
            (unsigned char *) pubkey, pubkey_len);
    }
%}

#ifdef SWIGPYTHON
%rename(CA_STEP5_derive_keys) ca_step5_derive_keys;
%inline %{
    static PyObject* ca_step5_derive_keys (const EAC_CTX *ctx,
            char *pubkey, size_t pubkey_len) /* typemap applied */ {
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
        nonce_str = PyBytes_FromStringAndSize(nonce->data, nonce->length);
        token_str = PyBytes_FromStringAndSize(token->data, token->length);
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

        return out;
    }
%}

#else

int
CA_STEP5_derive_keys(const EAC_CTX *ctx, const BUF_MEM *pub,
                   BUF_MEM **nonce, BUF_MEM **token);

#endif
