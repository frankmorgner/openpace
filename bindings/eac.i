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

%{
#include <eac/eac.h>
#include <openssl/bio.h>
#include <stdlib.h>
#include <string.h>

/* included in OpenPACE, but not propagated */
extern void BUF_MEM_clear_free(BUF_MEM *b);
%}


#define EAC_ID_PACE 0
#define EAC_ID_CA 1
#define EAC_ID_TA 2
#define EAC_ID_EAC 3

EAC_CTX *
EAC_CTX_new();

void
EAC_CTX_clear_free(EAC_CTX *ctx);

int
EAC_CTX_init_pace(EAC_CTX *ctx, int protocol, int curve);

#ifndef SWIG_CSTRING_UNIMPL

%rename(EAC_encrypt) eac_encrypt;
%inline %{
    static void eac_encrypt(char **out, int *out_len, const EAC_CTX *ctx,
            char *in, int in_len) {
        BUF_MEM *out_buf = NULL, *data = NULL;

        data = get_buf(in, in_len);
        out_buf = EAC_encrypt(ctx, data);
        buf2string(out_buf, out, out_len);

        BUF_MEM_clear_free(data);
        BUF_MEM_clear_free(out_buf);
        return;
    }
%}

%rename(EAC_decrypt) eac_decrypt;
%inline %{
    static void eac_decrypt(char **out, int *out_len, const EAC_CTX *ctx,
            char *in, int in_len) {
        BUF_MEM *out_buf = NULL, *data = NULL;

        data = get_buf(in, in_len);
        out_buf = EAC_decrypt(ctx, data);
        buf2string(out_buf, out, out_len);

        BUF_MEM_clear_free(data);
        BUF_MEM_clear_free(out_buf);
    }
%}

%rename(EAC_authenticate) eac_authenticate;
%inline %{
    static void eac_authenticate(char **out, int *out_len, const EAC_CTX *ctx,
            char *in, int in_len) {
        BUF_MEM *in_buf = NULL, *out_buf = NULL;

        in_buf = get_buf(in, in_len);
        out_buf = EAC_authenticate(ctx, in_buf);
        buf2string(out_buf, out, out_len);
        BUF_MEM_clear_free(in_buf);
        BUF_MEM_clear_free(out_buf);
    }
%}

%rename(EAC_Comp) eac_comp;
%inline %{
    static void eac_comp(char **out, int *out_len, const EAC_CTX *ctx, int id,
            char *in, int in_len) {

        BUF_MEM *in_buf = NULL, *out_buf = NULL;

        in_buf = get_buf(in, in_len);
        out_buf = EAC_Comp(ctx, id, in_buf);
        buf2string(out_buf, out, out_len);
        BUF_MEM_clear_free(in_buf);
        BUF_MEM_clear_free(out_buf);
    }
%}

%rename (EAC_CTX_print_private) eac_ctx_print_private;
%inline %{
    static void eac_ctx_print_private(char **out, int *out_len, EAC_CTX *eac_ctx, int indent) {
        BIO *bio = BIO_new(BIO_s_mem());
        if (!bio)
            goto err;

        EAC_CTX_print_private(bio, eac_ctx, indent);

        *out_len = BIO_get_mem_data(bio, NULL);
        if (*out_len <= 0)
            goto err;
        *out = malloc(*out_len);
        if (!*out)
            goto err;
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

%rename(EAC_CTX_init_ef_cardaccess) eac_ctx_init_ef_cardaccess;
%inline %{
    static int eac_ctx_init_ef_cardaccess(char *in, int in_len, EAC_CTX *ctx) { /* typemap applied */
        if (in_len < 0)
            return 0;
        else
            return EAC_CTX_init_ef_cardaccess((unsigned char*) in,
                    (unsigned int) in_len, ctx);
    }
%}

%rename(EAC_CTX_init_ef_cardsecurity) eac_ctx_init_ef_cardsecurity;
%inline %{
    static int eac_ctx_init_ef_cardsecurity(char *in, int in_len, EAC_CTX *ctx) { /* typemap applied */
        if (in_len < 0)
            return 0;
        else
            return EAC_CTX_init_ef_cardsecurity((unsigned char*) in,
                    (unsigned int) in_len, ctx);
    }
%}

%rename(EAC_CTX_init_ta) eac_ctx_init_ta;
%inline %{
    static int eac_ctx_init_ta(const EAC_CTX *ctx,
            char *privkey, int privkey_len, char *cert, int cert_len) {
        return EAC_CTX_init_ta(ctx,
            (unsigned char*) privkey, (size_t) privkey_len,
            (unsigned char*) cert, (size_t) cert_len);

    }
%}

#else

BUF_MEM *
EAC_encrypt(const EAC_CTX *ctx, const BUF_MEM *data);

BUF_MEM *
EAC_decrypt(const EAC_CTX *ctx, const BUF_MEM *data);

BUF_MEM *
EAC_authenticate(const EAC_CTX *ctx, const BUF_MEM *data);

BUF_MEM *
EAC_Comp(const EAC_CTX *ctx, int id, const BUF_MEM *pub);

#ifdef SWIGJAVA
%rename(EAC_CTX_init_ef_cardaccess) eac_ctx_init_ef_cardaccess;
%inline %{
    static int eac_ctx_init_ef_cardaccess(char *in, int in_len, EAC_CTX *ctx) { /* typemap applied */
        if (in_len < 0)
            return 0;
        else
            return EAC_CTX_init_ef_cardaccess((unsigned char*) in,
                    (unsigned int) in_len, ctx);
    }
%}

%rename(EAC_CTX_init_ef_cardsecurity) eac_ctx_init_ef_cardsecurity;
%inline %{
    static int eac_ctx_init_ef_cardsecurity(char *in, int in_len, EAC_CTX *ctx) { /* typemap applied */
        if (in_len < 0)
            return 0;
        else
            return EAC_CTX_init_ef_cardsecurity((unsigned char*) in,
                    (unsigned int) in_len, ctx);
    }
%}
#else
int
EAC_CTX_init_ef_cardaccess(unsigned char *in, unsigned int in_len, EAC_CTX *ctx);

int
EAC_CTX_init_ef_cardsecurity(unsigned char *in, unsigned int in_len, EAC_CTX *ctx);
#endif

int
EAC_CTX_init_ta(const EAC_CTX *ctx,
    const unsigned char *privkey, size_t privkey_len,
    const unsigned char *cert, size_t cert_len);

#endif

int
EAC_CTX_init_ca(EAC_CTX *ctx, int protocol, int curve);

int
EAC_CTX_set_encryption_ctx(EAC_CTX *ctx, int id);

int
EAC_increment_ssc(const EAC_CTX *ctx);

int
EAC_reset_ssc(const EAC_CTX *ctx);

int
EAC_set_ssc(const EAC_CTX *ctx, unsigned long ssc);

extern char *cvc_default_dir;
extern char *x509_default_dir;
