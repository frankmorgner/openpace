/*
 * Copyright (c) 2010-2012 Frank Morgner and Dominik Oepen
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
 * @file misc.c
 * @brief Miscellaneous functions used in OpenPACE
 *
 * @author Frank Morgner <morgner@informatik.hu-berlin.de>
 * @author Dominik Oepen <oepen@informatik.hu-berlin.de>
 */

#include "eac_err.h"
#include "misc.h"
#include <limits.h>
#include <openssl/ecdh.h>
#include <openssl/engine.h>
#include <openssl/ossl_typ.h>
#include <string.h>

struct ecdh_method
    {
    const char *name;
    int (*compute_key)(void *key, size_t outlen, const EC_POINT *pub_key, EC_KEY *ecdh,
                       void *(*KDF)(const void *in, size_t inlen, void *out, size_t *outlen));
#if 0
    int (*init)(EC_KEY *eckey);
    int (*finish)(EC_KEY *eckey);
#endif
    int flags;
    char *app_data;
    };

static int ecdh_compute_key_point(void *out, size_t outlen, const EC_POINT *pub_key,
   EC_KEY *ecdh,
   void *(*KDF)(const void *in, size_t inlen, void *out, size_t *outlen));

static ECDH_METHOD openssl_ecdh_meth_point = {
    "OpenSSL ECDH method with Point",
    ecdh_compute_key_point,
#if 0
    NULL, /* init   */
    NULL, /* finish */
#endif
    0,    /* flags  */
    NULL  /* app_data */
};

int ecdh_compute_key_point(void *out, size_t outlen, const EC_POINT *pub_key,
   EC_KEY *ecdh,
   void *(*KDF)(const void *in, size_t inlen, void *out, size_t *outlen))
   {
   BN_CTX *ctx = NULL;
   EC_POINT *tmp=NULL;
   const BIGNUM *priv_key;
   const EC_GROUP* group;
   int ret= -1;
   size_t buflen;
   unsigned char *buf=NULL;

   check((outlen < INT_MAX), "out of memory"); /* sort of, anyway */

   if ((ctx = BN_CTX_new()) == NULL) goto err;
   BN_CTX_start(ctx);

   priv_key = EC_KEY_get0_private_key(ecdh);
   check(priv_key, "No pivate key");

   group = EC_KEY_get0_group(ecdh);
   tmp = EC_POINT_new(group);
   check(tmp, "Out of memory");

   check((EC_POINT_mul(group, tmp, NULL, pub_key, priv_key, ctx)),
           "Arithmetic error");

    buflen = EC_POINT_point2oct(group, tmp, EC_KEY_get_conv_form(ecdh), NULL,
            0, ctx);
    check((buflen != 0), "Failed to convert point to hex");

    buf = OPENSSL_malloc(buflen);
    check(buf, "Out of memory");

    check((buflen == EC_POINT_point2oct(group, tmp, EC_KEY_get_conv_form(ecdh),
                    buf, buflen, ctx)), "Failed to convert point to hex");

    if (KDF != 0)
    {
        check((KDF(buf, buflen, out, &outlen) != NULL),
                "Key derivation function failed");
        ret = outlen;
    }
    else
    {
        /* no KDF, just copy as much as we can */
        if (outlen > buflen)
            outlen = buflen;
        memcpy(out, buf, outlen);
        ret = outlen;
    }

err:
    if (tmp) EC_POINT_free(tmp);
    if (ctx) BN_CTX_end(ctx);
    if (ctx) BN_CTX_free(ctx);
    if (buf) OPENSSL_free(buf);
    return(ret);
}

BUF_MEM *
BUF_MEM_create(size_t len)
{
    BUF_MEM *out = BUF_MEM_new();
    if (!out)
        return NULL;

    if (!BUF_MEM_grow(out, len)) {
        BUF_MEM_free(out);
        return NULL;
    }

    return out;
}

BUF_MEM *
BUF_MEM_create_init(const void *buf, size_t len)
{
    BUF_MEM *out;

    out = BUF_MEM_create(len);
    if (!out)
        return NULL;

    memcpy(out->data, buf, len);

    return out;
}

BUF_MEM *
BUF_MEM_dup(const BUF_MEM * in)
{
    BUF_MEM * out = NULL;

    if (!in)
        return NULL;

    out = BUF_MEM_create(in->length);
    check(out, "Failed to allocate memory");

    memcpy(out->data, in->data, in->length);
    out->max = in->max;

    return out;

err:
    if (out)
        BUF_MEM_free(out);

    return NULL;
}

BUF_MEM *
BN_bn2buf(const BIGNUM *bn)
{
    BUF_MEM * out;

    if (!bn)
        return NULL;

    out = BUF_MEM_create(BN_num_bytes(bn));
    if (!out)
        return NULL;

    out->length = BN_bn2bin(bn, (unsigned char *) out->data);

    return out;
}

BUF_MEM *
EC_POINT_point2buf(const EC_KEY * ecdh, BN_CTX * bn_ctx, const EC_POINT * ecp)
{
    size_t len;
    BUF_MEM * out;

    len = EC_POINT_point2oct(EC_KEY_get0_group(ecdh), ecp,
            EC_KEY_get_conv_form(ecdh), NULL, 0, bn_ctx);
    if (len == 0)
        return NULL;

    out = BUF_MEM_create(len);
    if (!out)
        return NULL;

    out->length = EC_POINT_point2oct(EC_KEY_get0_group(ecdh), ecp,
            EC_KEY_get_conv_form(ecdh), (unsigned char *) out->data, out->max,
            bn_ctx);

    return out;
}

const ECDH_METHOD *ECDH_OpenSSL_Point(void)
    {
    return &openssl_ecdh_meth_point;
    }
int
consttime_memcmp(const BUF_MEM *a, const BUF_MEM *b)
{
    unsigned int ret = 0x00;
    int i = 0;

    check((a && b), "Invalid arguments");

    /* Decide whether to compare with given or random data.
     * This leaks the length of a. */
    if (a->length != b->length)
        return 1;

    /* XOR all the Bytes */
    for (i = 0; i < b->length; i++)
        ret |= (unsigned char) (a->data[i] ^ b->data[i]);

err:
    return (1 & ((ret -1) >> 8)) - 1;
}
