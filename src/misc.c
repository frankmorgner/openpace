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
 * @file misc.c
 * @brief Miscellaneous functions used in OpenPACE
 *
 * @author Frank Morgner <frankmorgner@gmail.com>
 * @author Dominik Oepen <oepen@informatik.hu-berlin.de>
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "eac_err.h"
#include "misc.h"
#include <limits.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>
#include <openssl/ossl_typ.h>
#include <stdint.h>
#include <string.h>

static int ecdh_compute_key_point(void *out, size_t outlen, const EC_POINT *pub_key,
        EC_KEY *ecdh,
        void *(*KDF)(const void *in, size_t inlen, void *out, size_t *outlen));
static int new_ecdh_compute_key_point(unsigned char **psec, size_t *pseclen,
        const EC_POINT *pub_key, const EC_KEY *ecdh);

struct ec_key_method_st {
    const char *name;
    int32_t flags;
    int (*init)(EC_KEY *key);
    void (*finish)(EC_KEY *key);
    int (*copy)(EC_KEY *dest, const EC_KEY *src);
    int (*set_group)(EC_KEY *key, const EC_GROUP *grp);
    int (*set_private)(EC_KEY *key, const BIGNUM *priv_key);
    int (*set_public)(EC_KEY *key, const EC_POINT *pub_key);
    int (*keygen)(EC_KEY *key);
    int (*compute_key)(unsigned char **pout, size_t *poutlen,
            const EC_POINT *pub_key, const EC_KEY *ecdh);
    int (*sign)(int type, const unsigned char *dgst, int dlen, unsigned char
            *sig, unsigned int *siglen, const BIGNUM *kinv,
            const BIGNUM *r, EC_KEY *eckey);
    int (*sign_setup)(EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kinvp,
            BIGNUM **rp);
    ECDSA_SIG *(*sign_sig)(const unsigned char *dgst, int dgst_len,
            const BIGNUM *in_kinv, const BIGNUM *in_r,
            EC_KEY *eckey);

    int (*verify)(int type, const unsigned char *dgst, int dgst_len,
            const unsigned char *sigbuf, int sig_len, EC_KEY *eckey);
    int (*verify_sig)(const unsigned char *dgst, int dgst_len,
            const ECDSA_SIG *sig, EC_KEY *eckey);
};

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

#ifdef HAVE_EC_KEY_METHOD

static const EC_KEY_METHOD openssl_ec_key_meth_point = {
    "OpenSSL EC_KEY method with Point",
    0,
    0,0,0,0,0,0,
    NULL,
    new_ecdh_compute_key_point,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

const EC_KEY_METHOD *EC_KEY_OpenSSL_Point(void)
{
    return &openssl_ec_key_meth_point;
}

#else

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

const ECDH_METHOD *ECDH_OpenSSL_Point(void)
{
    return &openssl_ecdh_meth_point;
}
#endif

int new_ecdh_compute_key_point(unsigned char **psec, size_t *pseclen, const
        EC_POINT *pub_key, const EC_KEY *ecdh)
{
    /* The new API requires us to allocate the memory for the output buffer */
    int ret= -1;
    /* should be enough to hold an uncompressed point of a 528 bit curve
     * (e.g. secp521r1, which is the biggest curve of BSI TR-03110) */
    *psec = OPENSSL_malloc(133);
    check(*psec, "Out of memory");
    *pseclen = 133;
    ret = ecdh_compute_key_point(*psec, *pseclen, pub_key, (EC_KEY *) ecdh, NULL);
err:
    if (ret <= 0) {
        OPENSSL_free(*psec);
        *psec = NULL;
        *pseclen = 0;
        ret = 0;
    } else {
        *pseclen = ret;
        ret = 1;
    }
    return ret;
}

int ecdh_compute_key_point(void *out, size_t outlen, const EC_POINT *pub_key,
        EC_KEY *ecdh,
        void *(*KDF)(const void *in, size_t inlen, void *out, size_t *outlen))
{
    /* The old API allocates the memory for us */
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

    if (len == 0)
        return out;

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

err:
    return out;
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
EC_POINT_point2mem(const EC_KEY * ecdh, BN_CTX * bn_ctx, const EC_POINT * ecp)
{
    size_t len;
    BUF_MEM * out;

    if (!ecp)
        return NULL;

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
