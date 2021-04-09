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
 * @file pace_mappings.c
 * @brief Functions for domain parameter mappings
 *
 * @author Frank Morgner <frankmorgner@gmail.com>
 * @author Dominik Oepen <oepen@informatik.hu-berlin.de>
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "eac_dh.h"
#include "eac_ecdh.h"
#include "eac_err.h"
#include "eac_util.h"
#include "misc.h"
#include "pace_mappings.h"
#include "ssl_compat.h"
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>

BUF_MEM *
dh_gm_generate_key(const PACE_CTX * ctx, BN_CTX *bn_ctx)
{
    check_return(ctx, "Invalid arguments");

    return dh_generate_key(ctx->static_key, bn_ctx);
}

int
dh_gm_compute_key(PACE_CTX * ctx, const BUF_MEM * s, const BUF_MEM * in,
        BN_CTX *bn_ctx)
{
    int ret = 0;
    BUF_MEM * mem_h = NULL;
    BIGNUM * bn_s = NULL, *bn_h = NULL, *bn_g = NULL, *new_g = NULL;
    DH *static_key = NULL, *ephemeral_key = NULL;
    const BIGNUM *p, *q, *g;

    check(ctx && ctx->static_key && s && ctx->ka_ctx, "Invalid arguments");

    BN_CTX_start(bn_ctx);

    static_key = EVP_PKEY_get1_DH(ctx->static_key);
    if (!static_key)
        goto err;

    /* Convert nonce to BIGNUM */
    bn_s = BN_bin2bn((unsigned char *) s->data, s->length, bn_s);
    if (!bn_s)
        goto err;

    /* complete the DH and convert the result to a BIGNUM */
    mem_h = dh_compute_key(ctx->static_key, in, bn_ctx);
    if (!mem_h)
        goto err;
    bn_h = BN_bin2bn((unsigned char *) mem_h->data, mem_h->length, bn_h);
    if (!bn_h)
        goto err;

    /* Initialize ephemeral parameters with parameters from the static key */
    ephemeral_key = DHparams_dup(static_key);
    if (!ephemeral_key)
        goto err;

    DH_get0_pqg(static_key, &p, &q, &g);

    /* map to new generator */
    bn_g = BN_CTX_get(bn_ctx);
    new_g = BN_new();
    if (!bn_g || !new_g ||
        /* bn_g = g^s mod p */
        !BN_mod_exp(bn_g, g, bn_s, p, bn_ctx) ||
        /* ephemeral_key->g = bn_g * h mod p = g^s * h mod p */
        !BN_mod_mul(new_g, bn_g, bn_h, p, bn_ctx))
        goto err;

    if (!DH_set0_pqg(ephemeral_key, BN_dup(p), BN_dup(q), new_g))
        goto err;
    new_g = NULL;

    /* Copy ephemeral key to context structure */
    if (!EVP_PKEY_set1_DH(ctx->ka_ctx->key, ephemeral_key))
        goto err;

    ret = 1;

err:
    if (mem_h) {
        OPENSSL_cleanse(mem_h->data, mem_h->max);
        BUF_MEM_free(mem_h);
    }
    if (bn_h)
        BN_clear_free(bn_h);
    if (bn_s)
        BN_clear_free(bn_s);
    /* Decrement reference count, keys are still available via PACE_CTX */
    if (static_key)
        DH_free(static_key);
    if (ephemeral_key)
        DH_free(ephemeral_key);
    BN_CTX_end(bn_ctx);
    if (new_g)
        BN_clear_free(new_g);

    return ret;
}

BUF_MEM *
dh_im_generate_key(const PACE_CTX * ctx, BN_CTX *bn_ctx)
{
    check_return((ctx && ctx->ka_ctx), "Invalid arguments");

    return randb(EVP_CIPHER_key_length(ctx->ka_ctx->cipher));
}

int
dh_im_compute_key(PACE_CTX * ctx, const BUF_MEM * s, const BUF_MEM * in,
        BN_CTX *bn_ctx)
{
    int ret = 0;
    BUF_MEM * x_mem = NULL;
    BIGNUM * x_bn = NULL, *a = NULL, *p_1 = NULL, *q = NULL, *g_new = NULL;
    const BIGNUM *p, *g;
    DH *static_key = NULL, *ephemeral_key = NULL;

    check((ctx && in && ctx->ka_ctx), "Invalid arguments");
    if (in->length < (size_t) EVP_CIPHER_key_length(ctx->ka_ctx->cipher)
            || !ctx->static_key)
        goto err;

    BN_CTX_start(bn_ctx);

    static_key = EVP_PKEY_get1_DH(ctx->static_key);
    if (!static_key)
        goto err;

    /* Initialize ephemeral parameters with parameters from the static key */
    ephemeral_key = DHparams_dup_with_q(static_key);
    if (!ephemeral_key)
        goto err;
    DH_get0_pqg(ephemeral_key, &p, NULL, &g);

    /* Perform the actual mapping */
    x_mem = cipher_no_pad(ctx->ka_ctx, NULL, in, s, 1);
    if (!x_mem)
        goto err;
    x_bn = BN_bin2bn((unsigned char *) x_mem->data, x_mem->length, x_bn);
    a = BN_CTX_get(bn_ctx);
    q = DH_get_q(static_key, bn_ctx);
    p_1 = BN_dup(p);
    g_new = BN_dup(g);
    if (!x_bn || !a || !q || !p_1 || !g_new ||
            /* p_1 = p-1 */
            !BN_sub_word(p_1, 1) ||
            /* a = p-1 / q */
            !BN_div(a, NULL, p_1, q, bn_ctx) ||
            /* g~ = x^a mod p */
            !BN_mod_exp(g_new, x_bn, a, p, bn_ctx))
        goto err;

    /* check if g~ != 1 */
    check((!BN_is_one(g_new)), "Bad DH generator");

    DH_set0_pqg(ephemeral_key, BN_dup(p), q, g_new);
    g_new = NULL;
    q = NULL;

    /* Copy ephemeral key to context structure */
    if (!EVP_PKEY_set1_DH(ctx->ka_ctx->key, ephemeral_key))
        goto err;

    ret = 1;

err:
    if (q)
        BN_clear_free(q);
    if (g_new)
        BN_clear_free(g_new);
    if (p_1)
        BN_clear_free(p_1);
    if (x_bn)
        BN_clear_free(x_bn);
    if (x_mem)
        BUF_MEM_free(x_mem);
    /* Decrement reference count, keys are still available via PACE_CTX */
    if (static_key)
        DH_free(static_key);
    if (ephemeral_key)
        DH_free(ephemeral_key);
    BN_CTX_end(bn_ctx);

    return ret;
}

BUF_MEM *
ecdh_gm_generate_key(const PACE_CTX * ctx, BN_CTX *bn_ctx)
{
    check_return(ctx, "Invalid arguments");

    return ecdh_generate_key(ctx->static_key, bn_ctx);
}

int
ecdh_gm_compute_key(PACE_CTX * ctx, const BUF_MEM * s, const BUF_MEM * in,
        BN_CTX *bn_ctx)
{
    int ret = 0;
    BUF_MEM * mem_h = NULL;
    BIGNUM * bn_s = NULL, *order = NULL, *cofactor = NULL;
    EC_POINT * ecp_h = NULL, *ecp_g = NULL;
    EC_GROUP *group = NULL;
    EC_KEY *static_key = NULL, *ephemeral_key = NULL;
#ifdef HAVE_EC_KEY_METHOD
    const EC_KEY_METHOD *default_method;
#else
    const ECDH_METHOD *default_method;
#endif

    BN_CTX_start(bn_ctx);

    check((ctx && ctx->static_key && s && ctx->ka_ctx), "Invalid arguments");

    static_key = EVP_PKEY_get1_EC_KEY(ctx->static_key);
    check(static_key, "could not get key object");

    /* Extract group parameters */
    group = EC_GROUP_dup(EC_KEY_get0_group(static_key));
    order = BN_CTX_get(bn_ctx);
    cofactor = BN_CTX_get(bn_ctx);
    check(group && cofactor, "internal error");
    if (!EC_GROUP_get_order(group, order, bn_ctx)
            || !EC_GROUP_get_cofactor(group, cofactor, bn_ctx))
        goto err;

    /* Convert nonce to BIGNUM */
    bn_s = BN_bin2bn((unsigned char *) s->data, s->length, bn_s);
    if (!bn_s)
        goto err;

#ifdef HAVE_EC_KEY_METHOD
    default_method = EC_KEY_get_method(static_key);
    if (!EC_KEY_set_method(static_key, EC_KEY_OpenSSL_Point()))
        goto err;
    /* complete the ECDH and get the resulting point h */
    mem_h = ecdh_compute_key(ctx->static_key, in, bn_ctx);
    EC_KEY_set_method(static_key, default_method);
#else
    default_method = ECDH_get_default_method();
    ECDH_set_default_method(ECDH_OpenSSL_Point());
    /* complete the ECDH and get the resulting point h */
    mem_h = ecdh_compute_key(ctx->static_key, in, bn_ctx);
    ECDH_set_default_method(default_method);
#endif
    ecp_h = EC_POINT_new(group);
    if (!mem_h || !ecp_h || !EC_POINT_oct2point(group, ecp_h,
            (unsigned char *) mem_h->data, mem_h->length, bn_ctx))
        goto err;

    /* map to new generator */
    ecp_g = EC_POINT_new(group);
    /* g' = g*s + h*1 */
    if (!EC_POINT_mul(group, ecp_g, bn_s, ecp_h, BN_value_one(), bn_ctx))
        goto err;

    /* Initialize ephemeral parameters with parameters from the static key */
    ephemeral_key = EC_KEY_dup(static_key);
    if (!ephemeral_key)
        goto err;
    EVP_PKEY_set1_EC_KEY(ctx->ka_ctx->key, ephemeral_key);

    /* configure the new EC_KEY */
    if (!EC_GROUP_set_generator(group, ecp_g, order, cofactor)
            || !EC_GROUP_check(group, bn_ctx)
            || !EC_KEY_set_group(ephemeral_key, group))
        goto err;

    ret = 1;

err:
    if (ecp_g)
        EC_POINT_clear_free(ecp_g);
    if (ecp_h)
        EC_POINT_clear_free(ecp_h);
    if (mem_h)
        BUF_MEM_free(mem_h);
    if (bn_s)
        BN_clear_free(bn_s);
    BN_CTX_end(bn_ctx);
    /* Decrement reference count, keys are still available via PACE_CTX */
    if (static_key)
        EC_KEY_free(static_key);
    if (ephemeral_key)
        EC_KEY_free(ephemeral_key);
    if (group)
        EC_GROUP_clear_free(group);

    return ret;
}

BUF_MEM *
ecdh_im_generate_key(const PACE_CTX * ctx, BN_CTX *bn_ctx)
{
    check_return((ctx && ctx->ka_ctx), "Invalid arguments");

    return randb(EVP_CIPHER_key_length(ctx->ka_ctx->cipher));
}

int
ecdh_im_compute_key(PACE_CTX * ctx, const BUF_MEM * s, const BUF_MEM * in,
        BN_CTX *bn_ctx)
{
    int ret = 0;
    BUF_MEM * x_mem = NULL;
    BIGNUM * a = NULL, *b = NULL, *p = NULL;
    BIGNUM * x = NULL, *y = NULL, *v = NULL, *u = NULL;
    BIGNUM * tmp = NULL, *tmp2 = NULL, *bn_inv = NULL;
    BIGNUM * two = NULL, *three = NULL, *four = NULL, *six = NULL;
    BIGNUM * twentyseven = NULL;
    EC_KEY *static_key = NULL, *ephemeral_key = NULL;
    EC_POINT *g = NULL;

    BN_CTX_start(bn_ctx);

    check((ctx && ctx->static_key && s && ctx->ka_ctx), "Invalid arguments"); 

    static_key = EVP_PKEY_get1_EC_KEY(ctx->static_key);
    if (!static_key)
        goto err;

    /* Setup all the variables*/
    a = BN_CTX_get(bn_ctx);
    b = BN_CTX_get(bn_ctx);
    p = BN_CTX_get(bn_ctx);
    x = BN_CTX_get(bn_ctx);
    y = BN_CTX_get(bn_ctx);
    v = BN_CTX_get(bn_ctx);
    two = BN_CTX_get(bn_ctx);
    three = BN_CTX_get(bn_ctx);
    four = BN_CTX_get(bn_ctx);
    six = BN_CTX_get(bn_ctx);
    twentyseven = BN_CTX_get(bn_ctx);
    tmp = BN_CTX_get(bn_ctx);
    tmp2 = BN_CTX_get(bn_ctx);
    bn_inv = BN_CTX_get(bn_ctx);
    if (!bn_inv)
        goto err;

    /* Encrypt the Nonce using the symmetric key in */
    x_mem = cipher_no_pad(ctx->ka_ctx, NULL, in, s, 1);
    if (!x_mem)
        goto err;

    /* Fetch the curve parameters */
    if (!EC_GROUP_get_curve_GFp(EC_KEY_get0_group(static_key), p, a, b, bn_ctx))
        goto err;

    /* Assign constants */
    if (    !BN_set_word(two,2)||
            !BN_set_word(three,3)||
            !BN_set_word(four,4)||
            !BN_set_word(six,6)||
            !BN_set_word(twentyseven,27)
            ) goto err;

    /* Check prerequisites for curve parameters */
    check(
            /* p > 3;*/
           (BN_cmp(p, three) == 1) &&
           /* p mod 3 = 2; (p has the form p=q^n, q prime) */
           BN_nnmod(tmp, p, three, bn_ctx) &&
           (BN_cmp(tmp, two) == 0),
        "Unsuited curve");

    /* Convert encrypted nonce to BIGNUM */
    u = BN_bin2bn((unsigned char *) x_mem->data, x_mem->length, u);
    if (!u)
        goto err;

    if ( /* v = (3a - u^4) / 6u mod p */
            !BN_mod_mul(tmp, three, a, p, bn_ctx) ||
            !BN_mod_exp(tmp2, u, four, p, bn_ctx) ||
            !BN_mod_sub(v, tmp, tmp2, p, bn_ctx) ||
            !BN_mod_mul(tmp, u, six, p, bn_ctx) ||
            /* For division within a galois field we need to compute
             * the multiplicative inverse of a number */
            !BN_mod_inverse(bn_inv, tmp, p, bn_ctx) ||
            !BN_mod_mul(v, v, bn_inv, p, bn_ctx) ||

            /* x = (v^2 - b - ((u^6)/27)) */
            !BN_mod_sqr(tmp, v, p, bn_ctx) ||
            !BN_mod_sub(tmp2, tmp, b, p, bn_ctx) ||
            !BN_mod_exp(tmp, u, six, p, bn_ctx) ||
            !BN_mod_inverse(bn_inv, twentyseven, p, bn_ctx) ||
            !BN_mod_mul(tmp, tmp, bn_inv, p, bn_ctx) ||
            !BN_mod_sub(x, tmp2, tmp, p, bn_ctx) ||

            /* x -> x^(1/3) = x^((2p^n -1)/3) */
            !BN_mul(tmp, two, p, bn_ctx) ||
            !BN_sub(tmp, tmp, BN_value_one()) ||

            /* Division is defined, because p^n = 2 mod 3 */
            !BN_div(tmp, y, tmp, three, bn_ctx) ||
            !BN_mod_exp(tmp2, x, tmp, p, bn_ctx) ||
            !BN_copy(x, tmp2) ||

            /* x += (u^2)/3 */
            !BN_mod_sqr(tmp, u, p, bn_ctx) ||
            !BN_mod_inverse(bn_inv, three, p, bn_ctx) ||
            !BN_mod_mul(tmp2, tmp, bn_inv, p, bn_ctx) ||
            !BN_mod_add(tmp, x, tmp2, p, bn_ctx) ||
            !BN_copy(x, tmp) ||

            /* y = ux + v */
            !BN_mod_mul(y, u, x, p, bn_ctx) ||
            !BN_mod_add(tmp, y, v, p, bn_ctx) ||
            !BN_copy(y, tmp)
            )
        goto err;

    /* Initialize ephemeral parameters with parameters from the static key */
    ephemeral_key = EC_KEY_dup(static_key);
    if (!ephemeral_key)
        goto err;
    EVP_PKEY_set1_EC_KEY(ctx->ka_ctx->key, ephemeral_key);

    /* configure the new EC_KEY */
    g = EC_POINT_new(EC_KEY_get0_group(ephemeral_key));
    if (!g)
        goto err;
    if (!EC_POINT_set_affine_coordinates(EC_KEY_get0_group(ephemeral_key), g,
            x, y, bn_ctx))
        goto err;

    ret = 1;

err:
    if (x_mem)
        BUF_MEM_free(x_mem);
    if (u)
        BN_free(u);
    BN_CTX_end(bn_ctx);
    if (g)
        EC_POINT_clear_free(g);
    /* Decrement reference count, keys are still available via PACE_CTX */
    if (static_key)
        EC_KEY_free(static_key);
    if (ephemeral_key)
        EC_KEY_free(ephemeral_key);

    return ret;
}
