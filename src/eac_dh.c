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
 * @file eac_dh.c
 * @brief Diffie Hellman helper functions
 *
 * @author Frank Morgner <frankmorgner@gmail.com>
 * @author Dominik Oepen <oepen@informatik.hu-berlin.de>
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "eac_dh.h"
#include "eac_err.h"
#include "misc.h"
#include "ssl_compat.h"
#include <eac/eac.h>
#include <openssl/bn.h>
#include <openssl/evp.h>

/**
 * @brief Public key validation method described in RFC 2631.
 *
 * Verify that DH->pub_key lies within the interval [2,p-1]. If it does not,
 * the key is invalid.
 * If DH->q exists, compute y^q mod p. If the result == 1, the key is valid.
 * Otherwise the key is invalid.
 *
 * @param[in] dh DH object to use
 * @param[in] ctx BN_CTX object
 * @param[out] ret Can contain these flags as result:
 * DH_CHECK_PUBKEY_TOO_SMALL (smaller than 2)
 * DH_CHECK_PUBKEY_TOO_LARGE (bigger than p-1)
 * DH_CHECK_PUBKEY_INVALID (y^q mod p != 1)
 *
 * @return 1 on success or 0 if an error occurred
 */
static int
DH_check_pub_key_rfc(const DH *dh, BN_CTX *ctx, int *ret);
#define DH_CHECK_PUBKEY_INVALID        0x04

int
init_dh(DH ** dh, int standardizedDomainParameters)
{
    int i;
    DH *tmp = NULL;

    check(dh, "Invalid arguments");

    if (!*dh) {
        switch (standardizedDomainParameters) {
           case 0:
              tmp = DH_get_1024_160();
              break;
           case 1:
              tmp = DH_get_2048_224();
              break;
           case 2:
              tmp = DH_get_2048_256();
              break;
           default:
              log_err("Invalid arguments");
              goto err;
        }
        if (!tmp)
            goto err;
    } else {
        /*Note: this could be something not matching standardizedDomainParameters */
        tmp = *dh;
    }

    if (!DH_check(tmp, &i))
        goto err;

    /* RFC 5114 parameters do not use safe primes and OpenSSL does not know
     * how to deal with generator other then 2 or 5. Therefore we have to
     * ignore some of the checks */
    i &= ~DH_CHECK_P_NOT_SAFE_PRIME;
    i &= ~DH_UNABLE_TO_CHECK_GENERATOR;

    check(!i, "Bad DH key");

    *dh = tmp;

    return 1;

err:
    if (tmp && !*dh) {
        DH_free(tmp);
    }

    return 0;
}

static int
DH_check_pub_key_rfc(const DH *dh, BN_CTX *ctx, int *ret)
{
    BIGNUM *bn = NULL;
    int ok = 0;
    const BIGNUM *pub_key, *p, *q, *g;

    check((dh && ret), "Invalid arguments");

    BN_CTX_start(ctx);

    DH_get0_key(dh, &pub_key, NULL);
    DH_get0_pqg(dh, &p, &q, &g);

    /* Verify that y lies within the interval [2,p-1]. */
    if (!DH_check_pub_key(dh, pub_key, ret))
        goto err;

    /* If the DH is conform to RFC 2631 it should have a non-NULL q.
     * Others (like the DHs generated from OpenSSL) might have a problem with
     * this check. */
    if (q) {
        /* Compute y^q mod p. If the result == 1, the key is valid. */
        bn = BN_CTX_get(ctx);
        if (!bn || !BN_mod_exp(bn, pub_key, q, p, ctx))
            goto err;
        if (!BN_is_one(bn))
            *ret |= DH_CHECK_PUBKEY_INVALID;
    }
    ok = 1;

err:
    BN_CTX_end(ctx);
    return ok;
}


BIGNUM *
DH_get_q(const DH *dh, BN_CTX *ctx)
{
    BIGNUM *q_new = NULL, *bn = NULL;
    int i;
    const BIGNUM *p, *q;

    check(dh, "Invalid arguments");

    DH_get0_pqg(dh, &p, &q, NULL);
    if (!q) {
        q_new = BN_new();
        bn = BN_dup(p);

        /* DH primes should be strong, based on a Sophie Germain prime q
         * p=(2*q)+1 or (p-1)/2=q */
        if (!q_new || !bn ||
                !BN_sub_word(bn, 1) ||
                !BN_rshift1(q_new, bn)) {
            goto err;
        }
    } else {
        q_new = BN_dup(q);
    }

    /* q should always be prime */
    i = BN_is_prime_ex(q_new, BN_prime_checks, ctx, NULL);
    if (i <= 0) {
       if (i == 0)
          log_err("Unable to get Sophie Germain prime");
       goto err;
    }

    return q_new;

err:
    if (bn)
        BN_clear_free(bn);
    if (q_new)
        BN_clear_free(q_new);

    return NULL;
}

BIGNUM *
DH_get_order(const DH *dh, BN_CTX *ctx)
{
    BIGNUM *order = NULL, *bn = NULL;
    const BIGNUM *p, *g;

    check(dh && ctx, "Invalid argument");

    BN_CTX_start(ctx);

    DH_get0_pqg(dh, &p, NULL, &g);

    /* suppose the order of g is q-1 */
    order = DH_get_q(dh, ctx);
    bn = BN_CTX_get(ctx);
    if (!bn || !order || !BN_sub_word(order, 1)
          || !BN_mod_exp(bn, g, order, p, ctx))
        goto err;

    if (BN_cmp(bn, BN_value_one()) != 0) {
        /* if bn != 1, then q-1 is not the order of g, but p-1 should be */
        if (!BN_sub(order, p, BN_value_one()) ||
              !BN_mod_exp(bn, g, order, p, ctx))
           goto err;
        check(BN_cmp(bn, BN_value_one()) == 0, "Unable to get order");
    }

    BN_CTX_end(ctx);

    return order;

err:
    if (order)
        BN_clear_free(order);
    BN_CTX_end(ctx);

    return NULL;
}

BUF_MEM *
dh_generate_key(EVP_PKEY *key, BN_CTX *bn_ctx)
{
    int suc;
    DH *dh = NULL;
    BUF_MEM *ret = NULL;
    const BIGNUM *pub_key;


    check(key, "Invalid arguments");

    dh = EVP_PKEY_get1_DH(key);
    if (!dh)
        goto err;

    if (!DH_generate_key(dh) || !DH_check_pub_key_rfc(dh, bn_ctx, &suc))
        goto err;

    if (suc)
        goto err;

    DH_get0_key(dh, &pub_key, NULL);

    ret = BN_bn2buf(pub_key);

err:
    if (dh)
        DH_free(dh);
    return ret;
}

BUF_MEM *
dh_compute_key(EVP_PKEY *key, const BUF_MEM * in, BN_CTX *bn_ctx)
{
    BUF_MEM * out = NULL;
    BIGNUM * bn = NULL;
    DH *dh = NULL;

    check(key && in, "Invalid arguments");

    dh = EVP_PKEY_get1_DH(key);
    if (!dh)
        return NULL;

    /* decode public key */
    bn = BN_bin2bn((unsigned char *) in->data, in->length, bn);
    if (!bn)
        goto err;

    out = BUF_MEM_create(DH_size(dh));
    if (!out)
        goto err;

    out->length = DH_compute_key((unsigned char *) out->data, bn, dh);
    if ((int) out->length < 0)
        goto err;

    BN_clear_free(bn);
    DH_free(dh);

    return out;

err:
    if (out)
        BUF_MEM_free(out);
    if (bn)
        BN_clear_free(bn);
    if (dh)
        DH_free(dh);

    return NULL;
}

DH *
DHparams_dup_with_q(DH *dh)
{
    const BIGNUM *p, *q, *g;

    DH *dup = DHparams_dup(dh);
    if (dup) {
        DH_get0_pqg(dh, &p, &q, &g);
        DH_set0_pqg(dup, BN_dup(p), BN_dup(q), BN_dup(g));
    }

    return dup;
}
