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
 * @file eac_lib.c
 * @brief Data management functions
 *
 * @author Frank Morgner <frankmorgner@gmail.com>
 * @author Dominik Oepen <oepen@informatik.hu-berlin.de>
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ca_lib.h"
#include "eac_dh.h"
#include "eac_ecdh.h"
#include "eac_err.h"
#include "eac_lib.h"
#include "eac_util.h"
#include "misc.h"
#include "pace_lib.h"
#include "ssl_compat.h"
#include "ta_lib.h"
#include <eac/ca.h>
#include <eac/cv_cert.h>
#include <eac/eac.h>
#include <eac/pace.h>
#include <eac/ri.h>
#include <eac/ta.h>
#include <openssl/buffer.h>
#include <openssl/crypto.h>
#include <string.h>

void EAC_init(void)
{
    OpenSSL_add_all_algorithms();
    EAC_add_all_objects();
    EAC_set_x509_default_dir(X509DIR);
    EAC_set_cvc_default_dir(CVCDIR);
}

void EAC_cleanup(void)
{
    EAC_remove_all_objects();
    EVP_cleanup();
}

EAC_CTX *
EAC_CTX_new(void)
{
    EAC_CTX *ctx = OPENSSL_zalloc(sizeof(EAC_CTX));
    if (!ctx)
        return NULL;

    ctx->bn_ctx = BN_CTX_new();
    ctx->ca_ctxs = (STACK_OF(CA_CTX *)) sk_new_null();
    ctx->cipher_ctx = EVP_CIPHER_CTX_new();
    ctx->md_ctx = EVP_MD_CTX_create();
    ctx->pace_ctxs = (STACK_OF(PACE_CTX *)) sk_new_null();
    ctx->ri_ctxs = (STACK_OF(RI_CTX *)) sk_new_null();
    ctx->ssc = BN_new();
    ctx->ta_ctx = TA_CTX_new();

    if (!ctx->bn_ctx || !ctx->md_ctx || !ctx->pace_ctxs
            || !ctx->ta_ctx || !ctx->ca_ctxs || !ctx->cipher_ctx
            || !ctx->ri_ctxs || !ctx->ssc)
        goto err;

    EVP_CIPHER_CTX_init(ctx->cipher_ctx);
    ctx->tr_version = EAC_TR_VERSION_2_02;

    return ctx;

err:
    EAC_CTX_clear_free(ctx);
    return NULL;
}

int
EAC_CTX_init_pace(EAC_CTX *ctx, int protocol, int curve)
{
    PACE_CTX *pace_ctx = NULL;
    int r = 0;

    if (!ctx) {
        log_err("Invalid arguments");
        goto err;
    }

    pace_ctx = PACE_CTX_new();
    if (!pace_ctx
            || !PACE_CTX_set_protocol(pace_ctx, protocol, ctx->tr_version)
            || !EVP_PKEY_set_std_dp(pace_ctx->static_key, curve)) {
        log_err("Could not initialize PACE context");
        goto err;
    }

    r = 1;

err:
    if (r && sk_push((_STACK *) ctx->pace_ctxs, pace_ctx)) {
        ctx->pace_ctx = pace_ctx;
    } else {
        /* either an error occurred before
         * or we could not push it onto the stack */
        r = 0;
        PACE_CTX_clear_free(pace_ctx);
    }

    return r;
}

int
EAC_CTX_init_ta(const EAC_CTX *ctx,
           const unsigned char *privkey, size_t privkey_len,
           const unsigned char *cvca, size_t cvca_len)
{
    CVC_CERT *ta_cvca = NULL;
    int r = 0;

    check(ctx && ctx->ta_ctx, "Invalid arguments");

    if (privkey && privkey_len) {
        if (ctx->ta_ctx->priv_key)
            EVP_PKEY_free(ctx->ta_ctx->priv_key);
        ctx->ta_ctx->priv_key = d2i_AutoPrivateKey(&ctx->ta_ctx->priv_key,
                &privkey, privkey_len);
        if (!ctx->ta_ctx->priv_key)
            goto err;
    }

    if (cvca && cvca_len) {
        ta_cvca = CVC_d2i_CVC_CERT(&ta_cvca, &cvca, cvca_len);
    }
    r = TA_CTX_set_trust_anchor(ctx->ta_ctx, ta_cvca, ctx->bn_ctx);

err:
    if (ta_cvca)
        CVC_CERT_free(ta_cvca);

    return r;
}

int
EAC_CTX_init_ca(EAC_CTX *ctx, int protocol, int curve)
{
    CA_CTX *ca_ctx = NULL;
    int r = 0;

    if (!ctx || !ctx->ca_ctxs) {
        log_err("Invalid arguments");
        goto err;
    }

    ca_ctx = CA_CTX_new();
    check(ca_ctx, "Could not create CA context");

    if (!CA_CTX_set_protocol(ca_ctx, protocol)
            || !EVP_PKEY_set_std_dp(ca_ctx->ka_ctx->key, curve))
        goto err;

    r = 1;

err:
    if (r && sk_push((_STACK *) ctx->ca_ctxs, ca_ctx)) {
        ctx->ca_ctx = ca_ctx;
    } else {
        /* either an error occurred before
         * or we could not push it onto the stack */
        r = 0;
        CA_CTX_clear_free(ca_ctx);
    }

    return r;
}

int
EAC_CTX_init_ri(EAC_CTX *ctx, int protocol, int stnd_dp)
{
    BUF_MEM *pubkey = NULL;
    RI_CTX *ri_ctx = NULL;
    int r = 0;

    if (!ctx || !ctx->ri_ctxs) {
        log_err("Invalid arguments");
        goto err;
    }

    ri_ctx = RI_CTX_new();
    check(ri_ctx, "Could not create RI context");

    if (!RI_CTX_set_protocol(ri_ctx, protocol)
               || !EVP_PKEY_set_std_dp(ri_ctx->static_key, stnd_dp))
            goto err;

    if (!ri_ctx->generate_key)
        goto err;

    pubkey = ri_ctx->generate_key(ri_ctx->static_key, ctx->bn_ctx);
    if (!pubkey)
        goto err;
    else /* We do not need the buffered public key and throw it away immediately */
        BUF_MEM_clear_free(pubkey);

    r = 1;

err:
    if (r && sk_push((_STACK *) ctx->ri_ctxs, ri_ctx)) {
        ctx->ri_ctx = ri_ctx;
    } else {
        /* either an error occurred before
         * or we could not push it onto the stack */
        r = 0;
        RI_CTX_clear_free(ri_ctx);
    }

    return r;
}


static void
wrap_pace_ctx_clear_free(void * ctx)
{
    PACE_CTX_clear_free(ctx);
}

static void
wrap_ca_ctx_clear_free(void *ctx)
{
    CA_CTX_clear_free(ctx);
}

static void
wrap_ri_ctx_clear_free(void * ctx)
{
    RI_CTX_clear_free(ctx);
}

void
EAC_CTX_clear_free(EAC_CTX *ctx)
{
    if (ctx) {
        if (ctx->bn_ctx)
            BN_CTX_free(ctx->bn_ctx);
        if (ctx->md_ctx)
            EVP_MD_CTX_destroy(ctx->md_ctx);
        if (ctx->cipher_ctx)
            EVP_CIPHER_CTX_free(ctx->cipher_ctx);
        sk_pop_free((_STACK *) ctx->pace_ctxs, wrap_pace_ctx_clear_free);
        sk_pop_free((_STACK *) ctx->ca_ctxs, wrap_ca_ctx_clear_free);
        sk_pop_free((_STACK *) ctx->ri_ctxs, wrap_ri_ctx_clear_free);
        TA_CTX_clear_free(ctx->ta_ctx);
        KA_CTX_clear_free(ctx->key_ctx);
        if (ctx->ssc)
            BN_clear_free(ctx->ssc);
        OPENSSL_free(ctx);
    }
}

KA_CTX *
KA_CTX_new(void)
{
    KA_CTX * out = OPENSSL_zalloc(sizeof(KA_CTX));
    if (!out)
        goto err;

    out->key = EVP_PKEY_new();
    if (!out->key)
        goto err;

    return out;

err:
    if (out) {
        if (out->key)
            EVP_PKEY_free(out->key);
        OPENSSL_free(out);
    }
    return NULL;
}

KA_CTX *
KA_CTX_dup(const KA_CTX *ka_ctx)
{
    KA_CTX *out = NULL;

    check(ka_ctx, "Invalid arguments");

    out = OPENSSL_zalloc(sizeof(KA_CTX));
    if (!out)
        goto err;

    out->key = EVP_PKEY_dup(ka_ctx->key);
    if (!out->key && ka_ctx->key)
        goto err;

    out->md = ka_ctx->md;
    out->md_engine = ka_ctx->md_engine;
    out->cipher = ka_ctx->cipher;
    out->cipher_engine = ka_ctx->cipher_engine;
    out->generate_key = ka_ctx->generate_key;
    out->compute_key = ka_ctx->compute_key;
    out->mac_keylen = ka_ctx->mac_keylen;
    out->enc_keylen = ka_ctx->enc_keylen;
    if (ka_ctx->k_enc) {
        out->k_enc = BUF_MEM_create_init(ka_ctx->k_enc->data, ka_ctx->k_enc->length);
        if (!out->k_enc)
            goto err;
    }
    if (ka_ctx->k_mac) {
        out->k_mac = BUF_MEM_create_init(ka_ctx->k_mac->data, ka_ctx->k_mac->length);
        if (!out->k_mac)
            goto err;
    }
    if (ka_ctx->shared_secret) {
        out->shared_secret = BUF_MEM_create_init(ka_ctx->shared_secret->data, ka_ctx->shared_secret->length);
        if (!out->shared_secret)
            goto err;
    }

    return out;

err:
    KA_CTX_clear_free(out);

    return NULL;
}

void
KA_CTX_clear_free(KA_CTX *ctx)
{
    if (ctx) {
        if (ctx->cmac_ctx)
            CMAC_CTX_free(ctx->cmac_ctx);
        if (ctx->key)
            EVP_PKEY_free(ctx->key);
        if (ctx->shared_secret) {
            OPENSSL_cleanse(ctx->shared_secret->data, ctx->shared_secret->max);
            BUF_MEM_free(ctx->shared_secret);
        }
        if (ctx->k_mac) {
            OPENSSL_cleanse(ctx->k_mac->data, ctx->k_mac->max);
            BUF_MEM_free(ctx->k_mac);
        }
        if (ctx->k_enc) {
            OPENSSL_cleanse(ctx->k_enc->data, ctx->k_enc->max);
            BUF_MEM_free(ctx->k_enc);
        }
        OPENSSL_free(ctx->iv);
        OPENSSL_free(ctx);
    }
}

int
KA_CTX_set_protocol(KA_CTX *ctx, int protocol)
{
    if (!ctx) {
        log_err("Invalid arguments");
        return 0;
    }

    if (       protocol == NID_id_CA_DH_3DES_CBC_CBC
            || protocol == NID_id_PACE_DH_GM_3DES_CBC_CBC
            || protocol == NID_id_PACE_DH_IM_3DES_CBC_CBC) {
        ctx->generate_key = dh_generate_key;
        ctx->compute_key = dh_compute_key;
        ctx->mac_keylen = 16;
        ctx->md = EVP_sha1();
        ctx->cipher = EVP_des_ede_cbc();
        ctx->enc_keylen = EVP_CIPHER_key_length(ctx->cipher);

    } else if (protocol == NID_id_CA_DH_AES_CBC_CMAC_128
            || protocol == NID_id_PACE_DH_GM_AES_CBC_CMAC_128
            || protocol == NID_id_PACE_DH_IM_AES_CBC_CMAC_128) {
        ctx->generate_key = dh_generate_key;
        ctx->compute_key = dh_compute_key;
        ctx->mac_keylen = 16;
        ctx->cmac_ctx = NULL; /* We don't set cmac_ctx, because of potential segfaults */
        ctx->md = EVP_sha1();
        ctx->cipher = EVP_aes_128_cbc();
        ctx->enc_keylen = EVP_CIPHER_key_length(ctx->cipher);

    } else if (protocol == NID_id_CA_DH_AES_CBC_CMAC_192
            || protocol == NID_id_PACE_DH_GM_AES_CBC_CMAC_192
            || protocol == NID_id_PACE_DH_IM_AES_CBC_CMAC_192) {
        ctx->generate_key = dh_generate_key;
        ctx->compute_key = dh_compute_key;
        ctx->mac_keylen = 24;
        ctx->cmac_ctx = NULL; /* We don't set cmac_ctx, because of potential segfaults */
        ctx->md = EVP_sha256();
        ctx->cipher = EVP_aes_192_cbc();
        ctx->enc_keylen = EVP_CIPHER_key_length(ctx->cipher);

    } else if (protocol == NID_id_CA_DH_AES_CBC_CMAC_256
            || protocol == NID_id_PACE_DH_GM_AES_CBC_CMAC_256
            || protocol == NID_id_PACE_DH_IM_AES_CBC_CMAC_256) {
        ctx->generate_key = dh_generate_key;
        ctx->compute_key = dh_compute_key;
        ctx->mac_keylen = 32;
        ctx->cmac_ctx = NULL; /* We don't set cmac_ctx, because of potential segfaults */
        ctx->md = EVP_sha256();
        ctx->cipher = EVP_aes_256_cbc();
        ctx->enc_keylen = EVP_CIPHER_key_length(ctx->cipher);

    } else if (protocol == NID_id_CA_ECDH_3DES_CBC_CBC
            || protocol == NID_id_PACE_ECDH_GM_3DES_CBC_CBC
            || protocol == NID_id_PACE_ECDH_IM_3DES_CBC_CBC) {
        ctx->generate_key = ecdh_generate_key;
        ctx->compute_key = ecdh_compute_key;
        ctx->mac_keylen = 16;
        ctx->md = EVP_sha1();
        ctx->cipher = EVP_des_ede_cbc();
        ctx->enc_keylen = EVP_CIPHER_key_length(ctx->cipher);

    } else if (protocol == NID_id_CA_ECDH_AES_CBC_CMAC_128
            || protocol == NID_id_PACE_ECDH_GM_AES_CBC_CMAC_128
            || protocol == NID_id_PACE_ECDH_IM_AES_CBC_CMAC_128) {
        ctx->generate_key = ecdh_generate_key;
        ctx->compute_key = ecdh_compute_key;
        ctx->mac_keylen = 16;
        ctx->cmac_ctx = NULL; /* We don't set cmac_ctx, because of potential segfaults */
        ctx->md = EVP_sha1();
        ctx->cipher = EVP_aes_128_cbc();
        ctx->enc_keylen = EVP_CIPHER_key_length(ctx->cipher);

    } else if (protocol == NID_id_CA_ECDH_AES_CBC_CMAC_192
            || protocol == NID_id_PACE_ECDH_GM_AES_CBC_CMAC_192
            || protocol == NID_id_PACE_ECDH_IM_AES_CBC_CMAC_192) {
        ctx->generate_key = ecdh_generate_key;
        ctx->compute_key = ecdh_compute_key;
        ctx->mac_keylen = 24;
        ctx->cmac_ctx = NULL; /* We don't set cmac_ctx, because of potential segfaults */
        ctx->md = EVP_sha256();
        ctx->cipher = EVP_aes_192_cbc();
        ctx->enc_keylen = EVP_CIPHER_key_length(ctx->cipher);

    } else if (protocol == NID_id_CA_ECDH_AES_CBC_CMAC_256
            || protocol == NID_id_PACE_ECDH_GM_AES_CBC_CMAC_256
            || protocol == NID_id_PACE_ECDH_IM_AES_CBC_CMAC_256) {
        ctx->generate_key = ecdh_generate_key;
        ctx->compute_key = ecdh_compute_key;
        ctx->mac_keylen = 32;
        ctx->cmac_ctx = NULL; /* We don't set cmac_ctx, because of potential segfaults */
        ctx->md = EVP_sha256();
        ctx->cipher = EVP_aes_256_cbc();
        ctx->enc_keylen = EVP_CIPHER_key_length(ctx->cipher);

    } else {
        log_err("Unknown protocol");
        return 0;
    }

    return 1;
}
