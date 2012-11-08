/*
 * Copyright (c) 2010-2012 Frank Morgner and Dominik Oepen
 *
 * This file is part of OpenPACE.
 *
 * OpenPACE is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * OpenPACE is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with FFmpeg; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

/**
 * @file eac_lib.c
 * @brief Data management functions
 *
 * @author Frank Morgner <morgner@informatik.hu-berlin.de>
 * @author Dominik Oepen <oepen@informatik.hu-berlin.de>
 */

#include "ca_lib.h"
#include "eac_dh.h"
#include "eac_ecdh.h"
#include "eac_err.h"
#include "eac_lib.h"
#include "eac_util.h"
#include "misc.h"
#include "pace_lib.h"
#include "ta_lib.h"
#include <eac/ca.h>
#include <eac/cv_cert.h>
#include <eac/eac.h>
#include <eac/pace.h>
#include <eac/ri.h>
#include <eac/ta.h>
#include <openssl/buffer.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <string.h>

EAC_CTX *
EAC_CTX_new(void)
{
    EAC_CTX *ctx = OPENSSL_malloc(sizeof(EAC_CTX));
    if (!ctx)
        return NULL;

    ctx->bn_ctx = BN_CTX_new();
    ctx->pace_ctx = PACE_CTX_new();
    ctx->md_ctx = EVP_MD_CTX_create();
    ctx->ta_ctx = TA_CTX_new();
    ctx->ca_ctx = CA_CTX_new();
    ctx->cipher_ctx = EVP_CIPHER_CTX_new();
    ctx->ri_ctx = RI_CTX_new();
    ctx->ssc = BN_new();

    if (!ctx->bn_ctx || !ctx->md_ctx || !ctx->pace_ctx || !ctx->ta_ctx
            || !ctx->ca_ctx || !ctx->cipher_ctx || !ctx->ri_ctx || !ctx->ssc)
        goto err;

    ctx->tr_version = EAC_TR_VERSION_2_02;
    BN_CTX_init(ctx->bn_ctx);
    EVP_CIPHER_CTX_init(ctx->cipher_ctx);
    ctx->key_ctx = NULL;

    return ctx;

err:
    EAC_CTX_clear_free(ctx);
    return NULL;
}

int
EAC_CTX_init_pace(EAC_CTX *ctx, int protocol, int curve)
{
    if (!ctx || !ctx->pace_ctx) {
        log_err("Invalid arguments");
        return 0;
    }

    if (!PACE_CTX_set_protocol(ctx->pace_ctx, protocol, ctx->tr_version)
                || !EVP_PKEY_set_std_dp(ctx->pace_ctx->static_key, curve))
        return 0;

    return 1;
}

int
EAC_CTX_init_ta(const EAC_CTX *ctx,
           const unsigned char *privkey, size_t privkey_len,
           const unsigned char *cvca, size_t cvca_len)
{
    CVC_CERT *ta_cvca = NULL;
    int r = 0;

    check(ctx, "Invalid arguments");

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
EAC_CTX_init_ca(const EAC_CTX *ctx, int protocol, int curve,
                const unsigned char *priv, size_t priv_len,
                const unsigned char *pub, size_t pub_len)
{
    if (!ctx || !ctx->ca_ctx || !ctx->ca_ctx->ka_ctx
               || (!priv && pub)) {
        log_err("Invalid arguments");
        return 0;
    }

    if (protocol) {
        if (!CA_CTX_set_protocol(ctx->ca_ctx, protocol)
                || !EVP_PKEY_set_std_dp(ctx->ca_ctx->ka_ctx->key, curve))
            return 0;
    }

    if (priv && !pub) {
        if (!d2i_AutoPrivateKey(&ctx->ca_ctx->ka_ctx->key, &priv, priv_len))
            return 0;
    }

    if (priv && pub)
        return EVP_PKEY_set_keys(ctx->ca_ctx->ka_ctx->key, priv, priv_len,
                   pub, pub_len, ctx->bn_ctx);

    return 1;
}

int
EAC_CTX_init_ri(EAC_CTX *ctx, int protocol, int stnd_dp)
{

    BUF_MEM *pubkey = NULL;

    if (!ctx || !ctx->ri_ctx) {
        log_err("Invalid arguments");
        return 0;
    }

    if (!RI_CTX_set_protocol(ctx->ri_ctx, protocol)
               || !EVP_PKEY_set_std_dp(ctx->ri_ctx->static_key, stnd_dp))
            return 0;

    if (!ctx->ri_ctx->generate_key)
        return 0;

    pubkey = ctx->ri_ctx->generate_key(ctx->ri_ctx->static_key, ctx->bn_ctx);
    if (!pubkey)
        return 0;
    else /* We do not need the buffered public key and throw it away immediately */
        BUF_MEM_clear_free(pubkey);

    return 1;
}

void
EAC_CTX_clear_free(EAC_CTX *ctx) {
    if (ctx) {
        if (ctx->bn_ctx)
            BN_CTX_free(ctx->bn_ctx);
        if (ctx->md_ctx)
            EVP_MD_CTX_destroy(ctx->md_ctx);
        if (ctx->cipher_ctx)
            EVP_CIPHER_CTX_free(ctx->cipher_ctx);
        PACE_CTX_clear_free(ctx->pace_ctx);
        TA_CTX_clear_free(ctx->ta_ctx);
        CA_CTX_clear_free(ctx->ca_ctx);
        KA_CTX_clear_free(ctx->key_ctx);
        RI_CTX_clear_free(ctx->ri_ctx);
        if (ctx->ssc)
            BN_clear_free(ctx->ssc);
        OPENSSL_free(ctx);
    }
}

KA_CTX *
KA_CTX_new(void)
{
    KA_CTX * out = OPENSSL_malloc(sizeof(KA_CTX));
    if (!out)
        goto err;

    out->key = EVP_PKEY_new();
    if (!out->key)
        goto err;

    out->md = NULL;
    out->md_engine = NULL;
    out->cmac_ctx = NULL;
    out->cipher = NULL;
    out->cipher_engine = NULL;
    out->iv = NULL;
    out->generate_key = NULL;
    out->compute_key = NULL;
    out->mac_keylen = 0;
    out->enc_keylen = 0;
    out->shared_secret = NULL;
    out->k_enc = NULL;
    out->k_mac = NULL;

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

    out = OPENSSL_malloc(sizeof(KA_CTX));
    if (!out)
        goto err;

    out->key = EVP_PKEY_dup(ka_ctx->key);
    if (!out->key && ka_ctx->key)
        goto err;

    out->md = ka_ctx->md;
    out->md_engine = ka_ctx->md_engine;
    out->cmac_ctx = NULL;
    out->cipher = ka_ctx->cipher;
    out->cipher_engine = ka_ctx->cipher_engine;
    out->iv = NULL;
    out->generate_key = ka_ctx->generate_key;
    out->compute_key = ka_ctx->compute_key;
    out->mac_keylen = ka_ctx->mac_keylen;
    out->enc_keylen = ka_ctx->enc_keylen;
    if (ka_ctx->k_enc) {
        out->k_enc = BUF_MEM_create_init(ka_ctx->k_enc->data, ka_ctx->k_enc->length);
        if (!out->k_enc)
            goto err;
    } else
        out->k_enc = NULL;
    if (ka_ctx->k_mac) {
        out->k_mac = BUF_MEM_create_init(ka_ctx->k_mac->data, ka_ctx->k_mac->length);
        if (!out->k_mac)
            goto err;
    } else
        out->k_mac = NULL;
    if (ka_ctx->shared_secret) {
        out->shared_secret = BUF_MEM_create_init(ka_ctx->shared_secret->data, ka_ctx->shared_secret->length);
        if (!out->shared_secret)
            goto err;
    } else
        out->shared_secret = NULL;

    return out;

err:
    KA_CTX_clear_free(out);

    return NULL;
}

void
KA_CTX_clear_free(KA_CTX *ctx)
{
    if (ctx) {
        if (ctx->cmac_ctx) /* FIXME: Segfaults if CMAC_Init has not been called */
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
        free(ctx->iv);
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

    switch (protocol) {
        case NID_id_CA_DH_3DES_CBC_CBC:
        case NID_id_PACE_DH_GM_3DES_CBC_CBC:
        case NID_id_PACE_DH_IM_3DES_CBC_CBC:
            ctx->generate_key = dh_generate_key;
            ctx->compute_key = dh_compute_key;
            ctx->mac_keylen = 16;
            ctx->md = EVP_sha1();
            ctx->cipher = EVP_des_ede_cbc();
            ctx->enc_keylen = ctx->cipher->key_len;
            break;

        case NID_id_CA_DH_AES_CBC_CMAC_128:
        case NID_id_PACE_DH_GM_AES_CBC_CMAC_128:
        case NID_id_PACE_DH_IM_AES_CBC_CMAC_128:
            ctx->generate_key = dh_generate_key;
            ctx->compute_key = dh_compute_key;
            ctx->mac_keylen = 16;
            ctx->cmac_ctx = NULL; /* We don't set cmac_ctx, because of potential segfaults */
            ctx->md = EVP_sha1();
            ctx->cipher = EVP_aes_128_cbc();
            ctx->enc_keylen = ctx->cipher->key_len;
            break;

        case NID_id_CA_DH_AES_CBC_CMAC_192:
        case NID_id_PACE_DH_GM_AES_CBC_CMAC_192:
        case NID_id_PACE_DH_IM_AES_CBC_CMAC_192:
            ctx->generate_key = dh_generate_key;
            ctx->compute_key = dh_compute_key;
            ctx->mac_keylen = 24;
            ctx->cmac_ctx = NULL; /* We don't set cmac_ctx, because of potential segfaults */
            ctx->md = EVP_sha256();
            ctx->cipher = EVP_aes_192_cbc();
            ctx->enc_keylen = ctx->cipher->key_len;
            break;

        case NID_id_CA_DH_AES_CBC_CMAC_256:
        case NID_id_PACE_DH_GM_AES_CBC_CMAC_256:
        case NID_id_PACE_DH_IM_AES_CBC_CMAC_256:
            ctx->generate_key = dh_generate_key;
            ctx->compute_key = dh_compute_key;
            ctx->mac_keylen = 32;
            ctx->cmac_ctx = NULL; /* We don't set cmac_ctx, because of potential segfaults */
            ctx->md = EVP_sha256();
            ctx->cipher = EVP_aes_256_cbc();
            ctx->enc_keylen = ctx->cipher->key_len;
            break;

        case NID_id_CA_ECDH_3DES_CBC_CBC:
        case NID_id_PACE_ECDH_GM_3DES_CBC_CBC:
        case NID_id_PACE_ECDH_IM_3DES_CBC_CBC:
            ctx->generate_key = ecdh_generate_key;
            ctx->compute_key = ecdh_compute_key;
            ctx->mac_keylen = 16;
            ctx->md = EVP_sha1();
            ctx->cipher = EVP_des_ede_cbc();
            ctx->enc_keylen = ctx->cipher->key_len;
            break;

        case NID_id_CA_ECDH_AES_CBC_CMAC_128:
        case NID_id_PACE_ECDH_GM_AES_CBC_CMAC_128:
        case NID_id_PACE_ECDH_IM_AES_CBC_CMAC_128:
            ctx->generate_key = ecdh_generate_key;
            ctx->compute_key = ecdh_compute_key;
            ctx->mac_keylen = 16;
            ctx->cmac_ctx = NULL; /* We don't set cmac_ctx, because of potential segfaults */
            ctx->md = EVP_sha1();
            ctx->cipher = EVP_aes_128_cbc();
            ctx->enc_keylen = ctx->cipher->key_len;
            break;

        case NID_id_CA_ECDH_AES_CBC_CMAC_192:
        case NID_id_PACE_ECDH_GM_AES_CBC_CMAC_192:
        case NID_id_PACE_ECDH_IM_AES_CBC_CMAC_192:
            ctx->generate_key = ecdh_generate_key;
            ctx->compute_key = ecdh_compute_key;
            ctx->mac_keylen = 24;
            ctx->cmac_ctx = NULL; /* We don't set cmac_ctx, because of potential segfaults */
            ctx->md = EVP_sha256();
            ctx->cipher = EVP_aes_192_cbc();
            ctx->enc_keylen = ctx->cipher->key_len;
            break;

        case NID_id_CA_ECDH_AES_CBC_CMAC_256:
        case NID_id_PACE_ECDH_GM_AES_CBC_CMAC_256:
        case NID_id_PACE_ECDH_IM_AES_CBC_CMAC_256:
            ctx->generate_key = ecdh_generate_key;
            ctx->compute_key = ecdh_compute_key;
            ctx->mac_keylen = 32;
            ctx->cmac_ctx = NULL; /* We don't set cmac_ctx, because of potential segfaults */
            ctx->md = EVP_sha256();
            ctx->cipher = EVP_aes_256_cbc();
            ctx->enc_keylen = ctx->cipher->key_len;
            break;

        default:
            log_err("Unknown protocol");
            return 0;
    }

    return 1;
}
