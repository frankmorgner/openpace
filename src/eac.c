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
 * @file eac.c
 * @brief OpenEAC implementation
 *
 * @author Frank Morgner <frankmorgner@gmail.com>
 * @author Dominik Oepen <oepen@informatik.hu-berlin.de>
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "eac_err.h"
#include "eac_kdf.h"
#include "eac_lib.h"
#include "eac_util.h"
#include "misc.h"
#include <eac/eac.h>
#include <eac/pace.h>
#include <openssl/crypto.h>

BUF_MEM *
EAC_add_iso_pad(const EAC_CTX *eac_ctx, const BUF_MEM * m)
{
    check_return(eac_ctx && eac_ctx->key_ctx, "Invalid arguments");

    return add_iso_pad(m, EVP_CIPHER_block_size(eac_ctx->key_ctx->cipher));
}

BUF_MEM *
EAC_remove_iso_pad(const BUF_MEM *padded)
{
    BUF_MEM *out = NULL;
    unsigned int m_len;

    check(padded, "Invalid arguments");

    /* Find length of unpadded message */
    m_len = padded->length - 1;
    while (m_len >= 1) {
        if (padded->data[m_len] == (char) 0x80)
            break;
        check(padded->data[m_len] == 0x00, "Invalid padding");
        m_len--;
    }
    check(m_len != 0, "Invalid padding");

    /* Copy unpadded message to output buffer */
    out = BUF_MEM_create(m_len);
    check(out, "Out of memory");

    memcpy(out->data, padded->data, m_len);

err:
    return out;
}

int EAC_increment_ssc(const EAC_CTX *ctx)
{
    if (!ctx)
        return 0;

    return BN_add_word(ctx->ssc, 1);
}

int EAC_reset_ssc(const EAC_CTX *ctx)
{
    if (!ctx)
        return 0;

    BN_zero(ctx->ssc);

    return 1;
}

int EAC_set_ssc(const EAC_CTX *ctx, unsigned long ssc)
{
    if (!ctx)
        return 0;

    return BN_set_word(ctx->ssc, ssc);
}

BUF_MEM *
EAC_encrypt(const EAC_CTX *ctx, const BUF_MEM *data)
{
    check_return((ctx && ctx->key_ctx), "Invalid arguments");

    if (!update_iv(ctx->key_ctx, ctx->cipher_ctx, ctx->ssc))
        return NULL;

    return cipher_no_pad(ctx->key_ctx, ctx->cipher_ctx, ctx->key_ctx->k_enc, data, 1);
}

BUF_MEM *
EAC_decrypt(const EAC_CTX *ctx, const BUF_MEM *data)
{
    check_return((ctx && ctx->key_ctx), "Invalid arguments");

    if (!update_iv(ctx->key_ctx, ctx->cipher_ctx, ctx->ssc))
        return NULL;

    return cipher_no_pad(ctx->key_ctx, ctx->cipher_ctx, ctx->key_ctx->k_enc, data, 0);
}

BUF_MEM *
EAC_authenticate(const EAC_CTX *ctx, const BUF_MEM *data)
{
    int l;
    BUF_MEM *out = NULL, *to_authenticate = NULL;
    unsigned char *ssc_buf = NULL;

    check((ctx && data), "invalid arguments");

    l = encode_ssc(ctx->ssc, ctx->key_ctx, &ssc_buf);
    check(l >= 0, "Failed to encode SSC");

    to_authenticate = BUF_MEM_create(l + data->length);
    check(to_authenticate, "Failed to allocate memory");

    memcpy(to_authenticate->data, ssc_buf, l);
    memcpy(to_authenticate->data + l, data->data, data->length);
    to_authenticate->length = l + data->length;

    out = authenticate(ctx->key_ctx, to_authenticate);

err:
    if (ssc_buf)
        OPENSSL_free(ssc_buf);
    /* TR-03110 uses Encrypt then authenticate, so no need to wipe the memory
     * from the authenticated data */
    if (to_authenticate)
        BUF_MEM_free(to_authenticate);

    return out;
}

int
EAC_verify_authentication(const EAC_CTX *ctx, const BUF_MEM *data,
        const BUF_MEM *mac)
{
    BUF_MEM *my_mac = NULL;
    int ret = 0;

    check((ctx && data), "Invalid arguments");

    my_mac = EAC_authenticate(ctx, data);
    check(my_mac, "Failed to compute MAC");
    check((mac->length == my_mac->length), "Invalid MAC length");

    if (CRYPTO_memcmp(my_mac->data, mac->data, mac->length) == 0)
        ret = 1;

err:
    if (my_mac)
        BUF_MEM_free(my_mac);
    return ret;
}

BUF_MEM *
EAC_Comp(const EAC_CTX *ctx, int id, const BUF_MEM *pub)
{
    switch (id) {
        case EAC_ID_PACE:
            if (!ctx || !ctx->pace_ctx || !ctx->pace_ctx->ka_ctx) {
                log_err("Invalid arguments");
                return 0;
            }
            return Comp(ctx->pace_ctx->ka_ctx->key, pub, ctx->bn_ctx, ctx->md_ctx);

        case EAC_ID_TA:
            if (!ctx || !ctx->ta_ctx) {
                log_err("Invalid arguments");
                return 0;
            }
            if (ctx->ta_ctx->priv_key)
                return Comp(ctx->ta_ctx->priv_key, pub, ctx->bn_ctx, ctx->md_ctx);
            else
                return Comp(ctx->ta_ctx->pub_key, pub, ctx->bn_ctx, ctx->md_ctx);

        case EAC_ID_CA:
            if (!ctx || !ctx->ca_ctx || !ctx->ca_ctx->ka_ctx) {
                log_err("Invalid arguments");
                return 0;
            }
            return Comp(ctx->ca_ctx->ka_ctx->key, pub, ctx->bn_ctx, ctx->md_ctx);

        default:
            log_err("Invalid arguments");
            return NULL;
    }
}

BUF_MEM *
EAC_hash_certificate_description(const unsigned char *cert_desc,
        size_t cert_desc_len)
{
    BUF_MEM *cd, *out;

    cd = BUF_MEM_create_init(cert_desc, cert_desc_len);
    out = hash(EVP_sha256(), NULL, NULL, cd);
    if (cd)
        BUF_MEM_free(cd);

    return out;
}

int
EAC_CTX_set_encryption_ctx(EAC_CTX *ctx, int id)
{
    const KA_CTX *new;

    switch (id) {
        case EAC_ID_PACE:
            if (!ctx || !ctx->pace_ctx || !ctx->pace_ctx->ka_ctx ||
                    !ctx->pace_ctx->ka_ctx->k_enc || !ctx->pace_ctx->ka_ctx->k_mac) {
                log_err("Invalid arguments");
                return 0;
            }
            new = ctx->pace_ctx->ka_ctx;
            break;

        case EAC_ID_CA:
            if (!ctx || !ctx->ca_ctx || !ctx->ca_ctx->ka_ctx ||
                    !ctx->ca_ctx->ka_ctx->k_enc || !ctx->ca_ctx->ka_ctx->k_mac) {
                log_err("Invalid arguments");
                return 0;
            }
            new = ctx->ca_ctx->ka_ctx;
            break;

        case EAC_ID_EAC:
            if (!ctx || !ctx->key_ctx || !ctx->key_ctx->k_enc || !ctx->key_ctx->k_mac) {
                log_err("Invalid arguments");
                return 0;
            }
            return 1;
            break;

        default:
            log_err("Invalid arguments");
            return 0;
    }

    KA_CTX_clear_free(ctx->key_ctx);
    ctx->key_ctx = KA_CTX_dup(new);
    if (!ctx->key_ctx)
        return 0;

    return EAC_reset_ssc(ctx);
}

BUF_MEM *
KA_CTX_generate_key(const KA_CTX *ctx, BN_CTX *bn_ctx)
{
    check_return((ctx && ctx->generate_key), "Invalid arguments");

    return ctx->generate_key(ctx->key, bn_ctx);
}

int
KA_CTX_compute_key(KA_CTX *ctx, const BUF_MEM *in, BN_CTX *bn_ctx)
{
    if (!ctx || !ctx->compute_key) {
        log_err("Invalid arguments");
        return 0;
    }

    BUF_MEM_clear_free(ctx->shared_secret);
    ctx->shared_secret = ctx->compute_key(ctx->key, in, bn_ctx);
    if (!ctx->shared_secret)
        return 0;

    return 1;
}

int
KA_CTX_derive_keys(KA_CTX *ctx, const BUF_MEM *nonce, EVP_MD_CTX *md_ctx)
{
    if (!ctx) {
        log_err("Invalid arguments");
        return 0;
    }

    BUF_MEM_clear_free(ctx->k_mac);
    ctx->k_mac = kdf_mac(nonce, ctx, md_ctx);

    BUF_MEM_clear_free(ctx->k_enc);
    ctx->k_enc = kdf_enc(nonce, ctx, md_ctx);

    if (!ctx->k_mac || !ctx->k_enc)
        return 0;

    return 1;
}
