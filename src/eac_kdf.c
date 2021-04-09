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
 * @file eac_kdf.c
 * @brief Key derivation functions
 *
 * @author Frank Morgner <frankmorgner@gmail.com>
 * @author Dominik Oepen <oepen@informatik.hu-berlin.de>
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "eac_err.h"
#include "eac_kdf.h"
#include "eac_util.h"
#include "misc.h"
#include "ssl_compat.h"
#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif
#include <openssl/crypto.h>
#include <string.h>

BUF_MEM *
kdf(const BUF_MEM *key, const BUF_MEM *nonce, const uint32_t counter,
        const KA_CTX *ka_ctx, EVP_MD_CTX *md_ctx)
{
    size_t inlen, key_len;
    BUF_MEM *in = NULL, *digest = NULL, *out = NULL;

    check((key && ka_ctx->md && ka_ctx->cipher), "Invalid arguments");

    key_len = EVP_CIPHER_key_length(ka_ctx->cipher);
    check(0 < EVP_MD_size(ka_ctx->md)
            && key_len <= (size_t) EVP_MD_size(ka_ctx->md),
            "Message digest not suitable for cipher");

    in = BUF_MEM_new();
    check(in, "Failed to allocate memory");

    /* Concatenate secret || nonce || counter
     * nonce is optional */
    if (nonce) {
        inlen = key->length + nonce->length + sizeof counter;
        check(BUF_MEM_grow(in, inlen), "Failed to allocate memory");
        memcpy(in->data, key->data, key->length);
        memcpy(in->data + key->length, nonce->data, nonce->length);
        memcpy(in->data + key->length + nonce->length, &counter, sizeof counter);
    } else {
        inlen = key->length + sizeof counter;
        check(BUF_MEM_grow(in, inlen), "Failed to allocate memory");
        memcpy(in->data, key->data, key->length);
        memcpy(in->data + key->length, &counter, sizeof counter);
    }

    digest = hash(ka_ctx->md, md_ctx, ka_ctx->md_engine, in);
    check(digest, "Failed to compute hash");

    /* Truncate the hash to the length of the key */
    out = BUF_MEM_create_init(digest->data, key_len);

    OPENSSL_cleanse(in->data, in->max);
    BUF_MEM_free(in);
    OPENSSL_cleanse(digest->data, digest->max);
    BUF_MEM_free(digest);

    return out;

err:
    if (in) {
        OPENSSL_cleanse(in->data, in->max);
        BUF_MEM_free(in);
    }

    return NULL;
}

BUF_MEM *
kdf_pi(const PACE_SEC *pi, const BUF_MEM *nonce, const KA_CTX *ctx, EVP_MD_CTX *md_ctx)
{
    BUF_MEM * out;

    out = kdf(pi->encoded, nonce, htonl(KDF_PI_COUNTER), ctx, md_ctx);

    return out;
}

BUF_MEM *
kdf_enc(const BUF_MEM *nonce, const KA_CTX *ctx, EVP_MD_CTX *md_ctx)
{
    check_return(ctx, "Invalid arguments");

    return kdf(ctx->shared_secret, nonce, htonl(KDF_ENC_COUNTER), ctx, md_ctx);
}

BUF_MEM *
kdf_mac(const BUF_MEM *nonce, const KA_CTX *ctx, EVP_MD_CTX *md_ctx)
{
    check_return(ctx, "Invalid arguments");

    return kdf(ctx->shared_secret, nonce, htonl(KDF_MAC_COUNTER), ctx, md_ctx);
}
