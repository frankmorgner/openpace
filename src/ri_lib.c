/*
 * Copyright (c) 2011-2012 Dominik Oepen, Frank Morgner and Paul Wilhelm
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
 * @file ri_lib.c
 * @brief Data management functions
 *
 * @author Frank Morgner <frankmorgner@gmail.com>
 * @author Dominik Oepen <oepen@informatik.hu-berlin.de>
 * @author Paul Wilhelm  <wilhelm@math.hu-berlin.de>
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "eac_dh.h"
#include "eac_ecdh.h"
#include "eac_err.h"
#include "eac_lib.h"
#include "eac_util.h"
#include "ssl_compat.h"
#include <eac/ri.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <string.h>

void
RI_CTX_clear_free(RI_CTX * ctx)
{
    if (ctx) {
        if (ctx->static_key)
            EVP_PKEY_free(ctx->static_key);
        OPENSSL_free(ctx);
    }
}

RI_CTX *
RI_CTX_new(void)
{
    RI_CTX *out = NULL;

    out = (RI_CTX *)OPENSSL_zalloc(sizeof(RI_CTX));
    check(out, "Out of memory");

    out->static_key = EVP_PKEY_new();
    check(out->static_key, "Failed to create keypair for restricted identification");

    return out;

err:
    if (out) {
        if (out->static_key)
            EVP_PKEY_free(out->static_key);
        OPENSSL_free(out);
    }

    return NULL;
}

int
RI_CTX_set_protocol(RI_CTX * ctx, int protocol)
{
    if (!ctx) {
        log_err("Invalid arguments");
        return 0;
    }

    if (protocol == NID_id_RI_ECDH_SHA_1) {
        ctx->md = EVP_sha1();
        ctx->compute_key = ecdh_compute_key;
        ctx->generate_key = ecdh_generate_key;

    } else if (protocol == NID_id_RI_ECDH_SHA_224) {
        ctx->md = EVP_sha224();
        ctx->compute_key = ecdh_compute_key;
        ctx->generate_key = ecdh_generate_key;

    } else if (protocol == NID_id_RI_ECDH_SHA_256) {
        ctx->md = EVP_sha256();
        ctx->compute_key = ecdh_compute_key;
        ctx->generate_key = ecdh_generate_key;

    } else if (protocol == NID_id_RI_ECDH_SHA_384) {
        ctx->md = EVP_sha384();
        ctx->compute_key = ecdh_compute_key;
        ctx->generate_key = ecdh_generate_key;

    } else if (protocol == NID_id_RI_ECDH_SHA_512) {
        ctx->md = EVP_sha512();
        ctx->compute_key = ecdh_compute_key;
        ctx->generate_key = ecdh_generate_key;

    } else if (protocol == NID_id_RI_DH_SHA_1) {
        ctx->md = EVP_sha1();
        ctx->compute_key = dh_compute_key;
        ctx->generate_key = dh_generate_key;

    } else if (protocol == NID_id_RI_DH_SHA_224) {
        ctx->md = EVP_sha224();
        ctx->compute_key = dh_compute_key;
        ctx->generate_key = dh_generate_key;

    } else if (protocol == NID_id_RI_DH_SHA_256) {
        ctx->md = EVP_sha256();
        ctx->compute_key = dh_compute_key;
        ctx->generate_key = dh_generate_key;

    } else if (protocol == NID_id_RI_DH_SHA_384) {
        ctx->md = EVP_sha384();
        ctx->compute_key = dh_compute_key;
        ctx->generate_key = dh_generate_key;

    } else if (protocol == NID_id_RI_DH_SHA_512) {
        ctx->md = EVP_sha512();
        ctx->compute_key = dh_compute_key;
        ctx->generate_key = dh_generate_key;

    } else {
        log_err("Unknown object identifier");
        return 0;
    }
    ctx->protocol = protocol;

    return 1;
}
