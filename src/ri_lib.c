/*
 * Copyright (c) 2010-2012 Dominik Oepen and Frank Morgner
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
 * @file ri_lib.c
 * @brief Data management functions
 *
 * @author Frank Morgner <morgner@informatik.hu-berlin.de>
 * @author Dominik Oepen <oepen@informatik.hu-berlin.de>
 * @author Paul Wilhelm  <wilhelm@math.hu-berlin.de>
 */

#include "eac_dh.h"
#include "eac_ecdh.h"
#include "eac_err.h"
#include "eac_lib.h"
#include "eac_util.h"
#include <eac/ri.h>
#include <openssl/buffer.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
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

    out = (RI_CTX *)OPENSSL_malloc(sizeof(RI_CTX));
    if (!out)
        goto err;

    out->static_key = EVP_PKEY_new();
    if (!out->static_key)
        goto err;

    out->compute_key = NULL;
    out->generate_key = NULL;
    out->protocol = NID_undef;
    out->md = NULL;

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

    switch (protocol) {
        case NID_id_RI_ECDH_SHA_1:
            ctx->md = EVP_sha1();
            ctx->compute_key = ecdh_compute_key;
            ctx->generate_key = ecdh_generate_key;
            break;

        case NID_id_RI_ECDH_SHA_224:
            ctx->md = EVP_sha224();
            ctx->compute_key = ecdh_compute_key;
            ctx->generate_key = ecdh_generate_key;
            break;

        case NID_id_RI_ECDH_SHA_256:
            ctx->md = EVP_sha256();
            ctx->compute_key = ecdh_compute_key;
            ctx->generate_key = ecdh_generate_key;
            break;

        case NID_id_RI_ECDH_SHA_384:
            ctx->md = EVP_sha384();
            ctx->compute_key = ecdh_compute_key;
            ctx->generate_key = ecdh_generate_key;
            break;

        case NID_id_RI_ECDH_SHA_512:
            ctx->md = EVP_sha512();
            ctx->compute_key = ecdh_compute_key;
            ctx->generate_key = ecdh_generate_key;
            break;

        case NID_id_RI_DH_SHA_1:
            ctx->md = EVP_sha1();
            ctx->compute_key = dh_compute_key;
            ctx->generate_key = dh_generate_key;
            break;

        case NID_id_RI_DH_SHA_224:
            ctx->md = EVP_sha224();
            ctx->compute_key = dh_compute_key;
            ctx->generate_key = dh_generate_key;
            break;


        case NID_id_RI_DH_SHA_256:
            ctx->md = EVP_sha256();
            ctx->compute_key = dh_compute_key;
            ctx->generate_key = dh_generate_key;
            break;

        case NID_id_RI_DH_SHA_384:
            ctx->md = EVP_sha384();
            ctx->compute_key = dh_compute_key;
            ctx->generate_key = dh_generate_key;
            break;

        case NID_id_RI_DH_SHA_512:
            ctx->md = EVP_sha512();
            ctx->compute_key = dh_compute_key;
            ctx->generate_key = dh_generate_key;
            break;

        default:
            log_err("Unknown object identifier");
            return 0;
    }
    ctx->protocol = protocol;

    return 1;
}
