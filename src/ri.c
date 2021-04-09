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
 * @file ri.c
 * @brief Restricted Identification implementation
 *
 * @author Frank Morgner <frankmorgner@gmail.com>
 * @author Dominik Oepen <oepen@informatik.hu-berlin.de>
 * @author Paul Wilhelm  <wilhelm@math.hu-berlin.de>
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "eac_err.h"
#include "eac_lib.h"
#include "eac_util.h"
#include <eac/eac.h>
#include <openssl/crypto.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <string.h>

BUF_MEM *
RI_STEP2_compute_identifier(EAC_CTX *ctx, BUF_MEM *sector_pubkey)
{

    BUF_MEM *sector_identifier = NULL, *shared_secret = NULL;

    check((ctx && sector_pubkey && ctx->bn_ctx && ctx->ri_ctx
             && ctx->ri_ctx->compute_key
             && ctx->ri_ctx->static_key),
           "Invalid arguments");

    /* Perform the key agreement */
    shared_secret = ctx->ri_ctx->compute_key(ctx->ri_ctx->static_key,
            sector_pubkey, ctx->bn_ctx);
    check(shared_secret, "Failed to compute shared secret");

    /* Compute the hash of the shared secret (which is the sector identifier) */
    sector_identifier = hash(ctx->ri_ctx->md, ctx->md_ctx, NULL, shared_secret);

err:
    if (shared_secret)
        BUF_MEM_clear_free(shared_secret);

    return sector_identifier;
}

