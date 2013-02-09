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
 */

/**
 * @file
 *
 * @author Frank Morgner <morgner@informatik.hu-berlin.de>
 * @author Dominik Oepen <oepen@informatik.hu-berlin.de>
 */

#include "eac_err.h"
#include "eac_lib.h"
#include <openssl/crypto.h>

CA_CTX *
CA_CTX_new(void)
{
    CA_CTX *ctx = OPENSSL_malloc(sizeof(CA_CTX));
    if (!ctx)
        return NULL;

    ctx->ka_ctx = KA_CTX_new();
    if (!ctx->ka_ctx) {
            OPENSSL_free(ctx);
            return NULL;
    }
    ctx->version = 0;
    ctx->protocol = NID_undef;
    ctx->flags = 0;
    ctx->lookup_csca_cert = EAC_get_default_csca_lookup();

    return ctx;
}

void
CA_CTX_clear_free(CA_CTX *ctx)
{
    if (ctx) {
        KA_CTX_clear_free(ctx->ka_ctx);
        OPENSSL_free(ctx);
    }
}

int
CA_CTX_set_protocol(CA_CTX * ctx, int protocol)
{
    if (!ctx) {
        log_err("Invalid arguments");
        return 0;
    }

    if (!KA_CTX_set_protocol(ctx->ka_ctx, protocol))
        return 0;

    ctx->protocol = protocol;

    return 1;
}
