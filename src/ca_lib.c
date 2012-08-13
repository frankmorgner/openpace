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
 * @file
 *
 * @author Frank Morgner <morgner@informatik.hu-berlin.de>
 * @author Dominik Oepen <oepen@informatik.hu-berlin.de>
 */

#include "eac_err.h"
#include "eac_lib.h"
#include <openssl/crypto.h>
#include <openssl/err.h>

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
