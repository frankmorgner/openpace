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
 * @file eac_print.c
 * @brief Implementation of printing functions
 *
 * @author Frank Morgner <morgner@informatik.hu-berlin.de>
 * @author Dominik Oepen <oepen@informatik.hu-berlin.de>
 */

#include <eac/eac.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>

int
BUF_MEM_print(BIO *out, const BUF_MEM *buf, int indent)
{
    if (buf) {
        if (!BIO_dump_indent(out, buf->data, buf->length, indent))
            return 0;
    } else {
        if (!BIO_indent(out, indent, 80)
                || !BIO_printf(out, "<ABSENT>\n"))
            return 0;
    }
    return 1;
}

static int
KA_CTX_print_private(BIO *out, const KA_CTX *ctx, int indent)
{
    if (ctx) {
        if (!BIO_indent(out, indent, 80)
                || !BIO_printf(out, "Key Agreement Parameters:\n"))
            return 0;
        if (ctx->key)
            if (ctx->shared_secret) {
                /* If we have a shared secret, we also must have a private key
                 * which we can print. This is a bit clumsy but unfortunately
                 * OpenSSL doesn't offer a function to check whether or not an
                 * EVP_PKEY contains a private key. */
                if (!EVP_PKEY_print_private(out, ctx->key, indent+4, NULL))
                    return 0;
            } else {
                if (!EVP_PKEY_print_params(out, ctx->key, indent+4, NULL))
                    return 0;
            }
            else {
                if (!BIO_indent(out, indent+4, 80)
                        || !BIO_printf(out, "<ABSENT>\n"))
                    return 0;
            }
        if (!BIO_indent(out, indent, 80))
            return 0;
        if (ctx->cipher) {
            if (!BIO_printf(out, "Cipher: %s\n", EVP_CIPHER_name(ctx->cipher)))
                return 0;
        } else if (!BIO_printf(out, "Cipher: %s\n", "<ABSENT>"))
            return 0;
        if (!BIO_indent(out, indent, 80))
            return 0;
        if (ctx->md) {
            if (!BIO_printf(out, "Message Digest: %s\n", EVP_MD_name(ctx->md)))
                return 0;
        } else if (!BIO_printf(out, "Message Digest: %s\n", "<ABSENT>"))
                    return 0;
        if (!BIO_indent(out, indent, 80)
                || !BIO_printf(out, "Shared Secret:\n")
                || !BUF_MEM_print(out, ctx->shared_secret, indent+4)
                || !BIO_indent(out, indent, 80)
                || !BIO_printf(out, "K_enc:\n")
                || !BUF_MEM_print(out, ctx->k_enc, indent+4)
                || !BIO_indent(out, indent, 80)
                || !BIO_printf(out, "K_mac:\n")
                || !BUF_MEM_print(out, ctx->k_mac, indent+4))
            return 0;
    } else {
        if (!BIO_indent(out, indent, 80)
                || !BIO_printf(out, "<ABSENT>\n"))
            return 0;
    }
    return 1;
}

static int
TA_CTX_print_private(BIO *out, const TA_CTX *ctx, int indent)
{
    if (ctx) {
        if (!BIO_indent(out, indent, 80)
                || !BIO_printf(out, "OID: %s\n", OBJ_nid2sn(ctx->protocol))
                || !BIO_indent(out, indent, 80)
                || !BIO_printf(out, "Version: %d\n", ctx->version))
            return 0;

        if (!BIO_indent(out, indent, 80)
                || !BIO_printf(out, "PCD's Static Domain Parameters:\n"))
            return 0;
        if (ctx->priv_key) {
            if (!EVP_PKEY_print_private(out, ctx->priv_key, indent+4, NULL))
                return 0;
        } else {
            if (!BIO_indent(out, indent+4, 80)
                    || !BIO_printf(out, "<ABSENT>\n"))
                return 0;
        }
        if (ctx->pub_key) {
            if (!EVP_PKEY_print_params(out, ctx->pub_key, indent+4, NULL))
                return 0;
        } else {
            if (!BIO_indent(out, indent+4, 80)
                    || !BIO_printf(out, "<ABSENT>\n"))
                return 0;
        }
        if (!BIO_indent(out, indent, 80)
                || !BIO_printf(out, "Nonce:\n")
                || !BUF_MEM_print(out, ctx->nonce, indent+4))
            return 0;
    } else {
        if (!BIO_indent(out, indent, 80)
                || !BIO_printf(out, "<ABSENT>\n"))
            return 0;
    }
    return 1;
}

static int
CA_CTX_print_private(BIO *out, const CA_CTX *ctx, int indent)
{
    if (ctx) {
        if (!BIO_indent(out, indent, 80)
                || !BIO_printf(out, "OID: %s\n", OBJ_nid2sn(ctx->protocol))
                || !BIO_indent(out, indent, 80)
                || !BIO_printf(out, "Version: %d\n", ctx->version)
                || !BIO_indent(out, indent, 80)
                || !BIO_printf(out, "PICC's Static Domain Parameters:\n")
                || !KA_CTX_print_private(out, ctx->ka_ctx, indent+4))
            return 0;
    } else {
        if (!BIO_indent(out, indent, 80)
                || !BIO_printf(out, "<ABSENT>\n"))
            return 0;
    }
    return 1;
}

static int
RI_CTX_print_private(BIO *out, const RI_CTX *ctx, int indent)
{
    if (ctx) {
        if (!BIO_indent(out, indent, 80)
                || !BIO_printf(out, "OID: %s\n", OBJ_nid2sn(ctx->protocol)))
            return 0;

        if (ctx->md) {
            if (!BIO_indent(out, indent, 80)
                    || !BIO_printf(out, "Message Digest: %s\n", EVP_MD_name(ctx->md)))
                return 0;
        } else if (!BIO_indent(out, indent, 80)
                || !BIO_printf(out, "Message Digest: %s\n", "<ABSENT>"))
            return 0;

        if (!BIO_indent(out, indent, 80)
                || !BIO_printf(out, "PICC's static domain parameters:\n"))
            return 0;
        if (ctx->static_key) {
            if (!EVP_PKEY_print_params(out, ctx->static_key, indent+4, NULL))
                return 0;
        } else {
            if (!BIO_printf(out, "<ABSENT>\n"))
                return 0;
        }
    } else {
        if (!BIO_indent(out, indent, 80)
                || !BIO_printf(out, "<ABSENT>\n"))
            return 0;
    }

    return 1;
}

static int
PACE_CTX_print_private(BIO *out, const PACE_CTX *ctx, int indent)
{
    if (ctx) {
        if (!BIO_indent(out, indent, 80)
                || !BIO_printf(out, "OID: %s\n", OBJ_nid2sn(ctx->protocol))
                || !BIO_indent(out, indent, 80)
                || !BIO_printf(out, "Version: %d\n", ctx->version)
                || !BIO_indent(out, indent, 80)
                || !BIO_printf(out, "PICC's Static Domain Parameters:\n"))
            return 0;
        if (ctx->static_key) {
            if (!EVP_PKEY_print_params(out, ctx->static_key, indent+4, NULL))
                return 0;
            else {
                if (!BIO_indent(out, indent+4, 80)
                        || !BIO_printf(out, "<ABSENT>\n"))
                    return 0;
            }
        }
        if (!BIO_indent(out, indent, 80)
                || !BIO_printf(out, "Nonce:\n")
                || !BUF_MEM_print(out, ctx->nonce, indent+4)
                || !BIO_indent(out, indent, 80)
                || !BIO_printf(out, "Ephemeral Domain Parameters:\n")
                || !KA_CTX_print_private(out, ctx->ka_ctx, indent+4))
            return 0;
    } else {
        if (!BIO_indent(out, indent, 80)
                || !BIO_printf(out, "<ABSENT>\n"))
            return 0;
    }
    return 1;
}

int
EAC_CTX_print_private(BIO *out, const EAC_CTX *ctx, int indent)
{
    if (ctx) {
        if (!BIO_indent(out, indent, 80)
                || !BIO_printf(out, "Context for PACE\n")
                || !PACE_CTX_print_private(out, ctx->pace_ctx, indent+4)
                || !BIO_indent(out, indent, 80)
                || !BIO_printf(out, "Context for TA\n")
                || !TA_CTX_print_private(out, ctx->ta_ctx, indent+4)
                || !BIO_indent(out, indent, 80)
                || !BIO_printf(out, "Context for CA\n")
                || !CA_CTX_print_private(out, ctx->ca_ctx, indent+4)
                || !BIO_indent(out, indent, 80)
                || !BIO_printf(out, "Context for RI\n")
                || !RI_CTX_print_private(out, ctx->ri_ctx, indent+4))
            return 0;
    } else {
        if (!BIO_indent(out, indent, 80)
                || !BIO_printf(out, "<ABSENT>\n"))
            return 0;
    }
    return 1;
}
