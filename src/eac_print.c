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
 * @file eac_print.c
 * @brief Implementation of printing functions
 *
 * @author Frank Morgner <frankmorgner@gmail.com>
 * @author Dominik Oepen <oepen@informatik.hu-berlin.de>
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <eac/eac.h>
#include <eac/pace.h>
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
                || !BIO_printf(out, "keyID: 0x%02X\n", ctx->id)
                || !BIO_indent(out, indent, 80)
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
                || !BIO_printf(out, "keyID: 0x%02X\n", ctx->id)
                || !BIO_indent(out, indent, 80)
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
                || !BIO_printf(out, "parameterID: 0x%02X\n", ctx->id)
                || !BIO_indent(out, indent, 80)
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

#define stack_print_private(structure, bio, stack, indent) \
{ \
    int __i, __count; \
    structure *__ctx; \
    __count = sk_num((_STACK*) stack); \
    for (__i = 0; __i < __count; __i++) { \
        if (!BIO_indent(out, indent, 80)) break; \
        __ctx = sk_value((_STACK*) stack, __i); \
        if (!BIO_printf(out, "Context %d\n", __i+1)) break; \
        structure##_print_private(bio, __ctx, indent+4); \
    } \
}

int
EAC_CTX_print_private(BIO *out, const EAC_CTX *ctx, int indent)
{
    if (ctx) {
        if (!BIO_indent(out, indent, 80)
                || !BIO_printf(out, "%d Context%s for PACE (default has parameterID 0x%02X)\n",
                    sk_num((_STACK*) ctx->pace_ctxs),
                    sk_num((_STACK*) ctx->pace_ctxs) > 1 ? "s" : "",
                    ctx->pace_ctx ? ctx->pace_ctx->id : -1))
            return 0;
        stack_print_private(PACE_CTX, out, ctx->pace_ctxs, indent+4);
        if (!BIO_indent(out, indent, 80)
                || !BIO_printf(out, "Context for TA\n")
                || !TA_CTX_print_private(out, ctx->ta_ctx, indent+4)
                || !BIO_indent(out, indent, 80)
                || !BIO_printf(out, "%d Context%s for CA (default has keyID 0x%02X)\n",
                    sk_num((_STACK*) ctx->ca_ctxs),
                    sk_num((_STACK*) ctx->ca_ctxs) > 1 ? "s" : "",
                    ctx->ca_ctx ? ctx->ca_ctx->id : -1))
            return 0;
        stack_print_private(CA_CTX, out, ctx->ca_ctxs, indent+4);
        if (!BIO_indent(out, indent, 80)
                || !BIO_printf(out, "%d Context%s for RI (default has keyID 0x%02X)\n",
                    sk_num((_STACK*) ctx->ri_ctxs),
                    sk_num((_STACK*) ctx->ri_ctxs) > 1 ? "s" : "",
                    ctx->ri_ctx ? ctx->ri_ctx->id : -1))
            return 0;
        stack_print_private(RI_CTX, out, ctx->ri_ctxs, indent);
    } else {
        if (!BIO_indent(out, indent, 80)
                || !BIO_printf(out, "<ABSENT>\n"))
            return 0;
    }
    return 1;
}

const static char *pin_str = "PIN";
const static char *can_str = "CAN";
const static char *mrz_str = "MRZ";
const static char *puk_str = "PUK";
const static char *raw_str = "RAW";
const static char *undef_str = "UNDEF";

int
PACE_SEC_print_private(BIO *out, const PACE_SEC *sec, int indent)
{
    const char *s;
    if (sec) {
        switch (sec->type) {
            case PACE_RAW:
                s = raw_str;
                break;
            case PACE_PIN:
                s = pin_str;
                break;
            case PACE_PUK:
                s = puk_str;
                break;
            case PACE_CAN:
                s = can_str;
                break;
            case PACE_MRZ:
                s = mrz_str;
                break;
            case PACE_SEC_UNDEF:
                /* fall through */
            default:
                s = undef_str;
                break;
        }
        if (!BIO_indent(out, indent, 80)
                || !BIO_printf(out, "%s\n", s)
                || !BIO_indent(out, indent, 80)
                || !BIO_printf(out, "Secret:\n")
                || !BUF_MEM_print(out, sec->mem, indent)
                || !BIO_indent(out, indent, 80)
                || !BIO_printf(out, "Encoded Secret:\n")
                || !BUF_MEM_print(out, sec->encoded, indent))
            return 0;
    } else {
        if (!BIO_indent(out, indent, 80)
                || !BIO_printf(out, "<ABSENT>\n"))
            return 0;
    }
    return 1;
}
