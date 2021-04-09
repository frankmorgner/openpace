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
 * @file ta_lib.c
 *
 * @author Frank Morgner <frankmorgner@gmail.com>
 * @author Dominik Oepen <oepen@informatik.hu-berlin.de>
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "eac_err.h"
#include "eac_util.h"
#include "ssl_compat.h"
#include "ta_lib.h"
#include <eac/cv_cert.h>
#include <eac/ta.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/rsa.h>
#include <string.h>

TA_CTX *
TA_CTX_new(void) {
    TA_CTX *ctx = (TA_CTX *) OPENSSL_zalloc(sizeof(TA_CTX));
    if (!ctx)
        return NULL;

    ctx->lookup_cvca_cert = EAC_get_default_cvca_lookup();

    return ctx;
}

void
TA_CTX_clear_free(TA_CTX *ctx) {
    if (!ctx)
        return;

    if (ctx->pk_pcd)
        BUF_MEM_free(ctx->pk_pcd);
    if (ctx->priv_key)
        EVP_PKEY_free(ctx->priv_key);
    if (ctx->pub_key)
        EVP_PKEY_free(ctx->pub_key);
    if (ctx->trust_anchor)
        CVC_CERT_free(ctx->trust_anchor);
    if (ctx->current_cert)
        CVC_CERT_free(ctx->current_cert);
    if (ctx->new_trust_anchor)
        CVC_CERT_free(ctx->new_trust_anchor);
    BUF_MEM_clear_free(ctx->nonce);

    OPENSSL_free(ctx);
    return;
}

#include <time.h>
static int
cvc_check_time(const CVC_CERT *cert)
{
    time_t loc;
    struct tm exp_tm, eff_tm, *utc_tm;

    if (!cert || !cert->body
            || !cert->body->certificate_effective_date
            || cert->body->certificate_effective_date->length != 6
            || !is_bcd(cert->body->certificate_effective_date->data,
                cert->body->certificate_effective_date->length)
            || cert->body->certificate_expiration_date->length != 6
            || !is_bcd(cert->body->certificate_expiration_date->data,
                cert->body->certificate_expiration_date->length))
        return -1;

    /* FIXME gmtime is not thread safe */
    time(&loc);
    utc_tm = gmtime(&loc);
    if (!utc_tm)
        return -1;

    memcpy(&eff_tm, utc_tm, sizeof(struct tm));
    eff_tm.tm_sec = 0;          /* seconds */
    eff_tm.tm_min = 0;          /* minutes */
    eff_tm.tm_hour = 0;         /* hours */
    eff_tm.tm_wday = -1;        /* day of the week */
    eff_tm.tm_yday = -1;        /* day in the year */
    eff_tm.tm_year = 100        /* The number of years since 1900 */
        + ((unsigned char) cert->body->certificate_effective_date->data[0])*10
        + (unsigned char) cert->body->certificate_effective_date->data[1];
    eff_tm.tm_mon = ((unsigned char) cert->body->certificate_effective_date->data[2])*10
        + (unsigned char) cert->body->certificate_effective_date->data[3] - 1;
    eff_tm.tm_mday = ((unsigned char) cert->body->certificate_effective_date->data[4])*10
        + (unsigned char) cert->body->certificate_effective_date->data[5];

    memcpy(&exp_tm, utc_tm, sizeof(struct tm));
    exp_tm.tm_sec = 59;         /* seconds */
    exp_tm.tm_min = 59;         /* minutes */
    exp_tm.tm_hour = 23;        /* hours */
    exp_tm.tm_wday = -1;        /* day of the week */
    exp_tm.tm_yday = -1;        /* day in the year */
    exp_tm.tm_year = 100        /* The number of years since 1900 */
        + ((unsigned char) cert->body->certificate_expiration_date->data[0])*10
        + (unsigned char) cert->body->certificate_expiration_date->data[1];
    exp_tm.tm_mon = ((unsigned char) cert->body->certificate_expiration_date->data[2])*10
        + (unsigned char) cert->body->certificate_expiration_date->data[3] - 1;
    exp_tm.tm_mday = ((unsigned char) cert->body->certificate_expiration_date->data[4])*10
        + (unsigned char) cert->body->certificate_expiration_date->data[5];

    if (exp_tm.tm_mon < 0 || exp_tm.tm_mon > 12
            || exp_tm.tm_mday > 31
            || eff_tm.tm_mon < 0 || eff_tm.tm_mon > 11
            || eff_tm.tm_mday > 31
            || difftime(mktime(utc_tm), mktime(&eff_tm)) < 0
            || difftime(mktime(&exp_tm), mktime(utc_tm)) < 0) {
        return 0;
    }

    return 1;
}

static int
TA_CTX_set_parameters(TA_CTX *ctx, const CVC_CERT *cert,
        BN_CTX *bn_ctx)
{
    EVP_PKEY *pub = NULL;
    int ok = 0, oid;

    check(ctx && cert && cert->body && cert->body->public_key,
            "Invalid arguments");

    /* Extract the public key of the terminal and overwrite the current key. */
    if (ctx->priv_key) {
        pub = EVP_PKEY_dup(ctx->priv_key);
        check(pub, "Failed to create public key");
        check(CVC_pubkey2pkey(cert, bn_ctx, pub),
                "Failed to extract public key");
    } else {
        /* ctx->pub might be NULL (in case of a CVCA certificate). */
        pub = CVC_pubkey2pkey(cert, bn_ctx, ctx->pub_key);
        check(pub, "Failed to extract public key");
    }
    ctx->pub_key = pub;
    pub = NULL;

    /* Extract OID from the terminal certificate */
    oid = OBJ_obj2nid(cert->body->public_key->oid);
    check(oid != NID_undef, "Unknown public key format");

    /* Use the oid as the protocol identifier in the TA context */
    ctx->protocol = oid;

    ok = 1;

err:
    if (pub)
        EVP_PKEY_free(pub);
    return ok;
}

int
TA_CTX_import_certificate(TA_CTX *ctx, const CVC_CERT *next_cert,
           BN_CTX *bn_ctx)
{
    int ok = 0, i;
    CVC_CERT *trust_anchor = NULL;

    check(ctx && next_cert && next_cert->body && next_cert->body->chat &&
            next_cert->body->certificate_authority_reference,
           "Invalid arguments");

    /* Check date to see if the certificate is still valid
     * (not for link certificates). */
    if ((ctx->flags & TA_FLAG_SKIP_TIMECHECK) != TA_FLAG_SKIP_TIMECHECK
            && CVC_get_role(next_cert->body->chat) != CVC_CVCA) {
        check(cvc_check_time(next_cert) == 1,
                "Could not verify certificate's validity period");
    }

    /* get the current trust anchor */
    if (ctx->current_cert) {
        trust_anchor = ctx->current_cert;
    } else if (ctx->trust_anchor) {
        trust_anchor = ctx->trust_anchor;
    } else if (ctx->lookup_cvca_cert) {
        trust_anchor = ctx->lookup_cvca_cert(
                next_cert->body->certificate_authority_reference->data,
                next_cert->body->certificate_authority_reference->length);
        check(trust_anchor, "Could not look up trust anchor");

        /* lookup the whole certificate chain until we hit an CVCA
         * certificate, otherwise we won't have a complete public key */
        if (CVC_get_role(trust_anchor->body->chat) == CVC_CVCA) {
            TA_CTX_set_trust_anchor(ctx, trust_anchor, bn_ctx);
        } else {
            check(TA_CTX_import_certificate(ctx, trust_anchor, bn_ctx),
                    "Could not look up certificate chain");
        }
    }
    check(trust_anchor && trust_anchor->body
            && trust_anchor->body->certificate_holder_reference,
            "No trust anchor, can't verify certificate");

    /* Check chain integrity: The CAR of a certificate must be equal to the
     * the CHR of the next certificate in the chain */
    check((next_cert->body->certificate_authority_reference
                && trust_anchor->body->certificate_holder_reference
                && next_cert->body->certificate_authority_reference->length ==
                trust_anchor->body->certificate_holder_reference->length
                && memcmp(trust_anchor->body->certificate_holder_reference->data,
                    next_cert->body->certificate_authority_reference->data,
                    trust_anchor->body->certificate_holder_reference->length) == 0),
            "Current CHR does not match next CAR");

    i = CVC_verify_signature(next_cert,
            OBJ_obj2nid(trust_anchor->body->public_key->oid), ctx->pub_key);
    check((i > 0), "Could not verify current signature");

    /* Certificate has been verified as next part of the chain */
    if (ctx->current_cert) {
        if (trust_anchor == ctx->current_cert)
            trust_anchor = NULL;
        CVC_CERT_free(ctx->current_cert);
    }
    ctx->current_cert = CVC_CERT_dup(next_cert);
    if (!ctx->current_cert)
        goto err;

    /* Set a (new) trust anchor */
    if (CVC_get_role(next_cert->body->chat) == CVC_CVCA) {
        if (ctx->new_trust_anchor)
            CVC_CERT_free(ctx->new_trust_anchor);
        ctx->new_trust_anchor = CVC_CERT_dup(next_cert);
        if (!ctx->new_trust_anchor)
            goto err;
    }

    ok = TA_CTX_set_parameters(ctx, next_cert, bn_ctx);

err:
    if (trust_anchor && trust_anchor != ctx->current_cert
            && trust_anchor != ctx->trust_anchor) {
        CVC_CERT_free(trust_anchor);
    }

    return ok;
}

int
TA_CTX_set_trust_anchor(TA_CTX *ctx, const CVC_CERT *trust_anchor,
           BN_CTX *bn_ctx)
{
    int ok = 0;

    check(ctx, "Invalid Parameters");

    if (ctx->trust_anchor)
        CVC_CERT_free(ctx->trust_anchor);
    ctx->trust_anchor = CVC_CERT_dup(trust_anchor);
    if (!ctx->trust_anchor)
        goto err;

    if (ctx->current_cert) {
        CVC_CERT_free(ctx->current_cert);
        ctx->current_cert = NULL;
    }

    ok = TA_CTX_set_parameters(ctx, trust_anchor, bn_ctx);

err:
    return ok;
}
