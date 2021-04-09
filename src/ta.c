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
 * @file ta.c
 * @brief Protocol steps for the terminal authentication version 2
 *
 * @date 2011-04-03
 *
 * @author Frank Morgner <frankmorgner@gmail.com>
 * @author Dominik Oepen <oepen@informatik.hu-berlin.de>
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "eac_err.h"
#include "eac_lib.h"
#include "eac_util.h"
#include "misc.h"
#include "ta_lib.h"
#include <eac/cv_cert.h>
#include <eac/ta.h>
#include <openssl/bio.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <string.h>

void TA_disable_checks(EAC_CTX *ctx)
{
    if (ctx && ctx->ta_ctx)
        ctx->ta_ctx->flags = TA_FLAG_SKIP_TIMECHECK;
}

int
TA_STEP2_import_certificate(const EAC_CTX *ctx,
           const unsigned char *cert, size_t cert_len)
{
    CVC_CERT *ta_cert = NULL;
    int r = 0;

    check(ctx, "Invalid arguments");

    ta_cert = CVC_d2i_CVC_CERT(&ta_cert, &cert, cert_len);
    r = TA_CTX_import_certificate(ctx->ta_ctx, ta_cert, ctx->bn_ctx);

err:
    if (ta_cert)
        CVC_CERT_free(ta_cert);

    return r;
}

/**
 * @brief gets the data, which is signed in the process of TA
 *
 * @param[in] pcd_ta_comp_eph_pubkey compressed ephemeral CA public key of PCD
 * @param[in] id_picc compressed ephemeral PACE public key of PICC
 * @param[in] nonce nonce from PICC
 * @param[in] (optional) auxdata auxiliary data from PCD
 *
 * @return A buffer containing the data to be signed or NULL in case of an error
 */
static BUF_MEM *
get_ta_sigdata(const BUF_MEM *pcd_ta_comp_eph_pubkey,
        const BUF_MEM *id_picc, const BUF_MEM *nonce,
        const BUF_MEM *auxdata)
{
    size_t len;
    BUF_MEM *data = NULL;

    check_return(nonce && pcd_ta_comp_eph_pubkey, "Invalid arguments");

    /* Data to be signed: ID PICC || r PICC || Comp(~PK_PCD) || APCD */

    /* Authenticated auxiliary data are optional (only necessary if special
     * functions will be used later on) */
    if (auxdata) {
        len = id_picc->length + nonce->length +
            pcd_ta_comp_eph_pubkey->length + auxdata->length;
    } else {
        len = id_picc->length + nonce->length +
            pcd_ta_comp_eph_pubkey->length;
    }
    data = BUF_MEM_create(len);
    if (!data)
        return NULL;

    /* Concatenate the data */
    memcpy(data->data, id_picc->data, id_picc->length);
    memcpy(data->data + id_picc->length, nonce->data, nonce->length);
    memcpy(data->data + id_picc->length + nonce->length, pcd_ta_comp_eph_pubkey->data,
            pcd_ta_comp_eph_pubkey->length);
    if (auxdata)
        memcpy(data->data + id_picc->length + nonce->length +
                pcd_ta_comp_eph_pubkey->length, auxdata->data, auxdata->length);

    return data;
}

BUF_MEM *
TA_STEP3_generate_ephemeral_key(const EAC_CTX *ctx)
{
    BUF_MEM *comp_pub_key, *pub_key = NULL;

    check_return(ctx && ctx->ca_ctx && ctx->ca_ctx->ka_ctx,
            "Invalid arguments");

    pub_key = KA_CTX_generate_key(ctx->ca_ctx->ka_ctx, ctx->bn_ctx);

    comp_pub_key = Comp(ctx->ca_ctx->ka_ctx->key, pub_key, ctx->bn_ctx,
            ctx->md_ctx);

    if (pub_key)
        BUF_MEM_free(pub_key);

    return comp_pub_key;
}

/* Nonce for TA is always 8 bytes long */
#define TA_NONCE_SIZE 8
BUF_MEM *
TA_STEP4_get_nonce(const EAC_CTX *ctx)
{
    check_return(ctx && ctx->ta_ctx, "Invalid arguments");

    BUF_MEM_clear_free(ctx->ta_ctx->nonce);
    ctx->ta_ctx->nonce = randb(TA_NONCE_SIZE);

    check_return(ctx->ta_ctx->nonce, "Failed to generate nonce");

    return BUF_MEM_dup(ctx->ta_ctx->nonce);
}

int
TA_STEP4_set_nonce(const EAC_CTX *ctx, const BUF_MEM *nonce) {
    int r = 0;

    check(ctx && ctx->ta_ctx && nonce, "Invalid arguments");

    if (ctx->ta_ctx->nonce)
      BUF_MEM_free(ctx->ta_ctx->nonce);

    ctx->ta_ctx->nonce = BUF_MEM_dup(nonce);
    check(ctx->ta_ctx->nonce, "Failed to copy nonce");

    r = 1;
err:
    return r;
}

BUF_MEM *
TA_STEP5_sign(const EAC_CTX *ctx, const BUF_MEM *my_ta_comp_eph_pubkey,
           const BUF_MEM *opp_pace_comp_eph_pubkey, const BUF_MEM *auxdata)
{
    BUF_MEM *data = NULL, *signature = NULL;

    check(ctx && ctx->ta_ctx, "Invalid arguments");

    /* Get the data to be signed */
    data = get_ta_sigdata(my_ta_comp_eph_pubkey, opp_pace_comp_eph_pubkey,
            ctx->ta_ctx->nonce, auxdata);
    signature = EAC_sign(ctx->ta_ctx->protocol, ctx->ta_ctx->priv_key, data);

err:
    if (data)
        BUF_MEM_free(data);

    return signature;
}

int
TA_STEP6_verify(const EAC_CTX *ctx, const BUF_MEM *opp_ta_comp_eph_pubkey,
           const BUF_MEM *my_pace_comp_eph_pubkey, const BUF_MEM *auxdata,
           const BUF_MEM *signature)
{
    BUF_MEM *data = NULL;
    int r = -1;

    check(ctx && ctx->ta_ctx, "Invalid arguments");

    check(ctx->ta_ctx->nonce, "Conditions not satisfied");

    /* Get the data to be verified */
    data = get_ta_sigdata(opp_ta_comp_eph_pubkey, my_pace_comp_eph_pubkey,
            ctx->ta_ctx->nonce, auxdata);
    r = EAC_verify(ctx->ta_ctx->protocol, ctx->ta_ctx->pub_key, signature, data);

err:
    if (data)
        BUF_MEM_free(data);

    return r;
}
