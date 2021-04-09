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
 * @file pace_lib.c
 * @brief Data management functions
 *
 * @author Frank Morgner <frankmorgner@gmail.com>
 * @author Dominik Oepen <oepen@informatik.hu-berlin.de>
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "eac_dh.h"
#include "eac_ecdh.h"
#include "eac_err.h"
#include "eac_lib.h"
#include "eac_util.h"
#include "misc.h"
#include "ssl_compat.h"
#include "pace_mappings.h"
#include <eac/pace.h>
#include <openssl/buffer.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <string.h>

/**
 * @brief Encodes a shared secret according to TR-3110 Table F.2
 *
 * @param pi Password to encode
 *
 * @return BUF_MEM object containing the encoded password or NULL if an error occurred
 *
 * @note This function is automatically called during PACE, normally you should not need to use it.
 */
static BUF_MEM *
encoded_secret(const PACE_SEC * pi);
/* Data must include the check byte when used for PACE */
#define MRZ_SERIALNUMBER_LEN    (9+1)
#define MRZ_DATEOFBIRTH_LEN     (6+1)
#define MRZ_DATEOFEXPIRY_LEN    (6+1)
#define MRZ_SERIALNUMBER_OFF    5
#define MRZ_DATEOFBIRTH_OFF     30
#define MRZ_DATEOFEXPIRY_OFF    38
/**
 * @brief Encodes the Machine readable zone according to TR-03110 table A.3
 *
 * @param[in] mrz buffer containing the MRZ
 * @param[in] len size of the buffer
 *
 * @return the encoded MRZ or NULL on error
 */
static BUF_MEM *
encoded_mrz(const char *mrz, size_t len);

void
PACE_SEC_clear_free(PACE_SEC * s)
{
    if (s) {
        if (s->mem) {
            OPENSSL_cleanse(s->mem->data, s->mem->max);
            BUF_MEM_free(s->mem);
        }
        if (s->encoded) {
            OPENSSL_cleanse(s->encoded->data, s->encoded->max);
            BUF_MEM_free(s->encoded);
        }
        OPENSSL_free(s);
    }
}

PACE_SEC *
PACE_SEC_new(const char *sec, size_t sec_len, enum s_type type)
{
    PACE_SEC *out = OPENSSL_zalloc(sizeof(PACE_SEC));
    check(out, "Out of memory");

    switch (type) {
        case PACE_PUK:
        case PACE_CAN:
        case PACE_PIN:
        case PACE_MRZ:
        case PACE_RAW:
            out->type = type;
            break;

        default:
            log_err("Invalid arguments");
            goto err;
    }

    out->mem = BUF_MEM_create_init(sec, sec_len);
    out->encoded = encoded_secret(out);
    if (!out->mem || !out->encoded)
        goto err;

    return out;

err:
    PACE_SEC_clear_free(out);

    return NULL;
}

static BUF_MEM *
encoded_secret(const PACE_SEC * pi)
{
    /* Encoding of the secret according to TR-03110 2.02 Table A3 */
    BUF_MEM * out;

    check_return(pi && pi->mem, "Invalid arguments");

    switch (pi->type) {
        case PACE_PUK:
        case PACE_CAN:
        case PACE_PIN:
            if (!is_char_str((unsigned char*) pi->mem->data, (size_t) pi->mem->length))
                return NULL;
            /* fall through */
        case PACE_RAW:
            out = BUF_MEM_create_init(pi->mem->data, pi->mem->length);
            break;

        case PACE_MRZ:
            out = encoded_mrz(pi->mem->data, pi->mem->length);
            break;

        default:
            log_err("Invalid arguments");
            return NULL;
    }

    return out;
}

static BUF_MEM *
encoded_mrz(const char *in, size_t len)
{
    const char *serial, *dob, *doe;
    BUF_MEM *cat = NULL, *out = NULL;

    check(in, "Invalid arguments");

    /* Parse MRZ */
    check((len >= MRZ_SERIALNUMBER_OFF + MRZ_SERIALNUMBER_LEN
            && len >= MRZ_DATEOFBIRTH_OFF + MRZ_DATEOFBIRTH_LEN
            && len >= MRZ_DATEOFEXPIRY_OFF + MRZ_DATEOFEXPIRY_LEN),
           "Invalid data");

    serial = in + MRZ_SERIALNUMBER_OFF;
    dob = in + MRZ_DATEOFBIRTH_OFF;
    doe = in + MRZ_DATEOFEXPIRY_OFF;

    /* Concatenate Serial Number || Date of Birth || Date of Expiry */
    cat = BUF_MEM_create(MRZ_SERIALNUMBER_LEN + MRZ_DATEOFBIRTH_LEN +
            MRZ_DATEOFEXPIRY_LEN);
    if (!cat)
        goto err;
    memcpy(cat->data, serial, MRZ_SERIALNUMBER_LEN);
    memcpy(cat->data + MRZ_SERIALNUMBER_LEN, dob, MRZ_DATEOFBIRTH_LEN);
    memcpy(cat->data + MRZ_SERIALNUMBER_LEN + MRZ_DATEOFBIRTH_LEN,
            doe, MRZ_DATEOFEXPIRY_LEN);

    /* Compute and output SHA1 hash of concatenation */
    out = hash(EVP_sha1(), NULL, NULL, cat);

err:
    if(cat) {
        OPENSSL_cleanse(cat->data, cat->length);
        BUF_MEM_free(cat);
    }

    return out;
}

void
PACE_CTX_clear_free(PACE_CTX * ctx)
{
    if (ctx) {
        BUF_MEM_clear_free(ctx->nonce);
        KA_CTX_clear_free(ctx->ka_ctx);
        if (ctx->static_key)
            EVP_PKEY_free(ctx->static_key);
        if (ctx->my_eph_pubkey)
            BUF_MEM_free(ctx->my_eph_pubkey);
        OPENSSL_free(ctx);
    }
}

PACE_CTX *
PACE_CTX_new(void)
{
    PACE_CTX *out = OPENSSL_zalloc(sizeof(PACE_CTX));
    check(out, "Out of memory");

    out->ka_ctx = KA_CTX_new();
    out->static_key = EVP_PKEY_new();
    if (!out->ka_ctx || !out->static_key)
        goto err;

    out->id = -1;

    return out;

err:
    if (out) {
        if (out->static_key)
            EVP_PKEY_free(out->static_key);
        KA_CTX_clear_free(out->ka_ctx);
        OPENSSL_free(out);
    }

    return NULL;
}

int
PACE_CTX_set_protocol(PACE_CTX * ctx, int protocol, enum eac_tr_version tr_version)
{
    if (!ctx) {
        log_err("Invalid arguments");
        return 0;
    }
    if (!KA_CTX_set_protocol(ctx->ka_ctx, protocol))
        return 0;

    if (protocol == NID_id_PACE_ECDH_GM_3DES_CBC_CBC
            || protocol == NID_id_PACE_ECDH_GM_AES_CBC_CMAC_128
            || protocol == NID_id_PACE_ECDH_GM_AES_CBC_CMAC_192
            || protocol == NID_id_PACE_ECDH_GM_AES_CBC_CMAC_256) {
        ctx->map_generate_key = ecdh_gm_generate_key;
        ctx->map_compute_key = ecdh_gm_compute_key;

    } else if (protocol == NID_id_PACE_DH_GM_3DES_CBC_CBC
            || protocol == NID_id_PACE_DH_GM_AES_CBC_CMAC_128
            || protocol == NID_id_PACE_DH_GM_AES_CBC_CMAC_192
            || protocol == NID_id_PACE_DH_GM_AES_CBC_CMAC_256) {
        ctx->map_generate_key = dh_gm_generate_key;
        ctx->map_compute_key = dh_gm_compute_key;

    } else if (protocol == NID_id_PACE_DH_IM_3DES_CBC_CBC
            || protocol == NID_id_PACE_DH_IM_AES_CBC_CMAC_128
            || protocol == NID_id_PACE_DH_IM_AES_CBC_CMAC_192
            || protocol == NID_id_PACE_DH_IM_AES_CBC_CMAC_256) {
        if (tr_version > EAC_TR_VERSION_2_01) {
            log_err("Invalid arguments");
            return 0;
        }
        ctx->map_generate_key = dh_im_generate_key;
        ctx->map_compute_key = dh_im_compute_key;

    } else if (protocol == NID_id_PACE_ECDH_IM_3DES_CBC_CBC
            || protocol == NID_id_PACE_ECDH_IM_AES_CBC_CMAC_128
            || protocol == NID_id_PACE_ECDH_IM_AES_CBC_CMAC_192
            || protocol == NID_id_PACE_ECDH_IM_AES_CBC_CMAC_256) {
        if (tr_version > EAC_TR_VERSION_2_01) {
            log_err("Invalid arguments");
            return 0;
        }
        ctx->map_generate_key = ecdh_im_generate_key;
        ctx->map_compute_key = ecdh_im_compute_key;

    } else {
        log_err("Invalid arguments");
        return 0;
    }
    ctx->protocol = protocol;

    return 1;
}
