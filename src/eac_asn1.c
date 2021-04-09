/*
 * Copyright (c) 2010-2012 Dominik Oepen and Frank Morgner
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
 * @file eac_asn1.c
 * @brief ASN.1 structures related to PACE
 *
 * @author Dominik Oepen <oepen@informatik.hu-berlin.de>
 * @author Frank Morgner <frankmorgner@gmail.com>
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ca_lib.h"
#include "eac_asn1.h"
#include "eac_dh.h"
#include "eac_err.h"
#include "eac_util.h"
#include "misc.h"
#include "pace_lib.h"
#include <eac/eac.h>
#include <eac/pace.h>
#include <eac/ri.h>
#include <openssl/asn1.h>
#include <openssl/dh.h>
#include <openssl/ec.h>
#include <openssl/objects.h>
#include <openssl/obj_mac.h>

/** PACEInfo structure */
typedef struct pace_info_st {
    /** OID of the algorithm to be used */
    ASN1_OBJECT *protocol;
    /** Protocol Version number. Version number 1 is deprecated, version 2 is
        recommended */
    ASN1_INTEGER *version;
    /** Indicates the domain parameter identifier. named parameterID in BSI TR-03110 */
    ASN1_INTEGER *keyID;
    } PACE_INFO;

/** Algorithm Identifier structure */
typedef struct algorithm_identifier_st {
    /** OID of the algorithm */
    ASN1_OBJECT *algorithm;
    ASN1_TYPE *parameters;
} ALGORITHM_IDENTIFIER;

/** Subject Public Key Info structure */
typedef struct subject_public_key_info_st {
    ALGORITHM_IDENTIFIER *algorithmIdentifier;
    ASN1_BIT_STRING *subjectPublicKey;
} SUBJECT_PUBLIC_KEY_INFO;

/** Domain parameter structure */
typedef struct pace_dp_info_st {
    /** OID of the type of domain parameters*/
    ASN1_OBJECT *protocol;
    /** The actual domain parameters */
    ALGORITHM_IDENTIFIER *aid;
    /** Optional: specifies the local domain parameters if multiple sets of domain
        parameters are provided. named parameterID in BSI TR-03110 */
    ASN1_INTEGER *keyID;
} PACE_DP_INFO;

/** ChipAuthenticationInfo structure */
typedef struct ca_info_st {
    /** OID */
    ASN1_OBJECT *protocol;
    /** Protocol Version number. Currently Version 1 and Version 2 are supported */
    ASN1_INTEGER *version;
    /** keyID MAY be used to indicate the local key identifier */
    ASN1_INTEGER *keyID;
} CA_INFO;

/** CA Domain parameter structure */
typedef struct ca_dp_info_st {
    /** OID of the type of domain parameters*/
    ASN1_OBJECT *protocol;
    /** The actual domain parameters */
    ALGORITHM_IDENTIFIER *aid;
    /** Optional: specifies the local domain parameters if multiple sets of domain
        parameters are provided */
    ASN1_INTEGER *keyID;
} CA_DP_INFO;

/** CA public key info */
typedef struct ca_public_key_info_st {
    /** OID of the type of domain parameters*/
    ASN1_OBJECT *protocol;
    /** The actual public key */
    SUBJECT_PUBLIC_KEY_INFO *chipAuthenticationPublicKeyInfo;
    /** Optional: specifies the local domain parameters if multiple sets of domain
        parameters are provided */
    ASN1_INTEGER *keyID;
} CA_PUBLIC_KEY_INFO;

/** File ID */
typedef struct file_id_st {
    /** File identifier */
    ASN1_OCTET_STRING *fid;
    /** Short file ifentifier */
    ASN1_OCTET_STRING *sfid;
} FILE_ID;

/** TerminalAuthenticationInfo */
typedef struct ta_info_st {
    /** OID */
    ASN1_OBJECT *protocol;
    /** Protocol Version number. Currently Version 1 and Version 2 are supported */
    ASN1_INTEGER *version;
    /** FileIdentifier of EF.CVCA */
    FILE_ID *efCVCA;
} TA_INFO;

/** ProtocolParams */
typedef struct protocol_params_st {
    /* Protocol version. Currently only version 1 is supported */
    ASN1_INTEGER *version;
    /** keyID identifies the private key that shall be used */
    ASN1_INTEGER *keyID;
    /** Indicates whether explicit authorization is required to use the
     * corresponding secret key */
    ASN1_BOOLEAN *authorizedOnly;
} PROTOCOL_PARAMS;

/** Restricted Authentication Info*/
typedef struct ri_info_st {
    /** OID */
    ASN1_OBJECT *protocol;
    /** Protocol parameters */
    PROTOCOL_PARAMS *params;
    /** indicates the maximum length of the supported sector
     * specific public keys */
    ASN1_INTEGER *maxKeyLen;
} RI_INFO;

/** RI domain parameter info */
typedef struct ri_dp_info_st {
    /** OID of the type of domain parameters*/
    ASN1_OBJECT *protocol;
    /** The actual domain parameters */
    ALGORITHM_IDENTIFIER *aid;
} RI_DP_INFO;

/** Card Info Locator */
typedef struct card_info_locator_st {
    /** OID */
    ASN1_OBJECT *protocol;
    ASN1_IA5STRING *url;
    FILE_ID *efCardInfo;
} CARD_INFO_LOCATOR;

ASN1_SEQUENCE(PACE_INFO) = {
    ASN1_SIMPLE(PACE_INFO, protocol, ASN1_OBJECT),
    ASN1_SIMPLE(PACE_INFO, version, ASN1_INTEGER),
    ASN1_OPT(PACE_INFO, keyID, ASN1_INTEGER)
} ASN1_SEQUENCE_END(PACE_INFO)

IMPLEMENT_ASN1_FUNCTIONS(PACE_INFO)

ASN1_SEQUENCE(ALGORITHM_IDENTIFIER) = {
    ASN1_SIMPLE(ALGORITHM_IDENTIFIER, algorithm, ASN1_OBJECT),
    ASN1_SIMPLE(ALGORITHM_IDENTIFIER, parameters, ASN1_ANY)
} ASN1_SEQUENCE_END(ALGORITHM_IDENTIFIER)

ASN1_SEQUENCE(SUBJECT_PUBLIC_KEY_INFO) = {
        ASN1_SIMPLE(SUBJECT_PUBLIC_KEY_INFO, algorithmIdentifier, ALGORITHM_IDENTIFIER),
        ASN1_SIMPLE(SUBJECT_PUBLIC_KEY_INFO, subjectPublicKey, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(SUBJECT_PUBLIC_KEY_INFO)

/* PACEDomainParameterInfo */
ASN1_SEQUENCE(PACE_DP_INFO) = {
    ASN1_SIMPLE(PACE_DP_INFO, protocol, ASN1_OBJECT),
    ASN1_SIMPLE(PACE_DP_INFO, aid, ALGORITHM_IDENTIFIER),
    ASN1_OPT(PACE_DP_INFO, keyID, ASN1_INTEGER)
} ASN1_SEQUENCE_END(PACE_DP_INFO)

IMPLEMENT_ASN1_FUNCTIONS(PACE_DP_INFO)

/* ChipAuthenticationInfo */
ASN1_SEQUENCE(CA_INFO) = {
    ASN1_SIMPLE(CA_INFO, protocol, ASN1_OBJECT),
    ASN1_SIMPLE(CA_INFO, version, ASN1_INTEGER),
    ASN1_OPT(CA_INFO, keyID, ASN1_INTEGER)
} ASN1_SEQUENCE_END(CA_INFO)
IMPLEMENT_ASN1_FUNCTIONS(CA_INFO)

/* ChipAuthenticationDomainParameterInfo */
ASN1_SEQUENCE(CA_DP_INFO) = {
    ASN1_SIMPLE(CA_DP_INFO, protocol, ASN1_OBJECT),
    ASN1_SIMPLE(CA_DP_INFO, aid, ALGORITHM_IDENTIFIER),
    ASN1_OPT(CA_DP_INFO, keyID, ASN1_INTEGER)
} ASN1_SEQUENCE_END(CA_DP_INFO)
IMPLEMENT_ASN1_FUNCTIONS(CA_DP_INFO)

/* ChipAuthenticationPublicKeyInfo */
ASN1_SEQUENCE(CA_PUBLIC_KEY_INFO) = {
        ASN1_SIMPLE(CA_PUBLIC_KEY_INFO, protocol, ASN1_OBJECT),
        ASN1_SIMPLE(CA_PUBLIC_KEY_INFO, chipAuthenticationPublicKeyInfo, SUBJECT_PUBLIC_KEY_INFO),
        ASN1_OPT(CA_PUBLIC_KEY_INFO, keyID, ASN1_INTEGER)
} ASN1_SEQUENCE_END(CA_PUBLIC_KEY_INFO)
IMPLEMENT_ASN1_FUNCTIONS(CA_PUBLIC_KEY_INFO)

/* FileId */
ASN1_SEQUENCE(FILE_ID) = {
    ASN1_SIMPLE(FILE_ID, fid, ASN1_OCTET_STRING),
    ASN1_OPT(FILE_ID, sfid, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(FILE_ID)

/* TerminalAuthenticationInfo */
ASN1_SEQUENCE(TA_INFO) = {
    ASN1_SIMPLE(TA_INFO, protocol, ASN1_OBJECT),
    ASN1_SIMPLE(TA_INFO, version, ASN1_INTEGER),
    ASN1_OPT(TA_INFO, efCVCA, FILE_ID)
} ASN1_SEQUENCE_END(TA_INFO)
IMPLEMENT_ASN1_FUNCTIONS(TA_INFO)

/* ProtocolParams */
ASN1_SEQUENCE(PROTOCOL_PARAMS) = {
    ASN1_SIMPLE(PROTOCOL_PARAMS, version, ASN1_INTEGER),
    ASN1_SIMPLE(PROTOCOL_PARAMS, keyID, ASN1_INTEGER),
    ASN1_SIMPLE(PROTOCOL_PARAMS, authorizedOnly, ASN1_BOOLEAN)
} ASN1_SEQUENCE_END(PROTOCOL_PARAMS)

/* RestrictedIdentificationInfo */
ASN1_SEQUENCE(RI_INFO) = {
    ASN1_SIMPLE(RI_INFO, protocol, ASN1_OBJECT),
    ASN1_SIMPLE(RI_INFO, params, PROTOCOL_PARAMS),
    ASN1_OPT(RI_INFO, maxKeyLen, ASN1_INTEGER)
} ASN1_SEQUENCE_END(RI_INFO)
IMPLEMENT_ASN1_FUNCTIONS(RI_INFO)

/* RestrictedIdentificationDomainParameterInfo */
ASN1_SEQUENCE(RI_DP_INFO) = {
    ASN1_SIMPLE(RI_DP_INFO, protocol, ASN1_OBJECT),
    ASN1_SIMPLE(RI_DP_INFO, aid, ALGORITHM_IDENTIFIER),
} ASN1_SEQUENCE_END(RI_DP_INFO)
IMPLEMENT_ASN1_FUNCTIONS(RI_DP_INFO)

/* CardInfoLocator */
ASN1_SEQUENCE(CARD_INFO_LOCATOR) = {
    ASN1_SIMPLE(CARD_INFO_LOCATOR, protocol, ASN1_OBJECT),
    ASN1_SIMPLE(CARD_INFO_LOCATOR, url, ASN1_IA5STRING),
    ASN1_OPT(CARD_INFO_LOCATOR, efCardInfo, FILE_ID)
} ASN1_SEQUENCE_END(CARD_INFO_LOCATOR)



static EC_KEY *
ecpkparameters2eckey(ASN1_TYPE *ec_params)
{
    EC_GROUP *group = NULL;
    EC_KEY *ec = NULL;
    int length, fail = 1;
    unsigned char *encoded = NULL;
    const unsigned char *p;

    check(ec_params && ec_params->type == V_ASN1_SEQUENCE,
            "Invalid arguments");

    /* unfortunately we need to re-pack and re-parse the ECPKPARAMETERS,
     * because there is no official API for using it directly (see
     * openssl/crypto/ec/ec.h) */
    length = i2d_ASN1_TYPE(ec_params, &encoded);
    p = encoded;
    check(length > 0 && d2i_ECPKParameters(&group, &p, length),
            "Could not decode EC parameters");

    ec = EC_KEY_new();
    check(ec && EC_KEY_set_group(ec, group),
            "Could not initialize key object");

    fail = 0;

err:
    if (group)
        EC_GROUP_free(group);
    OPENSSL_free(encoded);
    if (fail) {
        if (ec)
            EC_KEY_free(ec);
        ec = NULL;
    }
    return ec;
}

static DH *
dhparams2dh(ASN1_TYPE *dh_params)
{
    DH *dh = NULL;
    int length = 1;
    unsigned char *encoded = NULL;
    const unsigned char *p;

    check(dh_params && dh_params->type == V_ASN1_SEQUENCE,
            "Invalid arguments");

    /* unfortunately we need to re-pack and re-parse the DHparams,
     * because there is no official API for using it directly (see
     * openssl/crypto/dh/dh.h) */
    length = i2d_ASN1_TYPE(dh_params, &encoded);
    p = encoded;
    check(length > 0 && d2i_DHparams(&dh, &p, length),
            "Could not decode DH parameters");

err:
    OPENSSL_free(encoded);
    return dh;
}

static EVP_PKEY *
aid2pkey(EVP_PKEY **key, ALGORITHM_IDENTIFIER *aid, BN_CTX *bn_ctx)
{
    EC_KEY *tmp_ec;
    DH *tmp_dh;
    EVP_PKEY *tmp_key = NULL, *ret = NULL;
    char obj_txt[32];
    int nid;

    /* If there is no key, allocate memory */
    if (!key || !*key) {
        tmp_key = EVP_PKEY_new();
        if (!tmp_key)
            goto err;
    } else
        tmp_key = *key;

    /* Extract actual parameters */
    nid = OBJ_obj2nid(aid->algorithm);
    if (       nid == NID_dhpublicnumber) {
        tmp_dh = dhparams2dh(aid->parameters);
        check(tmp_dh, "Could not decode DH key");
        EVP_PKEY_set1_DH(tmp_key, tmp_dh);
        DH_free(tmp_dh);

    } else if (nid == NID_X9_62_id_ecPublicKey
            || nid == NID_ecka_dh_SessionKDF_DES3
            || nid == NID_ecka_dh_SessionKDF_AES128
            || nid == NID_ecka_dh_SessionKDF_AES192
            || nid == NID_ecka_dh_SessionKDF_AES256) {
        tmp_ec = ecpkparameters2eckey(aid->parameters);
        check(tmp_ec, "Could not decode EC key");
        EVP_PKEY_set1_EC_KEY(tmp_key, tmp_ec);
        EC_KEY_free(tmp_ec);

    } else if (nid == NID_standardizedDomainParameters) {
        check(aid->parameters->type == V_ASN1_INTEGER,
                "Invalid data");
        check(EVP_PKEY_set_std_dp(tmp_key,
                    ASN1_INTEGER_get(aid->parameters->value.integer)),
                "Could not decode standardized domain parameter")

    } else {
        OBJ_obj2txt(obj_txt, sizeof obj_txt, aid->algorithm, 0);
        debug("Unknown Identifier (%s) for %s", OBJ_nid2sn(nid), obj_txt);
    }

    ret = tmp_key;
    if (key)
        *key = tmp_key;

err:
    if (tmp_key && tmp_key != ret) {
        EVP_PKEY_free(tmp_key);
    }

    return ret;
}


#define get_ctx_by_id(ctx, stack, _id) \
{ \
    int __i, __count; \
    __count = sk_num((_STACK*) stack); \
    for (__i = 0; __i < __count; __i++) { \
        ctx = sk_value((_STACK*) stack, __i); \
        if (ctx && ctx->id == _id) { \
            break; \
        } \
    } \
    if (__i >= __count) { \
        ctx = NULL; \
    } \
}

#define get_ctx_by_keyID(ctx, stack, keyID, structure) \
{ \
    int __id; \
    if (keyID) { \
        __id = (int) ASN1_INTEGER_get(keyID); \
    }  \
    else { \
        __id = -1; \
    } \
    /* lookup the context in the stack identified by info's keyID */ \
    get_ctx_by_id(ctx, stack, __id); \
    \
    /* if no context was found, create one and push it onto the stack */ \
    if (!ctx) { \
        ctx = structure##_new(); \
        if (ctx) { \
            if (!sk_push((_STACK *) stack, ctx)) { \
                structure##_clear_free(ctx); \
                ctx = NULL; \
            } else { \
                /* created and pushed successfully, now initialize id */ \
                if(keyID) { \
                    ctx->id = __id; \
                } else { \
                    ctx->id = -1; \
                } \
            } \
        } \
    } \
}

int
EAC_CTX_init_ef_cardaccess(const unsigned char * in, size_t in_len,
        EAC_CTX *ctx)
{
    ASN1_INTEGER *i = NULL;
    ASN1_OBJECT *oid = NULL;
    unsigned char *pubkey;
    size_t pubkey_len;
    CA_CTX *ca_ctx = NULL;
    CA_DP_INFO *tmp_ca_dp_info = NULL;
    CA_INFO *tmp_ca_info = NULL;
    CA_PUBLIC_KEY_INFO *ca_public_key_info = NULL;
    PACE_CTX *pace_ctx = NULL;
    PACE_DP_INFO *tmp_dp_info = NULL;
    PACE_INFO *tmp_info = NULL;
    RI_CTX *ri_ctx = NULL;
    RI_DP_INFO *tmp_ri_dp_info = NULL;
    RI_INFO *tmp_ri_info = NULL;
    TA_INFO *tmp_ta_info = NULL;
    char obj_txt[32];
    const unsigned char *info_start;
    int tag, class, nid, _count, _i, r = 0, has_no_pace_dp_info = 1;
    long data_len, info_len;
    unsigned int todo = 0;

    check((in && ctx && ctx->pace_ctxs && ctx->ca_ctxs && ctx->ri_ctxs),
        "Invalid arguments");

    /* We need to manually extract all members of the SET OF SecurityInfos,
     * because some files contain junk and look something like this:
     *
     *      SET { SecurityInfo, ..., SecurityInfo } , junk
     *
     * As far as we know, there is no way of telling OpenSSL to simply ignore
     * the junk in d2i_* functions. That's why we iterate manually through
     * the set */

    check(!(0x80 & ASN1_get_object(&in, &data_len, &tag, &class, in_len))
            && tag == V_ASN1_SET,
            "Invalid data");

    todo = data_len;

    while (todo > 0) {
        info_start = in;

        if (!(ASN1_get_object(&in, &data_len, &tag, &class, todo))
                || tag != V_ASN1_SEQUENCE) {
            /* we've reached the junk */
            break;
        }

        info_len = (in-info_start) + data_len;

        check(d2i_ASN1_OBJECT(&oid, &in, data_len),
                "Invalid oid");

        in = info_start;

        nid = OBJ_obj2nid(oid);
        if (       nid == NID_id_PACE_DH_GM_3DES_CBC_CBC
                || nid == NID_id_PACE_DH_IM_3DES_CBC_CBC
                || nid == NID_id_PACE_ECDH_GM_3DES_CBC_CBC
                || nid == NID_id_PACE_ECDH_IM_3DES_CBC_CBC
                || nid == NID_id_PACE_DH_GM_AES_CBC_CMAC_128
                || nid == NID_id_PACE_DH_GM_AES_CBC_CMAC_192
                || nid == NID_id_PACE_DH_GM_AES_CBC_CMAC_256
                || nid == NID_id_PACE_DH_IM_AES_CBC_CMAC_128
                || nid == NID_id_PACE_DH_IM_AES_CBC_CMAC_192
                || nid == NID_id_PACE_DH_IM_AES_CBC_CMAC_256
                || nid == NID_id_PACE_ECDH_GM_AES_CBC_CMAC_128
                || nid == NID_id_PACE_ECDH_GM_AES_CBC_CMAC_192
                || nid == NID_id_PACE_ECDH_GM_AES_CBC_CMAC_256
                || nid == NID_id_PACE_ECDH_IM_AES_CBC_CMAC_128
                || nid == NID_id_PACE_ECDH_IM_AES_CBC_CMAC_192
                || nid == NID_id_PACE_ECDH_IM_AES_CBC_CMAC_256) {
            /* PACEInfo */
            check(d2i_PACE_INFO(&tmp_info, &in, info_len),
                    "Could not decode PACE info");

            /* lookup or create a pace context */
            get_ctx_by_keyID(pace_ctx, ctx->pace_ctxs, tmp_info->keyID, PACE_CTX);
            if (!pace_ctx) {
                goto err;
            }

            pace_ctx->version = (unsigned char) ASN1_INTEGER_get(tmp_info->version);
            if (pace_ctx->version <= 0 || pace_ctx->version > 2)
                goto err;

            if (!PACE_CTX_set_protocol(pace_ctx,
                        OBJ_obj2nid(tmp_info->protocol), ctx->tr_version))
                goto err;

        } else if (nid == NID_id_PACE_ECDH_GM
                || nid == NID_id_PACE_ECDH_IM
                || nid == NID_id_PACE_DH_GM
                || nid == NID_id_PACE_DH_IM) {
            /* PACEDomainParameterInfo */
            has_no_pace_dp_info = 0;
            check(d2i_PACE_DP_INFO(&tmp_dp_info, &in, info_len),
                    "Could not decode PACE domain parameter information");

            /* lookup or create a pace context */
            get_ctx_by_keyID(pace_ctx, ctx->pace_ctxs, tmp_dp_info->keyID, PACE_CTX);
            if (!pace_ctx) {
                goto err;
            }

            if (!aid2pkey(&ctx->pace_ctx->static_key, tmp_dp_info->aid, ctx->bn_ctx))
                goto err;

        } else if (nid == NID_id_TA) {
            /* TAInfo */
            check(d2i_TA_INFO(&tmp_ta_info, &in, info_len),
                    "Could not decode TA info");

            ctx->ta_ctx->version = (unsigned char) ASN1_INTEGER_get(tmp_ta_info->version);
            if (ctx->ta_ctx->version <= 0 || ctx->ta_ctx->version > 2)
                goto err;
            /* OID in TAInfo is less specific than the one in the certificate
             * Therefore this OID will be overwritten when we import a certificate
             * later on.*/
            ctx->ta_ctx->protocol = OBJ_obj2nid(tmp_ta_info->protocol);
        } else if (nid == NID_id_CA_DH_3DES_CBC_CBC
                || nid == NID_id_CA_DH_AES_CBC_CMAC_128
                || nid == NID_id_CA_DH_AES_CBC_CMAC_192
                || nid == NID_id_CA_DH_AES_CBC_CMAC_256
                || nid == NID_id_CA_ECDH_3DES_CBC_CBC
                || nid == NID_id_CA_ECDH_AES_CBC_CMAC_128
                || nid == NID_id_CA_ECDH_AES_CBC_CMAC_192
                || nid == NID_id_CA_ECDH_AES_CBC_CMAC_256) {
            /* CAInfo */
            check(d2i_CA_INFO(&tmp_ca_info, &in, info_len),
                    "Could not decode CA info");

            /* lookup or create a ca context */
            get_ctx_by_keyID(ca_ctx, ctx->ca_ctxs, tmp_ca_info->keyID, CA_CTX);
            if (!ca_ctx) {
                goto err;
            }

            ca_ctx->version = (unsigned char) ASN1_INTEGER_get(tmp_ca_info->version);
            if (ca_ctx->version <= 0 || ca_ctx->version > 2
                    || !CA_CTX_set_protocol(ca_ctx, nid))
                goto err;

        } else if (nid == NID_id_CA_DH
                || nid == NID_id_CA_ECDH) {
            /* ChipAuthenticationDomainParameterInfo */
            check(d2i_CA_DP_INFO(&tmp_ca_dp_info, &in, info_len),
                    "Could not decode CA domain parameter info");

            /* lookup or create a ca context */
            get_ctx_by_keyID(ca_ctx, ctx->ca_ctxs, tmp_ca_dp_info->keyID, CA_CTX);
            if (!ca_ctx) {
                goto err;
            }

            if (!aid2pkey(&ca_ctx->ka_ctx->key, tmp_ca_dp_info->aid, ctx->bn_ctx))
                goto err;

        } else if (nid == NID_id_PK_DH
                || nid == NID_id_PK_ECDH) {
            /* ChipAuthenticationPublicKeyInfo */
            check(d2i_CA_PUBLIC_KEY_INFO(&ca_public_key_info, &in, info_len),
                    "Could not decode CA PK domain parameter info");

            /* lookup or create a ca context */
            if (!tmp_ca_info) {
                goto err;
            }
            get_ctx_by_keyID(ca_ctx, ctx->ca_ctxs, tmp_ca_info->keyID, CA_CTX);
            if (!ca_ctx) {
                goto err;
            }

            if (!aid2pkey(&ca_ctx->ka_ctx->key,
                        ca_public_key_info->chipAuthenticationPublicKeyInfo->algorithmIdentifier,
                        ctx->bn_ctx))
                goto err;

            if (nid == NID_id_PK_DH) {
                /* FIXME the public key for DH is actually an ASN.1
                 * UNSIGNED INTEGER, which is an ASN.1 INTEGER that is
                 * always positive. Parsing the unsigned integer should be
                 * done in EVP_PKEY_set_key. */
                const unsigned char *p = ca_public_key_info->chipAuthenticationPublicKeyInfo->subjectPublicKey->data;
                check(d2i_ASN1_UINTEGER(&i, &p,
                            ca_public_key_info->chipAuthenticationPublicKeyInfo->subjectPublicKey->length),
                        "Could not decode CA PK");
                pubkey = i->data;
                pubkey_len = i->length;
            } else {
                pubkey = ca_public_key_info->chipAuthenticationPublicKeyInfo->subjectPublicKey->data;
                pubkey_len = ca_public_key_info->chipAuthenticationPublicKeyInfo->subjectPublicKey->length;
            }

            if (!EVP_PKEY_set_keys(ca_ctx->ka_ctx->key, NULL, 0, pubkey, pubkey_len, ctx->bn_ctx))
                goto err;

        } else if (nid == NID_id_CI) {
            /* ChipIdentifer or cardInfoLocator */
        } else if (nid == NID_id_PT) {
        } else if (nid == NID_id_RI_DH_SHA_1
                || nid == NID_id_RI_DH_SHA_224
                || nid == NID_id_RI_DH_SHA_256
                || nid == NID_id_RI_DH_SHA_384
                || nid == NID_id_RI_DH_SHA_512
                || nid == NID_id_RI_ECDH_SHA_1
                || nid == NID_id_RI_ECDH_SHA_224
                || nid == NID_id_RI_ECDH_SHA_256
                || nid == NID_id_RI_ECDH_SHA_384
                || nid == NID_id_RI_ECDH_SHA_512) {
            /* RestrictedIdentificationInfo */
            check(d2i_RI_INFO(&tmp_ri_info, &in, info_len),
                    "Could not decode RI info");

            /* create a ri context */
            get_ctx_by_keyID(ri_ctx, ctx->ri_ctxs, NULL, RI_CTX);
            if (!ri_ctx) {
                goto err;
            }

            if (!RI_CTX_set_protocol(ri_ctx, nid))
                goto err;

        } else if (nid == NID_id_RI_DH
                || nid == NID_id_RI_ECDH) {
            /* RestrictedIdentificationDomainParameterInfo */
            check(d2i_RI_DP_INFO(&tmp_ri_dp_info, &in, info_len),
                    "Could not decode RI domain parameter info");

            _count = sk_num((_STACK*) ctx->ri_ctxs);
            for (_i = 0; _i < _count; _i++) {
                ri_ctx = sk_value((_STACK*) ctx->ri_ctxs, _i);
                if (!ri_ctx)
                    goto err;
                if (!aid2pkey(&ri_ctx->static_key, tmp_ri_dp_info->aid, ctx->bn_ctx))
                    goto err;
            }

        } else {
            OBJ_obj2txt(obj_txt, sizeof obj_txt, oid, 0);
            debug("Unknown Identifier (%s) for %s", OBJ_nid2sn(nid), obj_txt);
        }

        /* if we have created the first PACE context, use it as default */
        if (!ctx->pace_ctx)
            ctx->pace_ctx = pace_ctx;
        /* if we have created the first CA context, use it as default */
        if (!ctx->ca_ctx)
            ctx->ca_ctx = ca_ctx;
        /* if we have created the first RI context, use it as default */
        if (!ctx->ri_ctx)
            ctx->ri_ctx = ri_ctx;

        todo -= info_len;
        in = info_start+info_len;
    }

    /* although a PACEDomainParameterInfo MUST be present in every version of
     * BSI TR-03110, they are not included in the EAC worked Example. We
     * recognize this error and use the keyID as standardizedDomainParameter */
    if (ctx->pace_ctx && has_no_pace_dp_info) {
        if (!EVP_PKEY_set_std_dp(ctx->pace_ctx->static_key, ctx->pace_ctx->id))
            goto err;
    }

    r = 1;

err:
    if (oid)
        ASN1_OBJECT_free(oid);
    if (tmp_info)
        PACE_INFO_free(tmp_info);
    if (tmp_dp_info)
        PACE_DP_INFO_free(tmp_dp_info);
    if (tmp_ta_info)
        TA_INFO_free(tmp_ta_info);
    if (tmp_ca_info)
        CA_INFO_free(tmp_ca_info);
    if (tmp_ri_info)
        RI_INFO_free(tmp_ri_info);
    if (tmp_ri_dp_info)
        RI_DP_INFO_free(tmp_ri_dp_info);
    if (i)
        ASN1_INTEGER_free(i);
    if (tmp_ca_dp_info)
        CA_DP_INFO_free(tmp_ca_dp_info);
    if (ca_public_key_info)
        CA_PUBLIC_KEY_INFO_free(ca_public_key_info);

    return r;
}

BUF_MEM *
asn1_pubkey(int protocol, EVP_PKEY *key, BN_CTX *bn_ctx, enum eac_tr_version tr_version)
{
    CVC_PUBKEY *eac_pubkey = NULL;
    BUF_MEM *pubkey = NULL;
    int l;

    eac_pubkey = CVC_pkey2pubkey(tr_version == EAC_TR_VERSION_2_01 ? 1 : 0, protocol, key, bn_ctx, NULL);
    if (!eac_pubkey)
        goto err;

    pubkey = BUF_MEM_new();
    if (!pubkey)
        goto err;

    l = i2d_CVC_PUBKEY(eac_pubkey, (unsigned char **) &pubkey->data);
    if (l < 0) {
        BUF_MEM_free(pubkey);
        pubkey = NULL;
        goto err;
    }
    pubkey->length = l;
    pubkey->max = l;

err:
    if (eac_pubkey)
        CVC_PUBKEY_free(eac_pubkey);

    return pubkey;
}
