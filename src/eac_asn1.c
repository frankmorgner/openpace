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
 */

/**
 * @file eac_asn1.c
 * @brief ASN.1 structures related to PACE
 *
 * @author Dominik Oepen <oepen@informatik.hu-berlin.de>
 * @author Frank Morgner <morgner@informatik.hu-berlin.de>
 */

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
    union {
        DH *dh;
#ifdef HAVE_PATCHED_OPENSSL
        PACE_ECPARAMETERS *ec;
        ASN1_INTEGER *standardizedDomainParameters;
#endif
        ASN1_TYPE *other;
    } parameters;
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

typedef struct dh_pubkey_st {
    /** Object Identifier */
    ASN1_OBJECT *oid;
    /** Prime modulus */
    ASN1_OCTET_STRING *p;
    /** Order of the subgroup */
    ASN1_OCTET_STRING *q;
    /** Generator */
    ASN1_OCTET_STRING *g;
    /** Public value */
    ASN1_OCTET_STRING *y;
} DH_PUBKEY_BODY;
typedef DH_PUBKEY_BODY DH_PUBKEY;

typedef struct ecdh_pubkey_st {
    /** Object Identifier */
    ASN1_OBJECT *oid;
    /** Prime modulus */
    ASN1_OCTET_STRING *p;
    /** First coefficient */
    ASN1_OCTET_STRING *a;
    /** Second coefficient */
    ASN1_OCTET_STRING *b;
    /** Base point
     * Note: This is an Elliptic Curve Point */
    ASN1_OCTET_STRING *G;
    /** Order of the base point */
    ASN1_OCTET_STRING *r;
    /** Public point
     * Note: This is an Elliptic Curve Point */
    ASN1_OCTET_STRING *Y;
    /** Cofactor */
    ASN1_OCTET_STRING *f;
} ECDH_PUBKEY_BODY;
typedef ECDH_PUBKEY_BODY ECDH_PUBKEY;

static int
dh_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it, void *exarg);

/* the OpenSSL ASN.1 definitions */
ASN1_SEQUENCE(PACE_X9_62_PENTANOMIAL) = {
    ASN1_SIMPLE(PACE_X9_62_PENTANOMIAL, k1, LONG),
    ASN1_SIMPLE(PACE_X9_62_PENTANOMIAL, k2, LONG),
    ASN1_SIMPLE(PACE_X9_62_PENTANOMIAL, k3, LONG)
} ASN1_SEQUENCE_END(PACE_X9_62_PENTANOMIAL)

ASN1_ADB_TEMPLATE(char_two_def) = ASN1_SIMPLE(PACE_X9_62_CHARACTERISTIC_TWO, p.other, ASN1_ANY);

ASN1_ADB(PACE_X9_62_CHARACTERISTIC_TWO) = {
    ADB_ENTRY(NID_X9_62_onBasis, ASN1_SIMPLE(PACE_X9_62_CHARACTERISTIC_TWO, p.onBasis, ASN1_NULL)),
    ADB_ENTRY(NID_X9_62_tpBasis, ASN1_SIMPLE(PACE_X9_62_CHARACTERISTIC_TWO, p.tpBasis, ASN1_INTEGER)),
    ADB_ENTRY(NID_X9_62_ppBasis, ASN1_SIMPLE(PACE_X9_62_CHARACTERISTIC_TWO, p.ppBasis, PACE_X9_62_PENTANOMIAL))
} ASN1_ADB_END(PACE_X9_62_CHARACTERISTIC_TWO, 0, type, 0, &char_two_def_tt, NULL);

ASN1_SEQUENCE(PACE_X9_62_CHARACTERISTIC_TWO) = {
    ASN1_SIMPLE(PACE_X9_62_CHARACTERISTIC_TWO, m, LONG),
    ASN1_SIMPLE(PACE_X9_62_CHARACTERISTIC_TWO, type, ASN1_OBJECT),
    ASN1_ADB_OBJECT(PACE_X9_62_CHARACTERISTIC_TWO)
} ASN1_SEQUENCE_END(PACE_X9_62_CHARACTERISTIC_TWO)

ASN1_ADB_TEMPLATE(fieldID_def) = ASN1_SIMPLE(PACE_X9_62_FIELDID, p.other, ASN1_ANY);

ASN1_ADB(PACE_X9_62_FIELDID) = {
    ADB_ENTRY(NID_X9_62_prime_field, ASN1_SIMPLE(PACE_X9_62_FIELDID, p.prime, ASN1_INTEGER)),
    ADB_ENTRY(NID_X9_62_characteristic_two_field, ASN1_SIMPLE(PACE_X9_62_FIELDID, p.char_two, PACE_X9_62_CHARACTERISTIC_TWO))
} ASN1_ADB_END(PACE_X9_62_FIELDID, 0, fieldType, 0, &fieldID_def_tt, NULL);

ASN1_SEQUENCE(PACE_X9_62_FIELDID) = {
    ASN1_SIMPLE(PACE_X9_62_FIELDID, fieldType, ASN1_OBJECT),
    ASN1_ADB_OBJECT(PACE_X9_62_FIELDID)
} ASN1_SEQUENCE_END(PACE_X9_62_FIELDID)

ASN1_SEQUENCE(PACE_X9_62_CURVE) = {
    ASN1_SIMPLE(PACE_X9_62_CURVE, a, ASN1_OCTET_STRING),
    ASN1_SIMPLE(PACE_X9_62_CURVE, b, ASN1_OCTET_STRING),
    ASN1_OPT(PACE_X9_62_CURVE, seed, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(PACE_X9_62_CURVE)

ASN1_SEQUENCE(PACE_ECPARAMETERS) = {
    ASN1_SIMPLE(PACE_ECPARAMETERS, version, ASN1_INTEGER),
    ASN1_SIMPLE(PACE_ECPARAMETERS, fieldID, PACE_X9_62_FIELDID),
    ASN1_SIMPLE(PACE_ECPARAMETERS, curve, PACE_X9_62_CURVE),
    ASN1_SIMPLE(PACE_ECPARAMETERS, base, ASN1_OCTET_STRING),
    ASN1_SIMPLE(PACE_ECPARAMETERS, order, ASN1_INTEGER),
    ASN1_OPT(PACE_ECPARAMETERS, cofactor, ASN1_INTEGER)
} ASN1_SEQUENCE_END(PACE_ECPARAMETERS)
IMPLEMENT_ASN1_FUNCTIONS(PACE_ECPARAMETERS)

/* I stole this from dh_asn1.c */
ASN1_SEQUENCE_cb(PACE_DHparams, dh_cb) = {
    ASN1_SIMPLE(DH, p, BIGNUM),
    ASN1_SIMPLE(DH, g, BIGNUM),
    ASN1_OPT(DH, length, ZLONG),
} ASN1_SEQUENCE_END_cb(DH, PACE_DHparams)

ASN1_SEQUENCE(PACE_INFO) = {
    ASN1_SIMPLE(PACE_INFO, protocol, ASN1_OBJECT),
    ASN1_SIMPLE(PACE_INFO, version, ASN1_INTEGER),
    ASN1_OPT(PACE_INFO, keyID, ASN1_INTEGER)
} ASN1_SEQUENCE_END(PACE_INFO)

IMPLEMENT_ASN1_FUNCTIONS(PACE_INFO)

ASN1_ADB_TEMPLATE(aid_def) = ASN1_SIMPLE(ALGORITHM_IDENTIFIER, parameters.other, ASN1_ANY);

ASN1_ADB(ALGORITHM_IDENTIFIER) = {
    ADB_ENTRY(NID_dhpublicnumber, ASN1_SIMPLE(ALGORITHM_IDENTIFIER, parameters.dh, PACE_DHparams)),
#ifdef HAVE_PATCHED_OPENSSL
    ADB_ENTRY(NID_ecka_dh_SessionKDF_AES128, ASN1_SIMPLE(ALGORITHM_IDENTIFIER, parameters.ec, PACE_ECPARAMETERS)),
    ADB_ENTRY(NID_standardizedDomainParameters, ASN1_SIMPLE(ALGORITHM_IDENTIFIER, parameters.standardizedDomainParameters, ASN1_INTEGER))
#endif
} ASN1_ADB_END(ALGORITHM_IDENTIFIER, 0, algorithm, 0, &aid_def_tt, NULL);

ASN1_SEQUENCE(ALGORITHM_IDENTIFIER) = {
    ASN1_SIMPLE(ALGORITHM_IDENTIFIER, algorithm, ASN1_OBJECT),
    ASN1_ADB_OBJECT(ALGORITHM_IDENTIFIER)
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

ASN1_SEQUENCE(DH_PUBKEY_BODY) = {
    ASN1_SIMPLE(DH_PUBKEY_BODY, oid, ASN1_OBJECT),
    ASN1_IMP_OPT(DH_PUBKEY_BODY, p, ASN1_OCTET_STRING, 1),
    ASN1_IMP_OPT(DH_PUBKEY_BODY, q, ASN1_OCTET_STRING, 2),
    ASN1_IMP_OPT(DH_PUBKEY_BODY, g, ASN1_OCTET_STRING, 3),
    ASN1_IMP(DH_PUBKEY_BODY, y, ASN1_OCTET_STRING, 4),
} ASN1_SEQUENCE_END(DH_PUBKEY_BODY)
IMPLEMENT_ASN1_FUNCTIONS(DH_PUBKEY_BODY)

ASN1_ITEM_TEMPLATE(DH_PUBKEY) =
    ASN1_EX_TEMPLATE_TYPE(
            ASN1_TFLG_IMPTAG|ASN1_TFLG_APPLICATION,
            0x49, DH_PUBKEY, DH_PUBKEY_BODY)
ASN1_ITEM_TEMPLATE_END(DH_PUBKEY)
IMPLEMENT_ASN1_FUNCTIONS(DH_PUBKEY)

ASN1_SEQUENCE(ECDH_PUBKEY_BODY) = {
    ASN1_SIMPLE(ECDH_PUBKEY_BODY, oid, ASN1_OBJECT),
    ASN1_IMP_OPT(ECDH_PUBKEY_BODY, p, ASN1_OCTET_STRING, 1),
    ASN1_IMP_OPT(ECDH_PUBKEY_BODY, a, ASN1_OCTET_STRING, 2),
    ASN1_IMP_OPT(ECDH_PUBKEY_BODY, b, ASN1_OCTET_STRING, 3),
    ASN1_IMP_OPT(ECDH_PUBKEY_BODY, G, ASN1_OCTET_STRING, 4),
    ASN1_IMP_OPT(ECDH_PUBKEY_BODY, r, ASN1_OCTET_STRING, 5),
    ASN1_IMP(ECDH_PUBKEY_BODY, Y, ASN1_OCTET_STRING, 6),
    ASN1_IMP_OPT(ECDH_PUBKEY_BODY, f, ASN1_OCTET_STRING, 7),
} ASN1_SEQUENCE_END(ECDH_PUBKEY_BODY)
IMPLEMENT_ASN1_FUNCTIONS(ECDH_PUBKEY_BODY)

ASN1_ITEM_TEMPLATE(ECDH_PUBKEY) =
    ASN1_EX_TEMPLATE_TYPE(
            ASN1_TFLG_IMPTAG|ASN1_TFLG_APPLICATION,
            0x49, ECDH_PUBKEY, ECDH_PUBKEY_BODY)
ASN1_ITEM_TEMPLATE_END(ECDH_PUBKEY)
IMPLEMENT_ASN1_FUNCTIONS(ECDH_PUBKEY)

static int
dh_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it, void *exarg)
{
    if(operation == ASN1_OP_NEW_PRE) {
        *pval = (ASN1_VALUE *)DH_new();
        if(*pval) return 2;
        return 0;
    } else if(operation == ASN1_OP_FREE_PRE) {
        DH_free((DH *)*pval);
        *pval = NULL;
        return 2;
    }
    return 1;
}


int
EAC_ec_key_from_asn1(EC_KEY **key, ASN1_OCTET_STRING *p, ASN1_OCTET_STRING *a,
        ASN1_OCTET_STRING *b, ASN1_OCTET_STRING *base, ASN1_OCTET_STRING *base_order,
        ASN1_OCTET_STRING *pub, ASN1_OCTET_STRING *cofactor, BN_CTX *bn_ctx)
{
    int ret = 0;
    BIGNUM *p_bn = NULL, *cofactor_bn = NULL, *order_bn = NULL, *a_bn = NULL,
            *b_bn = NULL;
    EC_GROUP *group = NULL;
    EC_POINT *generator = NULL, *pub_point = NULL;
    EC_KEY *tmp = NULL;
    BN_CTX *lcl_bn_ctx = NULL;

    check((key && p && a && b  && base  && base_order  && cofactor),
            "Invalid arguments");

    if (bn_ctx)
        lcl_bn_ctx = bn_ctx;
    else {
        lcl_bn_ctx = BN_CTX_new();
        check(lcl_bn_ctx, "Failed to create BN context");
    }

    BN_CTX_start(lcl_bn_ctx);
    p_bn = BN_CTX_get(lcl_bn_ctx);
    a_bn = BN_CTX_get(lcl_bn_ctx);
    b_bn = BN_CTX_get(lcl_bn_ctx);
    order_bn = BN_CTX_get(lcl_bn_ctx);
    cofactor_bn = BN_CTX_get(lcl_bn_ctx);

    if (!cofactor_bn)
        goto err;

    /* Copy field and curve */
    if (!BN_bin2bn(ASN1_STRING_data(p), ASN1_STRING_length(p), p_bn) ||
        !BN_bin2bn(ASN1_STRING_data(a), ASN1_STRING_length(a), a_bn) ||
        !BN_bin2bn(ASN1_STRING_data(b), ASN1_STRING_length(b), b_bn))
            goto err;
    else
        group = EC_GROUP_new_curve_GFp(p_bn, a_bn, b_bn, lcl_bn_ctx);

    if (!group)
        goto err;

    /* Set generator, order and cofactor */
    if (!ASN1_INTEGER_to_BN(cofactor, cofactor_bn) ||
        !ASN1_INTEGER_to_BN(base_order, order_bn))
            goto err;

    generator = EC_POINT_new(group);
    if (!generator)
        goto err;

    if (!EC_POINT_oct2point(group, generator, ASN1_STRING_data(base),
            ASN1_STRING_length(base), lcl_bn_ctx))
        goto err;

    if (!EC_GROUP_set_generator(group, generator, order_bn, cofactor_bn))
        goto err;

    if (!*key) {
        tmp = EC_KEY_new();
        if(!tmp)
            goto err;
    } else
        tmp = *key;

    /* Set the group for the key*/
    if(!EC_KEY_set_group(tmp, group))
        goto err;

    /* Set the public point if available */
    if (pub) {
        pub_point = EC_POINT_new(group);
        if (!pub_point)
            goto err;

        if (!EC_POINT_oct2point(group, pub_point, ASN1_STRING_data(pub),
                ASN1_STRING_length(pub), lcl_bn_ctx))
            goto err;

        if (!EC_KEY_set_public_key(tmp, pub_point))
            goto err;
    }

    if (!*key)
        *key = tmp;

    ret = 1;

err:
    if (!ret && tmp && key && !*key)
        EC_KEY_free(tmp);
    if (group)
        EC_GROUP_clear_free(group);
    if (generator)
        EC_POINT_clear_free(generator);
    if (pub_point)
        EC_POINT_clear_free(pub_point);
    if (lcl_bn_ctx)
        BN_CTX_end(lcl_bn_ctx);
    if (!bn_ctx && lcl_bn_ctx) {
        BN_CTX_free(lcl_bn_ctx);
    }

    return ret;
}

static EC_KEY *
ec_key_from_PACE_ECPARAMETERS(const PACE_ECPARAMETERS *ec_params, BN_CTX *bn_ctx)
{
    EC_KEY *ec = NULL;

    check((ec_params && ec_params->fieldID  && ec_params->curve), "Invalid arguments");

    ec = EC_KEY_new();
    if (!ec)
        goto err;

    if (!EAC_ec_key_from_asn1(&ec, ec_params->fieldID->p.prime, ec_params->curve->a,
            ec_params->curve->b, ec_params->base, ec_params->order, NULL,
            ec_params->cofactor, bn_ctx))
            goto err;

    return ec;

err:
    if (ec)
        EC_KEY_free(ec);
    return NULL;
}

static EVP_PKEY *
aid2evp_pkey(EVP_PKEY **key, ALGORITHM_IDENTIFIER *aid, BN_CTX *bn_ctx)
{
    ASN1_INTEGER *i;
    EC_KEY *tmp_ec = NULL;
    EVP_PKEY *tmp_key = NULL, *ret = NULL;
    char obj_txt[32];
    int nid;
    PACE_ECPARAMETERS *ec = NULL;

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
        EVP_PKEY_set1_DH(tmp_key, aid->parameters.dh);

    } else if (nid == NID_X9_62_id_ecPublicKey
            || nid == NID_ecka_dh_SessionKDF_DES3
            || nid == NID_ecka_dh_SessionKDF_AES128
            || nid == NID_ecka_dh_SessionKDF_AES192
            || nid == NID_ecka_dh_SessionKDF_AES256) {
#ifndef HAVE_PATCHED_OPENSSL
        const unsigned char *p;
        p = aid->parameters.other->value.sequence->data;
        check(aid->parameters.other->type == V_ASN1_SEQUENCE
                && d2i_PACE_ECPARAMETERS(&ec, &p,
                    aid->parameters.other->value.sequence->length),
                "Invalid data");
#else
        ec = aid->parameters.ec;
#endif
        tmp_ec = ec_key_from_PACE_ECPARAMETERS(ec, bn_ctx);
        check(tmp_ec, "Could not decode EC key");

        EVP_PKEY_set1_EC_KEY(tmp_key, tmp_ec);

    } else if (nid == NID_standardizedDomainParameters) {
#ifndef HAVE_PATCHED_OPENSSL
        check(aid->parameters.other->type == V_ASN1_INTEGER,
                "Invalid data");
        i = aid->parameters.other->value.integer;
#else
        i = aid->parameters.standardizedDomainParameters;
#endif
        if (!EVP_PKEY_set_std_dp(tmp_key, ASN1_INTEGER_get(i)))
            goto err;

    } else {
        OBJ_obj2txt(obj_txt, sizeof obj_txt, aid->algorithm, 0);
        log_err("Unknown Identifier (%s) for %s",
                OBJ_nid2sn(nid),
                obj_txt);
    }

    ret = tmp_key;

err:
    if (tmp_ec)
        EC_KEY_free(tmp_ec);
#ifndef HAVE_PATCHED_OPENSSL
    if (ec)
        PACE_ECPARAMETERS_free(ec);
#endif

    if (ret) {
        /* success */
        if (key)
            *key = tmp_key;
    } else {
        /* error */
        if (tmp_key && !key && !*key)
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

            pace_ctx->version = ASN1_INTEGER_get(tmp_info->version);
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

            if (!aid2evp_pkey(&ctx->pace_ctx->static_key, tmp_dp_info->aid, ctx->bn_ctx))
                goto err;

        } else if (nid == NID_id_TA) {
            /* TAInfo */
            check(d2i_TA_INFO(&tmp_ta_info, &in, info_len),
                    "Could not decode TA info");

            ctx->ta_ctx->version = ASN1_INTEGER_get(tmp_ta_info->version);
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

            ca_ctx->version = ASN1_INTEGER_get(tmp_ca_info->version);
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

            if (!aid2evp_pkey(&ca_ctx->ka_ctx->key, tmp_ca_dp_info->aid, ctx->bn_ctx))
                goto err;

        } else if (nid == NID_id_PK_DH
                || nid == NID_id_PK_ECDH) {
            /* ChipAuthenticationPublicKeyInfo */
            check(d2i_CA_PUBLIC_KEY_INFO(&ca_public_key_info, &in, info_len),
                    "Could not decode CA PK domain parameter info");

            /* lookup or create a ca context */
            get_ctx_by_keyID(ca_ctx, ctx->ca_ctxs, tmp_ca_info->keyID, CA_CTX);
            if (!ca_ctx) {
                goto err;
            }

            if (!aid2evp_pkey(&ca_ctx->ka_ctx->key,
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
            /* ChipIdentifer */
        } else if (nid == NID_cardInfoLocator) {
            /* cardInfoLocator */
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

            /* lookup or create a ri context */
            get_ctx_by_keyID(ri_ctx, ctx->ri_ctxs, tmp_ri_info->params->keyID, RI_CTX);
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
                if (!aid2evp_pkey(&ri_ctx->static_key, tmp_ri_dp_info->aid, ctx->bn_ctx))
                    goto err;
            }

        } else {
            OBJ_obj2txt(obj_txt, sizeof obj_txt, oid, 0);
            log_err("Unknown Identifier (%s) for %s", OBJ_nid2sn(nid),
                    obj_txt);
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

static ASN1_OCTET_STRING *
BN_to_ASN1_UNSIGNED_INTEGER(const BIGNUM *bn, ASN1_OCTET_STRING *in)
{
    BUF_MEM *bn_buf = NULL;
    ASN1_OCTET_STRING *out;

    if (!in) {
        out = ASN1_OCTET_STRING_new();
    } else {
        out = in;
    }

    bn_buf = BN_bn2buf(bn);

    if (!bn_buf || !out
            /* BIGNUMs converted to binary don't have a sign,
             * so we copy everything to the octet string */
            || !M_ASN1_OCTET_STRING_set(out, bn_buf->data, bn_buf->length))
        goto err;

    BUF_MEM_free(bn_buf);

    return out;

err:
    if (bn_buf)
        BUF_MEM_free(bn_buf);
    if (out && !in)
        ASN1_OCTET_STRING_free(out);

    return NULL;
}

BUF_MEM *
asn1_pubkey(int protocol, EVP_PKEY *key, BN_CTX *bn_ctx, enum eac_tr_version tr_version)
{
    EC_KEY *ec = NULL;
    ECDH_PUBKEY *ecdhpub = NULL;
    DH *dh = NULL;
    DH_PUBKEY *dhpub = NULL;
    BIGNUM *bn = NULL, *a_bn = NULL, *b_bn = NULL;
    const EC_GROUP *group;
    BUF_MEM *pubkey = NULL, *Y_buf = NULL, *G_buf = NULL;
    int l;

    BN_CTX_start(bn_ctx);

    check(key, "Invalid arguments");

    pubkey = BUF_MEM_new();
    if (!pubkey)
        goto err;

    switch (EVP_PKEY_type(key->type)) {
        case EVP_PKEY_DH:
            dh = EVP_PKEY_get1_DH(key);
            if (!dh)
                goto err;

            dhpub = DH_PUBKEY_new();
            if (!dhpub) {
                goto err;
            }

            /* Object Identifier */
            dhpub->oid = OBJ_nid2obj(protocol);

            /* Public value */
            dhpub->y = BN_to_ASN1_UNSIGNED_INTEGER(dh->pub_key, dhpub->y);

            if (!dhpub->oid || !dhpub->y)
                goto err;

            if (tr_version == EAC_TR_VERSION_2_01) {
                /* Prime modulus */
                dhpub->p = BN_to_ASN1_UNSIGNED_INTEGER(dh->p, dhpub->p);

                /* Order of the subgroup */
                bn = DH_get_order(dh, bn_ctx);
                if (!bn)
                    goto err;
                dhpub->q = BN_to_ASN1_UNSIGNED_INTEGER(bn, dhpub->q);

                /* Generator */
                dhpub->g = BN_to_ASN1_UNSIGNED_INTEGER(dh->g, dhpub->g);

                if (!dhpub->p|| !dhpub->q || !dhpub->g)
                    goto err;

                BN_clear_free(bn);
            }

            l = i2d_DH_PUBKEY(dhpub, (unsigned char **) &pubkey->data);
            if (l < 0)
                goto err;
            pubkey->length = l;
            pubkey->max = l;

            DH_PUBKEY_free(dhpub);

            break;

        case EVP_PKEY_EC:
            ec = EVP_PKEY_get1_EC_KEY(key);
            if (!ec)
                goto err;
            group = EC_KEY_get0_group(ec);

            ecdhpub = ECDH_PUBKEY_new();
            if (!ecdhpub) {
                goto err;
            }

            /* Object Identifier */
            ecdhpub->oid = OBJ_nid2obj(protocol);
            if (!ecdhpub->oid)
                goto err;

            /* Public point */
            Y_buf = EC_POINT_point2buf(ec, bn_ctx, EC_KEY_get0_public_key(
                        ec));

            if (!Y_buf || !M_ASN1_OCTET_STRING_set(ecdhpub->Y, Y_buf->data,
                        Y_buf->length))
                goto err;

            if (tr_version == EAC_TR_VERSION_2_01) {
                bn = BN_CTX_get(bn_ctx);
                a_bn = BN_CTX_get(bn_ctx);
                b_bn = BN_CTX_get(bn_ctx);
                if (!b_bn
                        || !EC_GROUP_get_curve_GFp(group, bn, a_bn, b_bn, bn_ctx))
                    goto err;

                /* Prime modulus */
                ecdhpub->p = BN_to_ASN1_UNSIGNED_INTEGER(bn, ecdhpub->p);

                /* First coefficient */
                ecdhpub->a = BN_to_ASN1_UNSIGNED_INTEGER(a_bn, ecdhpub->a);

                /* Second coefficient */
                ecdhpub->b = BN_to_ASN1_UNSIGNED_INTEGER(b_bn, ecdhpub->b);

                /* Base Point */
                G_buf = EC_POINT_point2buf(ec, bn_ctx,
                        EC_GROUP_get0_generator(group));
                ecdhpub->G = ASN1_OCTET_STRING_new();
                if (!ecdhpub->G
                        || !M_ASN1_OCTET_STRING_set(
                            ecdhpub->G, G_buf->data, G_buf->length))
                    goto err;

                /* Order of the base point */
                if (!EC_GROUP_get_order(group, bn, bn_ctx))
                    goto err;
                ecdhpub->r = BN_to_ASN1_UNSIGNED_INTEGER(bn, ecdhpub->r);

                /* Cofactor */
                if (!EC_GROUP_get_cofactor(group, bn, bn_ctx))
                    goto err;
                ecdhpub->f = BN_to_ASN1_UNSIGNED_INTEGER(bn, ecdhpub->f);

                if (!ecdhpub->p || !ecdhpub->a || !ecdhpub->b || !ecdhpub->r ||
                        !ecdhpub->f)
                    goto err;

                BUF_MEM_free(G_buf);
            }

            BUF_MEM_free(Y_buf);

            l = i2d_ECDH_PUBKEY(ecdhpub, (unsigned char **) &pubkey->data);
            if (l < 0)
                goto err;
            pubkey->length = l;
            pubkey->max = l;

            ECDH_PUBKEY_free(ecdhpub);

            break;

        default:
            goto err;
    }

    /* Decrease reference count, keys are still available in EVP_PKEY structure */
    if (dh)
        DH_free(dh);
    if (ec)
        EC_KEY_free(ec);
    BN_CTX_end(bn_ctx);

    return pubkey;

err:
    BN_CTX_end(bn_ctx);
    if (Y_buf)
        BUF_MEM_free(Y_buf);
    if (G_buf)
        BUF_MEM_free(G_buf);
    if (pubkey)
        BUF_MEM_free(pubkey);
    if (ecdhpub)
        ECDH_PUBKEY_free(ecdhpub);
    if (dhpub)
        DH_PUBKEY_free(dhpub);
    /* Decrease reference count, keys are still available in EVP_PKEY structure */
    if (dh)
        DH_free(dh);
    if (ec)
        EC_KEY_free(ec);

    return NULL;
}
