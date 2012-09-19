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
 * @file eac_asn1.c
 * @brief ASN.1 structures related to PACE
 *
 * @author Frank Morgner <morgner@informatik.hu-berlin.de>
 * @author Dominik Oepen <oepen@informatik.hu-berlin.de>
 */

#include "eac_asn1.h"
#include "eac_dh.h"
#include "eac_err.h"
#include "misc.h"
#include "pace_lib.h"
#include <eac/eac.h>
#include <eac/pace.h>
#include <openssl/asn1.h>
#include <openssl/dh.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/objects.h>

/** PACEInfo structure */
typedef struct pace_info_st {
    /** OID of the algorithm to be used */
    ASN1_OBJECT *protocol;
    /** Protocol Version number. Version number 1 is deprecated, version 2 is
        recommended */
    ASN1_INTEGER *version;
    /** Indicates the domain parameter identifier */
    ASN1_INTEGER *parameterId;
    } PACE_INFO;

/** Algorithm Identifier structure */
typedef struct algorithm_identifier_st {
    /** OID of the algorithm */
    ASN1_OBJECT *algorithm;
    union {
        PACE_ECPARAMETERS *ec;
        DH *dh;
        ASN1_TYPE *other;
    } parameters;
    ASN1_INTEGER *standardizedDomainParameters;
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
        parameters are provided */
    ASN1_INTEGER *parameterId;
} PACE_DP_INFO;

/** ChipAuthenticationInfo structure */
typedef struct ca_info_st {
    /** OID */
    ASN1_OBJECT *protocol;
    /** Protocol Version number. Currently Version 1 and Version 2 are supported */
    ASN1_INTEGER *version;
    /** keyID MAY be used to indicate the local key identifier */
    ASN1_INTEGER *keyId;
} CA_INFO;

/** CA Domain parameter structure */
typedef struct ca_dp_info_st {
    /** OID of the type of domain parameters*/
    ASN1_OBJECT *protocol;
    /** The actual domain parameters */
    ALGORITHM_IDENTIFIER *aid;
    /** Optional: specifies the local domain parameters if multiple sets of domain
        parameters are provided */
    ASN1_INTEGER *keyId;
} CA_DP_INFO;

/** CA public key info */
typedef struct ca_public_key_info_st {
    /** OID of the type of domain parameters*/
    ASN1_OBJECT *protocol;
    /** The actual public key */
    SUBJECT_PUBLIC_KEY_INFO *chipAuthenticationPublicKeyInfo;
    /** Optional: specifies the local domain parameters if multiple sets of domain
        parameters are provided */
    ASN1_INTEGER *keyId;
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
    /** keyId identifies the private key that shall be used */
    ASN1_INTEGER *keyId;
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

static unsigned int
getlen (unsigned const char * in, unsigned int * len_len, const unsigned int max_len);
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

/* I stole this from dh_asn1.c */
ASN1_SEQUENCE_cb(PACE_DHparams, dh_cb) = {
    ASN1_SIMPLE(DH, p, BIGNUM),
    ASN1_SIMPLE(DH, g, BIGNUM),
    ASN1_OPT(DH, length, ZLONG),
} ASN1_SEQUENCE_END_cb(DH, PACE_DHparams)

ASN1_SEQUENCE(PACE_INFO) = {
    ASN1_SIMPLE(PACE_INFO, protocol, ASN1_OBJECT),
    ASN1_SIMPLE(PACE_INFO, version, ASN1_INTEGER),
    ASN1_OPT(PACE_INFO, parameterId, ASN1_INTEGER)
} ASN1_SEQUENCE_END(PACE_INFO)

IMPLEMENT_ASN1_FUNCTIONS(PACE_INFO)

ASN1_ADB_TEMPLATE(aid_def) = ASN1_SIMPLE(ALGORITHM_IDENTIFIER, parameters.other, ASN1_ANY);

ASN1_ADB(ALGORITHM_IDENTIFIER) = {
    ADB_ENTRY(NID_ecka_dh_SessionKDF_AES128, ASN1_SIMPLE(ALGORITHM_IDENTIFIER, parameters.ec, PACE_ECPARAMETERS)),
    ADB_ENTRY(NID_dhpublicnumber, ASN1_SIMPLE(ALGORITHM_IDENTIFIER, parameters.dh, PACE_DHparams)),
    ADB_ENTRY(NID_standardizedDomainParameters, ASN1_SIMPLE(ALGORITHM_IDENTIFIER, standardizedDomainParameters, ASN1_INTEGER))
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
    ASN1_OPT(PACE_DP_INFO, parameterId, ASN1_INTEGER)
} ASN1_SEQUENCE_END(PACE_DP_INFO)

IMPLEMENT_ASN1_FUNCTIONS(PACE_DP_INFO)

/* ChipAuthenticationInfo */
ASN1_SEQUENCE(CA_INFO) = {
    ASN1_SIMPLE(CA_INFO, protocol, ASN1_OBJECT),
    ASN1_SIMPLE(CA_INFO, version, ASN1_INTEGER),
    ASN1_OPT(CA_INFO, keyId, ASN1_INTEGER)
} ASN1_SEQUENCE_END(CA_INFO)
IMPLEMENT_ASN1_FUNCTIONS(CA_INFO)

/* ChipAuthenticationDomainParameterInfo */
ASN1_SEQUENCE(CA_DP_INFO) = {
    ASN1_SIMPLE(CA_DP_INFO, protocol, ASN1_OBJECT),
    ASN1_SIMPLE(CA_DP_INFO, aid, ALGORITHM_IDENTIFIER),
    ASN1_OPT(CA_DP_INFO, keyId, ASN1_INTEGER)
} ASN1_SEQUENCE_END(CA_DP_INFO)
IMPLEMENT_ASN1_FUNCTIONS(CA_DP_INFO)

/* ChipAuthenticationPublicKeyInfo */
ASN1_SEQUENCE(CA_PUBLIC_KEY_INFO) = {
        ASN1_SIMPLE(CA_PUBLIC_KEY_INFO, protocol, ASN1_OBJECT),
        ASN1_SIMPLE(CA_PUBLIC_KEY_INFO, chipAuthenticationPublicKeyInfo, SUBJECT_PUBLIC_KEY_INFO),
        ASN1_OPT(CA_PUBLIC_KEY_INFO, keyId, ASN1_INTEGER)
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
    ASN1_SIMPLE(PROTOCOL_PARAMS, keyId, ASN1_INTEGER),
    ASN1_SIMPLE(PROTOCOL_PARAMS, authorizedOnly, ASN1_BOOLEAN)
} ASN1_SEQUENCE_END(PROTOCOL_PARAMS)

/* RestrictedIdentificationInfo */
ASN1_SEQUENCE(RI_INFO) = {
    ASN1_SIMPLE(RI_INFO, protocol, ASN1_OBJECT),
    ASN1_SIMPLE(RI_INFO, params, PROTOCOL_PARAMS),
    ASN1_OPT(RI_INFO, maxKeyLen, ASN1_INTEGER)
} ASN1_SEQUENCE_END(RI_INFO)

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

    check((key && p && a && b  && base  && base_order  && cofactor),
            "Invalid arguments");

    BN_CTX_start(bn_ctx);
    p_bn = BN_CTX_get(bn_ctx);
    a_bn = BN_CTX_get(bn_ctx);
    b_bn = BN_CTX_get(bn_ctx);
    order_bn = BN_CTX_get(bn_ctx);
    cofactor_bn = BN_CTX_get(bn_ctx);

    if (!cofactor_bn)
        goto err;

    /* Copy field and curve */
    if (!BN_bin2bn(ASN1_STRING_data(p), ASN1_STRING_length(p), p_bn) ||
        !BN_bin2bn(ASN1_STRING_data(a), ASN1_STRING_length(a), a_bn) ||
        !BN_bin2bn(ASN1_STRING_data(b), ASN1_STRING_length(b), b_bn))
            goto err;
    else
        group = EC_GROUP_new_curve_GFp(p_bn, a_bn, b_bn, bn_ctx);

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
            ASN1_STRING_length(base), bn_ctx))
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
                ASN1_STRING_length(pub), bn_ctx))
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
    BN_CTX_end(bn_ctx);

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

/**
 * @brief Decode the length field of an ASN.1 DER encoded buffer
 * @param[in] in pointer to the beginning of the length field of the buffer
 * @param[out] len_len the length of the length field will be stored here
 * @return the decoded length or 0 in case of an error
 */

static unsigned int
getlen (const unsigned char *in, unsigned int *len_len, const unsigned int max_len)
{
    unsigned int len = 0;
    unsigned int i = 0;

    if (!in || !len_len || !max_len)
        return 0;

    if ((in[0] & 0x80) == 0x80 ) { /* MSB set => long form */
        *len_len = (in[0] & 0x7F) + 1;
        if (*len_len > max_len)
            goto err;

            for (i = 0; i < *len_len - 1; i++) {
            len <<= i*8;
            len += in[i+1];
            /* Check if the ASN.1 length encoded length is bigger than our buffer */
            if (len > max_len)
                goto err;
        }
    }
    else {/* MSB not set => short form */
        len = (unsigned int) in[0];
        *len_len = 1;
        /* Check if the ASN.1 length encoded length is bigger than our buffer */
        if (len > max_len)
            goto err;
    }
    return len;

err:
    *len_len = 0;
    return 0;
}

int
EAC_CTX_init_ef_cardaccess(const unsigned char * in, unsigned int in_len,
        EAC_CTX *ctx)
{
    unsigned int len = 0, len_len = 0, oid_len = 0;
    unsigned int todo = 0;
    ASN1_OBJECT *a = NULL;
    unsigned const char *oid_pos = NULL, *seq_pos = NULL;
    int nid, ret = 0;
    PACE_INFO *tmp_info = NULL;
    PACE_DP_INFO *tmp_dp_info = NULL;
    TA_INFO *tmp_ta_info = NULL;
    CA_INFO *tmp_ca_info = NULL;
    CA_DP_INFO *tmp_ca_dp_info = NULL;
    RI_DP_INFO *tmp_ri_dp_info = NULL;
    CA_PUBLIC_KEY_INFO *ca_public_key_info = NULL;
    EC_KEY *tmp_ec = NULL;
    BUF_MEM *pubkey = NULL;

    check((in && ctx  && ctx->pace_ctx && ctx->ca_ctx && ctx->ta_ctx),
        "Invalid arguments");

    check(in[0] == 0x31, "Invalid data"); /* SET */

    len = getlen(++in, &len_len, in_len - 1); /* Length of SET */
    /* Check length of input against ASN.1 encoded length */
    if (in_len < len + len_len + 1) { /* 1 Byte tag + length of the length field + length of data */
        log_err("Invalid data");
        goto err;
    }

    in += len_len;
    todo = len;
    while(todo > 0) { /* Manually extract all members of the SET OF SecurityInfos */
        check(in[0] == 0x30, "Invalid data");/* SEQUENCE */

        seq_pos = in;
        len = getlen(++in, &len_len, todo - 1); /* Length of SEQUENCE */
        oid_pos = in + len_len;
        in += len + len_len;
        todo -= len_len + 1;

        /* Read OID */
        check(oid_pos[0] == 0x06, "Invalid data"); /* OBJECT IDENTIFIER */
        oid_len = getlen(oid_pos+1, &len_len, todo); /* Length of OBJECT IDENTIFIER */
        todo -= len; /* Point todo past the SEQUENCE */

        /* XXX: I don't understand, why we have to increment the last parameter
         *      by two. This was found to work by trial and error. */
        if (d2i_ASN1_OBJECT(&a, &oid_pos, oid_len+2) == NULL)
            goto err;

        nid = OBJ_obj2nid(a);
        switch (nid) {
            /* PACEInfo */
            case NID_id_PACE_DH_GM_3DES_CBC_CBC:
            case NID_id_PACE_DH_IM_3DES_CBC_CBC:
            case NID_id_PACE_ECDH_GM_3DES_CBC_CBC:
            case NID_id_PACE_ECDH_IM_3DES_CBC_CBC:
            case NID_id_PACE_DH_GM_AES_CBC_CMAC_128:
            case NID_id_PACE_DH_GM_AES_CBC_CMAC_192:
            case NID_id_PACE_DH_GM_AES_CBC_CMAC_256:
            case NID_id_PACE_DH_IM_AES_CBC_CMAC_128:
            case NID_id_PACE_DH_IM_AES_CBC_CMAC_192:
            case NID_id_PACE_DH_IM_AES_CBC_CMAC_256:
            case NID_id_PACE_ECDH_GM_AES_CBC_CMAC_128:
            case NID_id_PACE_ECDH_GM_AES_CBC_CMAC_192:
            case NID_id_PACE_ECDH_GM_AES_CBC_CMAC_256:
            case NID_id_PACE_ECDH_IM_AES_CBC_CMAC_128:
            case NID_id_PACE_ECDH_IM_AES_CBC_CMAC_192:
            case NID_id_PACE_ECDH_IM_AES_CBC_CMAC_256:
                tmp_info = d2i_PACE_INFO(NULL, &seq_pos, len+2);
                check(tmp_info, "Could not decode PACE info");

                ctx->pace_ctx->version = ASN1_INTEGER_get(tmp_info->version);
                if (ctx->pace_ctx->version <= 0 || ctx->pace_ctx->version > 2)
                    goto err;

                ctx->pace_ctx->protocol = OBJ_obj2nid(tmp_info->protocol);

                if(tmp_info->parameterId) {
                    /* If we have standardized domain parameters we use them
                     * to generate a static key */
                    if (!EAC_CTX_init_pace(ctx,
                                ctx->pace_ctx->protocol,
                                (int) ASN1_INTEGER_get(tmp_info->parameterId)))
                        goto err;
                } else {
                    /* Otherwise we only use the protocol OID to setup our
                     * PACE context and hope to find a key in the proprietary
                     * PACEDomainParameterInfo */
                    if (!PACE_CTX_set_protocol(ctx->pace_ctx, ctx->pace_ctx->protocol, ctx->tr_version))
                        goto err;
                }
                PACE_INFO_free(tmp_info);
                tmp_info = NULL;
                break;
            /* PACEDomainParameterInfo */
            case NID_id_PACE_ECDH_GM:
            case NID_id_PACE_ECDH_IM:
            case NID_id_PACE_DH_GM:
            case NID_id_PACE_DH_IM:
                tmp_dp_info = d2i_PACE_DP_INFO(NULL, &seq_pos, len+3);
                check(tmp_dp_info, "Could not decode PACE domain parameter information");

                /* If there is no key, allocate memory */
                if (!ctx->pace_ctx->static_key)
                    ctx->pace_ctx->static_key = EVP_PKEY_new();
                if (!ctx->pace_ctx->static_key)
                    goto err;

                /* Extract actual parameters */
                switch (OBJ_obj2nid(tmp_dp_info->aid->algorithm)) {
                    case NID_dhpublicnumber:
                        EVP_PKEY_set1_DH(ctx->pace_ctx->static_key,
                                tmp_dp_info->aid->parameters.dh);
                        break;
                    case NID_X9_62_id_ecPublicKey:
                    case NID_ecka_dh_SessionKDF_DES3:
                    case NID_ecka_dh_SessionKDF_AES128:
                    case NID_ecka_dh_SessionKDF_AES192:
                    case NID_ecka_dh_SessionKDF_AES256:
                        tmp_ec = ec_key_from_PACE_ECPARAMETERS(tmp_dp_info->aid->parameters.ec, ctx->bn_ctx);
                        check(tmp_ec, "Could not decode EC key");

                        EVP_PKEY_set1_EC_KEY(ctx->pace_ctx->static_key,
                                tmp_ec);
                        break;
                    default:
                        log_err("Unknown PACE parameters");
                }
                PACE_DP_INFO_free(tmp_dp_info);
                tmp_dp_info = NULL;
                break;
            /* TAInfo */
            case NID_id_TA:
                tmp_ta_info = d2i_TA_INFO(NULL, &seq_pos, len+2);
                check(tmp_ta_info, "Could not decode TA info");

                ctx->ta_ctx->version = ASN1_INTEGER_get(tmp_ta_info->version);
                if (ctx->ta_ctx->version <= 0 || ctx->ta_ctx->version > 2)
                    goto err;
                /* OID in TAInfo is less specific than the one in the certificate
                 * Therefore this OID will be overwritten when we import a certificate
                 * later on.*/
                ctx->ta_ctx->protocol = OBJ_obj2nid(tmp_ta_info->protocol);
                TA_INFO_free(tmp_ta_info);
                tmp_ta_info = NULL;
                break;
            /* CAINfo */
            case NID_id_CA_DH_3DES_CBC_CBC:
            case NID_id_CA_DH_AES_CBC_CMAC_128 :
            case NID_id_CA_DH_AES_CBC_CMAC_192 :
            case NID_id_CA_DH_AES_CBC_CMAC_256 :
            case NID_id_CA_ECDH_3DES_CBC_CBC :
            case NID_id_CA_ECDH_AES_CBC_CMAC_128 :
            case NID_id_CA_ECDH_AES_CBC_CMAC_192 :
            case NID_id_CA_ECDH_AES_CBC_CMAC_256 :
                tmp_ca_info = d2i_CA_INFO(NULL, &seq_pos, len+2);
                check(tmp_ca_info, "Could not decode CA info");

                ctx->ca_ctx->version = ASN1_INTEGER_get(tmp_ca_info->version);
                if (ctx->ta_ctx->version <= 0 || ctx->ta_ctx->version > 2)
                    goto err;
                ctx->ca_ctx->protocol = OBJ_obj2nid(tmp_ca_info->protocol);
                CA_INFO_free(tmp_ca_info);
                tmp_ca_info = NULL;
                break;
            /* ChipAuthenticationDomainParameterInfo */
            case NID_id_CA_DH:
            case NID_id_CA_ECDH:
                /* HACK: the obscure offset (see line 621) must be 3 and not 2 for
                 * CADomainParameterInfo */
                tmp_ca_dp_info = d2i_CA_DP_INFO(NULL, &seq_pos, len+3);
                check(tmp_ca_dp_info, "Could not decode CA domain parameter info");

                /* TODO: Copy all the public keys into the EAC context.  As of
                 * now EAC_CTX can only hold one CA public key.  We could use
                 * EVP_PKEY_set_std_dp here, but we leave this to
                 * EAC_CTX_init_ca called by the user */

                CA_DP_INFO_free(tmp_ca_dp_info);
                tmp_ca_dp_info = NULL;
                break;
            /* ChipAuthenticationPublicKeyInfo */
            case NID_id_PK_DH:
            case NID_id_PK_ECDH:
                /* HACK: the obscure offset (see line 621) must be 3 and not 2 for
                 * RestrictedIdentificationDomainParameterInfo */
                ca_public_key_info = d2i_CA_PUBLIC_KEY_INFO(NULL, &seq_pos, len+3);
                check(ca_public_key_info, "Could not decode CA PK domain parameter info");

                if (!EVP_PKEY_set_std_dp(ctx->ca_ctx->ka_ctx->key,
                            ASN1_INTEGER_get(ca_public_key_info->chipAuthenticationPublicKeyInfo->algorithmIdentifier->standardizedDomainParameters)))
                    goto err;

                if (nid == NID_id_PK_DH) {
                    /* FIXME the public key for DH is actually an ASN.1
                     * UNSIGNED INTEGER, which is an ASN.1 INTEGER that is
                     * always positive. Parsing the unsigned integer should be
                     * done in EVP_PKEY_set_pubkey. */
                    const unsigned char *p = ca_public_key_info->chipAuthenticationPublicKeyInfo->subjectPublicKey->data;
                    ASN1_INTEGER *i = d2i_ASN1_UINTEGER(NULL, &p,
                            ca_public_key_info->chipAuthenticationPublicKeyInfo->subjectPublicKey->length);
                    pubkey = BUF_MEM_create_init(i->data, i->length);
                    ASN1_INTEGER_free(i);
                } else {
                    pubkey = BUF_MEM_create_init(
                            ca_public_key_info->chipAuthenticationPublicKeyInfo->subjectPublicKey->data,
                            ca_public_key_info->chipAuthenticationPublicKeyInfo->subjectPublicKey->length);
                }

                CA_PUBLIC_KEY_INFO_free(ca_public_key_info);
                ca_public_key_info = NULL;

                if (!EVP_PKEY_set_pubkey(ctx->ca_ctx->ka_ctx->key, pubkey, ctx->bn_ctx))
                    goto err;

                BUF_MEM_free(pubkey);
                pubkey = NULL;
                break;
            /* ChipIdentifer */
            case NID_id_CI:
                break;
            case NID_id_PT:
                break;
            case NID_id_RI_DH_SHA_1:
            case NID_id_RI_DH_SHA_224:
            case NID_id_RI_DH_SHA_256:
            case NID_id_RI_DH_SHA_384:
            case NID_id_RI_DH_SHA_512:
            case NID_id_RI_ECDH_SHA_1:
            case NID_id_RI_ECDH_SHA_224:
            case NID_id_RI_ECDH_SHA_256:
            case NID_id_RI_ECDH_SHA_384:
            case NID_id_RI_ECDH_SHA_512:
                if (!RI_CTX_set_protocol(ctx->ri_ctx, nid))
                    goto err;
                break;
            /* RestrictedIdentificationDomainParameterInfo */
            case NID_id_RI_DH:
            case NID_id_RI_ECDH:
                /* HACK: the obscure offset (see line 621) must be 3 and not 2 for
                /* RestrictedIdentificationDomainParameterInfo */
                tmp_ri_dp_info = d2i_RI_DP_INFO(NULL, &seq_pos, len+3);
                check(tmp_ri_dp_info, "Could not decode RI domain parameter info");

                /* TODO: Copy all the public keys into the EAC context.  As of
                 * now EAC_CTX can only hold one RI public key.  We could use
                 * EVP_PKEY_set_std_dp here, but we leave this to
                 * EAC_CTX_init_ri called by the user */

                RI_DP_INFO_free(tmp_ri_dp_info);
                tmp_ri_dp_info = NULL;
                break;
            default:
                log_err("Unknown parameter: %s", OBJ_nid2sn(nid));
                break;
        }
    }

    ret = 1;

err:
    if (a)
        ASN1_OBJECT_free(a);
    if (tmp_info)
        PACE_INFO_free(tmp_info);
    if (tmp_dp_info)
        PACE_DP_INFO_free(tmp_dp_info);
    if (tmp_ta_info)
        TA_INFO_free(tmp_ta_info);
    if (tmp_ca_info)
        CA_INFO_free(tmp_ca_info);
    if (tmp_ec)
        EC_KEY_free(tmp_ec);
    if (pubkey)
        BUF_MEM_free(pubkey);

    return ret;
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
