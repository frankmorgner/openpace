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
 * @file
 * @brief Library for card verifiable certificates
 *
 * @author Dominik Oepen <oepen@informatik.hu-berlin.de>
 * @author Frank Morgner <morgner@informatik.hu-berlin.de>
 */

#include "eac_asn1.h"
#include "eac_err.h"
#include "eac_util.h"
#include "misc.h"
#include <eac/cv_cert.h>
#include <eac/eac.h>
#include <openssl/asn1t.h>
#include <openssl/buffer.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/rsa.h>
#include <openssl/stack.h>
#include <string.h>

/** Check whether or not  a specific bit is set */
#define CHECK_BIT(var,pos) ((var) & (1<<(pos)))

/* Number of bits and bytes of the relative authorization field in the CHAT.
 * See TR-03110 pp. 85 */
#define EAC_AT_CHAT_BYTES 5
#define EAC_AT_CHAT_BITS 38
#define EAC_IS_CHAT_BYTES 1
#define EAC_IS_CHAT_BITS 6
#define EAC_ST_CHAT_BYTES 1
#define EAC_ST_CHAT_BITS 6

/** Human readable names of the individual bits of the CHAT of an
    authentication terminal*/
static const char *at_chat_strings[] = {
        "Age Verification",
        "Community ID Verification",
        "Restricted Identification",
        "Privileged Terminal",
        "CAN allowed",
        "PIN Management",
        "Install Certificate",
        "Install Qualified Certificate",
        "Read DG 1 (Document Type)",
        "Read DG 2 (Issuing State)",
        "Read DG 3 (Date of Expiry)",
        "Read DG 4 (Given Names)",
        "Read DG 5 (Family Names)",
        "Read DG 6 (Religious/Artistic Name)",
        "Read DG 7 (Academic Title)",
        "Read DG 8 (Date of Birth)",
        "Read DG 9 (Place of Birth)",
        "Read DG 10 (Nationality)",
        "Read DG 11 (Sex)",
        "Read DG 12 (OptionalDataR)",
        "Read DG 13",
        "Read DG 14",
        "Read DG 15",
        "Read DG 16",
        "Read DG 17 (Normal Place of Residence)",
        "Read DG 18 (Community ID)",
        "Read DG 19 (Residence Permit I)",
        "Read DG 20 (Residence Permit II)",
        "Read DG 21 (OptionalDataRW)",
        "RFU",
        "RFU",
        "RFU",
        "RFU",
        "Write DG 21 (OptionalDataRW)",
        "Write DG 20 (Residence Permit I)",
        "Write DG 19 (Residence Permit II)",
        "Write DG 18 (Community ID)",
        "Write DG 17 (Normal Place of Residence)"
};

/** Human readable names of the individual bits of the CHAT of an
    inspection system */
static const char *is_chat_strings[] = {
        "Read fingerprint",
        "Read iris",
        "RFU",
        "RFU",
        "RFU",
        "Read eID application"
};

/** Human readable names of the individual bits of the CHAT of a
    signature terminal */
static const char *st_chat_strings[] = {
        "Generate electronic signature",
        "Generate qualified electronic signature",
        "RFU",
        "RFU",
        "RFU",
        "RFU"
};

/** Human readable names of the individual members of a certificate description */
static const char *cert_desc_field_strings[] = {
    "issuerName",
    "issuerURL",
    "subjectName",
    "subjectURL",
    "redirectURL",
    "termsOfUsage",
    "commCertificates",
};

/**
 * @defgroup CVC_CERT_ASN1     ASN1 structures for Card Verifiable Certificates
 * @{ ************************************************************************/

ASN1_SEQUENCE(CVC_CHAT_SEQ) = {
        ASN1_SIMPLE(CVC_CHAT_SEQ, terminal_type, ASN1_OBJECT),
        /* tag: 0x53*/
        ASN1_APP_IMP(CVC_CHAT_SEQ, relative_authorization, ASN1_OCTET_STRING, 0x13) /* discretionary data */
} ASN1_SEQUENCE_END(CVC_CHAT_SEQ)
/* Change the tag of the CHAT to 0x7f4c */
ASN1_ITEM_TEMPLATE(CVC_CHAT) =
        ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_IMPTAG|ASN1_TFLG_APPLICATION, 0x4c, CVC_CHAT, CVC_CHAT_SEQ)
ASN1_ITEM_TEMPLATE_END(CVC_CHAT)
IMPLEMENT_ASN1_FUNCTIONS(CVC_CHAT)
IMPLEMENT_ASN1_PRINT_FUNCTION(CVC_CHAT)

/* Actually we would need two types of public keys: one for ECDSA and one for
 * RSA. Since I did not find a suitable solution using the OpenSSL ASN.1 macros,
 * I used an ugly hack. The same type is used for both kind of keys. The optional
 * members modulus and a can are used to hold the modulus and the public exponent
 * in the RSA case. In this case these members actually are not optional, so we
 * need additional sanity checks in the corresponding d2i functions */
ASN1_SEQUENCE(CVC_PUBKEY) = {
    ASN1_SIMPLE(CVC_PUBKEY, oid, ASN1_OBJECT),
    /* tag: 0x81 */
    ASN1_IMP_OPT(CVC_PUBKEY, modulus, ASN1_OCTET_STRING, 0x1),
    /* tag: 0x82 */
    ASN1_IMP_OPT(CVC_PUBKEY, a, ASN1_OCTET_STRING, 0x2),
    /* tag: 0x83 */
    ASN1_IMP_OPT(CVC_PUBKEY, b, ASN1_OCTET_STRING, 0x3),
    /* tag: 0x84 */
    ASN1_IMP_OPT(CVC_PUBKEY, base, ASN1_OCTET_STRING, 0x4),
    /* tag: 0x85 */
    ASN1_IMP_OPT(CVC_PUBKEY, base_order, ASN1_OCTET_STRING, 0x5),
    /* tag: 0x86 */
    ASN1_IMP_OPT(CVC_PUBKEY, public_point, ASN1_OCTET_STRING, 0x6),
    /* tag: 0x87 */
    ASN1_IMP_OPT(CVC_PUBKEY, cofactor, ASN1_OCTET_STRING, 0x7)
} ASN1_SEQUENCE_END(CVC_PUBKEY)
IMPLEMENT_ASN1_FUNCTIONS(CVC_PUBKEY)
IMPLEMENT_ASN1_PRINT_FUNCTION(CVC_PUBKEY)

ASN1_SEQUENCE(CVC_DISCRETIONARY_DATA_TEMPLATE_SEQ) = {
    ASN1_SIMPLE(CVC_DISCRETIONARY_DATA_TEMPLATE_SEQ, type, ASN1_OBJECT),
    /* tag: 0x80 */
    ASN1_IMP_OPT(CVC_DISCRETIONARY_DATA_TEMPLATE_SEQ, discretionary_data1, ASN1_OCTET_STRING, 0),
    /* tag: 0x81 */
    ASN1_IMP_OPT(CVC_DISCRETIONARY_DATA_TEMPLATE_SEQ, discretionary_data2, ASN1_OCTET_STRING, 1),
    /* tag: 0x53*/
    ASN1_APP_IMP_OPT(CVC_DISCRETIONARY_DATA_TEMPLATE_SEQ, discretionary_data3, ASN1_OCTET_STRING, 19),
} ASN1_SEQUENCE_END(CVC_DISCRETIONARY_DATA_TEMPLATE_SEQ)
/* Change the tag of the CVC_DISCRETIONARY_DATA_TEMPLATE to 0x73 */
ASN1_ITEM_TEMPLATE(CVC_DISCRETIONARY_DATA_TEMPLATE) =
        ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_IMPTAG|ASN1_TFLG_APPLICATION, 0x13, CVC_DISCRETIONARY_DATA_TEMPLATE, CVC_DISCRETIONARY_DATA_TEMPLATE_SEQ)
ASN1_ITEM_TEMPLATE_END(CVC_DISCRETIONARY_DATA_TEMPLATE)
IMPLEMENT_ASN1_FUNCTIONS(CVC_DISCRETIONARY_DATA_TEMPLATE)

ASN1_SEQUENCE(CVC_CERT_BODY_SEQ) = {
        /* tag: 0x5f29 */
        ASN1_APP_IMP(CVC_CERT_BODY_SEQ, certificate_profile_identifier, ASN1_INTEGER, 0x29),
        /* tag: 0x42 */
        ASN1_APP_IMP(CVC_CERT_BODY_SEQ, certificate_authority_reference, ASN1_OCTET_STRING, 0x2),
        /* public key: tag:0x7f49 */
        ASN1_APP_IMP(CVC_CERT_BODY_SEQ, public_key, CVC_PUBKEY, 0x49),
        /* tag: 0x5f20 */
        ASN1_APP_IMP(CVC_CERT_BODY_SEQ, certificate_holder_reference, ASN1_OCTET_STRING, 0x20),
        /* tag: 0x7f4c */
        ASN1_SIMPLE(CVC_CERT_BODY_SEQ, chat, CVC_CHAT),
        /* tag: 0x5f25 */
        ASN1_APP_IMP(CVC_CERT_BODY_SEQ, certificate_effective_date, ASN1_OCTET_STRING, 0x25),
        /* tag: 0x5f24 */
        ASN1_APP_IMP(CVC_CERT_BODY_SEQ, certificate_expiration_date, ASN1_OCTET_STRING, 0x24),
        /* tag: 0x65 */
        ASN1_APP_IMP_SEQUENCE_OF_OPT(CVC_CERT_BODY_SEQ, certificate_extensions, CVC_DISCRETIONARY_DATA_TEMPLATE, 0x05),
} ASN1_SEQUENCE_END(CVC_CERT_BODY_SEQ)
/* Change the tag of the Certificate Body to 0x7f4e */
ASN1_ITEM_TEMPLATE(CVC_CERT_BODY) =
        ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_IMPTAG|ASN1_TFLG_APPLICATION, 0x4e, CVC_CERT_BODY, CVC_CERT_BODY_SEQ)
ASN1_ITEM_TEMPLATE_END(CVC_CERT_BODY)
DECLARE_ASN1_FUNCTIONS(CVC_CERT_BODY)
IMPLEMENT_ASN1_FUNCTIONS(CVC_CERT_BODY)

ASN1_SEQUENCE(CVC_CERT_SEQ) = {
        /* tag: 0x7F4E */
        ASN1_SIMPLE(CVC_CERT_SEQ, body, CVC_CERT_BODY),
        /* tag: 0x5F37 */
        ASN1_APP_IMP(CVC_CERT_SEQ, signature, ASN1_OCTET_STRING, 0x37),
} ASN1_SEQUENCE_END(CVC_CERT_SEQ)

/* Change the tag of the CV Cert to 0x7f21 */
ASN1_ITEM_TEMPLATE(CVC_CERT) =
        ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_IMPTAG|ASN1_TFLG_APPLICATION, 0x21, CVC_CERT, CVC_CERT_SEQ)
ASN1_ITEM_TEMPLATE_END(CVC_CERT)
IMPLEMENT_ASN1_FUNCTIONS(CVC_CERT)
IMPLEMENT_ASN1_PRINT_FUNCTION(CVC_CERT)
/*IMPLEMENT_ASN1_PRINT_FUNCTION(CVC_CHAT)*/

ASN1_ADB_TEMPLATE(cert_def) = ASN1_SIMPLE(CVC_CERTIFICATE_DESCRIPTION, termsOfUsage.other, ASN1_ANY);

ASN1_ADB(CVC_CERTIFICATE_DESCRIPTION) = {
#ifdef HAVE_PATCHED_OPENSSL
        ADB_ENTRY(NID_id_plainFormat, ASN1_IMP(CVC_CERTIFICATE_DESCRIPTION, termsOfUsage.plainTerms, ASN1_UTF8STRING, 0x05)),
        ADB_ENTRY(NID_id_htmlFormat, ASN1_IMP(CVC_CERTIFICATE_DESCRIPTION, termsOfUsage.htmlTerms, ASN1_IA5STRING, 0x05)),
        ADB_ENTRY(NID_id_pdfFormat, ASN1_IMP(CVC_CERTIFICATE_DESCRIPTION, termsOfUsage.pdfTerms, ASN1_OCTET_STRING, 0x05))
#endif
} ASN1_ADB_END(CVC_CERTIFICATE_DESCRIPTION, 0, descriptionType, 0, &cert_def_tt, NULL);

ASN1_SEQUENCE(CVC_COMMCERT_SEQ) = {
        ASN1_SET_OF(CVC_COMMCERT_SEQ, values, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(CVC_COMMCERT_SEQ)
ASN1_SEQUENCE(CVC_CERTIFICATE_DESCRIPTION) = {
        ASN1_SIMPLE(CVC_CERTIFICATE_DESCRIPTION, descriptionType, ASN1_OBJECT),
        ASN1_IMP(CVC_CERTIFICATE_DESCRIPTION, issuerName, ASN1_UTF8STRING, 0x01),
        ASN1_IMP_OPT(CVC_CERTIFICATE_DESCRIPTION, issuerURL, ASN1_PRINTABLESTRING, 0x02),
        ASN1_IMP(CVC_CERTIFICATE_DESCRIPTION, subjectName, ASN1_UTF8STRING, 0x03),
        ASN1_IMP_OPT(CVC_CERTIFICATE_DESCRIPTION, subjectURL, ASN1_PRINTABLESTRING, 0x04),
        ASN1_ADB_OBJECT(CVC_CERTIFICATE_DESCRIPTION),
        ASN1_IMP_OPT(CVC_CERTIFICATE_DESCRIPTION, redirectURL, ASN1_PRINTABLESTRING, 0x06),
        ASN1_IMP_OPT(CVC_CERTIFICATE_DESCRIPTION, commCertificates, CVC_COMMCERT_SEQ, 0x07),
} ASN1_SEQUENCE_END(CVC_CERTIFICATE_DESCRIPTION)
IMPLEMENT_ASN1_FUNCTIONS(CVC_CERTIFICATE_DESCRIPTION)
IMPLEMENT_ASN1_PRINT_FUNCTION(CVC_CERTIFICATE_DESCRIPTION)
/** @} ***********************************************************************/

/** Check and convert the CAR or CHR to a human readable string */
static char *
cvc_get_reference_string(ASN1_OCTET_STRING *ref);
/**
 *  @brief Convert the effective date of a certificate to a string
 *
 *  @param[in] cert The certificate
 *
 *  @return Null terminated string representation of the date or NULL in case
 * of an error
 */
char *
cvc_get_date_string(ASN1_OCTET_STRING *date);
/**
 * @brief Extract the rsa public key from a CV certificate
 * @param cert CV certificate
 * @return the rsa public key or NULL in case of an error
 */
static RSA *
CVC_get_rsa_pubkey(const CVC_CERT *cert);
/**
 * @brief Extract the ECC public key from a CV certificate
 * @param cert CV certificate
 * @param domainParameters used in case of a DV or terminal certificate
 * @return the ECC public key or NULL in case of an error
 */
static EC_KEY *
CVC_get_ec_pubkey(EVP_PKEY *domainParameters, const CVC_CERT *cert, BN_CTX *bn_ctx);

CVC_CERT *d2i_CVC_CERT_bio(BIO *bp, CVC_CERT **cvc)
{
    return ASN1_item_d2i_bio(ASN1_ITEM_rptr(CVC_CERT), bp, cvc);
}

CVC_CERT *
CVC_d2i_CVC_CERT(CVC_CERT **cert, const unsigned char **in, long len)
{
    CVC_CERT *ret = NULL;
    int nid;

    ret = d2i_CVC_CERT(cert, in, len);
    if (!ret)
        goto err;

    /* Check whether or not all the necessary parameters for the given type of
     * public key are provided. This is necessary because of the ugly hack used
     * to support both ECDSA and RSA keys (see comment at the definition of
     * CVC_PUBKEY for details) */
    nid = OBJ_obj2nid(ret->body->public_key->oid);
    if (       nid == NID_id_TA_ECDSA_SHA_1
            || nid == NID_id_TA_ECDSA_SHA_224
            || nid == NID_id_TA_ECDSA_SHA_256
            || nid == NID_id_TA_ECDSA_SHA_384
            || nid == NID_id_TA_ECDSA_SHA_512) {
        check(ret->body->public_key->public_point,
                "public key missing");
    } else if (nid == NID_id_TA_RSA_v1_5_SHA_1
            || nid == NID_id_TA_RSA_v1_5_SHA_256
            || nid == NID_id_TA_RSA_v1_5_SHA_512
            || nid == NID_id_TA_RSA_PSS_SHA_1
            || nid == NID_id_TA_RSA_PSS_SHA_256
            || nid == NID_id_TA_RSA_PSS_SHA_512) {
        check(ret->body->public_key->modulus && ret->body->public_key->a,
                "public key missing");
    } else {
        log_err("unknown credentials in certificate");
        goto err;
    }

    return ret;

err:
    if(ret && !cert) {
        CVC_CERT_free(ret);
    }

    return NULL;
}

int
CVC_verify_signature(const CVC_CERT *cert, EVP_PKEY *key)
{
    int r = -1;
    unsigned char *body = NULL;
    int body_len;
    BUF_MEM *signature = NULL, *body_buf = NULL;
    EVP_PKEY_CTX *tmp_key_ctx = NULL;

    if (!cert || !cert->signature || !key)
        goto err;


    body_len = i2d_CVC_CERT_BODY(cert->body, &body);
    if (body_len <= 0)
        goto err;
    body_buf = BUF_MEM_create_init(body, (size_t) body_len);

    /* Get signature from certificate and convert it to a X9.62 representation */
    signature = BUF_MEM_create_init(cert->signature->data, cert->signature->length);

    r = EAC_verify(OBJ_obj2nid(cert->body->public_key->oid),
            key, signature, body_buf);

err:
    if (tmp_key_ctx)
        EVP_PKEY_CTX_free(tmp_key_ctx);
    if (body)
        OPENSSL_free(body);
    if (body_buf)
        BUF_MEM_free(body_buf);
    if (signature)
        BUF_MEM_free(signature);

    return r;
}

char *
CVC_get_car(const CVC_CERT *cert)
{
    if (!cert || !cert->body)
        return NULL;

    return cvc_get_reference_string(cert->body->certificate_authority_reference);
}

char *
CVC_get_chr(const CVC_CERT *cert)
{
    if (!cert || !cert->body)
        return NULL;

    return cvc_get_reference_string(cert->body->certificate_holder_reference);
}

char *
CVC_get_effective_date(const CVC_CERT *cert)
{
    if (!cert || !cert->body)
        return NULL;

    return cvc_get_date_string(cert->body->certificate_effective_date);
}

char *
CVC_get_expiration_date(const CVC_CERT *cert)
{
    if (!cert || !cert->body)
        return NULL;

    return cvc_get_date_string(cert->body->certificate_expiration_date);
}

enum cvc_terminal_role
CVC_get_role(const CVC_CHAT *chat)
{
    if (!chat || !chat->relative_authorization
            || !chat->relative_authorization->data
            || chat->relative_authorization->length < 1)
        return -1;

    /* The left most bits encode the terminal type */
    return (chat->relative_authorization->data[0] >> 6) & 3;
}

EVP_PKEY *
CVC_get_pubkey(EVP_PKEY *domainParameters, const CVC_CERT *cert, BN_CTX *bn_ctx) {
    EVP_PKEY *key = NULL;
    EC_KEY *ec = NULL;
    RSA *rsa = NULL;
    int nid;

    if (!cert || !cert->body || !cert->body->public_key)
        goto err;

    key = EVP_PKEY_new();
    if (!key)
        goto err;

    nid = OBJ_obj2nid(cert->body->public_key->oid);
    if (nid == NID_id_TA_ECDSA_SHA_1
            || nid == NID_id_TA_ECDSA_SHA_224
            || nid == NID_id_TA_ECDSA_SHA_256
            || nid == NID_id_TA_ECDSA_SHA_384
            || nid == NID_id_TA_ECDSA_SHA_512) {
        ec = CVC_get_ec_pubkey(domainParameters, cert, bn_ctx);
        if (!ec)
            goto err;
        EVP_PKEY_set1_EC_KEY(key, ec);
    } else if (nid == NID_id_TA_RSA_v1_5_SHA_1
            || nid == NID_id_TA_RSA_v1_5_SHA_256
            || nid == NID_id_TA_RSA_v1_5_SHA_512
            || nid == NID_id_TA_RSA_PSS_SHA_1
            || nid == NID_id_TA_RSA_PSS_SHA_256
            || nid == NID_id_TA_RSA_PSS_SHA_512) {
        rsa = CVC_get_rsa_pubkey(cert);
        if (!rsa)
            goto err;
        EVP_PKEY_set1_RSA(key, rsa);
    } else {
        log_err("Unknown protocol");
        goto err;
    }

    if (ec)
        EC_KEY_free(ec);
    if (rsa)
        RSA_free(rsa);
    return key;

err:
    if (ec)
        EC_KEY_free(ec);
    if (rsa)
        RSA_free(rsa);
    if (key)
        EVP_PKEY_free(key);
    return NULL;
}

RSA *CVC_get_rsa_pubkey(const CVC_CERT *cert) {
    RSA *key = NULL;

    if (!cert || !cert->body || !cert->body->public_key)
        goto err;

    /* The RSA parameters are contained in the EC parameters (see the comment in
     * line 128 */
    check((cert->body->public_key->modulus && cert->body->public_key->a),
            "Invalid key format");

    key = RSA_new();
    if (!key)
        goto err;

    /* There are no setter functions in rsa.h so we need to modify the
     * struct directly */
    key->n = BN_bin2bn(cert->body->public_key->modulus->data,
            cert->body->public_key->modulus->length, key->n);
    key->e = BN_bin2bn(cert->body->public_key->a->data,
            cert->body->public_key->a->length, key->e);

    if (!key->n || !key->e)
        goto err;

    return key;

err:
    if (key)
        RSA_free(key);
    return NULL;
}

EC_KEY *
CVC_get_ec_pubkey(EVP_PKEY *domainParameters, const CVC_CERT *cert, BN_CTX *bn_ctx)
{
    EC_KEY *key = NULL;
    const EC_GROUP *group;
    EC_POINT *point = NULL;

    if (!cert || !cert->body || !cert->body->public_key || !cert->body->chat)
        goto err;

    /* If cert is a CVCA certificate it MUST contain all domain parameters (and
     * we can ignore the domainParameters parameter). */
    if (CVC_get_role(cert->body->chat) == CVC_CVCA) {
        check((cert->body->public_key->public_point
                && cert->body->public_key->modulus
                && cert->body->public_key->a
                && cert->body->public_key->b
                && cert->body->public_key->base
                && cert->body->public_key->base_order
                && cert->body->public_key->cofactor),
            "Invalid key format");

        key = EC_KEY_new();
        if (!key)
            goto err;

        if (!EAC_ec_key_from_asn1(&key, cert->body->public_key->modulus,
                    cert->body->public_key->a,
                    cert->body->public_key->b,
                    cert->body->public_key->base,
                    cert->body->public_key->base_order,
                    cert->body->public_key->public_point,
                    cert->body->public_key->cofactor,
                    bn_ctx))
                goto err;
    } else {
        /* If cert is not a CVCA certificate it MUST NOT contain any domain
         * parameters. We take the domain parameters from the domainParameters
         * parameter and the public point from the certificate. */
        check((cert->body->public_key->public_point
                && !cert->body->public_key->modulus
                && !cert->body->public_key->a
                && !cert->body->public_key->b
                && !cert->body->public_key->base
                && !cert->body->public_key->base_order
                && !cert->body->public_key->cofactor),
            "Invalid key format");

        check((domainParameters && (EVP_PKEY_type(domainParameters->type) == EVP_PKEY_EC)),
               "Incorrect domain parameters");

        key = EC_KEY_dup((EC_KEY *)EVP_PKEY_get0(domainParameters));
        check(key, "Failed to extract domain parameters");

        group = EC_KEY_get0_group(key);
        point = EC_POINT_new(group);
        if (!point
                || !EC_POINT_oct2point(group, point,
                    cert->body->public_key->public_point->data,
                    cert->body->public_key->public_point->length,
                    bn_ctx)
                || !EC_KEY_set_public_key(key, point)
                || !EC_KEY_check_key(key))
            goto err;
    }

    EC_POINT_free(point);
    return key;

err:
    if (key)
        EC_KEY_free(key);
    if (point)
        EC_POINT_free(point);
    return NULL;
}

int
CVC_print(BIO *bio, const CVC_CERT *cv, int indent)
{
    int r = 0, i, count;
    char *effective_date = NULL, *expiration_date = NULL;
    char *car = NULL, *chr = NULL;
    CVC_DISCRETIONARY_DATA_TEMPLATE *p;

    if (!bio || !cv || !cv->body || !cv->body->public_key)
        goto err;

    effective_date = CVC_get_effective_date(cv);
    expiration_date = CVC_get_expiration_date(cv);
    car = CVC_get_car(cv);
    chr = CVC_get_chr(cv);

    if (!effective_date || !expiration_date || !car || !chr)
        goto err;

    if (!BIO_indent(bio, indent, 80)
            || !BIO_printf(bio, "Profile identifier: %d\n", CVC_get_profile_identifier(cv))
            || !BIO_indent(bio, indent, 80)
            || !BIO_printf(bio, "CAR: %s\n", car)
            || !CVC_PUBKEY_print_ctx(bio, cv->body->public_key, indent, NULL)
            || !BIO_indent(bio, indent, 80)
            || !BIO_printf(bio, "CHR: %s\n", chr)
            || !BIO_indent(bio, indent, 80)
            || !BIO_printf(bio, "CHAT:\n")
            || !cvc_chat_print(bio, cvc_get_chat(cv), indent+2)
            || !BIO_indent(bio, indent, 80)
            || !BIO_printf(bio, "Effective Date: %s\n", effective_date)
            || !BIO_indent(bio, indent, 80)
            || !BIO_printf(bio, "Expiration Date: %s\n", expiration_date))
        goto err;

    count = sk_num((_STACK*) cv->body->certificate_extensions);
    if (count > 0) {
        if (!BIO_indent(bio, indent, 80)
                || !BIO_printf(bio, "Certificate Extensions:\n"))
            goto err;
    }
    for (i = 0; i < count; i++) {
        p = sk_value((_STACK*) cv->body->certificate_extensions, i);
#if 0
        if (!CVC_DISCRETIONARY_DATA_TEMPLATE_print_ctx(bio, p, indent+2, NULL))
            goto err;
#else
        if (!BIO_indent(bio, indent+2, 80)
                || !BIO_printf(bio, "%s\n", OBJ_nid2sn(OBJ_obj2nid(p->type))))
                goto err;
#endif
    }

    r = 1;

err:
    if (effective_date)
        OPENSSL_free(effective_date);
    if (expiration_date)
        OPENSSL_free(expiration_date);
    if (car)
        OPENSSL_free(car);
    if (chr)
        OPENSSL_free(chr);

    return r;
}

int
cvc_chat_print_authorizations(BIO *bio, const CVC_CHAT *chat, int indent)
{
	int ok = 0, nid = 0, rel_auth_len = 0, rel_auth_num_bytes = 0, i, j = 1;
	const char **strings;

	if (!bio || !chat || !chat->relative_authorization
	            || !chat->relative_authorization->data)
	        goto err;

	/* Figure out what kind of CHAT we have */
	nid = OBJ_obj2nid(chat->terminal_type);
    if (nid == NID_id_AT) {
        strings = at_chat_strings;
        rel_auth_len = EAC_AT_CHAT_BITS;
        rel_auth_num_bytes = EAC_AT_CHAT_BYTES;
    } else if (nid == NID_id_IS) {
        strings = is_chat_strings;
        rel_auth_len = EAC_IS_CHAT_BITS;
        rel_auth_num_bytes = EAC_IS_CHAT_BYTES;
    } else if (nid == NID_id_ST) {
        strings = st_chat_strings;
        rel_auth_len = EAC_ST_CHAT_BITS;
        rel_auth_num_bytes = EAC_ST_CHAT_BYTES;
    } else {
        goto err;
    }

    /* Sanity check: Does the received CHAT have the correct length? */
    if(chat->relative_authorization->length != rel_auth_num_bytes)
        goto err;

    /* Dump the relative authorization bit string in human readable form.
     * Each set Bit means one authorization */
    for (i = 0; i < rel_auth_len; i++) {
        if (i % 8 == 0 && i != 0)
            j++;
        if (CHECK_BIT(chat->relative_authorization->data[rel_auth_num_bytes - j],
                i % 8)) {
            if (!BIO_indent(bio, indent, 80)
                    || !BIO_printf(bio, "%s\n", strings[i]))
                goto err;
        }
    }

    ok = 1;

err:
	return ok;
}

int
cvc_chat_print(BIO *bio, const CVC_CHAT *chat, int indent)
{

    int ok = 0, nid = 0, role;

    if (!bio || !chat || !chat->relative_authorization
            || !chat->relative_authorization->data)
        goto err;

    /* Figure out what kind of CHAT we have */
    nid = OBJ_obj2nid(chat->terminal_type);
    if (       nid == NID_id_AT) {
        if (!BIO_indent(bio, indent, 80)
                || !BIO_printf(bio, "Authentication terminal\n"))
            goto err;
    } else if (nid == NID_id_IS) {
        if (!BIO_indent(bio, indent, 80)
                || !BIO_printf(bio, "Inspection system\n"))
            goto err;
    } else if (nid == NID_id_ST) {
        if (!BIO_indent(bio, indent, 80)
                || !BIO_printf(bio, "Signature terminal\n"))
            goto err;
    } else {
        BIO_indent(bio, indent, 80);
        BIO_printf(bio, "Invalid terminal type\n");
        goto err;
    }

    cvc_chat_print_authorizations(bio, chat, indent+2);

    /* The most significant two bits contain the role of the terminal */
    role = CVC_get_role(chat);
    switch(role) {
        case CVC_CVCA:
            if (!BIO_indent(bio, indent+2, 80)
                    || !BIO_printf(bio, "CVCA certificate\n"))
                goto err;
            break;
        case CVC_DV:
        case CVC_DocVer:
            if (!BIO_indent(bio, indent+2, 80)
                    || !BIO_printf(bio, "DV certificate\n"))
                goto err;
            break;
        case CVC_Terminal:
            if (!BIO_indent(bio, indent+2, 80)
                    || !BIO_printf(bio, "Terminal certificate\n"))
                goto err;
            break;
        default:
            goto err;
    }

    ok = 1;

err:
    return ok;
}

short
CVC_get_profile_identifier(const CVC_CERT *cert)
{
    long l;

    if (!cert || !cert->body || !cert->body->certificate_profile_identifier ||
                !cert->body->certificate_profile_identifier->data)
        return -1;
    l = ASN1_INTEGER_get(cert->body->certificate_profile_identifier);
    return (l == 0) ? 0 : -1; /* The only specified version number is 0 right now */
}

char *
cvc_get_reference_string(ASN1_OCTET_STRING *ref)
{
    char *ret = NULL;

    check(ref, "Invalid input");
    check(is_chr(ref->data, ref->length), "Invalid certificate reference");

    ret = OPENSSL_malloc(ref->length + 1);
    check(ret, "Not enough memory");

    memcpy(ret, ref->data, ref->length);
    /* Null-terminate string */
    ret[ref->length] = '\0';

err:
    return ret;
}

char *
cvc_get_date_string(ASN1_OCTET_STRING *date)
{
    char *ret;

    if (!date || !date->data || date->length != 6
            || !is_bcd(date->data, date->length))
        return NULL;

    ret = OPENSSL_malloc(11);
    if (!ret)
        return NULL;

    /* Convert to ASCII date */
    ret[0] = '2';
    ret[1] = '0';
    ret[2] = date->data[0] + 0x30;
    ret[3] = date->data[1] + 0x30;
    ret[4] = '-';
    ret[5] = date->data[2] + 0x30;
    ret[6] = date->data[3] + 0x30;
    ret[7] = '-';
    ret[8] = date->data[4] + 0x30;
    ret[9] = date->data[5] + 0x30;
    ret[10] = '\0';

    return ret;
}

int
certificate_description_print(BIO *bio,
        const CVC_CERTIFICATE_DESCRIPTION *desc, int indent)
{
    ASN1_OCTET_STRING *s;
    const unsigned char *p;
    int ret, nid, count, i;

    if (desc == NULL)
        return 0;

    if (!BIO_indent(bio, indent, 80)
            || !BIO_printf(bio, "%s\t%s\n", cert_desc_field_strings[0],
                desc->issuerName->data))
        return 0;
    if (desc->issuerURL) {
        if (!BIO_indent(bio, indent, 80)
                || !BIO_printf(bio, "%s\t%s\n", cert_desc_field_strings[1],
                    desc->issuerURL->data))
            return 0;
    }
    if (!BIO_indent(bio, indent, 80)
            || !BIO_printf(bio, "%s\t%s\n", cert_desc_field_strings[2],
                desc->subjectName->data))
        return 0;
    if (desc->subjectURL) {
        if (!BIO_indent(bio, indent, 80)
                || !BIO_printf(bio, "%s\t%s\n", cert_desc_field_strings[3],
                    desc->subjectURL->data))
            return 0;
    }
    if (desc->redirectURL) {
        if (!BIO_indent(bio, indent, 80)
                || !BIO_printf(bio, "%s\t%s\n", cert_desc_field_strings[4],
                    desc->redirectURL->data))
            return 0;
    }
    if (desc->commCertificates) {
        count = sk_num((_STACK*) desc->commCertificates->values);
        if (count > 0) {
            if (!BIO_indent(bio, indent, 80)
                    || !BIO_printf(bio, "%s\n", cert_desc_field_strings[6]))
                return 0;
            for (i = 0; i < count; i++) {
                s = sk_value((_STACK*) desc->commCertificates->values, i);
                if (!BIO_puts(bio, "\n")
                        || !BIO_dump_indent(bio, (char *) s->data, s->length, indent+2))
                    return 0;
            }
        }
    }

    nid = OBJ_obj2nid(desc->descriptionType);
    if (nid == NID_id_plainFormat) {
#ifndef HAVE_PATCHED_OPENSSL
            if (desc->termsOfUsage.other->type != V_ASN1_SEQUENCE)
                return 0;
            ASN1_UTF8STRING *s = NULL;
            p = desc->termsOfUsage.other->value.sequence->data;
            if (!d2i_ASN1_UTF8STRING(&s, &p,
                        desc->termsOfUsage.other->value.sequence->length))
                return 0;
            p = s->data;
#else
            p = desc->termsOfUsage.plainTerms->data;
#endif
            if (!BIO_indent(bio, indent, 80)
                    || !BIO_printf(bio, "%s\n%s\n", cert_desc_field_strings[5],
                        p))
                return 0;
#ifndef HAVE_PATCHED_OPENSSL
            ASN1_UTF8STRING_free(s);
#endif
            ret = 1;
    } else if (nid == NID_id_htmlFormat) {
        ret = 2;
    } else if (nid == NID_id_pdfFormat) {
        ret = 3;
    } else {
        /* Unknown format for terms of usage */
        ret = 4;
    }

    return ret;
}

const CVC_CHAT *
cvc_get_chat(const CVC_CERT *cvc)
{

    if (!cvc || !cvc->body)
        return NULL;

    return cvc->body->chat;
}

int
CVC_check_description(const CVC_CERT *cv, const unsigned char *cert_desc_in,
        const unsigned int cert_desc_in_len)
{

    BUF_MEM *desc_hash = NULL;
    const EVP_MD *md;
    ASN1_OCTET_STRING *hash_check = NULL;
    BUF_MEM *cert_desc = BUF_MEM_create_init(cert_desc_in, cert_desc_in_len);
    int i, count;
    CVC_DISCRETIONARY_DATA_TEMPLATE *p;

    unsigned int ret = -1;

    if (!cv || !cv->body || !cv->body->public_key)
        goto err;

    int nid = OBJ_obj2nid(cv->body->public_key->oid);
    /* Choose the correct hash function */
    if (       nid == NID_id_TA_ECDSA_SHA_1
            || nid == NID_id_TA_RSA_v1_5_SHA_1
            || nid == NID_id_TA_RSA_PSS_SHA_1) {
        md = EVP_sha1();
    } else if (nid == NID_id_TA_ECDSA_SHA_256
            || nid == NID_id_TA_RSA_v1_5_SHA_256
            || nid == NID_id_TA_RSA_PSS_SHA_256) {
        md = EVP_sha256();
    } else if (     nid == NID_id_TA_ECDSA_SHA_512
            || nid == NID_id_TA_RSA_v1_5_SHA_512
            || nid == NID_id_TA_RSA_PSS_SHA_512) {
        md = EVP_sha512();
    } else if (     nid == NID_id_TA_ECDSA_SHA_224) {
        md = EVP_sha224();
    } else if (     nid == NID_id_TA_ECDSA_SHA_384) {
        md = EVP_sha384();
    } else {
        goto err;
    }

    count = sk_num((_STACK*) cv->body->certificate_extensions);
    for (i = 0; i < count; i++) {
        p = sk_value((_STACK*) cv->body->certificate_extensions, i);
        if (OBJ_obj2nid(p->type) == NID_id_description) {
            hash_check = p->discretionary_data1;
            break;
        }
    }

    if (hash_check) {
        /* Check whether or not the hash in the certificate has the correct size */
        if (hash_check->length != EVP_MD_size(md)) {
            ret = 0;
            goto err;
        }

        /* Hash the certificate description */
        desc_hash = hash(md, NULL, NULL, cert_desc);

        /* Compare it with the hash in the certificate */
        if (!memcmp(desc_hash->data, hash_check->data, desc_hash->length))
            ret = 1;
    } else
        ret = 0;

err:
    if (desc_hash)
        BUF_MEM_free(desc_hash);
    if (cert_desc)
        BUF_MEM_free(cert_desc);

    return ret;
}
