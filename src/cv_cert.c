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
 * @file
 * @brief Library for card verifiable certificates
 *
 * @author Dominik Oepen <oepen@informatik.hu-berlin.de>
 * @author Frank Morgner <frankmorgner@gmail.com>
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "eac_asn1.h"
#include "eac_dh.h"
#include "eac_err.h"
#include "eac_util.h"
#include "misc.h"
#include "ssl_compat.h"
#include "ta_lib.h"
#include <eac/cv_cert.h>
#include <eac/eac.h>
#include <openssl/asn1t.h>
#include <openssl/buffer.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/rsa.h>
#include <openssl/dh.h>
#include <openssl/stack.h>
#include <string.h>

/** Check whether or not  a specific bit is set */
#define CHECK_BIT(var,pos) ((var) & (1<<(pos)))

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

/* Actually we would need two types of public keys: one for ECDSA and one for
 * RSA. Since I did not find a suitable solution using the OpenSSL ASN.1 macros,
 * I used an ugly hack. The same type is used for both kind of keys. The optional
 * members cont1 and cont2 can are used to hold the modulus and the public exponent
 * in the RSA case. In this case these members actually are not optional, so we
 * need additional sanity checks in the corresponding d2i functions */
ASN1_SEQUENCE(CVC_PUBKEY_BODY) = {
    ASN1_SIMPLE(CVC_PUBKEY_BODY, oid, ASN1_OBJECT),
    /* tag: 0x81 */
    ASN1_IMP_OPT(CVC_PUBKEY_BODY, cont1, ASN1_OCTET_STRING, 0x1),
    /* tag: 0x82 */
    ASN1_IMP_OPT(CVC_PUBKEY_BODY, cont2, ASN1_OCTET_STRING, 0x2),
    /* tag: 0x83 */
    ASN1_IMP_OPT(CVC_PUBKEY_BODY, cont3, ASN1_OCTET_STRING, 0x3),
    /* tag: 0x84 */
    ASN1_IMP_OPT(CVC_PUBKEY_BODY, cont4, ASN1_OCTET_STRING, 0x4),
    /* tag: 0x85 */
    ASN1_IMP_OPT(CVC_PUBKEY_BODY, cont5, ASN1_OCTET_STRING, 0x5),
    /* tag: 0x86 */
    ASN1_IMP_OPT(CVC_PUBKEY_BODY, cont6, ASN1_OCTET_STRING, 0x6),
    /* tag: 0x87 */
    ASN1_IMP_OPT(CVC_PUBKEY_BODY, cont7, ASN1_OCTET_STRING, 0x7)
} ASN1_SEQUENCE_END(CVC_PUBKEY_BODY)
ASN1_ITEM_TEMPLATE(CVC_PUBKEY) =
    ASN1_EX_TEMPLATE_TYPE(
            ASN1_TFLG_IMPTAG|ASN1_TFLG_APPLICATION,
            0x49, CVC_PUBKEY, CVC_PUBKEY_BODY)
ASN1_ITEM_TEMPLATE_END(CVC_PUBKEY)
IMPLEMENT_ASN1_FUNCTIONS(CVC_PUBKEY)

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
        ASN1_SIMPLE(CVC_CERT_BODY_SEQ, public_key, CVC_PUBKEY),
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

ASN1_SEQUENCE(CVC_COMMCERT_SEQ) = {
        ASN1_SET_OF(CVC_COMMCERT_SEQ, values, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(CVC_COMMCERT_SEQ)
ASN1_SEQUENCE(CVC_CERTIFICATE_DESCRIPTION) = {
        ASN1_SIMPLE(CVC_CERTIFICATE_DESCRIPTION, descriptionType, ASN1_OBJECT),
        ASN1_IMP(CVC_CERTIFICATE_DESCRIPTION, issuerName, ASN1_UTF8STRING, 0x01),
        ASN1_IMP_OPT(CVC_CERTIFICATE_DESCRIPTION, issuerURL, ASN1_PRINTABLESTRING, 0x02),
        ASN1_IMP(CVC_CERTIFICATE_DESCRIPTION, subjectName, ASN1_UTF8STRING, 0x03),
        ASN1_IMP_OPT(CVC_CERTIFICATE_DESCRIPTION, subjectURL, ASN1_PRINTABLESTRING, 0x04),
        ASN1_IMP_OPT(CVC_CERTIFICATE_DESCRIPTION, termsOfUsage, ASN1_OCTET_STRING, 0x05),
        ASN1_IMP_OPT(CVC_CERTIFICATE_DESCRIPTION, redirectURL, ASN1_PRINTABLESTRING, 0x06),
        ASN1_IMP_OPT(CVC_CERTIFICATE_DESCRIPTION, commCertificates, CVC_COMMCERT_SEQ, 0x07),
} ASN1_SEQUENCE_END(CVC_CERTIFICATE_DESCRIPTION)
IMPLEMENT_ASN1_FUNCTIONS(CVC_CERTIFICATE_DESCRIPTION)


ASN1_SEQUENCE(CVC_CERT_REQUEST_BODY_SEQ) = {
        /* tag: 0x5f29 */
        ASN1_APP_IMP(CVC_CERT_REQUEST_BODY_SEQ, certificate_profile_identifier, ASN1_INTEGER, 0x29),
        /* tag: 0x42 */
        ASN1_APP_IMP_OPT(CVC_CERT_REQUEST_BODY_SEQ, certificate_authority_reference, ASN1_OCTET_STRING, 0x2),
        /* public key: tag:0x7f49 */
        ASN1_SIMPLE(CVC_CERT_REQUEST_BODY_SEQ, public_key, CVC_PUBKEY),
        /* tag: 0x5f20 */
        ASN1_APP_IMP(CVC_CERT_REQUEST_BODY_SEQ, certificate_holder_reference, ASN1_OCTET_STRING, 0x20),
        /* tag: 0x65 */
        ASN1_APP_IMP_SEQUENCE_OF_OPT(CVC_CERT_REQUEST_BODY_SEQ, certificate_extensions, CVC_DISCRETIONARY_DATA_TEMPLATE, 0x05),
} ASN1_SEQUENCE_END(CVC_CERT_REQUEST_BODY_SEQ)
/* Change the tag of the Certificate Request Body to 0x7f4e */
ASN1_ITEM_TEMPLATE(CVC_CERT_REQUEST_BODY) =
        ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_IMPTAG|ASN1_TFLG_APPLICATION, 0x4e, CVC_CERT_REQUEST_BODY, CVC_CERT_REQUEST_BODY_SEQ)
ASN1_ITEM_TEMPLATE_END(CVC_CERT_REQUEST_BODY)
IMPLEMENT_ASN1_FUNCTIONS(CVC_CERT_REQUEST_BODY)

ASN1_SEQUENCE(CVC_CERT_REQUEST_SEQ) = {
        /* tag: 0x7F4E */
        ASN1_SIMPLE(CVC_CERT_REQUEST_SEQ, body, CVC_CERT_REQUEST_BODY),
        /* tag: 0x5F37 */
        ASN1_APP_IMP(CVC_CERT_REQUEST_SEQ, inner_signature, ASN1_OCTET_STRING, 0x37),
} ASN1_SEQUENCE_END(CVC_CERT_REQUEST_SEQ)

/* Change the tag of the CV Cert Request to 0x7f21 */
ASN1_ITEM_TEMPLATE(CVC_CERT_REQUEST) =
        ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_IMPTAG|ASN1_TFLG_APPLICATION, 0x21, CVC_CERT_REQUEST, CVC_CERT_REQUEST_SEQ)
ASN1_ITEM_TEMPLATE_END(CVC_CERT_REQUEST)
IMPLEMENT_ASN1_FUNCTIONS(CVC_CERT_REQUEST)

ASN1_SEQUENCE(CVC_CERT_AUTHENTICATION_REQUEST_SEQ) = {
        /* tag: 0x7f21 */
        ASN1_SIMPLE(CVC_CERT_AUTHENTICATION_REQUEST_SEQ, request, CVC_CERT_REQUEST),
        /* tag: 0x42 */
        ASN1_APP_IMP(CVC_CERT_AUTHENTICATION_REQUEST_SEQ, certificate_authority_reference, ASN1_OCTET_STRING, 0x2),
        /* tag: 0x5F37 */
        ASN1_APP_IMP(CVC_CERT_AUTHENTICATION_REQUEST_SEQ, outer_signature, ASN1_OCTET_STRING, 0x37),
} ASN1_SEQUENCE_END(CVC_CERT_AUTHENTICATION_REQUEST_SEQ)

/* Change the tag of the Authentication Request to 0x67 */
ASN1_ITEM_TEMPLATE(CVC_CERT_AUTHENTICATION_REQUEST) =
    ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_IMPTAG|ASN1_TFLG_APPLICATION, 7, CVC_CERT_AUTHENTICATION_REQUEST, CVC_CERT_AUTHENTICATION_REQUEST_SEQ)
ASN1_ITEM_TEMPLATE_END(CVC_CERT_AUTHENTICATION_REQUEST)
IMPLEMENT_ASN1_FUNCTIONS(CVC_CERT_AUTHENTICATION_REQUEST)


/** @} ***********************************************************************/

/**
 * @brief Generate an EC Key from the ASN1 encoded parameters. This function is
 * needed because asn1.h does not export a d2i_asn1 function
 *
 * @param[out] key where to write the new EC key
 * @param[in] p prime modulus of the field
 * @param[in] a first coefficient of the curve
 * @param[in] b second coefficient of the curve
 * @param[in] base generator of the curve
 * @param[in] base_order order of the generator
 * @param[in] pub public point of the key
 * @param[in] cofactor
 * @param[in] bn_ctx (optional)
 */
static int
EAC_ec_key_from_asn1(EC_KEY **key, ASN1_OCTET_STRING *p, ASN1_OCTET_STRING *a,
        ASN1_OCTET_STRING *b, ASN1_OCTET_STRING *base, ASN1_OCTET_STRING *base_order,
        ASN1_OCTET_STRING *pub, ASN1_OCTET_STRING *cofactor, BN_CTX *bn_ctx);
static ASN1_OCTET_STRING *
BN_to_ASN1_UNSIGNED_INTEGER(const BIGNUM *bn, ASN1_OCTET_STRING *in);
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
static int
CVC_pubkey2rsa(const CVC_PUBKEY *public_key, EVP_PKEY *key);
int
CVC_pubkey2eckey(int all_parameters, const CVC_PUBKEY *public_key,
        BN_CTX *bn_ctx, EVP_PKEY *key);

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
        check(ret->body->public_key->cont6,
                "public key missing");
    } else if (nid == NID_id_TA_RSA_v1_5_SHA_1
            || nid == NID_id_TA_RSA_v1_5_SHA_256
            || nid == NID_id_TA_RSA_v1_5_SHA_512
            || nid == NID_id_TA_RSA_PSS_SHA_1
            || nid == NID_id_TA_RSA_PSS_SHA_256
            || nid == NID_id_TA_RSA_PSS_SHA_512) {
        check(ret->body->public_key->cont1 && ret->body->public_key->cont2,
                "public key missing");
    } else {
        debug("unknown credentials in certificate");
    }

    return ret;

err:
    if(ret && !cert) {
        CVC_CERT_free(ret);
    }

    return NULL;
}

int
CVC_verify_signature(const CVC_CERT *cert, int protocol, EVP_PKEY *key)
{
    int r = -1;
    unsigned char *body = NULL;
    int body_len;
    BUF_MEM *signature = NULL, *body_buf = NULL;

    if (!cert || !cert->signature || !key)
        goto err;


    body_len = i2d_CVC_CERT_BODY(cert->body, &body);
    if (body_len <= 0)
        goto err;
    body_buf = BUF_MEM_create_init(body, (size_t) body_len);

    /* Get signature from certificate and convert it to a X9.62 representation */
    signature = BUF_MEM_create_init(cert->signature->data, cert->signature->length);

    r = EAC_verify(protocol, key, signature, body_buf);

err:
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
CVC_pubkey2pkey(const CVC_CERT *cert, BN_CTX *bn_ctx,
        EVP_PKEY *key)
{
    int nid;
    int all_parameters;
    EVP_PKEY *out = NULL, *tmp_key = NULL;

    if (!cert || !cert->body || !cert->body->public_key)
        goto err;

    if (key)
        tmp_key = key;
    else {
        tmp_key = EVP_PKEY_new();
        if (!tmp_key)
            goto err;
    }

    /* If cert is a CVCA certificate it MUST contain all domain parameters (and
     * we can ignore the domainParameters parameter). */
    if (CVC_get_role(cert->body->chat) == CVC_CVCA)
        all_parameters = 1;
    else
        all_parameters = 0;

    nid = OBJ_obj2nid(cert->body->public_key->oid);
    if (nid == NID_id_TA_ECDSA_SHA_1
            || nid == NID_id_TA_ECDSA_SHA_224
            || nid == NID_id_TA_ECDSA_SHA_256
            || nid == NID_id_TA_ECDSA_SHA_384
            || nid == NID_id_TA_ECDSA_SHA_512) {
        if (!CVC_pubkey2eckey(all_parameters, cert->body->public_key, bn_ctx, tmp_key))
            goto err;
    } else if (nid == NID_id_TA_RSA_v1_5_SHA_1
            || nid == NID_id_TA_RSA_v1_5_SHA_256
            || nid == NID_id_TA_RSA_v1_5_SHA_512
            || nid == NID_id_TA_RSA_PSS_SHA_1
            || nid == NID_id_TA_RSA_PSS_SHA_256
            || nid == NID_id_TA_RSA_PSS_SHA_512) {
        if (!CVC_pubkey2rsa(cert->body->public_key, tmp_key))
            goto err;
    } else {
        log_err("Unknown protocol");
        goto err;
    }

    out = tmp_key;

err:
    if (!out && !key && tmp_key)
        EVP_PKEY_free(tmp_key);

    return out;
}

static int
CVC_pubkey2rsa(const CVC_PUBKEY *public_key, EVP_PKEY *out)
{
    int ok = 0;
    RSA *rsa = NULL;

    if (!out || !public_key)
        goto err;

    /* for RSA all parameters must always be present */
    check(public_key->cont1 && public_key->cont2, "Invalid key format");

    rsa = RSA_new();
    if (!rsa)
        goto err;

    check(RSA_set0_key(rsa,
                BN_bin2bn(public_key->cont1->data, public_key->cont1->length,
                    NULL),
                BN_bin2bn(public_key->cont2->data, public_key->cont2->length,
                    NULL), NULL),
            "Internal error");

    ok = EVP_PKEY_set1_RSA(out, rsa);

err:
    if (rsa)
        RSA_free(rsa);

    return ok;
}

int
CVC_pubkey2eckey(int all_parameters, const CVC_PUBKEY *public_key,
        BN_CTX *bn_ctx, EVP_PKEY *key)
{
    EC_KEY *ec = NULL;
    const EC_GROUP *group;
    EC_POINT *point = NULL;
    int ok = 0;

    if (!public_key || !key)
        goto err;

    if (all_parameters) {
        ec = EC_KEY_new();
        if (!ec)
            goto err;

        if (!EAC_ec_key_from_asn1(&ec, public_key->cont1,
                    public_key->cont2,
                    public_key->cont3,
                    public_key->cont4,
                    public_key->cont5,
                    public_key->cont6,
                    public_key->cont7,
                    bn_ctx)) {
            log_err("Internal error");
            goto err;
        }

        ok = EVP_PKEY_set1_EC_KEY(key, ec);
    } else {
        /* If cert is not a CVCA certificate it MUST NOT contain any domain
         * parameters. We take the domain parameters from the domainParameters
         * parameter and the public point from the certificate. */
        check((public_key->cont6
                && !public_key->cont1
                && !public_key->cont2
                && !public_key->cont3
                && !public_key->cont4
                && !public_key->cont5
                && !public_key->cont7),
            "Invalid key format");

        check(EVP_PKEY_base_id(key) == EVP_PKEY_EC,
               "Incorrect domain parameters");

        ec = EVP_PKEY_get1_EC_KEY(key);
        check(ec, "Failed to extract domain parameters");

        group = EC_KEY_get0_group(ec);
        point = EC_POINT_new(group);
        check(point
                && EC_POINT_oct2point(group, point,
                    public_key->cont6->data,
                    public_key->cont6->length,
                    bn_ctx)
                && EC_KEY_set_public_key(ec, point)
                && EC_KEY_check_key(ec),
                "Internal error");

        ok = 1;
    }

err:
    if (point)
        EC_POINT_free(point);
    if (ec)
        EC_KEY_free(ec);

    return ok;
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
        if (!BIO_indent(bio, indent+2, 80)
                || !BIO_printf(bio, "%s\n", OBJ_nid2sn(OBJ_obj2nid(p->type))))
                goto err;
    }

    r = 1;

err:
    free(effective_date);
    free(expiration_date);
    free(car);
    free(chr);

    return r;
}

int
CVC_verify_request_signature(const CVC_CERT_REQUEST *request)
{
    int r = -1, nid;
    unsigned char *body = NULL;
    int body_len;
    BUF_MEM *inner_signature = NULL, *body_buf = NULL;
    EVP_PKEY *key = NULL;

    if (!request||!request->body||!request->inner_signature||!request->body->public_key)
        goto err;

    key = EVP_PKEY_new();
    if (!key)
        goto err;

    nid = OBJ_obj2nid(request->body->public_key->oid);
    if (nid == NID_id_TA_ECDSA_SHA_1
            || nid == NID_id_TA_ECDSA_SHA_224
            || nid == NID_id_TA_ECDSA_SHA_256
            || nid == NID_id_TA_ECDSA_SHA_384
            || nid == NID_id_TA_ECDSA_SHA_512) {
        if (!CVC_pubkey2eckey(1, request->body->public_key, NULL, key))
            goto err;
    } else if (nid == NID_id_TA_RSA_v1_5_SHA_1
            || nid == NID_id_TA_RSA_v1_5_SHA_256
            || nid == NID_id_TA_RSA_v1_5_SHA_512
            || nid == NID_id_TA_RSA_PSS_SHA_1
            || nid == NID_id_TA_RSA_PSS_SHA_256
            || nid == NID_id_TA_RSA_PSS_SHA_512) {
        if (!CVC_pubkey2rsa(request->body->public_key, key))
            goto err;
    } else {
        log_err("Unknown protocol");
        goto err;
    }

    body_len = i2d_CVC_CERT_REQUEST_BODY(request->body, &body);
    if (body_len <= 0)
        goto err;
    body_buf = BUF_MEM_create_init(body, (size_t) body_len);

    /* Get signature from certificate and convert it to a X9.62 representation */
    inner_signature = BUF_MEM_create_init(request->inner_signature->data, request->inner_signature->length);

    r = EAC_verify(nid, key, inner_signature, body_buf);

err:
    if (key)
        EVP_PKEY_free(key);
    if (body)
        OPENSSL_free(body);
    if (body_buf)
        BUF_MEM_free(body_buf);
    if (inner_signature)
        BUF_MEM_free(inner_signature);

    return r;
}

int
CVC_verify_authentication_request_signatures(EAC_CTX *ctx,
        const CVC_CERT_AUTHENTICATION_REQUEST *authentication)
{
    int r = -1;
    unsigned char *request = NULL;
    int request_len;
    BUF_MEM *outer_signature = NULL, *data = NULL;
    const CVC_CERT *trust_anchor = NULL;

    if (!ctx || !ctx->ta_ctx || !ctx->ta_ctx->lookup_cvca_cert || !authentication
            || !authentication->request || !authentication->outer_signature
            || !authentication->certificate_authority_reference)
        goto err;

    /* find the original certificate for verification of the outer signature */
    trust_anchor = ctx->ta_ctx->lookup_cvca_cert(
            authentication->certificate_authority_reference->data,
            authentication->certificate_authority_reference->length);
    if (!trust_anchor)
            goto err;

    /* import this certificate to set up ctx->ta_ctx->pub_key with the original
     * certificate's public key */
    r = TA_CTX_import_certificate(ctx->ta_ctx, trust_anchor, ctx->bn_ctx);
    if (r != 1)
        goto err;
    r = -1;

    /* Data to be signed: request || car */
    request_len = i2d_CVC_CERT_REQUEST(authentication->request, &request);
    if (request_len <= 0)
        goto err;
    data = BUF_MEM_create(
            authentication->certificate_authority_reference->length
            + (size_t) request_len);
    memcpy(data->data, request, request_len);
    memcpy(data->data + request_len,
            authentication->certificate_authority_reference->data,
            authentication->certificate_authority_reference->length);

    outer_signature = BUF_MEM_create_init(
            authentication->outer_signature->data,
            authentication->outer_signature->length);

    r = EAC_verify(ctx->ta_ctx->protocol, ctx->ta_ctx->pub_key,
            outer_signature, data);
    if (r != 1)
        goto err;

    r = CVC_verify_request_signature(authentication->request);

err:
    if (request)
        OPENSSL_free(request);
    if (data)
        BUF_MEM_free(data);
    if (outer_signature)
        BUF_MEM_free(outer_signature);

    return r;
}

int certificate_request_print(BIO *bio,
        const CVC_CERT_REQUEST *request, int indent)
{
    int r = 0, i, count;
    char *car = NULL, *chr = NULL;
    CVC_DISCRETIONARY_DATA_TEMPLATE *p;

    if (!bio || !request || !request->body || !request->body->public_key)
        goto err;

    if (request->body->certificate_authority_reference) {
        car = cvc_get_reference_string(request->body->certificate_authority_reference);
        if (!car)
            goto err;
    }

    chr = cvc_get_reference_string(request->body->certificate_holder_reference);
    if (!chr)
        goto err;

    if (!BIO_indent(bio, indent, 80)
            || !BIO_printf(bio, "Profile identifier: %ld\n", ASN1_INTEGER_get(request->body->certificate_profile_identifier))
            || !BIO_indent(bio, indent, 80)
            || !BIO_printf(bio, "CAR: %s\n", car)
            || !BIO_indent(bio, indent, 80)
            || !BIO_printf(bio, "CHR: %s\n", chr)
            || !BIO_indent(bio, indent, 80))
        goto err;

    count = sk_num((_STACK*) request->body->certificate_extensions);
    if (count > 0) {
        if (!BIO_indent(bio, indent, 80)
                || !BIO_printf(bio, "Certificate Extensions:\n"))
            goto err;
    }
    for (i = 0; i < count; i++) {
        p = sk_value((_STACK*) request->body->certificate_extensions, i);
        if (!BIO_indent(bio, indent+2, 80)
                || !BIO_printf(bio, "%s\n", OBJ_nid2sn(OBJ_obj2nid(p->type))))
                goto err;
    }

    r = 1;

err:
    free(car);
    free(chr);

    return r;
}

int certificate_authentication_request_print(BIO *bio,
        const CVC_CERT_AUTHENTICATION_REQUEST *authentication, int indent)
{
    int r = 0;
    char *car = NULL;

    if (!bio || !authentication)
        goto err;

    car = cvc_get_reference_string(authentication->certificate_authority_reference);
    if (!car)
        goto err;

    if (!BIO_indent(bio, indent, 80)
            || !BIO_printf(bio, "Certificate request:\n")
            || !certificate_request_print(bio, authentication->request,
                indent+2)
            || !BIO_indent(bio, indent, 80)
            || !BIO_printf(bio, "CAR: %s\n", car))
        goto err;

    r = 1;

err:
    free(car);

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
        if (!BIO_indent(bio, indent, 80)
                || !BIO_printf(bio, "Unknown terminal type\n"))
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

    ret = malloc(ref->length + 1);
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

    ret = malloc(11);
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
            if (!BIO_indent(bio, indent, 80)
                    || !BIO_printf(bio, "%s\n%.*s\n", cert_desc_field_strings[5],
                        desc->termsOfUsage->length, desc->termsOfUsage->data))
                return 0;
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

BUF_MEM *CVC_hash_description(const CVC_CERT *cv,
        const unsigned char *cert_desc, size_t cert_desc_len)
{
    BUF_MEM *cert_desc_buf = NULL, *desc_hash = NULL;
    const EVP_MD *md;
    int nid;

    if (!cv || !cv->body || !cv->body->public_key)
        goto err;

    nid = OBJ_obj2nid(cv->body->public_key->oid);
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

    /* Hash the certificate description */
    cert_desc_buf = BUF_MEM_create_init(cert_desc, cert_desc_len);
    desc_hash = hash(md, NULL, NULL, cert_desc_buf);

err:
    if (cert_desc_buf)
        BUF_MEM_free(cert_desc_buf);

    return desc_hash;
}

int
CVC_check_description(const CVC_CERT *cv, const unsigned char *cert_desc_in,
        const unsigned int cert_desc_in_len)
{

    BUF_MEM *desc_hash = NULL;
    ASN1_OCTET_STRING *hash_check = NULL;
    int i, count;
    CVC_DISCRETIONARY_DATA_TEMPLATE *p;

    unsigned int ret = -1;

    count = sk_num((_STACK*) cv->body->certificate_extensions);
    for (i = 0; i < count; i++) {
        p = sk_value((_STACK*) cv->body->certificate_extensions, i);
        if (OBJ_obj2nid(p->type) == NID_id_description) {
            hash_check = p->discretionary_data1;
            break;
        }
    }

    if (hash_check) {
        desc_hash = CVC_hash_description(cv, cert_desc_in, cert_desc_in_len);
        if (!desc_hash)
            goto err;

        /* Check whether or not the hash in the certificate has the correct size */
        if (hash_check->length != desc_hash->length) {
            ret = 0;
            goto err;
        }

        /* Compare it with the hash in the certificate */
        if (!memcmp(desc_hash->data, hash_check->data, desc_hash->length))
            ret = 1;
    } else
        ret = 0;

err:
    if (desc_hash)
        BUF_MEM_free(desc_hash);

    return ret;
}

static int CVC_eckey2pubkey(int all_parameters,
        EVP_PKEY *key, BN_CTX *bn_ctx, CVC_PUBKEY *out)
{
    EC_KEY *ec = NULL;
    const EC_GROUP *group;
    int ok = 0;
    BIGNUM *a_bn = NULL, *b_bn = NULL, *bn = NULL;
    BUF_MEM *Y_buf = NULL, *G_buf = NULL;

    check(out && key && bn_ctx, "Invalid Arguments");

    BN_CTX_start(bn_ctx);
    ec = EVP_PKEY_get1_EC_KEY(key);
    check(ec, "Could not get EC key");

    group = EC_KEY_get0_group(ec);
    if (!group)
        goto err;

    /* Public point */
    Y_buf = EC_POINT_point2mem(ec, bn_ctx, EC_KEY_get0_public_key(ec));
    out->cont6 = ASN1_OCTET_STRING_new();
    if (!Y_buf || !out->cont6 ||
            !ASN1_OCTET_STRING_set(out->cont6,
                (const unsigned char *) Y_buf->data, Y_buf->length))
        goto err;

    /* If cert is not a CVCA certificate it MUST NOT contain any domain
     * parameters. It only carries the public key. */
    if (all_parameters) {
        /* If cert is a CVCA certificate it MUST contain all domain parameters. */
        bn = BN_CTX_get(bn_ctx);
        a_bn = BN_CTX_get(bn_ctx);
        b_bn = BN_CTX_get(bn_ctx);
        if (!EC_GROUP_get_curve_GFp(group, bn, a_bn, b_bn, bn_ctx))
            goto err;

        /* Prime modulus */
        out->cont1 = BN_to_ASN1_UNSIGNED_INTEGER(bn, out->cont1);

        /* First coefficient */
        out->cont2 = BN_to_ASN1_UNSIGNED_INTEGER(a_bn, out->cont2);

        /* Second coefficient */
        out->cont3 = BN_to_ASN1_UNSIGNED_INTEGER(b_bn, out->cont3);

        /* Base Point */
        G_buf = EC_POINT_point2mem(ec, bn_ctx,
                EC_GROUP_get0_generator(group));
        out->cont4 = ASN1_OCTET_STRING_new();
        if (!out->cont4
                || !ASN1_OCTET_STRING_set(out->cont4,
                    (const unsigned char *) G_buf->data, G_buf->length))
            goto err;

        /* Order of the base point */
        if (!EC_GROUP_get_order(group, bn, bn_ctx))
            goto err;
        out->cont5 = BN_to_ASN1_UNSIGNED_INTEGER(bn, out->cont5);

        /* Cofactor */
        if (!EC_GROUP_get_cofactor(group, bn, bn_ctx))
            goto err;
        out->cont7 = BN_to_ASN1_UNSIGNED_INTEGER(bn, out->cont7);

        if (!out->cont1 || !out->cont2 || !out->cont3 || !out->cont4
                || !out->cont5 || !out->cont7)
            goto err;
    }

    ok = 1;

err:
    if (ec)
        EC_KEY_free(ec);
    if (Y_buf)
        BUF_MEM_free(Y_buf);
    if (G_buf)
        BUF_MEM_free(G_buf);
    BN_CTX_end(bn_ctx);

    return ok;
}

static int CVC_rsa2pubkey(EVP_PKEY *key, CVC_PUBKEY *out)
{
    RSA *rsa = NULL;
    int ok = 0;
    const BIGNUM *n, *e;

    check(key && out, "Invalid Arguments");

    rsa = EVP_PKEY_get1_RSA(key);
    check(rsa, "Could not get RSA key");

    RSA_get0_key(rsa, &n, &e, NULL);
    out->cont1 = BN_to_ASN1_UNSIGNED_INTEGER(n, out->cont1);
    out->cont2 = BN_to_ASN1_UNSIGNED_INTEGER(e, out->cont2);
    if (!out->cont1 || !out->cont2)
        goto err;

    ok = 1;

err:
    if (rsa)
        RSA_free(rsa);

    return ok;
}

static int CVC_dh2pubkey(int all_parameters, EVP_PKEY *key, BN_CTX *bn_ctx,
        CVC_PUBKEY *out)
{
    DH *dh = NULL;
    BIGNUM *bn = NULL;
    const BIGNUM *pub_key, *p, *g;
    int ok = 0;

    check(out, "Invalid argument");

    dh = EVP_PKEY_get1_DH(key);
    check(dh, "Could not get DH key");

    /* Public value */
    DH_get0_key(dh, &pub_key, NULL);
    out->cont4 = BN_to_ASN1_UNSIGNED_INTEGER(pub_key, out->cont4);
    if (!out->cont4)
        goto err;

    if (all_parameters) {
        DH_get0_pqg(dh, &p, NULL, &g);

        /* Prime modulus */
        out->cont1 = BN_to_ASN1_UNSIGNED_INTEGER(p, out->cont1);

        /* Order of the subgroup */
        bn = DH_get_order(dh, bn_ctx);
        if (!bn)
            goto err;
        out->cont2 = BN_to_ASN1_UNSIGNED_INTEGER(bn, out->cont2);

        /* Generator */
        out->cont3 = BN_to_ASN1_UNSIGNED_INTEGER(g, out->cont3);

        if (!out->cont1|| !out->cont2 || !out->cont3)
            goto err;
    }

    ok = 1;

err:
    if (bn)
        BN_free(bn);
    if (dh)
        DH_free(dh);

    return ok;
}

CVC_PUBKEY *
CVC_pkey2pubkey(int all_parameters, int protocol, EVP_PKEY *key,
        BN_CTX *bn_ctx, CVC_PUBKEY *in)
{
    CVC_PUBKEY *pubkey = NULL, *out = NULL;
    BN_CTX *tmp_ctx = NULL;

    check(key, "Invalid argument");

    if (!bn_ctx) {
        tmp_ctx = BN_CTX_new();
        if (!tmp_ctx)
            goto err;
        bn_ctx = tmp_ctx;
    }

    if (in) {
        pubkey = in;
    } else {
        pubkey = CVC_PUBKEY_new();
        if (!pubkey)
            goto err;
    }

    pubkey->oid = OBJ_nid2obj(protocol);
    check(pubkey->oid, "Could not encode oid");

    switch (EVP_PKEY_base_id(key)) {
        case EVP_PKEY_EC:
            if (!CVC_eckey2pubkey(all_parameters, key, bn_ctx, pubkey))
                goto err;
            break;
        case EVP_PKEY_DH:
        case EVP_PKEY_DHX:
            if (!CVC_dh2pubkey(all_parameters, key, bn_ctx, pubkey))
                goto err;
            break;
        case EVP_PKEY_RSA:
            if (!CVC_rsa2pubkey(key, pubkey))
                goto err;
            break;
        default:
            check(0, "unhandled type of key");
    }

    out = pubkey;

err:
    if (tmp_ctx)
        BN_CTX_free(tmp_ctx);
    if (!out && !in && pubkey)
        CVC_PUBKEY_free(pubkey);

    return out;
}

static int
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

    if (!p_bn || !a_bn || !b_bn || !order_bn || !cofactor_bn)
        goto err;

    /* Copy field and curve */
    if (!BN_bin2bn(ASN1_STRING_get0_data(p), ASN1_STRING_length(p), p_bn) ||
        !BN_bin2bn(ASN1_STRING_get0_data(a), ASN1_STRING_length(a), a_bn) ||
        !BN_bin2bn(ASN1_STRING_get0_data(b), ASN1_STRING_length(b), b_bn))
            goto err;
    else
        group = EC_GROUP_new_curve_GFp(p_bn, a_bn, b_bn, lcl_bn_ctx);

    if (!group)
        goto err;

    /* Set generator, order and cofactor */
    if (!BN_bin2bn(ASN1_STRING_get0_data(cofactor), ASN1_STRING_length(cofactor), cofactor_bn) ||
        !BN_bin2bn(ASN1_STRING_get0_data(base_order), ASN1_STRING_length(base_order), order_bn))
            goto err;

    generator = EC_POINT_new(group);
    if (!generator)
        goto err;

    if (!EC_POINT_oct2point(group, generator, ASN1_STRING_get0_data(base),
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

        if (!EC_POINT_oct2point(group, pub_point, ASN1_STRING_get0_data(pub),
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
            || !ASN1_OCTET_STRING_set(out,
                (const unsigned char *) bn_buf->data, bn_buf->length))
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
