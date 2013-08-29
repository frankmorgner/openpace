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
 * @brief Interface for Card Verifiable Certificates
 *
 * @author Dominik Oepen <oepen@informatik.hu-berlin.de>
 * @author Frank Morgner <morgner@informatik.hu-berlin.de>
 */

#ifndef CVC_CERT_H_
#define CVC_CERT_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <eac/objects.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/bio.h>

#ifndef ASN1_APP_IMP
/** Application specific, IMPLICIT tagged ASN1 type */
#define ASN1_APP_IMP(stname, field, type, tag) ASN1_EX_TYPE(ASN1_TFLG_IMPTAG|ASN1_TFLG_APPLICATION, tag, stname, field, type)
#endif
#ifndef ASN1_APP_IMP_OPT
/** Application specific, IMPLICIT tagged, optional ASN1 type */
#define ASN1_APP_IMP_OPT(stname, field, type, tag) ASN1_EX_TYPE(ASN1_TFLG_IMPTAG|ASN1_TFLG_APPLICATION|ASN1_TFLG_OPTIONAL, tag, stname, field, type)
#endif
#ifndef ASN1_APP_EXP_OPT
/** Application specific, EXPLICIT tagged, optional ASN1 type */
#define ASN1_APP_EXP_OPT(stname, field, type, tag) ASN1_EX_TYPE(ASN1_TFLG_EXPTAG|ASN1_TFLG_APPLICATION|ASN1_TFLG_OPTIONAL, tag, stname, field, type)
#endif
#ifndef ASN1_APP_IMP_SEQUENCE_OF_OPT
#define ASN1_APP_IMP_SEQUENCE_OF_OPT(stname, field, type, tag) \
    ASN1_EX_TYPE(ASN1_TFLG_SEQUENCE_OF|ASN1_TFLG_IMPTAG|ASN1_TFLG_APPLICATION|ASN1_TFLG_OPTIONAL, tag, stname, field, type)
#endif

/** @brief Effective role of the certificate holder */
enum cvc_terminal_role {
    /** @brief Terminal (inspection system/authentication terminal/signature terminal) */
    CVC_Terminal = 0,
    /** @brief Document Verifier (official domestic) */
    CVC_DV,
    /** @brief Document Verifier (non-official/foreign) */
    CVC_DocVer, /* XXX Ugly */
    /** @brief Country Verifying Certificate Authority */
    CVC_CVCA
};

/** @brief Certificate Holder Authentication Template
 *
 * @see TR-03110 C.1.5. */
typedef struct cvc_chat_seq_st {
    /** @brief Role of terminal to which this certificate belongs (Inspection
     * System, Authentication Terminal or Signature Terminal) */
    ASN1_OBJECT *terminal_type;
    /** @brief Access rights of the terminal to which this certificate belongs. */
    ASN1_OCTET_STRING *relative_authorization;
} CVC_CHAT_SEQ;
/** @brief Short name for CVC_CHAT_SEQ */
typedef CVC_CHAT_SEQ CVC_CHAT;
DECLARE_ASN1_FUNCTIONS(CVC_CHAT)

/**
 * @brief Public key data object which may contain domain parameters.
 *
 * This data structure is used for defined public keys (RSA public key, DH
 * public key, EC public key).
 *
 * @see TR-03110 D.3.
 */
typedef struct cvc_pubkey_st {
    /** @brief Object Identifier which specifies the exact protocol to be used during TA */
    ASN1_OBJECT *oid;
    /** @brief Composite modulus (RSA)/prime modulus (DH, EC) */
    ASN1_OCTET_STRING *modulus;
    /** @brief Public exponent (RSA)/order of the Subgroup (DH)/first coefficient (EC) */
    ASN1_OCTET_STRING *a;
    /** @brief Order of the subgroup (DH)/second coefficient (EC) */
    ASN1_OCTET_STRING *b;
    /** @brief Generator (DH)/base point (EC) */
    ASN1_OCTET_STRING *base;
    /** @brief Public value (DH)/order of the base point (EC) */
    ASN1_OCTET_STRING *base_order;
    /** @brief Public point (EC) */
    ASN1_OCTET_STRING *public_point;
    /** @brief Cofactor (EC) */
    ASN1_OCTET_STRING *cofactor;
} CVC_PUBKEY;

/**
 * @brief Discretionary data template, used to encode certificate extensions.
 *
 * Consists of an OID and up to two hash values. This data structure is used
 * for both possible certificate extensions.
 */
typedef struct cvc_discretionary_data_template_seq_st {
    /** @brief OID which specifies the type of the extension **/
    ASN1_OBJECT *type;
    /** @brief holds descretionary data */
    ASN1_OCTET_STRING *discretionary_data1;
    /** @brief holds descretionary data */
    ASN1_OCTET_STRING *discretionary_data2;
    /** @brief holds descretionary data */
    ASN1_OCTET_STRING *discretionary_data3;
} CVC_DISCRETIONARY_DATA_TEMPLATE_SEQ;
/** @brief Short name for CVC_CERT_BODY_SEQ */
typedef CVC_DISCRETIONARY_DATA_TEMPLATE_SEQ CVC_DISCRETIONARY_DATA_TEMPLATE;
DECLARE_ASN1_FUNCTIONS(CVC_DISCRETIONARY_DATA_TEMPLATE)
DECLARE_ASN1_ITEM(CVC_DISCRETIONARY_DATA_TEMPLATE)


/**
 * @brief The body of the CV certificate (without signature)
 *
 * @see TR-03110 C.1. */
typedef struct cvc_cert_body_seq_st {
    /** @brief Certificate Profile of this certificate (must be 0).
     *
     * @see TR-03110 C.1.1. */
    ASN1_INTEGER *certificate_profile_identifier;
    /** @brief Reference to certificate authority that issued this certificate (in Latin1)
     *
     * @see TR-03110 C.1.2. */
    ASN1_UTF8STRING *certificate_authority_reference;
    /** @brief Public key associated with this certificate
     *
     * @see TR-03110 C.1.3. */
    CVC_PUBKEY *public_key;
    /** @brief Reference to the holder of this certificate (in Latin1)
     *
     * @see TR-03110 C.1.4. */
    ASN1_UTF8STRING *certificate_holder_reference;
    /** @brief Certificate Holder Authorisation Template */
    CVC_CHAT *chat;
    /** @brief Date the certificate was issued (YYMMDD, BCD encoded)
     *
     * @see TR-03110 C.1.5. */
    ASN1_OCTET_STRING *certificate_effective_date;
    /** @brief Date until which the certicate is valid (YYMMDD, BCD encoded)
     *
     * @see TR-03110 C.1.6. */
    ASN1_OCTET_STRING *certificate_expiration_date;
    /** @brief Optional extensions
     *
     * @see TR-03110 C.1.7. */
	STACK_OF(CVC_DISCRETIONARY_DATA_TEMPLATE) *certificate_extensions;
} CVC_CERT_BODY_SEQ;
/** @brief Short name for CVC_CERT_BODY_SEQ */
typedef CVC_CERT_BODY_SEQ CVC_CERT_BODY;

/**
 * @brief The actual certifcate, consisting of the body and a signature
 *
 *  @see TR-03110 C.1. */
typedef struct cvc_cert_seq_st {
    /** @brief Body of the certificate */
    CVC_CERT_BODY *body;
    /** @brief Signature calculated over the hash of the certificate body */
    ASN1_OCTET_STRING *signature;
} CVC_CERT_SEQ;
/** @brief Short name for CVC_CERT_SEQ */
typedef CVC_CERT_SEQ CVC_CERT;
/*void CVC_CERT_print_ctx(BIO *bio, CVC_CERT *cert, int indent, const ASN1_PCTX *pctx);*/
/* FIXME the default printing functions currently crash
DECLARE_ASN1_PRINT_FUNCTION(CVC_CERT)
DECLARE_ASN1_PRINT_FUNCTION(CVC_CHAT)
*/

typedef struct cvc_commcert_seq_st {
    /** @brief Contains hash values of admissible X.509 certificates of the remote
     *  terminal (optional) */
    STACK_OF(ASN1_OCTET_STRING) *values;
} CVC_COMMCERT_SEQ;
/**
 * @brief This structure holds further information about a card verifiable
 * certificate in human readable form.
 *
 * The certificate description is used by a local terminal as part of the user
 * interaction for online authentication of a remote terminal and may be
 * ignored by the MRTD chip.
 *
 *  @see TR-03110 C.3.1.
 */
 typedef struct cvc_certificate_description_st {
    /** @brief Format of the description (Plain Text, PDF or HTML) */
    ASN1_OBJECT *descriptionType;
    /** @brief Human readable name of the issuer of this certificate */
    ASN1_UTF8STRING *issuerName;
    /** @brief Optional URL that points to informations about the issuer of this
     *  certificate */
    ASN1_PRINTABLESTRING *issuerURL;
    /** @brief Human readable name of the holder of this certificate */
    ASN1_UTF8STRING *subjectName;
    /** @brief Optional URL that points to informations about the holder of this
     *  certificate */
    ASN1_PRINTABLESTRING *subjectURL;
     /** @brief Terms of Usage of the Service holding the certificate. May be
     *  formatted as either plain text, HTML or PDF */
    union {
#ifdef HAVE_PATCHED_OPENSSL
        /** @brief Plain text Terms of Usage */
        ASN1_UTF8STRING *plainTerms;
        /** @brief HTML formatted Terms of Usage */
        ASN1_IA5STRING *htmlTerms;
        /** @brief PDF formatted Terms of Usage */
        ASN1_OCTET_STRING *pdfTerms;
#endif
        /** @brief Otherwise formatted Terms of Usage (not specified) */
        ASN1_TYPE *other;
    } termsOfUsage;

    /** @brief Not used */
    ASN1_PRINTABLESTRING *redirectURL;
    /** @brief Contains hash values of admissible X.509 certificates of the remote
     *  terminal (optional) */
    CVC_COMMCERT_SEQ *commCertificates;
} CVC_CERTIFICATE_DESCRIPTION;
DECLARE_ASN1_FUNCTIONS(CVC_CERTIFICATE_DESCRIPTION)
DECLARE_ASN1_PRINT_FUNCTION(CVC_CERTIFICATE_DESCRIPTION)

/**
 * @addtogroup management
 * @{ ************************************************************************/

/**
 * @brief Convert ASN1 formatted CV certificate to the internal structure
 *
 * @param[in,out] cert (optional) Where to save the CV certificate
 * @param[in] in ASN1 formatted CV certificate
 * @param[in] len Length of \a in
 *
 * @return CV certificate or NULL in case of an error
 * */
CVC_CERT *CVC_d2i_CVC_CERT(CVC_CERT **cert, const unsigned char **in, long len);

/**
 * @brief Convert a CV certificate description to its ASN1 representation
 *
 * @param[in] a CV certificate description
 * @param[out] out Where to write the ASN1 representation of \a a
 *
 * @return Number of bytes successfully encoded or a negative value if an
 * error occured.
 */
int i2d_CVC_CERT(CVC_CERT *a, unsigned char **out);

/**
 * @brief Duplicate a CV certificate
 *
 * @param[in] x CV certificate to duplicate
 *
 * @return Duplicated CV certificate or NULL in case of an error
 */
#define CVC_CERT_dup(x) ASN1_dup_of(CVC_CERT, i2d_CVC_CERT, CVC_d2i_CVC_CERT, x)

/**
 * @brief Duplicate a CHAT 
 *
 * @param[in] x CHAT to duplicate
 *
 * @return Duplicated CHAT or NULL in case of an error
 */
#define CVC_CHAT_dup(x) ASN1_dup_of(CVC_CHAT, i2d_CVC_CHAT, d2i_CVC_CHAT, x)

/**
 * @brief Allocate memory for a CV certificate
 *
 * @return CHAT or NULL in case of an error
 */
CVC_CERT *CVC_CERT_new(void);
/**
 * @brief Free a CV certificate.
 *
 * @param[in] a CV certificate to free
 * */
void CVC_CERT_free(CVC_CERT *a);

/**
 * @brief Load a CV certificate from a BIO object
 *
 * This function seeks the BIO so that subsequent reads of multiple
 * certificates are possible.
 *
 * @param[in,out] bp bio object where to read from
 * @param[in,out] cvc (optional) CV certificate to use
 *
 * @return CV certificate read or NULL in case of an error
 */
CVC_CERT *d2i_CVC_CERT_bio(BIO *bp, CVC_CERT **cvc);



/** @} ***********************************************************************/

/**
 * @addtogroup printing
 * @{ ************************************************************************/

/**
 * @brief Print CV certificate description in human readable form
 *
 * @param[in] bio Where to print the data
 * @param[in] desc CV certificate desciption to print
 * @param[in] indent Number of spaces to prepend
 *
 * @return 1 on success or 0 in case of an error
 */
int certificate_description_print(BIO *bio,
        const CVC_CERTIFICATE_DESCRIPTION *desc, int indent);

/**
 * @brief Print CHAT in human readable form
 *
 * @param[in] bio Where to print the data
 * @param[in] chat CHAT to dump
 * @param[in] indent Number of spaces to prepend
 *
 * @return 1 on success or 0 in case of an error
 * */
int
cvc_chat_print(BIO *bio, const CVC_CHAT *chat, int indent);

/**
 * @brief Print the relative authorization contained in a CHAT in human readable
 * form
 *
 * @param[in] bio Where to print the data
 * @param[in] chat CHAT which contains the relative authorization
 * @param[in] indent Number of spaces to prepend
 *
 * @return 1 on success or 0 in case of an error
 * */
int
cvc_chat_print_authorizations(BIO *bio, const CVC_CHAT *chat, int indent);

/**
 * @brief Print CV certificate in human readable form
 *
 * @param[in] bio Where to print the data
 * @param[in] cv CV certificate to print
 * @param[in] indent Number of spaces to prepend
 *
 * @return 1 on success or 0 in case of an error
 * */
int
CVC_print(BIO *bio, const CVC_CERT *cv, int indent);

/**
 *  @brief Get the CHAT contained in a CV certifcate.
 *
 *  @param[in] cvc CV certificate

 *  @return Pointer to the CHAT of \a cvc or NULL in case of an error
 */
const CVC_CHAT *
cvc_get_chat(const CVC_CERT *cvc);

/** @} ***********************************************************************/

/**
 * @brief Extract the public key from a CV certificate. Since EC domain parameters
 * are only included in CVCA certificates, they must be passed as parameters
 * for DV and terminal certificates
 *
 * @param[in] domainParameters domain parameters for DV and terminal certificates (optional)
 * @param[in] cert the certificate containing the public key
 * @param[in] bn_ctx
 *
 * @return An EVP_PKEY container with the public key or NULL in case of an error
 *
 * @note Result should be freed with \c EVP_PKEY_free()
 */
EVP_PKEY *
CVC_get_pubkey(EVP_PKEY *domainParameters, const CVC_CERT *cert, BN_CTX *bn_ctx);

/**
 * @brief Extract the terminal-type (terminal, DV, CVCA) from the CHAT
 *
 * @param[in] chat CHAT
 *
 * @return -1 in case of an error or one of the following values:
 * - \c CVC_CVCA (CVCA certificate)
 * - \c CVC_DV (DVCA certificate)
 * - \c CVC_DocVer (DVCA certificate)
 * - \c CVC_Terminal (terminal certificate)
 */
enum cvc_terminal_role
CVC_get_role(const CVC_CHAT *chat);

/**
 * @brief Return the profile identifier of a CV certificate as an integer
 *
 * @param[in] cert The certificate from which we want to return the profile identifier
 *
 * @return The profile identifier or -1 in case of an error
 */
short
CVC_get_profile_identifier(const CVC_CERT *cert);
/**
 * @brief Return the CAR of a CV certificate as a string
 *
 * @param[in] cert The certificate from which we want to return the CAR
 *
 * @return CAR string or NULL in case of an error
 *
 * @note Result should be freed with \c OpenSSL_free()
 */
char *
CVC_get_car(const CVC_CERT *cert);
/**
 * @brief Return the CAR of a CV certificate as a string
 *
 * @param[in] cert The certificate from which we want to return the CHR
 *
 * @return CHR string or NULL in case of an error
 *
 * @note Result should be freed with \c OpenSSL_free()
 */
char *
CVC_get_chr(const CVC_CERT *cert);
/**
 * @brief Convert the effective date and expiration date,
 *        of a certificate to a string
 *
 * @param[in] cert The certificate
 *
 * @return Null terminated string representation of the date
 *
 * @note Result should be freed with \c OpenSSL_free()
 */
char *
CVC_get_effective_date(const CVC_CERT *cert);
/**
 * @brief Convert the expiration date of a certificate to a string
 *
 * @param[in] cert The certificate
 *
 * @return Null terminated string representation of the date or NULL in case
 * of an error
 *
 * @note Result should be freed with \c OpenSSL_free()
 */
char *
CVC_get_expiration_date(const CVC_CERT *cert);

/**
 * @brief Verify the signature of a CV certificate using the public key of the
 * certificate issuer
 *
 * @param[in] cert CV certificate to verify
 * @param[in] key Public key used for verification
 *
 * @return 1 if the signature was verified, 0 if not and a negative value in
 * case of an error.
 */
int
CVC_verify_signature(const CVC_CERT *cert, EVP_PKEY *key);

/**
 * @brief Check whether or not the certificate contains the correct hash of the
 * CV certificate description
 *
 * @param[in] cv CV certificate
 * @param[in] cert_desc_in ASN1 representation of the CV certificate description
 * @param[in] cert_desc_in_len Length of \a cvc_desc_in
 *
 * @return 1 if the certificate contains the correct hash, 0 if not or -1 in
 * case of an error.
 */
int
CVC_check_description(const CVC_CERT *cv, const unsigned char *cert_desc_in,
        const unsigned int cert_desc_in_len);

/** @cond */
/* I stole these from ec_asn1.c */
typedef struct x9_62_pentanomial_st {
    long k1;
    long k2;
    long k3;
    } PACE_X9_62_PENTANOMIAL;

typedef struct pace_x9_62_characteristic_two_st {
    long m;
    ASN1_OBJECT  *type;
    union   {
        char *ptr;
        /* NID_X9_62_onBasis */
        ASN1_NULL    *onBasis;
        /* NID_X9_62_tpBasis */
        ASN1_INTEGER *tpBasis;
        /* NID_X9_62_ppBasis */
        PACE_X9_62_PENTANOMIAL *ppBasis;
        /* anything else */
        ASN1_TYPE *other;
        } p;
    } PACE_X9_62_CHARACTERISTIC_TWO;

typedef struct pace_x9_62_fieldid_st {
        ASN1_OBJECT *fieldType;
    union   {
        char *ptr;
        /* NID_X9_62_prime_field */
        ASN1_INTEGER *prime;
        /* NID_X9_62_characteristic_two_field */
        PACE_X9_62_CHARACTERISTIC_TWO *char_two;
        /* anything else */
        ASN1_TYPE *other;
        } p;
    } PACE_X9_62_FIELDID;

typedef struct pace_x9_62_curve_st {
        ASN1_OCTET_STRING *a;
        ASN1_OCTET_STRING *b;
        ASN1_BIT_STRING   *seed;
        } PACE_X9_62_CURVE;

typedef struct pace_ec_parameters_st {
    ASN1_INTEGER           *version;
    PACE_X9_62_FIELDID     *fieldID;
    PACE_X9_62_CURVE       *curve;
    ASN1_OCTET_STRING *base;
    ASN1_INTEGER      *order;
    ASN1_INTEGER      *cofactor;
    } PACE_ECPARAMETERS;
/** @endcond */

#ifdef __cplusplus
}
#endif
#endif /* CVC_CERT_H_ */
