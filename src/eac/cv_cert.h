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
 * @brief Interface for Card Verifiable Certificates
 *
 * @author Dominik Oepen <oepen@informatik.hu-berlin.de>
 * @author Frank Morgner <frankmorgner@gmail.com>
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

struct eac_ctx;

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
    /** @brief Document Verifier (non-official/foreign) */
    CVC_DocVer, /* XXX Ugly */
    /** @brief Document Verifier (official domestic) */
    CVC_DV,
    /** @brief Country Verifying Certificate Authority */
    CVC_CVCA
};

/* Number of bits and bytes of the relative authorization field in the CHAT.
 * See TR-03110 pp. 85 */
#define EAC_AT_CHAT_BYTES 5
#define EAC_AT_CHAT_BITS 38
#define EAC_IS_CHAT_BYTES 1
#define EAC_IS_CHAT_BITS 6
#define EAC_ST_CHAT_BYTES 1
#define EAC_ST_CHAT_BITS 6

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
    ASN1_OCTET_STRING *cont1;
    /** @brief Public exponent (RSA)/order of the Subgroup (DH)/first coefficient (EC) */
    ASN1_OCTET_STRING *cont2;
    /** @brief Order of the subgroup (DH)/second coefficient (EC) */
    ASN1_OCTET_STRING *cont3;
    /** @brief Generator (DH)/base point (EC) */
    ASN1_OCTET_STRING *cont4;
    /** @brief Public value (DH)/order of the base point (EC) */
    ASN1_OCTET_STRING *cont5;
    /** @brief Public point (EC) */
    ASN1_OCTET_STRING *cont6;
    /** @brief Cofactor (EC) */
    ASN1_OCTET_STRING *cont7;
} CVC_PUBKEY_BODY;
typedef CVC_PUBKEY_BODY CVC_PUBKEY;
DECLARE_ASN1_FUNCTIONS(CVC_PUBKEY)
DECLARE_ASN1_ITEM(CVC_PUBKEY)

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
DECLARE_ASN1_FUNCTIONS(CVC_CERT_BODY)
DECLARE_ASN1_ITEM(CVC_CERT_BODY)

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
    ASN1_OCTET_STRING *termsOfUsage;
    /** @brief Not used */
    ASN1_PRINTABLESTRING *redirectURL;
    /** @brief Contains hash values of admissible X.509 certificates of the remote
     *  terminal (optional) */
    CVC_COMMCERT_SEQ *commCertificates;
} CVC_CERTIFICATE_DESCRIPTION;
DECLARE_ASN1_FUNCTIONS(CVC_CERTIFICATE_DESCRIPTION)


/**
 * @brief The body of the CV certificate request (without signature)
 *
 * @see TR-03110 C.2. */
typedef struct cvc_cert_request_body_seq_st {
    /** @brief Certificate Profile of this certificate request (must be 0).
     *
     * @see TR-03110 C.2.1. */
    ASN1_INTEGER *certificate_profile_identifier;
    /** @brief Reference to certificate authority that issued this certificate request (in Latin1)
     *
     * @see TR-03110 C.2.2. */
    ASN1_UTF8STRING *certificate_authority_reference;
    /** @brief Public key associated with this certificate request
     *
     * @see TR-03110 C.2.3. */
    CVC_PUBKEY *public_key;
    /** @brief Reference to the holder of this certificate request (in Latin1)
     *
     * @see TR-03110 C.2.4. */
    ASN1_UTF8STRING *certificate_holder_reference;
    /** @brief Optional extensions
     *
     * @see TR-03110 C.2.5. */
	STACK_OF(CVC_DISCRETIONARY_DATA_TEMPLATE) *certificate_extensions;
} CVC_CERT_REQUEST_BODY_SEQ;
/** @brief Short name for CVC_CERT_REQUEST_BODY_SEQ */
typedef CVC_CERT_REQUEST_BODY_SEQ CVC_CERT_REQUEST_BODY;
DECLARE_ASN1_FUNCTIONS(CVC_CERT_REQUEST_BODY)

/**
 * @brief The actual certifcate request, consisting of the body and inner signature
 *
 *  @see TR-03110 C.2. */
typedef struct cvc_cert_request_seq_st {
    /** @brief Body of the certificate request */
    CVC_CERT_REQUEST_BODY *body;
    /** @brief Signature calculated over the hash of the certificate request body */
    ASN1_OCTET_STRING *inner_signature;
} CVC_CERT_REQUEST_SEQ;
/** @brief Short name for CVC_CERT_REQUEST_SEQ */
typedef CVC_CERT_REQUEST_SEQ CVC_CERT_REQUEST;
DECLARE_ASN1_FUNCTIONS(CVC_CERT_REQUEST)

/**
 * @brief The authentication request, consisting of the certificate request, certificate authority reference and outer signature
 *
 *  @see TR-03110 C.2. */
typedef struct cvc_cert_authentication_request_seq_st {
    /** @brief certificate request */
    CVC_CERT_REQUEST *request;
    /** @brief Reference to certificate authority that issued this authentication request (in Latin1)
     *
     * @see TR-03110 C.2.2. */
    ASN1_UTF8STRING *certificate_authority_reference;
    /** @brief Signature calculated over the hash of the certificate request */
    ASN1_OCTET_STRING *outer_signature;
} CVC_CERT_AUTHENTICATION_REQUEST_SEQ;
/** @brief Short name for CVC_CERT_AUTHENTICATION_REQUEST_SEQ */
typedef CVC_CERT_AUTHENTICATION_REQUEST_SEQ CVC_CERT_AUTHENTICATION_REQUEST;
DECLARE_ASN1_FUNCTIONS(CVC_CERT_AUTHENTICATION_REQUEST)

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
int i2d_CVC_CERT(
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  const
#endif
  CVC_CERT *a, unsigned char **out);

/**
 * @brief Duplicate a CV certificate
 *
 * @param[in] x CV certificate to duplicate
 *
 * @return Duplicated CV certificate or NULL in case of an error
 */
#define CVC_CERT_dup(x) ASN1_dup_of(CVC_CERT, i2d_CVC_CERT, CVC_d2i_CVC_CERT, x)

/**
 * @brief Duplicate a CVC public key
 *
 * @param[in] x CVC public key to duplicate
 *
 * @return Duplicated CVC public or NULL in case of an error
 */
#define CVC_PUBKEY_dup(x) ASN1_dup_of(CVC_PUBKEY, i2d_CVC_PUBKEY, d2i_CVC_PUBKEY, x)

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

/**
 * @brief Extract the public key from a CV certificate. Since EC domain parameters
 * are only included in CVCA certificates, they must be passed as parameters
 * for DV and terminal certificates
 *
 * @param[in] cert the certificate containing the public key
 * @param[in] bn_ctx
 * @param[in,out] out (optional) where to save the extracted key. May contain domain parameters.
 *
 * @return An EVP_PKEY container with the public key or NULL in case of an error
 */
EVP_PKEY *
CVC_pubkey2pkey(const CVC_CERT *cert, BN_CTX *bn_ctx, EVP_PKEY *out);

CVC_PUBKEY *
CVC_pkey2pubkey(int all_parameters, int protocol, EVP_PKEY *key,
        BN_CTX *bn_ctx, CVC_PUBKEY *out);



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
 * @brief Print CV certificate request in human readable form
 *
 * @param[in] bio Where to print the data
 * @param[in] request CV certificate request to print
 * @param[in] indent Number of spaces to prepend
 *
 * @return 1 on success or 0 in case of an error
 */
int certificate_request_print(BIO *bio,
        const CVC_CERT_REQUEST *request, int indent);

/**
 * @brief Print CV certificate authentication request in human readable form
 *
 * @param[in] bio Where to print the data
 * @param[in] request CV certificate authentication request to print
 * @param[in] indent Number of spaces to prepend
 *
 * @return 1 on success or 0 in case of an error
 */
int certificate_authentication_request_print(BIO *bio,
        const CVC_CERT_AUTHENTICATION_REQUEST *authentication, int indent);

/** @} ***********************************************************************/

/**
 *  @brief Get the CHAT contained in a CV certifcate.
 *
 *  @param[in] cvc CV certificate

 *  @return Pointer to the CHAT of \a cvc or NULL in case of an error
 */
const CVC_CHAT *
cvc_get_chat(const CVC_CERT *cvc);

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
 * @param[in] protocol Mechanism for verification
 * @param[in] key Public key used for verification
 *
 * @return 1 if the signature was verified, 0 if not and a negative value in
 * case of an error.
 */
int
CVC_verify_signature(const CVC_CERT *cert, int protocol, EVP_PKEY *key);

/**
 * @brief Verify the inner signature of a CV certificate request
 *
 * @param[in] request CV certificate request to verify
 *
 * @return 1 if the signature was verified, 0 if not and a negative value in
 * case of an error.
 */
int
CVC_verify_request_signature(const CVC_CERT_REQUEST *request);

/**
 * @brief Verify the inner and outer signature of a CV certificate request
 *
 * @param[in,out] ctx EAC context
 * @param[in] authentication CV certificate request to verify
 *
 * @return 1 if the signatures were verified, 0 if not and a negative value in
 * case of an error.
 */
int
CVC_verify_authentication_request_signatures(struct eac_ctx *ctx,
        const CVC_CERT_AUTHENTICATION_REQUEST *authentication);

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

/**
 * @brief Create a hash over a certificate's description
 *
 * @param[in] cv CV certificate
 * @param[in] cert_desc_in ASN1 representation of the CV certificate description
 * @param[in] cert_desc_in_len Length of \a cvc_desc_in
 *
 * @return hashed description or NULL in case of an error.
 */
BUF_MEM *CVC_hash_description(const CVC_CERT *cv,
        const unsigned char *cert_desc, size_t cert_desc_len);

#ifdef __cplusplus
}
#endif
#endif /* CVC_CERT_H_ */
