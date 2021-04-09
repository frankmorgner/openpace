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
 * @file eac.h
 * @brief Interface for Extended Access Control
 *
 * @author Frank Morgner <frankmorgner@gmail.com>
 * @author Dominik Oepen <oepen@informatik.hu-berlin.de>
 */

#ifndef EAC_H_
#define EAC_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <eac/cv_cert.h>
#include <eac/objects.h>
#include <openssl/asn1.h>
#include <openssl/buffer.h>
#include <openssl/cmac.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

/** @defgroup management Data Management and Initialization
 *  @defgroup printing Data Printing
 *  @defgroup eacproto Protocol Steps for Extended Access Control
 *  @{
 *      @defgroup paceproto  Protocol Steps for Password Authenticated Connection Establishment
 *      @defgroup taproto Protocol Steps for Terminal Authentication
 *      @defgroup caproto Protocol Steps for Chip Authentication
 *      @defgroup riproto Protocol Steps for Restricted Authentication
 *  @}
 *  @defgroup sm Cryptographic Wrappers for Secure Messaging
 */


/**
 * @brief Identification of the specifications to use.
 *
 * @note TR-03110 v2.01 differs from all later versions of the Technical
 * Guideline in how the authentication token is calculated. Therefore old test
 * cards are incompatible with the newer specification.
 */
enum eac_tr_version {
    /** @brief Undefined type, if nothing else matches */
    EAC_TR_VERSION = 0,
    /** @brief Perform EAC according to TR-03110 v2.01 */
    EAC_TR_VERSION_2_01,
    /** @brief Perform EAC according to TR-03110 v2.02 and later */
    EAC_TR_VERSION_2_02,
};

/**
 * @brief Context for a key agreement and subsequent derivation of session
 * keys.
 * @note The key agreement itself is done via an underlying DH or ECDH.
 */
typedef struct ka_ctx {
        /** @brief Digest to use for key derivation */
        const EVP_MD * md;
        /** @brief Digest's engine */
        ENGINE * md_engine;
        /** @brief Context for CMAC */
        CMAC_CTX * cmac_ctx;
        /** @brief Cipher to use for encryption/decryption */
        const EVP_CIPHER * cipher;
        /** @brief Cipher's engine */
        ENGINE * cipher_engine;
        /** @brief Initialisation vector for encryption/decryption */
        unsigned char * iv;
        /** @brief Length of the computed key for the message authentication code */
        int mac_keylen;
        /** @brief Length of the computed key for the encryption/decryption */
        int enc_keylen;

         /**
         * @brief Generates a key pair for key agreement.
         *
         * @param[in] key Object for key generation, usually \c &KA_CTX.key
         * @param[in] bn_ctx (optional)
         *
         * @return Public key or NULL in case of an error
         */
        BUF_MEM * (*generate_key)(EVP_PKEY *key, BN_CTX *bn_ctx);
        /**
         * @brief Completes a key agreement by computing the shared secret
         *
         * @param[in] key Object for key computation, usually \c &KA_CTX.key
         * @param[in] in Public key from the other party
         * @param[in] bn_ctx (optional)
         *
         * @return Shared secret or NULL in case of an error
         */
        BUF_MEM * (*compute_key)(EVP_PKEY *key, const BUF_MEM *in, BN_CTX *bn_ctx);

        /** @brief Container for the key pair used for key agreement */
        EVP_PKEY *key;

        /** @brief Shared secret computed during the key agreement protocol */
        BUF_MEM *shared_secret;
        /** @brief Symmetric key used for encryption/decryption. Derived from KA_CTX.shared_secret. */
        BUF_MEM *k_enc;
        /** @brief Symmetric key used for integrity protection. Derived from KA_CTX.shared_secret. */
        BUF_MEM *k_mac;
} KA_CTX;

/** @brief Context for the Password Authenticated Connection Establishment protocol
 */
typedef struct pace_ctx {
    /** @brief Identifier of the protocol's OID specifying the exact PACE parameters
     * to use
     *
     * The OID of the \c PACEInfo structure in the \c EF.CardAccess is used,
     * because it is more specific than the OID contained in the (optional) \c
     * PaceDomainParameterInfo structures.
     *
     * Accepts the following values:
     * - \c NID_id_PACE_DH_GM_3DES_CBC_CBC
     * - \c NID_id_PACE_DH_GM_AES_CBC_CMAC_128
     * - \c NID_id_PACE_DH_GM_AES_CBC_CMAC_192
     * - \c NID_id_PACE_DH_GM_AES_CBC_CMAC_256
     * - \c NID_id_PACE_ECDH_GM_3DES_CBC_CBC
     * - \c NID_id_PACE_ECDH_GM_AES_CBC_CMAC_128
     * - \c NID_id_PACE_ECDH_GM_AES_CBC_CMAC_192
     * - \c NID_id_PACE_ECDH_GM_AES_CBC_CMAC_256
     * - \c NID_id_PACE_DH_IM_3DES_CBC_CBC
     * - \c NID_id_PACE_DH_IM_AES_CBC_CMAC_128
     * - \c NID_id_PACE_DH_IM_AES_CBC_CMAC_192
     * - \c NID_id_PACE_DH_IM_AES_CBC_CMAC_256
     * - \c NID_id_PACE_ECDH_IM_3DES_CBC_CBC
     * - \c NID_id_PACE_ECDH_IM_AES_CBC_CMAC_128
     * - \c NID_id_PACE_ECDH_IM_AES_CBC_CMAC_192
     * - \c NID_id_PACE_ECDH_IM_AES_CBC_CMAC_256
     */
    int protocol;
    /** @brief (currently unused) Version of the PACE protocol, MUST be 1 or 2 */
    unsigned char version;
    /** @brief identifier of this PACE context */
    int id;
    /** @brief Points to the implementation of a specific mapping
     *
     * @see PACE_STEP3A_generate_mapping_data() */
    BUF_MEM * (*map_generate_key)(const struct pace_ctx *ctx, BN_CTX *bn_ctx);
    /** @brief Points to the implementation of a specific mapping
     *
     * @see PACE_STEP3A_map_generator() */
    int (*map_compute_key)(struct pace_ctx * ctx, const BUF_MEM * s,
                    const BUF_MEM * in, BN_CTX *bn_ctx);

    /** @brief PICC's static domain parameters */
    EVP_PKEY *static_key;
    /** @brief Key agreement object used with the ephemeral domain parameters */
    KA_CTX *ka_ctx;
    /** @brief PICC's decrypted challenge generated in PACE step 1 */
    BUF_MEM *nonce;
    /** @brief The own ephemeral public key generated in PACe step 3b */
    BUF_MEM *my_eph_pubkey;
} PACE_CTX;

/** @brief Context for the Restricted Identification protocol
 */
typedef struct ri_ctx {
    /** @brief Identifier of the hash function
     * to use
     *
     * see tr 03110 p. 60
     * - \c NID_id_RI_DH_SHA_1
     * - \c NID_id_RI_DH_SHA_224
     * - \c NID_id_RI_DH_SHA_256
     * - \c NID_id_RI_DH_SHA_384
     * - \c NID_id_RI_DH_SHA_512
     * - \c NID_id_RI_ECDH_SHA_1
     * - \c NID_id_RI_ECDH_SHA_224
     * - \c NID_id_RI_ECDH_SHA_256
     * - \c NID_id_RI_ECDH_SHA_384
     * - \c NID_id_RI_ECDH_SHA_512
     */
    int protocol;
    /** @brief identifier of this RI context */
    int id;
    /** @brief Digest to use for derivation of I^{sector}_{ID} */
    const EVP_MD * md;
    /**
    * @brief Generates a key pair for key agreement.
    *
    * @param[in] key Object for key generation, usually \c &KA_CTX.key
    * @param[in] bn_ctx (optional)
    *
    * @return Public key or NULL in case of an error
    */
    BUF_MEM * (*generate_key)(EVP_PKEY *key, BN_CTX *bn_ctx);
    /**
     * @brief Completes a key agreement by computing the shared secret
     *
     * @param[in] key Object for key computation, usually \c &KA_CTX.key
     * @param[in] in Public key from the other party
     * @param[in] bn_ctx (optional)
     *
     * @return Shared secret or NULL in case of an error
     */
    BUF_MEM * (*compute_key)(EVP_PKEY *key, const BUF_MEM *in, BN_CTX *bn_ctx);
    /** @brief PICC's static domain parameters */
    EVP_PKEY *static_key;
} RI_CTX;

/** @brief callback for finding the CVCA trust anchor */
typedef CVC_CERT * (*CVC_lookup_cvca_cert) (const unsigned char *chr, size_t car_len);

/** @brief Context for the Terminal Authentication protocol */
typedef struct ta_ctx {
    /** @brief (currently unused) Version of the TA protocol, MUST be 1 or 2 */
    unsigned char version;
    /** @brief Identifier of the protocol's OID specifying the exact TA
     * parameters to use.
     *
     * Accepts the following values:
     * - \c NID_id_TA_RSA_v1_5_SHA_1
     * - \c NID_id_TA_RSA_v1_5_SHA_256
     * - \c NID_id_TA_RSA_PSS_SHA_1
     * - \c NID_id_TA_RSA_PSS_SHA_256
     * - \c NID_id_TA_RSA_v1_5_SHA_512
     * - \c NID_id_TA_RSA_PSS_SHA_512
     * - \c NID_id_TA_ECDSA_SHA_1
     * - \c NID_id_TA_ECDSA_SHA_224
     * - \c NID_id_TA_ECDSA_SHA_256
     * - \c NID_id_TA_ECDSA_SHA_384
     * - \c NID_id_TA_ECDSA_SHA_512
     */
    int protocol;
    /** @brief (currently unused) engine for signing and signature verification */
    ENGINE *key_engine;
    /** @brief TA private key used for signing the challenge */
    EVP_PKEY *priv_key;
    /** @brief TA public key used for signing the challenge */
    EVP_PKEY *pub_key;
    /** @brief PCD's public key extracted from it's CV certificate */
    BUF_MEM *pk_pcd;
    /** @brief PICC's challenge */
    BUF_MEM *nonce;
    /** @brief Trust anchor for CV certificate validation */
    CVC_CERT *trust_anchor;
    /** @brief Most recent verified CV certificate in a certificate chain */
    CVC_CERT *current_cert;
    /** @brief When a complete CV certificate chain has been verified, this will be the new trust anchor */
    CVC_CERT *new_trust_anchor;
    /** @brief Flags to control some of the behaviour of the CA
     *
     * Accepts the following values:
     * - \c TA_FLAG_SKIP_TIMECHECK
     */
    int flags;

    /** @brief Lookup the CVCA trust anchor
     *
     * This function is called when a CV certificate is imported although the
     * terminal authentication was not initialized with a trust anchor.
     *
     * @see TA_STEP2_import_certificate()
     * */
    CVC_lookup_cvca_cert lookup_cvca_cert;
} TA_CTX;

/** @brief callback for finding the X.509 trust anchor */
typedef X509_STORE * (*X509_lookup_csca_cert) (unsigned long issuer_name_hash);

/** @brief Context for the Chip Authentication protocol */
typedef struct ca_ctx {
    /** @brief (currently unused) Version of the CA protocol, MUST be 1 or 2 */
    unsigned char version;
    /** @brief Identifier of the protocol's OID specifying the exact CA parameters to use.
     *
     * Accepts the following values:
     * - \c NID_id_CA_DH_3DES_CBC_CBC
     * - \c NID_id_CA_DH_AES_CBC_CMAC_128
     * - \c NID_id_CA_DH_AES_CBC_CMAC_192
     * - \c NID_id_CA_DH_AES_CBC_CMAC_256
     * - \c NID_id_CA_ECDH_3DES_CBC_CBC
     * - \c NID_id_CA_ECDH_AES_CBC_CMAC_128
     * - \c NID_id_CA_ECDH_AES_CBC_CMAC_192
     * - \c NID_id_CA_ECDH_AES_CBC_CMAC_256
     */
    int protocol;
    /** @brief identifier of this CA context */
    int id;
    /** @brief Flags to control some of the behaviour of the CA
     *
     * Accepts the following values:
     * - \c CA_FLAG_DISABLE_PASSIVE_AUTH
     */
    int flags;
    /** @brief Key agreement object used with the PICC's private key */
    KA_CTX *ka_ctx;

    /** @brief callback for finding the X.509 trust anchor
     *
     * This function is called when passive authentication with the signed
     * public key of the card.
     *
     * @see CA_get_pubkey()
     * */
    X509_lookup_csca_cert lookup_csca_cert;
} CA_CTX;

/** @brief Context for the Extended Access Control protocol */
typedef struct eac_ctx {
    /** @brief Perform EAC conforming to this version of TR-03110 */
    enum eac_tr_version tr_version;
    /** @brief Context for various operations with \c BIGNUM objects */
    BN_CTX * bn_ctx;
    /** @brief Context for various hashing operations */
    EVP_MD_CTX * md_ctx;
    /** @brief Context for various cipher operations */
    EVP_CIPHER_CTX * cipher_ctx;
    /** @brief Context for the currently selected Password Authenticated Connection Establishment protocol
     *
     * Points to an element of \c pace_ctxs */
    PACE_CTX *pace_ctx;
    /** @brief stack of available Password Authenticated Connection Establishment configurations */
    STACK_OF(PACE_CTX *) pace_ctxs;
    /** @brief Context for the currently selected Restricted Identification protocol
     *
     * Points to an element of \c ri_ctxs */
    RI_CTX *ri_ctx;
    /** @brief stack of available Restricted Identification configurations */
    STACK_OF(RI_CTX *) ri_ctxs;
    /** @brief Context for the currently selected Terminal Authentication protocol */
    TA_CTX *ta_ctx;
    /** @brief Context for the currently selected Chip Authentication protocol
     *
     * Points to an element of \c ca_ctxs */
    CA_CTX *ca_ctx;
    /** @brief stack of available Chip Authentication configurations */
    STACK_OF(CA_CTX *) ca_ctxs;
    /** @brief Context for currently selected secure messaging established with PACE or CA */
    KA_CTX *key_ctx;
    /** @brief Send sequence counter */
    BIGNUM *ssc;
} EAC_CTX;

/** @brief TR-03110 always uses CMAC of 8 bytes length for AES MAC */
#define EAC_AES_MAC_LENGTH 8

/**
 * @addtogroup management
 *
 * @{ ************************************************************************/

/**
 * @brief Initializes OpenSSL and the EAC identifier
 *
 * @see \c OpenSSL_add_all_algorithms()
 */
void EAC_init(void);

/**
 * @brief Wrapper to \c EVP_cleanup()
 */
void EAC_cleanup(void);

/**
 * @brief Create a new EAC context
 * @return New EAC context or NULL in case of an error
 */
EAC_CTX *
EAC_CTX_new(void);

/**
 * @brief Free an EAC context.
 *
 * Sensitive memory is cleared with OPENSSL_cleanse().
 *
 * @param[in] ctx EAC context to free
 */
void EAC_CTX_clear_free(EAC_CTX *ctx);

/**
 * @brief Initialize an EAC context for PACE
 *
 * @param[in,out] ctx EAC context to initialize
 * @param[in] protocol Identifier of the protocol's OID specifying the exact PACE parameters
 * @param[in] curve Standardized domain parameter identifier
 *
 * @return 1 on success or 0 in case of an error
 *
 * @see PACE_CTX.protocol lists possible values for \a protocol
 */
int
EAC_CTX_init_pace(EAC_CTX *ctx, int protocol, int curve);

/**
 * @brief Initialize an EAC context for TA with the terminal's PKI data. Use
 * either a CV certificate or a known CAR for initialization.
 *
 * @param[in,out] ctx EAC context
 * @param[in] privkey (optional) Private key to the given CV certificate
 * @param[in] privkey_len Length of \a privkey
 * @param[in] cvca (optional) CV certificate to use as trust anchor for verification of other CV certificates
 * @param[in] cvca_len (optional) Length of \a cvca
 *
 * @return 1 on success or 0 in case of an error
 */
int
EAC_CTX_init_ta(const EAC_CTX *ctx,
           const unsigned char *privkey, size_t privkey_len,
           const unsigned char *cvca, size_t cvca_len);

/**
  * @brief Initialize an EAC context for Chip Authentication
  *
  * @param[in, out] ctx EAC context
  * @param[in] protocol Identifier of the protocol's OID specifying the exact CA parameters to use
  * @param[in] curve Standardized domain parameter identifier
  *
  * @return 1 on success or 0 in case of an error
  *
  * @see CA_CTX.protocol lists possible values for \a protocol
  */
int EAC_CTX_init_ca(EAC_CTX *ctx, int protocol, int curve);

/**
 * @brief Initialize an EAC context for Restricted Identification
 *
 * @param[in, out] ctx EAC context
 * @param[in] protocol protocol Identifier of the protocol's OID specifying the exact RI parameters to use
 * @param[in] stnd_dp Standardized domain parameter identifier
 *
 * @return 1 on success or 0 in case of an error
 *
 * @see RI_CTX.protocol lists possible values for \a protocol
 */
int
EAC_CTX_init_ri(EAC_CTX *ctx, int protocol, int stnd_dp);

/**
 * @brief Initialize an EAC context for PACE, TA and CA from the data
 * given in an \c EF.CardAccess
 *
 * @param[in] in \c EF.CardAccess
 * @param[in] in_len Length of \a in
 * @param[in,out] ctx EAC context to initialize
 *
 * @return 1 on success or 0 in case of an error
 */
int EAC_CTX_init_ef_cardaccess(unsigned const char * in, size_t in_len,
        EAC_CTX *ctx);

/**
 * @brief Initialize an EAC context for PACE, TA and CA from the data
 * given in an \c EF.CardSecurity
 *
 * Performs passive authentication if required.
 *
 * @param[in] ef_cardsecurity buffer containing the ASN.1 encoded EF.CardSecurity
 * @param[in] ef_cardsecurity_len length of \a ef_cardsecurity
 * @param[in,out] ctx EAC context to initialize
 *
 * @return 1 on success or 0 in case of an error
 */
int EAC_CTX_init_ef_cardsecurity(
        const unsigned char *ef_cardsecurity, size_t ef_cardsecurity_len,
        EAC_CTX *ctx);

/**
 * @brief Return the EAC context's CVCA lookup callback
 *
 * @param[in] ctx EAC context
 * @param[in,out] lookup_cvca_cert lookup callback
 *
 * @return 1 on success or 0 in case of an error
 */
int EAC_CTX_get_cvca_lookup(const EAC_CTX *ctx, CVC_lookup_cvca_cert *lookup_cvca_cert);
/**
 * @brief Set the CVCA lookup callback
 *
 * @param[in] ctx EAC context
 * @param[in] lookup_cvca_cert lookup callback
 *
 * @return 1 on success or 0 in case of an error
 */
int EAC_CTX_set_cvca_lookup(EAC_CTX *ctx, CVC_lookup_cvca_cert lookup_cvca_cert);
/**
 * @brief Return the default lookup of the country verifying CA
 *
 * The default callback looks at /etc/eac/$issuer_name_hash.cer for the CSCA
 * certificate, where $issuer_name_hash is an eight character lower hex value
 * of the CSCA subject name.
 *
 * @return default lookup of the country verifying CA
 *
 * @see `openssl x509 -in CERTIFICATE.cer -inform DER -hash -noout` to obtain the hash value.
 */
CVC_lookup_cvca_cert EAC_get_default_cvca_lookup(void);

/**
 * @brief Set directory for \c EAC_get_default_cvca_lookup()
 *
 * @param cvc_default_dir
 */
void EAC_set_cvc_default_dir(const char *default_dir);

/**
 * @brief Get the CSCA lookup callback
 *
 * @param[in] ctx EAC context
 * @param[in,out] lookup_cvca_cert lookup callback
 *
 * @return 1 on success or 0 in case of an error
 */
int EAC_CTX_get_csca_lookup_cert(const EAC_CTX *ctx, X509_lookup_csca_cert *lookup_cvca_cert);
/**
 * @brief Set the CSCA lookup callback
 *
 * @param[in] ctx EAC context
 * @param[in] lookup_cvca_cert lookup callback
 *
 * @return 1 on success or 0 in case of an error
 */
int EAC_CTX_set_csca_lookup_cert(EAC_CTX *ctx, X509_lookup_csca_cert lookup_cvca_cert);
/**
 * @brief Return the default lookup of the country signing CA
 *
 * The default callback looks at /etc/eac/$chr for the CVCA
 * certificate, where $chr is the card holder reference of the CVCA.
 *
 * @return default lookup of the country verifying CA
 */
X509_lookup_csca_cert EAC_get_default_csca_lookup(void);

/**
 * @brief Set directory for \c EAC_get_default_csca_lookup()
 *
 * @param x509_default_dir
 */
void EAC_set_x509_default_dir(const char *default_dir);

/** @} ***********************************************************************/

/**
 * @addtogroup sm
 *
 * @{ ************************************************************************/

/**
 * @brief Pad a buffer using ISO/IEC 9797-1 padding method 2.
 *
 * The block size is calculated from the currently selected SM context.
 *
 * @param[in] ctx EAC context
 * @param[in] unpadded Buffer to pad
 *
 * @return Padded input or NULL in case of an error
 */
BUF_MEM *
EAC_add_iso_pad(const EAC_CTX *ctx, const BUF_MEM * unpadded);
/**
 * @brief Remove ISO/IEC 9797-1 padding method 2 from a message
 *
 * @param[in] padded Padded message
 *
 * @return Unpadded message or NULL in case of an error
 */
BUF_MEM *
EAC_remove_iso_pad(const BUF_MEM * padded);

/**
 * @brief Increment the Send Sequence Counter
 *
 * @param ctx
 *
 * @return 1 on success or 0 in case of an error
 */
int EAC_increment_ssc(const EAC_CTX *ctx);

/**
 * @brief Reset the Send Sequence Counter
 *
 * @param ctx
 *
 * @return 1 on success or 0 in case of an error
 */
int EAC_reset_ssc(const EAC_CTX *ctx);
/**
 * @brief Set the Send Sequence Counter
 *
 * @param ctx
 * @param ssc
 *
 * @return 1 on success or 0 in case of an error
 */
int EAC_set_ssc(const EAC_CTX *ctx, unsigned long ssc);

/**
 * @brief Encrypts data according to TR-03110 F.2.
 *
 * @param[in] ctx EAC context
 * @param[in] data Data to encrypt
 *
 * @return Encrypted data or NULL in case of an error
 *
 * @note \a data must already be padded to block length
 */
BUF_MEM *
EAC_encrypt(const EAC_CTX *ctx, const BUF_MEM *data);

/**
 * @brief Decrypt data according to TR-03110 F.2.
 *
 * @param[in] ctx EAC context
 * @param[in] data Data to decrypt
 *
 * @return Decrypted data or NULL in case of an error
 *
 * @note \a data must already be padded to block length
 */
BUF_MEM *
EAC_decrypt(const EAC_CTX *ctx, const BUF_MEM *data);

/**
 * @brief Authenticate data according to TR-03110 F.2.
 *
 * @param[in] ctx EAC context
 * @param[in] data Data to authenticate
 *
 * @return MAC or NULL in case of an error
 *
 * @note \a data must already be padded to block length
 */
BUF_MEM *
EAC_authenticate(const EAC_CTX *ctx, const BUF_MEM *data);
/**
 * @brief Verify authenticated data according to TR-03110 F.2
 *
 * @param[in] ctx EAC context
 * @param[in] data Data to authenticate
 * @param[in] mac The MAC that is going to be verified
 *
 * @return 1 if the MAC can be correctly verified, 0 otherwise
 */
int
EAC_verify_authentication(const EAC_CTX *ctx, const BUF_MEM *data,
        const BUF_MEM *mac);

/**
 * @brief Compresse a public key according to TR-03110 Table A.2.
 *
 * @param[in] ctx EAC context
 * @param[in] id accepts \c EAC_ID_PACE, \c EAC_ID_CA, \c EAC_ID_TA
 * @param[in] pub Raw public key
 *
 * @return Compressed public key or NULL in case of an error
 */
BUF_MEM *
EAC_Comp(const EAC_CTX *ctx, int id, const BUF_MEM *pub);

/**
 * @brief Compute the hash of a CV certificate description.
 *
 * The hash can then be compared to the hash contained in the corresponding CV
 * certificate.
 *
 * @param[in] cert_desc ASN1 encoded CV certificate description
 * @param[in] cert_desc_len Length of \a cert_desc
 *
 * @return Hash of \a cert_desc or NULL in case of an error
 */
BUF_MEM *
EAC_hash_certificate_description(const unsigned char *cert_desc,
        size_t cert_desc_len);

/** @brief Identifies the PACE context */
#define EAC_ID_PACE 0
/** @brief Identifies the CA context */
#define EAC_ID_CA 1
/** @brief Identifies the TA context */
#define EAC_ID_TA 2
/** @brief Identifies the currently used channel for encryption/decryption */
#define EAC_ID_EAC 3

/**
 * @brief Set the SM context for encryption, decryption and authentication.
 *
 * Calls \a EAC_reset_ssc()
 *
 * @param[in,out] ctx EAC context
 * @param[in] id accepts \c EAC_ID_PACE, \c EAC_ID_CA, \c EAC_ID_EAC
 *
 * @return 1 on success or 0 in case of an error
 */
int
EAC_CTX_set_encryption_ctx(EAC_CTX *ctx, int id);

/** @} ***********************************************************************/

/**
 * @addtogroup printing
 *
 * @{ ************************************************************************/

/**
 * @brief Print EAC context including private data.
 *
 * @param[in] out Where to print the data
 * @param[in] ctx EAC context to be printed
 * @param[in] indent Number of whitespaces used for indenting the output
 *
 * @return 1 on success or 0 in case of an error
 */
int EAC_CTX_print_private(BIO *out, const EAC_CTX *ctx, int indent);
/**
 * @brief Prints buffer
 *
 * @param[in] out Where to print the data
 * @param[in] buf Buffer to print
 * @param[in] indent Number of whitespaces used for indenting the output
 *
 * @return 1 on success or 0 in case of an error
 */
int BUF_MEM_print(BIO *out, const BUF_MEM *buf, int indent);

/**
 * @brief Frees and wipes a buffer
 *
 * Calls \c OPENSSL_cleanse() and \c BUF_MEM_free().
 *
 * @param[in] b Where to print the data
 *
 */
void
BUF_MEM_clear_free(BUF_MEM *b);

/** @} ***********************************************************************/
#ifdef __cplusplus
}
#endif
#endif
