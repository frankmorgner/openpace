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
 * @file eac.h
 * @brief Interface for Extended Access Control
 *
 * @author Frank Morgner <morgner@informatik.hu-berlin.de>
 * @author Dominik Oepen <oepen@informatik.hu-berlin.de>
 */

#ifndef EAC_H_
#define EAC_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "cv_cert.h"
#include <openssl/asn1.h>
#include <openssl/buffer.h>
#include <openssl/cmac.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

/** Identification of the specifications to use.
 * @note TR-03110 v2.01 differs from all later versions of the Technical
 * Guideline in how the authentication token is calculated. Therefore old test
 * cards are incompatible with the newer specification.
 */
enum eac_tr_version {
    /** Undefined type, if nothing else matches */
    EAC_TR_VERSION = 0,
    /** Perform EAC according to TR-03110 v2.01 */
    EAC_TR_VERSION_2_01,
    /** Perform EAC according to TR-03110 v2.02 and later */
    EAC_TR_VERSION_2_02,
};

/**
 * @brief Context for a key agreement and subsequent derivation of session
 * keys.
 * @note The key agreement itself is usually done via an underlying DH or ECDH.
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
 *
 * Encompasses information about cipher, message digest, key agreement scheme,
 * mapping method.
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
 *
 * Encompasses information about hash function, message digest, key agreement scheme,
 * mapping method.
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
    int flags;
} TA_CTX;

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
    /** @brief Key agreement object used with the PICC's private key */
    KA_CTX *ka_ctx;
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
    /** @brief Context for the Password Authenticated Connection Establishment protocol */
    PACE_CTX *pace_ctx;
    /** @brief Context for the Restricted Identification protocol */
    RI_CTX *ri_ctx;
    /** @brief Context for the Terminal Authentication protocol */
    TA_CTX *ta_ctx;
    /** @brief Context for the Chip Authentication protocol */
    CA_CTX *ca_ctx;
    /** @brief Context for secure messaging established with PACE or CA */
    KA_CTX *key_ctx;
} EAC_CTX;

/** @brief TR-03110 always uses CMAC of 8 bytes length for AES MAC */
#define EAC_AES_MAC_LENGTH 8

/**
 * @addtogroup management
 *
 * @{ ************************************************************************/

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
 * @param[in] cert (optional) CV certificate to use as trust anchor for verification
 * @param[in] cert_len (optional) Length of \a cert
 * @param[in] car (optional) Certificate Authorisation Reference
 * @param[in] car_len (optional) Length of \a car
 *
 * @return 1 on success or 0 in case of an error
 */
int
EAC_CTX_init_ta(const EAC_CTX *ctx,
           const unsigned char *privkey, size_t privkey_len,
           const unsigned char *cert, size_t cert_len,
           const unsigned char *car, size_t car_len);

/**
  * @brief Initialize an EAC context for Chip Authentication
  *
  * @param[in, out] ctx EAC context
  * @param[in] protocol Identifier of the protocol's OID specifying the exact CA parameters to use
  * @param[in] curve Standardized domain parameter identifier
  * @param[in] priv (optional) Private CA key
  * @param[in] priv_len Length of \a priv
  * @param[in] pub Public CA key
  * @param[in] pub_len Length of \a pub
  *
  * @return 1 on success or 0 in case of an error
  *
  * @see CA_CTX.protocol lists possible values for \a protocol
  */
int EAC_CTX_init_ca(const EAC_CTX *ctx, int protocol, int curve,
                const unsigned char *priv, size_t priv_len,
                const unsigned char *pub, size_t pub_len);

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
int EAC_CTX_init_ef_cardaccess(unsigned const char * in, unsigned int in_len,
        EAC_CTX *ctx);

/** @} ***********************************************************************/

/**
 * @addtogroup sm
 *
 * @{ ************************************************************************/

/**
 * @brief Pad a buffer using ISO/IEC 9797-1 padding method 2.
 *
 * @param[in] m Buffer to pad
 * @param[in] block_size Pad to this block size
 *
 * @return Padded input or NULL in case of an error
 */
BUF_MEM *
EAC_add_iso_pad(const BUF_MEM * m, int block_size);

/**
 * @brief Encrypts data according to TR-03110 F.2.
 *
 * \a ssc is used to generate initialization vector for encryption.
 *
 * @param[in] ctx EAC context
 * @param[in] ssc Send sequence counter
 * @param[in] data Data to encrypt
 *
 * @return Encrypted data or NULL in case of an error
 *
 * @note \a data must already be padded to block length
 */
BUF_MEM *
EAC_encrypt(const EAC_CTX *ctx, const BIGNUM *ssc, const BUF_MEM *data);

/**
 * @brief Decrypt data according to TR-03110 F.2.
 *
 * \a ssc is used to generate initialisation vector for decryption.
 *
 * @param[in] ctx EAC context
 * @param[in] ssc Send sequence counter
 * @param[in] data Data to decrypt
 *
 * @return Decrypted data or NULL in case of an error
 *
 * @note \a data must already be padded to block length
 */
BUF_MEM *
EAC_decrypt(const EAC_CTX *ctx, const BIGNUM *ssc, const BUF_MEM *data);

/**
 * @brief Authenticate data according to TR-03110 F.2.
 *
 * \a ssc is encoded and prepended to the data.
 *
 * @param[in] ctx EAC context
 * @param[in] ssc Send sequence counter
 * @param[in] data Data to authenticate
 * @param[in] datalen Length of \a data
 *
 * @return MAC or NULL in case of an error
 *
 * @note \a data must already be padded to block length
 */
BUF_MEM *
EAC_authenticate(const EAC_CTX *ctx, const BIGNUM *ssc, const BUF_MEM *data);

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

/** @} ***********************************************************************/

#endif
