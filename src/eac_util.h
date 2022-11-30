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
 * @file eac_util.h
 * @brief Interface to utility functions
 *
 * @author Frank Morgner <frankmorgner@gmail.com>
 * @author Dominik Oepen <oepen@informatik.hu-berlin.de>
 */

#ifndef PACE_UTIL_H_
#define PACE_UTIL_H_

#include <eac/eac.h>
#include <openssl/buffer.h>
#include <openssl/cmac.h>
#include <openssl/evp.h>

/**
 * @defgroup wrapper               Wrapper functions
 * @{ ************************************************************************/
/**
 * @brief Wrapper for the OpenSSL hash functions.
 *
 * @param[in] md specifies the hash function to use
 * @param[in] ctx (optional)
 * @param[in] impl (optional)
 * @param[in] in data to be hashed
 *
 * @return message digest or NULL if an error occurred
 */
BUF_MEM *
hash(const EVP_MD * md, EVP_MD_CTX * ctx, ENGINE * impl, const BUF_MEM * in);
/**
 * @brief Wrapper to the OpenSSL encryption functions.
 * Automatic padding is disabled.
 *
 * @param[in] ctx PACE context containing the cipher to use
 * @param[in] key_enc the key used for en-/decryption
 * @param[in] data the data to en-/decrypt
 * @param[in] enc specifies wether to encrypt (1) or decrypt (0)
 *
 * @return encrypted/decrypted data or NULL if an error occurred
 */
BUF_MEM *
cipher_no_pad(KA_CTX *ctx, EVP_CIPHER_CTX *cipher_ctx, const BUF_MEM *key_enc, const BUF_MEM *data, int enc);
/**
 * @brief Wrapper to the OpenSSL pseudo-random number generator.
 *
 * @param[in] numbytes number of bytes to randomize
 *
 * @return a buffer of randomized bytes or NULL if an error occurred
 */
BUF_MEM *
randb(int numbytes);
/**
 * @brief Computes message authentication code in retail-mode according to
 * ISO/IEC 9797-1 MAC algorithm 3 / padding method 2 with block cipher DES and
 * IV=0.
 *
 * @param[in] key authentication key
 * @param[in] in buffer to authenticate
 *
 * @return message authentication code or NULL if an error occurred
 */
BUF_MEM *
retail_mac_des(const BUF_MEM * key, const BUF_MEM * in);
/**
 * @brief Compute a CMAC of the input buffer using the encryption algorithm
 *           specified in the PACE context structure
 *
 * @param[in] ctx EVP_CIPHER_CTX object (optional)
 * @param[in] type contains the encryption algorithm to use
 * @param[in] key the symmetric key used for the computation. The key must have
 *           the correct length for the encryption algorithm used
 * @param[in] in buffer that contains the data to for CMAC computation
 * @param[in] maclen length in number of bytes of the MAC
 *
 * @return buffer containing the CMAC or NULL in case of error
 */
BUF_MEM *
cmac(CMAC_CTX *ctx, const EVP_CIPHER *type, const BUF_MEM * key,
        const BUF_MEM * in, size_t maclen);
/** @} ***********************************************************************/

/**
 * @defgroup encoding               Encoding
 * @{ ************************************************************************/
BUF_MEM *
add_iso_pad(const BUF_MEM * m, int block_size);

/**
 * @brief Encodes a send sequence counter according to TR-3110 F.3
 *
 * @param[in] ssc Send sequence counter to encode
 * @param[in] ctx PACE_CTX object
 * @param[out] encoded where to store the encoded SSC
 *
 * @return length of encoded SSC or -1 if an error occurred
 */
int
encode_ssc(const BIGNUM *ssc, const KA_CTX *ctx, unsigned char **encoded);

/**
 * @brief Computes the new initialisation vector according to the SSC and the
 * algorithm
 *
 * @param[in,out] ctx contains the parameters needed for the generation of the IV
 * and the IV itself
 * @param[in] ssc the send sequence counter
 *
 * @return 1 if everything worked, 0 in case of an error
 */
int
update_iv(KA_CTX *ctx, EVP_CIPHER_CTX *cipher_ctx, const BIGNUM *ssc);

/**
 * @brief Checks if str is a character string according to TR-3110 D.2.1.4 or
 * the ISO/IEC 8859­1 character set respectively
 *
 * @param[in] str The string to check
 * @param[in] length Length of the string
 *
 * @return 1 if str is a character string or 0 if it is not
 */
int
is_char_str(const unsigned char *str, const size_t length);
/**
 * @brief Checks if \c is BCD encoded
 *
 * @param[in] data buffer to check
 * @param[in] length of \a data
 *
 * @return 1 if data is BCD encoded or 0 if it is not
 */
int
is_bcd(const unsigned char *data, size_t length);
/**
 * @brief Checks if \c is a valid Certificate Holder Reference
 *
 * @param[in] data buffer to check
 * @param[in] length of \a data
 *
 * @return 1 if data is a CHR or 0 if it is not
 *
 * @see BSI TR-03110 2.05 Table A.11
 */
int
is_chr(const unsigned char *data, size_t length);
/** @} ***********************************************************************/

/**
 * @brief Authenticate data
 *
 * @param[in] ctx contains the information on how to authenticate the data
 * @param[data] the data that should be authenticated
 *
 * @return the authenticated data or NULL in case of an error
 * @note the data has to be padded correctly for this function
 */
BUF_MEM *
authenticate(const KA_CTX *ctx, const BUF_MEM *data);
int
verify_authentication_token(int protocol, const KA_CTX *ka_ctx, BN_CTX *bn_ctx,
                   enum eac_tr_version tr_version, const BUF_MEM *token);
BUF_MEM *
get_authentication_token(int protocol, const KA_CTX *ka_ctx, BN_CTX *bn_ctx,
                   enum eac_tr_version tr_version, const BUF_MEM *pub_opp);

BUF_MEM *
Comp(EVP_PKEY *key, const BUF_MEM *pub, BN_CTX *bn_ctx, EVP_MD_CTX *md_ctx);

/**
 * @brief Initializes a \c EVP_PKEY object using the standardized domain
 * parameters. This parameter can be found in the PACEInfo part of an
 * EF.CardAccess.
 *
 * @param[in,out] key The key object to initialize
 * @param[in] stnd_dp Identifier of the standardized domain parameters
 *
 * @return 1 in case of success, 0 otherwise
 */
int
EVP_PKEY_set_std_dp(EVP_PKEY *key, int stnd_dp);

/**
 * @brief Verifies an signature created with a Terminal for EAC.
 *
 * Handles plain signatures as well as X.509 signatures. In order to perform
 * ECDSA verification the data is hashed before calling \c EVP_PKEY_verify()
 * (see \c ECDSA_verify()).
 *
 * @param [in] protocol     The protocol identifier used for TA
 * @param [in] key         The terminal's parameters for signing
 * @param [in] signature The terminal's signature
 * @param [in] data         The data that was signed
 *
 * @return 1 if the signature has been verified, 0 if not or -1 in case of an error
 */
int
EAC_verify(int protocol, EVP_PKEY *key,
           const BUF_MEM *signature, const BUF_MEM *data);

/**
 * @brief Signs data for a Terminal for EAC.
 *
 * Creates plain signatures as well as X.509 signatures. In order to perform
 * ECDSA signing the data is hashed before calling \c EVP_PKEY_sign()
 * (see \c ECDSA_sign()).
 *
 * @param [in] protocol     The protocol identifier used for TA
 * @param [in] key         The terminal's parameters for signing
 * @param [in] data         The data to sign
 *
 * @return Signature or NULL in case of an error
 */
BUF_MEM *
EAC_sign(int protocol, EVP_PKEY *key, const BUF_MEM *data);

int
EVP_PKEY_set_keys(EVP_PKEY *evp_pkey,
           const unsigned char *pubkey, size_t pubkey_len,
        const unsigned char *privkey, size_t privkey_len,
           BN_CTX *bn_ctx);
BUF_MEM *
get_pubkey(EVP_PKEY *key, BN_CTX *bn_ctx);
#endif /*PACE_UTIL_H_*/
