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
 * @file ca.h
 * @brief Interface for Chip Authentication
 *
 * Chip Authentication (CA) is a protocol which is used to
 * check the authenticity of a MRTD chip and establish a
 * secure channel for further communication. The chip contains
 * one or more key pairs used for key agreement. After successful
 * key agreement symmetric keys are derived from the shared secret.
 * OpenPACE implements CA version 2.
 *
 * @author Frank Morgner <frankmorgner@gmail.com>
 * @author Dominik Oepen <oepen@informatik.hu-berlin.de>
 */

#ifndef CA_H_
#define CA_H_

#include "eac.h"
#include <openssl/buffer.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Skip the passive authentication */
#define CA_FLAG_DISABLE_PASSIVE_AUTH 1

/**
 * @addtogroup management
 *
 * @{ ************************************************************************/

/**
 * @brief Disable passive authentication for this EAC_CTX
 *
 * @param ctx EAC context
 */
void CA_disable_passive_authentication(EAC_CTX *ctx);

/** @} ***********************************************************************/

/**
 * @brief Extract the public key from a EF.CardSecurity file
 *
 * Perform passive authentication if required.
 *
 * @param[in] ctx EAC context
 * @param[in] ef_cardsecurity buffer containing the ASN.1 encoded EF.CardSecurity
 * @param[in] ef_cardsecurity_len length of \a ef_cardsecurity
 *
 * @return The public key or NULL in case of an error
 */
BUF_MEM *
CA_get_pubkey(const EAC_CTX *ctx,
        const unsigned char *ef_cardsecurity,
        size_t ef_cardsecurity_len);

/**
 * @brief Initialize the CA context with keys
 *
 * @param[in] ctx EAC context
 * @param[in] priv (optional) Private CA key. Can be an encoded key or a raw point/integer.
 * @param[in] priv_len Length of \a priv
 * @param[in] pub (optional) Public CA key
 * @param[in] pub_len Length of \a pub
 *
 * @see See \c d2i_AutoPrivateKey() for supported encodings of \c priv
 *
 * @return 1 on success or 0 in case of an error
 */
int
CA_set_key(const EAC_CTX *ctx,
        const unsigned char *priv, size_t priv_len,
        const unsigned char *pub, size_t pub_len);
/**
 * @addtogroup caproto
 *
 * @{ ************************************************************************/

/**
 * @brief Get the PICC's encoded public key.
 *
 * @param[in] ctx EAC context
 *
 * @return Encoded public key or NULL in case of an error
 *
 * @see <a href="http://frankmorgner.github.io/openpace/protocols.html#id4">CA's Protocol Specification</a>
 */
BUF_MEM *
CA_STEP1_get_pubkey(const EAC_CTX *ctx);
/**
 * @brief Get the PCD's ephemeral public key (generated in TA step 3)
 *
 * @param[in] ctx EAC context
 *
 * @return Public key or NULL in case of an error
 *
 * @see <a href="http://frankmorgner.github.io/openpace/protocols.html#id4">CA's Protocol Specification</a>
 */
BUF_MEM *
CA_STEP2_get_eph_pubkey(const EAC_CTX *ctx);
/**
 * @brief Check whether the public key matches the compressed public key
 * previously received in TA
 *
 * @param[in] ctx EAC context
 * @param[in] comp_pubkey Compressed public key (received in TA step 3)
 * @param[in] pubkey Uncompressed public key (received in CA step 2)
 *
 * @return 1 if the keys match, 0 if they don't or -1 in case of an error
 *
 * @see <a href="http://frankmorgner.github.io/openpace/protocols.html#id4">CA's Protocol Specification</a>
 */
int
CA_STEP3_check_pcd_pubkey(const EAC_CTX *ctx,
        const BUF_MEM *comp_pubkey, const BUF_MEM *pubkey);
/**
 * @brief Compute the shared secret using the PICC's static key pair and the
 * PCD's ephemeral key pair.
 *
 * @param[in,out] ctx EAC context. The secret is saved in \a ctx.
 * @param[in] pubkey Public key from the other party
 *
 * @return 1 on success or 0 in case of an error
 *
 * @see \c CA_get_pubkey() extracts the PICC's public key from an \c EF.CardSecurity
 *
 * @see <a href="http://frankmorgner.github.io/openpace/protocols.html#id4">CA's Protocol Specification</a>
 */
int
CA_STEP4_compute_shared_secret(const EAC_CTX *ctx, const BUF_MEM *pubkey);

/**
 * @brief Derives the PICC's encryption and authentication keys
 *
 * @param[in,out] ctx EAC context. The keys are saved in \a ctx.
 * @param[in]  pub   PCD's ephemeral public key
 * @param[out] nonce Generated nonce
 * @param[out] token Authentication token
 *
 * @return 1 on success or 0 in case of an error
 *
 * @see <a href="http://frankmorgner.github.io/openpace/protocols.html#id4">CA's Protocol Specification</a>
 */
int
CA_STEP5_derive_keys(const EAC_CTX *ctx, const BUF_MEM *pub,
                   BUF_MEM **nonce, BUF_MEM **token);

/**
 * @brief Derives the PCD's encryption and authentication keys
 *
 * @param[in,out] ctx EAC context. The keys are saved in \a ctx.
 * @param[in] nonce PICC's generated nonce
 * @param[in] token PICC's authentication token to verify
 *
 * @return 1 on success or 0 in case of an error
 *
 * @see <a href="http://frankmorgner.github.io/openpace/protocols.html#id4">CA's Protocol Specification</a>
 */
int
CA_STEP6_derive_keys(EAC_CTX *ctx, const BUF_MEM *nonce, const BUF_MEM *token);

/** @} ***********************************************************************/

#ifdef  __cplusplus
}
#endif
#endif
