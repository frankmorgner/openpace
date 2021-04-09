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
 * @file eac_dh.h
 * @brief Interface to Diffie Hellman helper functions
 *
 * @author Frank Morgner <frankmorgner@gmail.com>
 * @author Dominik Oepen <oepen@informatik.hu-berlin.de>
 */

#ifndef PACE_DH_H_
#define PACE_DH_H_

#include <openssl/bn.h>
#include <openssl/buffer.h>
#include <openssl/dh.h>

/**
 * @brief initializes a DH key structure. If the structure is already initialized,
 * nothing is done
 *
 * @param[in/out] dh DH object to use
 * @param[in] standardizedDomainParameters specifies which parameters to use
 * (see TR-03110, p. 52)
 *
 * @return 1 on success or 0 if an error occurred
 */
int
init_dh(DH ** dh, int standardizedDomainParameters);
/**
 * @brief Computes the prime on which the modulus is based.
 *
 * If DH->q does not exist, tries to guess a Sophie Germain prime matching the
 * DH's modulus.
 *
 * @param[in] dh DH object to use
 * @param[in] ctx BN_CTX object
 *
 * @return q or NULL if an error occurred
 */
BIGNUM *
DH_get_q(const DH *dh, BN_CTX *ctx);
/**
 * @brief Computes the order of the DH's generator.
 *
 * @param[in] dh DH object to use
 * @param[in] ctx BN_CTX object (optional)
 *
 * @return order of g or NULL if an error occurred
 *
 * @note This calculation is for DHs using a safe prime, which will generate
 * either an order-q or an order-2q group (see crypto/dh/dh_gen.c:151).
 */
BIGNUM *
DH_get_order(const DH *dh, BN_CTX *ctx);
/**
 * @brief Generates a DH key pair
 *
 * @param[in] key
 * @param[in] bn_ctx BIGNUM context
 *
 * @return public key of the generated key pair or NULL if an error occurred
 */
BUF_MEM *
dh_generate_key(EVP_PKEY *key, BN_CTX *bn_ctx);
/**
 * @brief Computes a DH key
 *
 * @see PACE_STEP3B_dh_compute_key()
 */
BUF_MEM *
dh_compute_key(EVP_PKEY *key, const BUF_MEM * in, BN_CTX *bn_ctx);

/**
 * @brief Duplicate Diffie-Hellman-Parameters including parameter q.
 *
 * DHparams_dup creates a duplicated object copying only p, g and optionally
 * the length. This object is used to also copy the parameter q.
 *
 * @param dh Diffie-Hellman-Parameters
 *
 * @return Duplicate object or NULL in case of an error
 */
DH *
DHparams_dup_with_q(DH *dh);

#endif /*PACE_DH_H_*/
