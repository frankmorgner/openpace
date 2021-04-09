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
 * @file eac_ecdh.h
 * @brief Interface to elliptic curve Diffie Hellman helper functions
 *
 * @author Frank Morgner <frankmorgner@gmail.com>
 * @author Dominik Oepen <oepen@informatik.hu-berlin.de>
 */

#ifndef PACE_ECDH_H_
#define PACE_ECDH_H_

#include <openssl/bn.h>
#include <openssl/buffer.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
/**
 * @brief initializes a key for ECDH. If the object is already initialised,
 * nothing is don
 *
 * @param[in/out] ecdh elliptic curve object to use
 * @param[in] standardizedDomainParameters specifies which parameters to use
 * (see TR-03110, p. 52)
 *
 * @return 1 on success or 0 if an error occurred
 */
int
init_ecdh(EC_KEY ** ecdh, int standardizedDomainParameters);
/**
 * @brief Generates an ECDH keypair
 *
 * @param[in] key
 * @param[in] bn_ctx BIGNUM context
 *
 * @return public key of the generated keypair or NULL if an error occurred
 */
BUF_MEM *
ecdh_generate_key(EVP_PKEY *key, BN_CTX *bn_ctx);
/**
 * @brief Computes an ECDH key
 *
 * @see PACE_STEP3B_dh_compute_key()
 */
BUF_MEM *
ecdh_compute_key(EVP_PKEY *key, const BUF_MEM * in, BN_CTX *bn_ctx);

#endif /*PACE_ECDH_H_*/
