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
 * @file pace_mappings.h
 * @brief Interface to functions for domain parameter mappings
 *
 * @author Frank Morgner <frankmorgner@gmail.com>
 * @author Dominik Oepen <oepen@informatik.hu-berlin.de>
 */

#ifndef PACE_MAPPINGS_H_
#define PACE_MAPPINGS_H_

#include <eac/pace.h>
#include <openssl/bn.h>
#include <openssl/buffer.h>

/**
 * @defgroup encoding               Mapping
 * @{ ************************************************************************/

BUF_MEM *
dh_gm_generate_key(const PACE_CTX * ctx, BN_CTX *bn_ctx);
/**
 * @brief Computes a key for DH Generic Mapping (see TR-3110 A.3.5.1)
 *
 * @see PACE_STEP3A_map_compute_key()
 */
int
dh_gm_compute_key(PACE_CTX * ctx, const BUF_MEM * s, const BUF_MEM * in,
        BN_CTX *bn_ctx);
/**
 * @brief Generates a key for DH Integrated Mapping (see TR-3110 A.3.5.2)
 *
 * @see PACE_STEP3A_map_compute_key()
 */
BUF_MEM *
dh_im_generate_key(const PACE_CTX *ctx, BN_CTX *bn_ctx);
/**
 * @brief Computes a key for DH Integrated Mapping (see TR-3110 A.3.5.2)
 *
 * @see PACE_STEP3A_map_compute_key()
 */
int
dh_im_compute_key(PACE_CTX * ctx, const BUF_MEM * s, const BUF_MEM * in,
        BN_CTX *bn_ctx);
BUF_MEM *
ecdh_gm_generate_key(const PACE_CTX * ctx, BN_CTX *bn_ctx);
/**
 * @brief Computes a key for ECDH Generic Mapping (see TR-3110 A.3.4.1)
 *
 * @see PACE_STEP3A_map_compute_key()
 */
int
ecdh_gm_compute_key(PACE_CTX * ctx, const BUF_MEM * s, const BUF_MEM * in,
        BN_CTX *bn_ctx);
/**
 * @brief Generates a key for ECDH Integrated Mapping (see TR-3110 A.3.4.2)
 *
 * @see PACE_STEP3A_map_compute_key()
 */
BUF_MEM *
ecdh_im_generate_key(const PACE_CTX *ctx, BN_CTX *bn_ctx);
/**
 * @brief Computes a key for ECDH Integrated Mapping (see TR-3110 A.3.4.2)
 *
 * @see PACE_STEP3A_map_compute_key()
 */
int
ecdh_im_compute_key(PACE_CTX * ctx, const BUF_MEM * s, const BUF_MEM * in,
        BN_CTX *bn_ctx);

/** @} ***********************************************************************/

#endif /*PACE_MAPPINGS_H_*/
