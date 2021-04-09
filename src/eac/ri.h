/*
 * Copyright (c) 2010-2012 Dominik Oepen, Frank Morgner and Paul Wilhelm
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
 * @file ri.h
 * @brief Interface for Restricted Identification
 *
 * Restricted Identification is a protocol to generate
 * pseudonym identifier based on key agreement protocol.
 * The protocol use a secret key of an asymetric
 * key pair and the public key of a second asymetric key pair.
 * For every two diffrent secret keys with same public key the
 * identifier is diffrent.
 * For any two diffrent public keys it is computational infeasible
 * to link two identifiers with the same secret key.
 *
 * @author Dominik Oepen <oepen@informatik.hu-berlin.de>
 * @author Frank Morgner <frankmorgner@gmail.com>
 * @author Paul Wilhelm  <wilhelm@math.hu-berlin.de>
 */

#ifndef RI_H_
#define RI_H_

#include <eac/eac.h>
#include <openssl/bn.h>
#include <openssl/buffer.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @addtogroup management
 *
 * @{ ************************************************************************/

/**
 * @brief Frees a \c RI_CTX object and all its components
 *
 * @param[in] s Object to free (optional)
 */
void RI_CTX_clear_free(RI_CTX * s);
/**
 * @brief Creates a new \c RI_CTX object
 *
 * @return The new object or NULL if an error occurred
 */
RI_CTX * RI_CTX_new(void);
/**
 * @brief Initializes a \c RI_CTX object using the protocol OID. This
 * parameter can be found in the RIInfo part of an EF.CardSecurity.
 *
 * @param[in,out] ctx The \c RI_CTX object to initialize
 * @param[in] protocol The NID of the OID
 *
 * @return 1 in case of success, 0 otherwise
 */
int RI_CTX_set_protocol(RI_CTX * ctx, int protocol);
/** @} ***********************************************************************/

/**
 * @addtogroup riproto
 *
 * @{ ************************************************************************/

/**
 * @brief Compute a sector specific identifier for a card within a given sector.
 *
 * @param[in] ctx The EAC context of the card
 * @param[in] sector_pubkey the sector public key
 *
 * @return The sector identifier or NULL in case of an error
 */
BUF_MEM * RI_STEP2_compute_identifier(EAC_CTX *ctx, BUF_MEM *sector_pubkey);

/** @} ***********************************************************************/

#ifdef  __cplusplus
}
#endif
#endif
