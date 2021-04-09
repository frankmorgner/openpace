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
 * @file pace_lib.h
 * @brief Interface to PACE library functions
 *
 * @author Frank Morgner <frankmorgner@gmail.com>
 * @author Dominik Oepen <oepen@informatik.hu-berlin.de>
 */

#ifndef PACE_LIB_H_
#define PACE_LIB_H_

#include <eac/eac.h>
/**
 * @brief Frees a \c PACE_CTX object and all its components
 *
 * @param[in] s Object to free (optional)
 */
void PACE_CTX_clear_free(PACE_CTX * s);
/**
 * @brief Creates a new \c PACE_CTX object
 *
 * @return The new object or NULL if an error occurred
 */
PACE_CTX * PACE_CTX_new(void);
/**
 * @brief Initializes a \c PACE_CTX object using the protocol OID. This
 * parameter can be found in the PACEInfo part of an EF.CardAccess.
 *
 * @param[in,out] ctx The \c PACE_CTX object to initialize
 * @param[in] protocol The NID of the OID
 * @param[in] tr_version
 *
 * @return 1 in case of success, 0 otherwise
 */
int PACE_CTX_set_protocol(PACE_CTX * ctx, int protocol, enum eac_tr_version tr_version);

#endif
