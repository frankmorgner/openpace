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
 * @file misc.h
 * @brief Miscellaneous functions used in OpenPACE
 *
 * @author Frank Morgner <frankmorgner@gmail.com>
 * @author Dominik Oepen <oepen@informatik.hu-berlin.de>
 */

#ifndef MISC_H
#define MISC_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <openssl/bn.h>
#include <openssl/buffer.h>
#include <openssl/ec.h>

/**
 * @brief Creates a BUF_MEM object
 *
 * @param len required length of the buffer
 *
 * @return Initialized BUF_MEM object or NULL if an error occurred
 */
BUF_MEM *
BUF_MEM_create(size_t len);
/**
 * @brief Creates and initializes a BUF_MEM object
 *
 * @param buf Initial data
 * @param len Length of buf
 *
 * @return Initialized BUF_MEM object or NULL if an error occurred
 */
BUF_MEM *
BUF_MEM_create_init(const void *buf, size_t len);
/**
 * @brief duplicates a BUF_MEM structure
 *
 * @param in BUF_MEM to duplicate
 *
 * @return pointer to the new BUF_MEM or NULL in case of error
 */
BUF_MEM *
BUF_MEM_dup(const BUF_MEM * in);

/**
 * @brief converts an BIGNUM object to a BUF_MEM object
 *
 * @param bn bignumber to convert
 *
 * @return converted bignumber or NULL if an error occurred
 */
BUF_MEM *
BN_bn2buf(const BIGNUM *bn);

/**
 * @brief converts an EC_POINT object to a BUF_MEM object
 *
 * @param ecdh EC_KEY object
 * @param bn_ctx object (optional)
 * @param ecp elliptic curve point to convert
 *
 * @return converted elliptic curve point or NULL if an error occurred
 */
BUF_MEM *
EC_POINT_point2mem(const EC_KEY * ecdh, BN_CTX * bn_ctx, const EC_POINT * ecp);

#ifdef HAVE_EC_KEY_METHOD
const EC_KEY_METHOD *EC_KEY_OpenSSL_Point(void);
#else
const ECDH_METHOD *ECDH_OpenSSL_Point(void);
#endif

void
EAC_add_all_objects(void);
void
EAC_remove_all_objects(void);
#endif
