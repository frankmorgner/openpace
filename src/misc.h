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
 */

/**
 * @file misc.h
 * @brief Miscellaneous functions used in OpenPACE
 *
 * @author Frank Morgner <morgner@informatik.hu-berlin.de>
 * @author Dominik Oepen <oepen@informatik.hu-berlin.de>
 */

#ifndef MISC_H
#define MISC_H

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
EC_POINT_point2buf(const EC_KEY * ecdh, BN_CTX * bn_ctx, const EC_POINT * ecp);

const ECDH_METHOD *ECDH_OpenSSL_Point(void);

/**
 * @brief Compare two buffers. The length of the first buffer is leaked but no
 * other information should be leaked via the time this function requires.
 *
 * @param[in] a The reference buffer. The length of this buffer is leaked if an
 * attacker controls the second buffer.
 * @param[in] b The buffer that is compared against the reference buffer.
 *
 * @return 0 iff both buffer are equal
 */
int
consttime_memcmp(const BUF_MEM *a, const BUF_MEM *b);

void
EAC_add_all_objects(void);
#endif
