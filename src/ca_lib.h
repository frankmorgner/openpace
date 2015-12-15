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
 * @file
 * @brief Interface for Chip Authentication library functions
 *
 * @author Frank Morgner <frankmorgner@gmail.com>
 * @author Dominik Oepen <oepen@informatik.hu-berlin.de>
 */

#ifndef CA_LIB_H_
#define CA_LIB_H_

#include <eac/eac.h>

#ifdef __cplusplus
extern "C" {
#endif

int
CA_CTX_set_protocol(CA_CTX * ctx, int protocol);

/**
 * @brief Create a new \CA_CTX structure
 * @return The new structure or NULL in case of an error
 */
CA_CTX *
CA_CTX_new(void);

/**
 * @brief Free a \c CA_CTX object and all its components.
 *
 * Sensitive memory is cleared with OPENSSL_cleanse().
 *
 * @param ctx The \c CA_CTX to free
 */
void
CA_CTX_clear_free(CA_CTX *ctx);

#ifdef  __cplusplus
}
#endif
#endif
