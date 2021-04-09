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
 * @file ta_lib.h
 *
 * @author Frank Morgner <frankmorgner@gmail.com>
 * @author Dominik Oepen <oepen@informatik.hu-berlin.de>
 */

#ifndef TA_LIB_H_
#define TA_LIB_H_

#include <eac/cv_cert.h>
#include <eac/eac.h>
#include <openssl/bn.h>

/**
 * @brief Import the parameters and public key from a card verifiable
 * certificate into a TA_CTX structure. This function is used to verify
 * certificate chains by subsequently importing all the certificates, starting
 * with the DVCA or link certificate.
 * @param ctx The TA_CTX structure to initialize
 * @param next_cert The card verifiable certificate to be imported
 * @param bn_ctx (optional)
 * @return 1 on success or 0 in case of an error
 */
int
TA_CTX_import_certificate(TA_CTX *ctx, const CVC_CERT *next_cert,
           BN_CTX *bn_ctx);

/**
 * @brief Import the parameters and public key from a card verifiable
 * certificate into a TA_CTX structure. This function is used to set the trust
 * anchor (the CVCA certificate).
 * @param ctx The TA_CTX structure to initialize
 * @param trust_anchor The card verifiable certificate to be imported
 * @param bn_ctx (optional)
 * @return 1 on success or 0 in case of an error
 */
int
TA_CTX_set_trust_anchor(TA_CTX *ctx, const CVC_CERT *trust_anchor,
           BN_CTX *bn_ctx);

/**
 * @brief Create a new \TA_CTX structure
 * @return The new structure or NULL in case of an error
 */
TA_CTX *
TA_CTX_new(void);

/**
 * @brief Free a \c TA_CTX object and all its components.
 *
 * Sensitive memory is cleared with OPENSSL_cleanse().
 *
 * @param ctx The \c TA_CTX to free
 */
void
TA_CTX_clear_free(TA_CTX *ctx);

#endif
