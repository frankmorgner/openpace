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
 * @file eac_lib.h
 * @brief Interface for EAC library functions
 *
 * @author Frank Morgner <frankmorgner@gmail.com>
 * @author Dominik Oepen <oepen@informatik.hu-berlin.de>
 */

#ifndef EAC_LIB_H_
#define EAC_LIB_H_

#include <eac/eac.h>
#include <openssl/bn.h>
#include <openssl/buffer.h>

#ifdef __cplusplus
extern "C" {
#endif

BUF_MEM *
KA_CTX_generate_key(const KA_CTX *ctx, BN_CTX *bn_ctx);
int
KA_CTX_compute_key(KA_CTX *ctx, const BUF_MEM *in, BN_CTX *bn_ctx);
int
KA_CTX_derive_keys(KA_CTX *ka_ctx, const BUF_MEM *nonce, EVP_MD_CTX *md_ctx);

void KA_CTX_clear_free(KA_CTX *ctx);
KA_CTX *KA_CTX_new(void);
KA_CTX *KA_CTX_dup(const KA_CTX *ka_ctx);
int KA_CTX_set_protocol(KA_CTX *ctx, int protocol);

#ifdef  __cplusplus
}
#endif
#endif
