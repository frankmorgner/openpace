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
 * @file ta.h
 * @brief Interface for Terminal Authentication
 *
 * Terminal authentication (TA) is a protocol used to check
 * the authenticity of a Terminal communicating with an MRTD chip.
 * It is also used to establish the effective access rights of
 * the terminal for all further communication. TA is a challenge-
 * response protocol in which the certificate issues a challenge
 * which is signed by the terminal. In order to be able to prove
 * the authenticity of the answer, the MRTD chip needs to be provided
 * with a certificate chain, which goes back to its own trust
 * anchor.
 *
 * @date 2011-04-03
 *
 * @author Frank Morgner <frankmorgner@gmail.com>
 * @author Dominik Oepen <oepen@informatik.hu-berlin.de>
 */

#ifndef TA_H_
#define TA_H_

#include <eac/eac.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Skip checking effective and expiration date of cv certificates against the system's current time */
#define TA_FLAG_SKIP_TIMECHECK 1

/**
 * @addtogroup taproto
 *
 * @{ ************************************************************************/

/**
 * @brief Enables \c TA_FLAG_SKIP_TIMECHECK in the TA context
 *
 * @param[in] ctx EAC context for which to disable TA checks
 */
void
TA_disable_checks(EAC_CTX *ctx);

/**
 * @brief Imports a CV Certificate to the EAC context
 *
 * This function should be used to subsequently verify all certificates of a
 * certificate chain. The signature and date of the certificate are verified
 * using the trust anchor or the most recently imported certificate. The TA
 * context is adjusted to use domain parameters of the imported certificate. If
 * the chain contains a new trust anchor (i.e. a CVCA certificate), the old
 * trust anchor is replaced when EAC is completed.
 *
 * @param[in,out] ctx EAC context
 * @param[in] cert raw Certificate to import
 * @param[in] cert_len Length of \a cert
 *
 * @return 1 on success or 0 in case of an error
 *
 * @see <a href="http://frankmorgner.github.io/openpace/protocols.html#id3">TA's Protocol Specification</a>
 */
int
TA_STEP2_import_certificate(const EAC_CTX *ctx,
           const unsigned char *cert, size_t cert_len);
/**
 * @brief Generates ephemeral key for CA
 *
 * @param[in,out] ctx EAC context. The CA context of \a ctx is initialized for key agreement
 *
 * @return Ephemeral public key or NULL in case of an error
 *
 * @see <a href="http://frankmorgner.github.io/openpace/protocols.html#id3">TA's Protocol Specification</a>
 */
BUF_MEM *
TA_STEP3_generate_ephemeral_key(const EAC_CTX *ctx);
/**
 * @brief Generates a nonce for the PCD
 *
 * @param[in,out] ctx EAC context. The nonce is saved in \a ctx
 *
 * @return Nonce or NULL in case of an error
 *
 * @note EAC_CTX_init_ca must have been called before the nonce can be generated
 *
 * @see <a href="http://frankmorgner.github.io/openpace/protocols.html#id3">TA's Protocol Specification</a>
 */
BUF_MEM *
TA_STEP4_get_nonce(const EAC_CTX *ctx);
/**
 * @brief Import the nonce from the PICC
 *
 * @param[in,out] ctx EAC context. The nonce is saved in \a ctx
 * @param nonce The nonce to be copied
 *
 * @return 1 on success or 0 in case of an error
 *
 * @see <a href="http://frankmorgner.github.io/openpace/protocols.html#id3">TA's Protocol Specification</a>
 */
int
TA_STEP4_set_nonce(const EAC_CTX *ctx, const BUF_MEM *nonce);
/**
 * @brief Signs data for terminal authentication.
 *
 * @param[in] ctx EAC context
 * @param[in] my_ta_eph_pubkey PCD's ephemeral public key generated in Step 3
 * @param[in] opp_pace_eph_pubkey PICC's ephemeral public key generated in PACE Step 3b
 * @param[in] auxdata (optional) Auxiliary data from PCD
 *
 * @return Signature or NULL in case of an error
 *
 * @see <a href="http://frankmorgner.github.io/openpace/protocols.html#id3">TA's Protocol Specification</a>
 */
BUF_MEM *
TA_STEP5_sign(const EAC_CTX *ctx, const BUF_MEM *my_ta_eph_pubkey,
           const BUF_MEM *opp_pace_eph_pubkey, const BUF_MEM *auxdata);
/**
 * @brief Verifies PCD's signature from TA step 5
 *
 * @param[in] ctx EAC context
 * @param[in] opp_ta_comp_eph_pubkey PCD's compressed ephemeral public key generated in Step 3
 * @param[in] my_pace_comp_eph_pubkey PICC's compressed ephemeral public key generated in PACE Step 3b
 * @param[in] auxdata (optional) Auxiliary data from PCD
 * @param[in] signature Data to verify
 *
 * @return 1 if the signature has been verified, 0 if not or -1 in case of an error
 *
 * @see <a href="http://frankmorgner.github.io/openpace/protocols.html#id3">TA's Protocol Specification</a>
 */
int
TA_STEP6_verify(const EAC_CTX *ctx, const BUF_MEM *opp_ta_comp_eph_pubkey,
           const BUF_MEM *my_pace_comp_eph_pubkey, const BUF_MEM *auxdata,
           const BUF_MEM *signature);

/** @} ***********************************************************************/

#ifdef  __cplusplus
}
#endif
#endif
