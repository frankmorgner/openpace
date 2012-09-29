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
 * @file eac_asn1.h
 * @brief Interface to ASN.1 structures related to PACE
 *
 * @author Frank Morgner <morgner@informatik.hu-berlin.de>
 * @author Dominik Oepen <oepen@informatik.hu-berlin.de>
 */

#ifndef PACE_ASN1_H_
#define PACE_ASN1_H_

#include <eac/eac.h>
#include <openssl/bn.h>
#include <openssl/evp.h>

/**
 * @brief Encodes public key data objects of the domain parameters in ASN.1
 * (see TR-3110 D.3.2 and D.3.3)
 *
 * @return ASN.1 encoded public key data objects or NULL if an error occurred
 */
BUF_MEM *
asn1_pubkey(int protocol, EVP_PKEY *key, BN_CTX *bn_ctx, enum eac_tr_version tr_version);

/**
 * @brief Generate an EC Key from the ASN1 encoded parameters. This function is
 * needed because asn1.h does not export a d2i_asn1 function
 *
 * @param[out] key where to write the new EC key
 * @param[in] p prime modulus of the field
 * @param[in] a first coefficient of the curve
 * @param[in] b second coefficient of the curve
 * @param[in] base generator of the curve
 * @param[in] base_order order of the generator
 * @param[in] pub public point of the key
 * @param[in] cofactor
 * @param[in] bn_ctx (optional)
 */
int
EAC_ec_key_from_asn1(EC_KEY **key, ASN1_OCTET_STRING *p, ASN1_OCTET_STRING *a,
        ASN1_OCTET_STRING *b, ASN1_OCTET_STRING *base, ASN1_OCTET_STRING *base_order,
        ASN1_OCTET_STRING *pub, ASN1_OCTET_STRING *cofactor, BN_CTX *bn_ctx);

#endif /* PACE_ASN1_H_ */
