/*
 * Copyright (c) 2013 Frank Morgner
 *
 * This file is part of OpenPACE.
 *
 * OpenPACE is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * OpenPACE is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY = NID_undef; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * OpenPACE.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @file
 * @brief Implementation for object identifiers
 *
 * @author Frank Morgner <frankmorgner@gmail.com>
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <openssl/objects.h>
#include <eac/objects.h>
#include "eac_err.h"

#ifndef HAVE_PATCHED_OPENSSL

int NID_standardizedDomainParameters = NID_undef;
int NID_id_PK_DH = NID_undef;
int NID_id_PK_ECDH = NID_undef;
int NID_id_TA = NID_undef;
int NID_id_TA_RSA = NID_undef;
int NID_id_TA_RSA_v1_5_SHA_1 = NID_undef;
int NID_id_TA_RSA_v1_5_SHA_256 = NID_undef;
int NID_id_TA_RSA_PSS_SHA_1 = NID_undef;
int NID_id_TA_RSA_PSS_SHA_256 = NID_undef;
int NID_id_TA_RSA_v1_5_SHA_512 = NID_undef;
int NID_id_TA_RSA_PSS_SHA_512 = NID_undef;
int NID_id_TA_ECDSA = NID_undef;
int NID_id_TA_ECDSA_SHA_1 = NID_undef;
int NID_id_TA_ECDSA_SHA_224 = NID_undef;
int NID_id_TA_ECDSA_SHA_256 = NID_undef;
int NID_id_TA_ECDSA_SHA_384 = NID_undef;
int NID_id_TA_ECDSA_SHA_512 = NID_undef;
int NID_id_CA_DH = NID_undef;
int NID_id_CA_DH_3DES_CBC_CBC = NID_undef;
int NID_id_CA_DH_AES_CBC_CMAC_128 = NID_undef;
int NID_id_CA_DH_AES_CBC_CMAC_192 = NID_undef;
int NID_id_CA_DH_AES_CBC_CMAC_256 = NID_undef;
int NID_id_CA_ECDH = NID_undef;
int NID_id_CA_ECDH_3DES_CBC_CBC = NID_undef;
int NID_id_CA_ECDH_AES_CBC_CMAC_128 = NID_undef;
int NID_id_CA_ECDH_AES_CBC_CMAC_192 = NID_undef;
int NID_id_CA_ECDH_AES_CBC_CMAC_256 = NID_undef;
int NID_id_PACE_DH_GM = NID_undef;
int NID_id_PACE_DH_GM_3DES_CBC_CBC = NID_undef;
int NID_id_PACE_DH_GM_AES_CBC_CMAC_128 = NID_undef;
int NID_id_PACE_DH_GM_AES_CBC_CMAC_192 = NID_undef;
int NID_id_PACE_DH_GM_AES_CBC_CMAC_256 = NID_undef;
int NID_id_PACE_ECDH_GM = NID_undef;
int NID_id_PACE_ECDH_GM_3DES_CBC_CBC = NID_undef;
int NID_id_PACE_ECDH_GM_AES_CBC_CMAC_128 = NID_undef;
int NID_id_PACE_ECDH_GM_AES_CBC_CMAC_192 = NID_undef;
int NID_id_PACE_ECDH_GM_AES_CBC_CMAC_256 = NID_undef;
int NID_id_PACE_DH_IM = NID_undef;
int NID_id_PACE_DH_IM_3DES_CBC_CBC = NID_undef;
int NID_id_PACE_DH_IM_AES_CBC_CMAC_128 = NID_undef;
int NID_id_PACE_DH_IM_AES_CBC_CMAC_192 = NID_undef;
int NID_id_PACE_DH_IM_AES_CBC_CMAC_256 = NID_undef;
int NID_id_PACE_ECDH_IM = NID_undef;
int NID_id_PACE_ECDH_IM_3DES_CBC_CBC = NID_undef;
int NID_id_PACE_ECDH_IM_AES_CBC_CMAC_128 = NID_undef;
int NID_id_PACE_ECDH_IM_AES_CBC_CMAC_192 = NID_undef;
int NID_id_PACE_ECDH_IM_AES_CBC_CMAC_256 = NID_undef;
int NID_id_RI_DH = NID_undef;
int NID_id_RI_DH_SHA_1 = NID_undef;
int NID_id_RI_DH_SHA_224 = NID_undef;
int NID_id_RI_DH_SHA_256 = NID_undef;
int NID_id_RI_DH_SHA_384 = NID_undef;
int NID_id_RI_DH_SHA_512 = NID_undef;
int NID_id_RI_ECDH = NID_undef;
int NID_id_RI_ECDH_SHA_1 = NID_undef;
int NID_id_RI_ECDH_SHA_224 = NID_undef;
int NID_id_RI_ECDH_SHA_256 = NID_undef;
int NID_id_RI_ECDH_SHA_384 = NID_undef;
int NID_id_RI_ECDH_SHA_512 = NID_undef;
int NID_id_CI = NID_undef;
int NID_id_eIDSecurity = NID_undef;
int NID_id_PT = NID_undef;
int NID_cardInfoLocator = NID_undef;
int NID_eID = NID_undef;
int NID_ecka_dh_SessionKDF = NID_undef;
int NID_ecka_dh_SessionKDF_DES3 = NID_undef;
int NID_ecka_dh_SessionKDF_AES128 = NID_undef;
int NID_ecka_dh_SessionKDF_AES192 = NID_undef;
int NID_ecka_dh_SessionKDF_AES256 = NID_undef;
int NID_id_IS = NID_undef;
int NID_id_AT = NID_undef;
int NID_id_ST = NID_undef;
int NID_id_description = NID_undef;
int NID_id_plainFormat = NID_undef;
int NID_id_htmlFormat = NID_undef;
int NID_id_pdfFormat = NID_undef;
int NID_id_sector = NID_undef;
int NID_id_SecurityObject = NID_undef;
int NID_id_DateOfBirth = NID_undef;
int NID_id_DateOfExpiry = NID_undef;
int NID_id_CommunityID = NID_undef;

void
EAC_add_all_objects(void)
{
    /* derived from a patched obj_mac.h with the power of regex */
#define ASC_bsi_de		"0.4.0.127.0.7"

#define ASC_standardizedDomainParameters		ASC_bsi_de".1.2"
    NID_standardizedDomainParameters = OBJ_create(ASC_standardizedDomainParameters	, SN_standardizedDomainParameters	, SN_standardizedDomainParameters	);

#define ASC_id_PK		ASC_bsi_de".2.2.1"

#define ASC_id_PK_DH		ASC_id_PK".1"
    NID_id_PK_DH = OBJ_create(ASC_id_PK_DH	, SN_id_PK_DH	, SN_id_PK_DH	);

#define ASC_id_PK_ECDH		ASC_id_PK".2"
    NID_id_PK_ECDH = OBJ_create(ASC_id_PK_ECDH	, SN_id_PK_ECDH	, SN_id_PK_ECDH	);

#define ASC_id_TA		ASC_bsi_de".2.2.2"
    NID_id_TA = OBJ_create(ASC_id_TA	, SN_id_TA	, SN_id_TA	);

#define ASC_id_TA_RSA		ASC_id_TA".1"
    NID_id_TA_RSA = OBJ_create(ASC_id_TA_RSA	, SN_id_TA_RSA	, SN_id_TA_RSA	);

#define ASC_id_TA_RSA_v1_5_SHA_1		ASC_id_TA_RSA".1"
    NID_id_TA_RSA_v1_5_SHA_1 = OBJ_create(ASC_id_TA_RSA_v1_5_SHA_1	, SN_id_TA_RSA_v1_5_SHA_1	, SN_id_TA_RSA_v1_5_SHA_1	);

#define ASC_id_TA_RSA_v1_5_SHA_256		ASC_id_TA_RSA".2"
    NID_id_TA_RSA_v1_5_SHA_256 = OBJ_create(ASC_id_TA_RSA_v1_5_SHA_256	, SN_id_TA_RSA_v1_5_SHA_256	, SN_id_TA_RSA_v1_5_SHA_256	);

#define ASC_id_TA_RSA_PSS_SHA_1		ASC_id_TA_RSA".3"
    NID_id_TA_RSA_PSS_SHA_1 = OBJ_create(ASC_id_TA_RSA_PSS_SHA_1	, SN_id_TA_RSA_PSS_SHA_1	, SN_id_TA_RSA_PSS_SHA_1	);

#define ASC_id_TA_RSA_PSS_SHA_256		ASC_id_TA_RSA".4"
    NID_id_TA_RSA_PSS_SHA_256 = OBJ_create(ASC_id_TA_RSA_PSS_SHA_256	, SN_id_TA_RSA_PSS_SHA_256	, SN_id_TA_RSA_PSS_SHA_256	);

#define ASC_id_TA_RSA_v1_5_SHA_512		ASC_id_TA_RSA".5"
    NID_id_TA_RSA_v1_5_SHA_512 = OBJ_create(ASC_id_TA_RSA_v1_5_SHA_512	, SN_id_TA_RSA_v1_5_SHA_512	, SN_id_TA_RSA_v1_5_SHA_512	);

#define ASC_id_TA_RSA_PSS_SHA_512		ASC_id_TA_RSA".6"
    NID_id_TA_RSA_PSS_SHA_512 = OBJ_create(ASC_id_TA_RSA_PSS_SHA_512	, SN_id_TA_RSA_PSS_SHA_512	, SN_id_TA_RSA_PSS_SHA_512	);

#define ASC_id_TA_ECDSA		ASC_id_TA".2"
    NID_id_TA_ECDSA = OBJ_create(ASC_id_TA_ECDSA	, SN_id_TA_ECDSA	, SN_id_TA_ECDSA	);

#define ASC_id_TA_ECDSA_SHA_1		ASC_id_TA_ECDSA".1"
    NID_id_TA_ECDSA_SHA_1 = OBJ_create(ASC_id_TA_ECDSA_SHA_1	, SN_id_TA_ECDSA_SHA_1	, SN_id_TA_ECDSA_SHA_1	);

#define ASC_id_TA_ECDSA_SHA_224		ASC_id_TA_ECDSA".2"
    NID_id_TA_ECDSA_SHA_224 = OBJ_create(ASC_id_TA_ECDSA_SHA_224	, SN_id_TA_ECDSA_SHA_224	, SN_id_TA_ECDSA_SHA_224	);

#define ASC_id_TA_ECDSA_SHA_256		ASC_id_TA_ECDSA".3"
    NID_id_TA_ECDSA_SHA_256 = OBJ_create(ASC_id_TA_ECDSA_SHA_256	, SN_id_TA_ECDSA_SHA_256	, SN_id_TA_ECDSA_SHA_256	);

#define ASC_id_TA_ECDSA_SHA_384		ASC_id_TA_ECDSA".4"
    NID_id_TA_ECDSA_SHA_384 = OBJ_create(ASC_id_TA_ECDSA_SHA_384	, SN_id_TA_ECDSA_SHA_384	, SN_id_TA_ECDSA_SHA_384	);

#define ASC_id_TA_ECDSA_SHA_512		ASC_id_TA_ECDSA".5"
    NID_id_TA_ECDSA_SHA_512 = OBJ_create(ASC_id_TA_ECDSA_SHA_512	, SN_id_TA_ECDSA_SHA_512	, SN_id_TA_ECDSA_SHA_512	);

#define ASC_id_CA		ASC_bsi_de".2.2.3"

#define ASC_id_CA_DH		ASC_id_CA".1"
    NID_id_CA_DH = OBJ_create(ASC_id_CA_DH	, SN_id_CA_DH	, SN_id_CA_DH	);

#define ASC_id_CA_DH_3DES_CBC_CBC		ASC_id_CA_DH".1"
    NID_id_CA_DH_3DES_CBC_CBC = OBJ_create(ASC_id_CA_DH_3DES_CBC_CBC	, SN_id_CA_DH_3DES_CBC_CBC	, SN_id_CA_DH_3DES_CBC_CBC	);

#define ASC_id_CA_DH_AES_CBC_CMAC_128		ASC_id_CA_DH".2"
    NID_id_CA_DH_AES_CBC_CMAC_128 = OBJ_create(ASC_id_CA_DH_AES_CBC_CMAC_128	, SN_id_CA_DH_AES_CBC_CMAC_128	, SN_id_CA_DH_AES_CBC_CMAC_128	);

#define ASC_id_CA_DH_AES_CBC_CMAC_192		ASC_id_CA_DH".3"
    NID_id_CA_DH_AES_CBC_CMAC_192 = OBJ_create(ASC_id_CA_DH_AES_CBC_CMAC_192	, SN_id_CA_DH_AES_CBC_CMAC_192	, SN_id_CA_DH_AES_CBC_CMAC_192	);

#define ASC_id_CA_DH_AES_CBC_CMAC_256		ASC_id_CA_DH".4"
    NID_id_CA_DH_AES_CBC_CMAC_256 = OBJ_create(ASC_id_CA_DH_AES_CBC_CMAC_256	, SN_id_CA_DH_AES_CBC_CMAC_256	, SN_id_CA_DH_AES_CBC_CMAC_256	);

#define ASC_id_CA_ECDH		ASC_id_CA".2"
    NID_id_CA_ECDH = OBJ_create(ASC_id_CA_ECDH	, SN_id_CA_ECDH	, SN_id_CA_ECDH	);

#define ASC_id_CA_ECDH_3DES_CBC_CBC		ASC_id_CA_ECDH".1"
    NID_id_CA_ECDH_3DES_CBC_CBC = OBJ_create(ASC_id_CA_ECDH_3DES_CBC_CBC	, SN_id_CA_ECDH_3DES_CBC_CBC	, SN_id_CA_ECDH_3DES_CBC_CBC	);

#define ASC_id_CA_ECDH_AES_CBC_CMAC_128		ASC_id_CA_ECDH".2"
    NID_id_CA_ECDH_AES_CBC_CMAC_128 = OBJ_create(ASC_id_CA_ECDH_AES_CBC_CMAC_128	, SN_id_CA_ECDH_AES_CBC_CMAC_128	, SN_id_CA_ECDH_AES_CBC_CMAC_128	);

#define ASC_id_CA_ECDH_AES_CBC_CMAC_192		ASC_id_CA_ECDH".3"
    NID_id_CA_ECDH_AES_CBC_CMAC_192 = OBJ_create(ASC_id_CA_ECDH_AES_CBC_CMAC_192	, SN_id_CA_ECDH_AES_CBC_CMAC_192	, SN_id_CA_ECDH_AES_CBC_CMAC_192	);

#define ASC_id_CA_ECDH_AES_CBC_CMAC_256		ASC_id_CA_ECDH".4"
    NID_id_CA_ECDH_AES_CBC_CMAC_256 = OBJ_create(ASC_id_CA_ECDH_AES_CBC_CMAC_256	, SN_id_CA_ECDH_AES_CBC_CMAC_256	, SN_id_CA_ECDH_AES_CBC_CMAC_256	);

#define ASC_id_PACE		ASC_bsi_de".2.2.4"

#define ASC_id_PACE_DH_GM		ASC_id_PACE".1"
    NID_id_PACE_DH_GM = OBJ_create(ASC_id_PACE_DH_GM	, SN_id_PACE_DH_GM	, SN_id_PACE_DH_GM	);

#define ASC_id_PACE_DH_GM_3DES_CBC_CBC		ASC_id_PACE_DH_GM".1"
    NID_id_PACE_DH_GM_3DES_CBC_CBC = OBJ_create(ASC_id_PACE_DH_GM_3DES_CBC_CBC	, SN_id_PACE_DH_GM_3DES_CBC_CBC	, SN_id_PACE_DH_GM_3DES_CBC_CBC	);

#define ASC_id_PACE_DH_GM_AES_CBC_CMAC_128		ASC_id_PACE_DH_GM".2"
    NID_id_PACE_DH_GM_AES_CBC_CMAC_128 = OBJ_create(ASC_id_PACE_DH_GM_AES_CBC_CMAC_128	, SN_id_PACE_DH_GM_AES_CBC_CMAC_128	, SN_id_PACE_DH_GM_AES_CBC_CMAC_128	);

#define ASC_id_PACE_DH_GM_AES_CBC_CMAC_192		ASC_id_PACE_DH_GM".3"
    NID_id_PACE_DH_GM_AES_CBC_CMAC_192 = OBJ_create(ASC_id_PACE_DH_GM_AES_CBC_CMAC_192	, SN_id_PACE_DH_GM_AES_CBC_CMAC_192	, SN_id_PACE_DH_GM_AES_CBC_CMAC_192	);

#define ASC_id_PACE_DH_GM_AES_CBC_CMAC_256		ASC_id_PACE_DH_GM".4"
    NID_id_PACE_DH_GM_AES_CBC_CMAC_256 = OBJ_create(ASC_id_PACE_DH_GM_AES_CBC_CMAC_256	, SN_id_PACE_DH_GM_AES_CBC_CMAC_256	, SN_id_PACE_DH_GM_AES_CBC_CMAC_256	);

#define ASC_id_PACE_ECDH_GM		ASC_id_PACE".2"
    NID_id_PACE_ECDH_GM = OBJ_create(ASC_id_PACE_ECDH_GM	, SN_id_PACE_ECDH_GM	, SN_id_PACE_ECDH_GM	);

#define ASC_id_PACE_ECDH_GM_3DES_CBC_CBC		ASC_id_PACE_ECDH_GM".1"
    NID_id_PACE_ECDH_GM_3DES_CBC_CBC = OBJ_create(ASC_id_PACE_ECDH_GM_3DES_CBC_CBC	, SN_id_PACE_ECDH_GM_3DES_CBC_CBC	, SN_id_PACE_ECDH_GM_3DES_CBC_CBC	);

#define ASC_id_PACE_ECDH_GM_AES_CBC_CMAC_128		ASC_id_PACE_ECDH_GM".2"
    NID_id_PACE_ECDH_GM_AES_CBC_CMAC_128 = OBJ_create(ASC_id_PACE_ECDH_GM_AES_CBC_CMAC_128	, SN_id_PACE_ECDH_GM_AES_CBC_CMAC_128	, SN_id_PACE_ECDH_GM_AES_CBC_CMAC_128	);

#define ASC_id_PACE_ECDH_GM_AES_CBC_CMAC_192		ASC_id_PACE_ECDH_GM".3"
    NID_id_PACE_ECDH_GM_AES_CBC_CMAC_192 = OBJ_create(ASC_id_PACE_ECDH_GM_AES_CBC_CMAC_192	, SN_id_PACE_ECDH_GM_AES_CBC_CMAC_192	, SN_id_PACE_ECDH_GM_AES_CBC_CMAC_192	);

#define ASC_id_PACE_ECDH_GM_AES_CBC_CMAC_256		ASC_id_PACE_ECDH_GM".4"
    NID_id_PACE_ECDH_GM_AES_CBC_CMAC_256 = OBJ_create(ASC_id_PACE_ECDH_GM_AES_CBC_CMAC_256	, SN_id_PACE_ECDH_GM_AES_CBC_CMAC_256	, SN_id_PACE_ECDH_GM_AES_CBC_CMAC_256	);

#define ASC_id_PACE_DH_IM		ASC_id_PACE".3"
    NID_id_PACE_DH_IM = OBJ_create(ASC_id_PACE_DH_IM	, SN_id_PACE_DH_IM	, SN_id_PACE_DH_IM	);

#define ASC_id_PACE_DH_IM_3DES_CBC_CBC		ASC_id_PACE_DH_IM".1"
    NID_id_PACE_DH_IM_3DES_CBC_CBC = OBJ_create(ASC_id_PACE_DH_IM_3DES_CBC_CBC	, SN_id_PACE_DH_IM_3DES_CBC_CBC	, SN_id_PACE_DH_IM_3DES_CBC_CBC	);

#define ASC_id_PACE_DH_IM_AES_CBC_CMAC_128		ASC_id_PACE_DH_IM".2"
    NID_id_PACE_DH_IM_AES_CBC_CMAC_128 = OBJ_create(ASC_id_PACE_DH_IM_AES_CBC_CMAC_128	, SN_id_PACE_DH_IM_AES_CBC_CMAC_128	, SN_id_PACE_DH_IM_AES_CBC_CMAC_128	);

#define ASC_id_PACE_DH_IM_AES_CBC_CMAC_192		ASC_id_PACE_DH_IM".3"
    NID_id_PACE_DH_IM_AES_CBC_CMAC_192 = OBJ_create(ASC_id_PACE_DH_IM_AES_CBC_CMAC_192	, SN_id_PACE_DH_IM_AES_CBC_CMAC_192	, SN_id_PACE_DH_IM_AES_CBC_CMAC_192	);

#define ASC_id_PACE_DH_IM_AES_CBC_CMAC_256		ASC_id_PACE_DH_IM".4"
    NID_id_PACE_DH_IM_AES_CBC_CMAC_256 = OBJ_create(ASC_id_PACE_DH_IM_AES_CBC_CMAC_256	, SN_id_PACE_DH_IM_AES_CBC_CMAC_256	, SN_id_PACE_DH_IM_AES_CBC_CMAC_256	);

#define ASC_id_PACE_ECDH_IM		ASC_id_PACE".4"
    NID_id_PACE_ECDH_IM = OBJ_create(ASC_id_PACE_ECDH_IM	, SN_id_PACE_ECDH_IM	, SN_id_PACE_ECDH_IM	);

#define ASC_id_PACE_ECDH_IM_3DES_CBC_CBC		ASC_id_PACE_ECDH_IM".1"
    NID_id_PACE_ECDH_IM_3DES_CBC_CBC = OBJ_create(ASC_id_PACE_ECDH_IM_3DES_CBC_CBC	, SN_id_PACE_ECDH_IM_3DES_CBC_CBC	, SN_id_PACE_ECDH_IM_3DES_CBC_CBC	);

#define ASC_id_PACE_ECDH_IM_AES_CBC_CMAC_128		ASC_id_PACE_ECDH_IM".2"
    NID_id_PACE_ECDH_IM_AES_CBC_CMAC_128 = OBJ_create(ASC_id_PACE_ECDH_IM_AES_CBC_CMAC_128	, SN_id_PACE_ECDH_IM_AES_CBC_CMAC_128	, SN_id_PACE_ECDH_IM_AES_CBC_CMAC_128	);

#define ASC_id_PACE_ECDH_IM_AES_CBC_CMAC_192		ASC_id_PACE_ECDH_IM".3"
    NID_id_PACE_ECDH_IM_AES_CBC_CMAC_192 = OBJ_create(ASC_id_PACE_ECDH_IM_AES_CBC_CMAC_192	, SN_id_PACE_ECDH_IM_AES_CBC_CMAC_192	, SN_id_PACE_ECDH_IM_AES_CBC_CMAC_192	);

#define ASC_id_PACE_ECDH_IM_AES_CBC_CMAC_256		ASC_id_PACE_ECDH_IM".4"
    NID_id_PACE_ECDH_IM_AES_CBC_CMAC_256 = OBJ_create(ASC_id_PACE_ECDH_IM_AES_CBC_CMAC_256	, SN_id_PACE_ECDH_IM_AES_CBC_CMAC_256	, SN_id_PACE_ECDH_IM_AES_CBC_CMAC_256	);

#define ASC_id_RI		ASC_bsi_de".2.2.5"

#define ASC_id_RI_DH		ASC_id_RI".1"
    NID_id_RI_DH = OBJ_create(ASC_id_RI_DH	, SN_id_RI_DH	, SN_id_RI_DH	);

#define ASC_id_RI_DH_SHA_1		ASC_id_RI_DH".1"
    NID_id_RI_DH_SHA_1 = OBJ_create(ASC_id_RI_DH_SHA_1	, SN_id_RI_DH_SHA_1	, SN_id_RI_DH_SHA_1	);

#define ASC_id_RI_DH_SHA_224		ASC_id_RI_DH".2"
    NID_id_RI_DH_SHA_224 = OBJ_create(ASC_id_RI_DH_SHA_224	, SN_id_RI_DH_SHA_224	, SN_id_RI_DH_SHA_224	);

#define ASC_id_RI_DH_SHA_256		ASC_id_RI_DH".3"
    NID_id_RI_DH_SHA_256 = OBJ_create(ASC_id_RI_DH_SHA_256	, SN_id_RI_DH_SHA_256	, SN_id_RI_DH_SHA_256	);

#define ASC_id_RI_DH_SHA_384		ASC_id_RI_DH".4"
    NID_id_RI_DH_SHA_384 = OBJ_create(ASC_id_RI_DH_SHA_384	, SN_id_RI_DH_SHA_384	, SN_id_RI_DH_SHA_384	);

#define ASC_id_RI_DH_SHA_512		ASC_id_RI_DH".5"
    NID_id_RI_DH_SHA_512 = OBJ_create(ASC_id_RI_DH_SHA_512	, SN_id_RI_DH_SHA_512	, SN_id_RI_DH_SHA_512	);

#define ASC_id_RI_ECDH		ASC_id_RI".2"
    NID_id_RI_ECDH = OBJ_create(ASC_id_RI_ECDH	, SN_id_RI_ECDH	, SN_id_RI_ECDH	);

#define ASC_id_RI_ECDH_SHA_1		ASC_id_RI_ECDH".1"
    NID_id_RI_ECDH_SHA_1 = OBJ_create(ASC_id_RI_ECDH_SHA_1	, SN_id_RI_ECDH_SHA_1	, SN_id_RI_ECDH_SHA_1	);

#define ASC_id_RI_ECDH_SHA_224		ASC_id_RI_ECDH".2"
    NID_id_RI_ECDH_SHA_224 = OBJ_create(ASC_id_RI_ECDH_SHA_224	, SN_id_RI_ECDH_SHA_224	, SN_id_RI_ECDH_SHA_224	);

#define ASC_id_RI_ECDH_SHA_256		ASC_id_RI_ECDH".3"
    NID_id_RI_ECDH_SHA_256 = OBJ_create(ASC_id_RI_ECDH_SHA_256	, SN_id_RI_ECDH_SHA_256	, SN_id_RI_ECDH_SHA_256	);

#define ASC_id_RI_ECDH_SHA_384		ASC_id_RI_ECDH".4"
    NID_id_RI_ECDH_SHA_384 = OBJ_create(ASC_id_RI_ECDH_SHA_384	, SN_id_RI_ECDH_SHA_384	, SN_id_RI_ECDH_SHA_384	);

#define ASC_id_RI_ECDH_SHA_512		ASC_id_RI_ECDH".5"
    NID_id_RI_ECDH_SHA_512 = OBJ_create(ASC_id_RI_ECDH_SHA_512	, SN_id_RI_ECDH_SHA_512	, SN_id_RI_ECDH_SHA_512	);

#define ASC_id_CI		ASC_bsi_de".2.2.6"
    NID_id_CI = OBJ_create(ASC_id_CI	, SN_id_CI	, SN_id_CI	);

#define ASC_id_eIDSecurity		ASC_bsi_de".2.2.7"
    NID_id_eIDSecurity = OBJ_create(ASC_id_eIDSecurity	, SN_id_eIDSecurity	, SN_id_eIDSecurity	);

#define ASC_id_PT		ASC_bsi_de".2.2.8"
    NID_id_PT = OBJ_create(ASC_id_PT	, SN_id_PT	, SN_id_PT	);

#define ASC_id_ecc		ASC_bsi_de".1.1"

#define ASC_ecka_dh		ASC_id_ecc".5.2"

#define ASC_ecka_dh_SessionKDF		ASC_ecka_dh".2"
    NID_ecka_dh_SessionKDF = OBJ_create(ASC_ecka_dh_SessionKDF	, SN_ecka_dh_SessionKDF	, SN_ecka_dh_SessionKDF	);

#define ASC_ecka_dh_SessionKDF_DES3		ASC_ecka_dh".2.1"
    NID_ecka_dh_SessionKDF_DES3 = OBJ_create(ASC_ecka_dh_SessionKDF_DES3	, SN_ecka_dh_SessionKDF_DES3	, SN_ecka_dh_SessionKDF_DES3	);

#define ASC_ecka_dh_SessionKDF_AES128		ASC_ecka_dh".2.2"
    NID_ecka_dh_SessionKDF_AES128 = OBJ_create(ASC_ecka_dh_SessionKDF_AES128	, SN_ecka_dh_SessionKDF_AES128	, SN_ecka_dh_SessionKDF_AES128	);

#define ASC_ecka_dh_SessionKDF_AES192		ASC_ecka_dh".2.3"
    NID_ecka_dh_SessionKDF_AES192 = OBJ_create(ASC_ecka_dh_SessionKDF_AES192	, SN_ecka_dh_SessionKDF_AES192	, SN_ecka_dh_SessionKDF_AES192	);

#define ASC_ecka_dh_SessionKDF_AES256		ASC_ecka_dh".2.4"
    NID_ecka_dh_SessionKDF_AES256 = OBJ_create(ASC_ecka_dh_SessionKDF_AES256	, SN_ecka_dh_SessionKDF_AES256	, SN_ecka_dh_SessionKDF_AES256	);

#define ASC_id_roles		ASC_bsi_de".3.1.2"

#define ASC_id_IS		ASC_id_roles".1"
    NID_id_IS = OBJ_create(ASC_id_IS	, SN_id_IS	, SN_id_IS	);

#define ASC_id_AT		ASC_id_roles".2"
    NID_id_AT = OBJ_create(ASC_id_AT	, SN_id_AT	, SN_id_AT	);

#define ASC_id_ST		ASC_id_roles".3"
    NID_id_ST = OBJ_create(ASC_id_ST	, SN_id_ST	, SN_id_ST	);

#define ASC_id_extensions		ASC_bsi_de".3.1.3"

#define ASC_id_description		ASC_id_extensions".1"
    NID_id_description = OBJ_create(ASC_id_description	, SN_id_description	, SN_id_description	);

#define ASC_id_plainFormat		ASC_id_description".1"
    NID_id_plainFormat = OBJ_create(ASC_id_plainFormat	, SN_id_plainFormat	, SN_id_plainFormat	);

#define ASC_id_htmlFormat		ASC_id_description".2"
    NID_id_htmlFormat = OBJ_create(ASC_id_htmlFormat	, SN_id_htmlFormat	, SN_id_htmlFormat	);

#define ASC_id_pdfFormat		ASC_id_description".3"
    NID_id_pdfFormat = OBJ_create(ASC_id_pdfFormat	, SN_id_pdfFormat	, SN_id_pdfFormat	);

#define ASC_id_sector		ASC_id_extensions".2"
    NID_id_sector = OBJ_create(ASC_id_sector	, SN_id_sector	, SN_id_sector	);

#define ASC_id_eID		ASC_bsi_de".3.2"

#define ASC_id_SecurityObject		ASC_id_eID".1"
    NID_id_SecurityObject = OBJ_create(ASC_id_SecurityObject	, SN_id_SecurityObject	, SN_id_SecurityObject	);

#define ASC_id_AuxiliaryData		ASC_bsi_de".3.1.4"

#define ASC_id_DateOfBirth		ASC_id_AuxiliaryData".1"
    NID_id_DateOfBirth = OBJ_create(ASC_id_DateOfBirth	, SN_id_DateOfBirth	, SN_id_DateOfBirth	);

#define ASC_id_DateOfExpiry		ASC_id_AuxiliaryData".2"
    NID_id_DateOfExpiry = OBJ_create(ASC_id_DateOfExpiry	, SN_id_DateOfExpiry	, SN_id_DateOfExpiry	);

#define ASC_id_CommunityID		ASC_id_AuxiliaryData".3"
    NID_id_CommunityID = OBJ_create(ASC_id_CommunityID	, SN_id_CommunityID	, SN_id_CommunityID	);

    if (NID_undef == NID_standardizedDomainParameters
            || NID_undef == NID_id_PK_DH
            || NID_undef == NID_id_PK_ECDH
            || NID_undef == NID_id_TA
            || NID_undef == NID_id_TA_RSA
            || NID_undef == NID_id_TA_RSA_v1_5_SHA_1
            || NID_undef == NID_id_TA_RSA_v1_5_SHA_256
            || NID_undef == NID_id_TA_RSA_PSS_SHA_1
            || NID_undef == NID_id_TA_RSA_PSS_SHA_256
            || NID_undef == NID_id_TA_RSA_v1_5_SHA_512
            || NID_undef == NID_id_TA_RSA_PSS_SHA_512
            || NID_undef == NID_id_TA_ECDSA
            || NID_undef == NID_id_TA_ECDSA_SHA_1
            || NID_undef == NID_id_TA_ECDSA_SHA_224
            || NID_undef == NID_id_TA_ECDSA_SHA_256
            || NID_undef == NID_id_TA_ECDSA_SHA_384
            || NID_undef == NID_id_TA_ECDSA_SHA_512
            || NID_undef == NID_id_CA_DH
            || NID_undef == NID_id_CA_DH_3DES_CBC_CBC
            || NID_undef == NID_id_CA_DH_AES_CBC_CMAC_128
            || NID_undef == NID_id_CA_DH_AES_CBC_CMAC_192
            || NID_undef == NID_id_CA_DH_AES_CBC_CMAC_256
            || NID_undef == NID_id_CA_ECDH
            || NID_undef == NID_id_CA_ECDH_3DES_CBC_CBC
            || NID_undef == NID_id_CA_ECDH_AES_CBC_CMAC_128
            || NID_undef == NID_id_CA_ECDH_AES_CBC_CMAC_192
            || NID_undef == NID_id_CA_ECDH_AES_CBC_CMAC_256
            || NID_undef == NID_id_PACE_DH_GM
            || NID_undef == NID_id_PACE_DH_GM_3DES_CBC_CBC
            || NID_undef == NID_id_PACE_DH_GM_AES_CBC_CMAC_128
            || NID_undef == NID_id_PACE_DH_GM_AES_CBC_CMAC_192
            || NID_undef == NID_id_PACE_DH_GM_AES_CBC_CMAC_256
            || NID_undef == NID_id_PACE_ECDH_GM
            || NID_undef == NID_id_PACE_ECDH_GM_3DES_CBC_CBC
            || NID_undef == NID_id_PACE_ECDH_GM_AES_CBC_CMAC_128
            || NID_undef == NID_id_PACE_ECDH_GM_AES_CBC_CMAC_192
            || NID_undef == NID_id_PACE_ECDH_GM_AES_CBC_CMAC_256
            || NID_undef == NID_id_PACE_DH_IM
            || NID_undef == NID_id_PACE_DH_IM_3DES_CBC_CBC
            || NID_undef == NID_id_PACE_DH_IM_AES_CBC_CMAC_128
            || NID_undef == NID_id_PACE_DH_IM_AES_CBC_CMAC_192
            || NID_undef == NID_id_PACE_DH_IM_AES_CBC_CMAC_256
            || NID_undef == NID_id_PACE_ECDH_IM
            || NID_undef == NID_id_PACE_ECDH_IM_3DES_CBC_CBC
            || NID_undef == NID_id_PACE_ECDH_IM_AES_CBC_CMAC_128
            || NID_undef == NID_id_PACE_ECDH_IM_AES_CBC_CMAC_192
            || NID_undef == NID_id_PACE_ECDH_IM_AES_CBC_CMAC_256
            || NID_undef == NID_id_RI_DH
            || NID_undef == NID_id_RI_DH_SHA_1
            || NID_undef == NID_id_RI_DH_SHA_224
            || NID_undef == NID_id_RI_DH_SHA_256
            || NID_undef == NID_id_RI_DH_SHA_384
            || NID_undef == NID_id_RI_DH_SHA_512
            || NID_undef == NID_id_RI_ECDH
            || NID_undef == NID_id_RI_ECDH_SHA_1
            || NID_undef == NID_id_RI_ECDH_SHA_224
            || NID_undef == NID_id_RI_ECDH_SHA_256
            || NID_undef == NID_id_RI_ECDH_SHA_384
            || NID_undef == NID_id_RI_ECDH_SHA_512
            || NID_undef == NID_id_CI
            || NID_undef == NID_id_eIDSecurity
            || NID_undef == NID_id_PT
            || NID_undef == NID_ecka_dh_SessionKDF
            || NID_undef == NID_ecka_dh_SessionKDF_DES3
            || NID_undef == NID_ecka_dh_SessionKDF_AES128
            || NID_undef == NID_ecka_dh_SessionKDF_AES192
            || NID_undef == NID_ecka_dh_SessionKDF_AES256
            || NID_undef == NID_id_IS
            || NID_undef == NID_id_AT
            || NID_undef == NID_id_ST
            || NID_undef == NID_id_description
            || NID_undef == NID_id_plainFormat
            || NID_undef == NID_id_htmlFormat
            || NID_undef == NID_id_pdfFormat
            || NID_undef == NID_id_sector
            || NID_undef == NID_id_SecurityObject
            || NID_undef == NID_id_DateOfBirth
            || NID_undef == NID_id_DateOfExpiry
            || NID_undef == NID_id_CommunityID) {
        log_err("Error adding objects");
    }
}
void
EAC_remove_all_objects(void)
{
    OBJ_cleanup();
}
#else
void
EAC_add_all_objects(void)
{
}
void
EAC_remove_all_objects(void)
{
}
#endif
