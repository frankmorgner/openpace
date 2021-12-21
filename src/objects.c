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

ASN1_OBJECT *EAC_OBJ_nid2obj(int n)
{
    return OBJ_nid2obj(n);
}
const char *EAC_OBJ_nid2ln(int n)
{
    return OBJ_nid2ln(n);
}
const char *EAC_OBJ_nid2sn(int n)
{
    return OBJ_nid2sn(n);
}
int EAC_OBJ_obj2nid(const ASN1_OBJECT *o)
{
    return OBJ_obj2nid(o);
}
ASN1_OBJECT *EAC_OBJ_txt2obj(const char *s, int no_name)
{
    return OBJ_txt2obj(s, no_name);
}
int EAC_OBJ_txt2nid(const char *s)
{
    return OBJ_txt2nid(s);
}
int EAC_OBJ_ln2nid(const char *s)
{
    return OBJ_ln2nid(s);
}
int EAC_OBJ_sn2nid(const char *s)
{
    return OBJ_sn2nid(s);
}

#ifndef HAVE_PATCHED_OPENSSL

int objects_initialized = 0;

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
    int obj;

    if (objects_initialized)
        return;

    /* derived from a patched obj_mac.h with the power of regex */
#define ASC_bsi_de		"0.4.0.127.0.7"

#define ASC_standardizedDomainParameters		ASC_bsi_de".1.2"
    obj = OBJ_create(ASC_standardizedDomainParameters	, SN_standardizedDomainParameters	, SN_standardizedDomainParameters	);
    if (obj != NID_undef)
        NID_standardizedDomainParameters = obj;

#define ASC_id_PK		ASC_bsi_de".2.2.1"

#define ASC_id_PK_DH		ASC_id_PK".1"
    obj = OBJ_create(ASC_id_PK_DH	, SN_id_PK_DH	, SN_id_PK_DH	);
    if (obj != NID_undef)
        NID_id_PK_DH = obj;

#define ASC_id_PK_ECDH		ASC_id_PK".2"
    obj = OBJ_create(ASC_id_PK_ECDH	, SN_id_PK_ECDH	, SN_id_PK_ECDH	);
    if (obj != NID_undef)
        NID_id_PK_ECDH = obj;

#define ASC_id_TA		ASC_bsi_de".2.2.2"
    obj = OBJ_create(ASC_id_TA	, SN_id_TA	, SN_id_TA	);
    if (obj != NID_undef)
        NID_id_TA = obj;

#define ASC_id_TA_RSA		ASC_id_TA".1"
    obj = OBJ_create(ASC_id_TA_RSA	, SN_id_TA_RSA	, SN_id_TA_RSA	);
    if (obj != NID_undef)
        NID_id_TA_RSA = obj;

#define ASC_id_TA_RSA_v1_5_SHA_1		ASC_id_TA_RSA".1"
    obj = OBJ_create(ASC_id_TA_RSA_v1_5_SHA_1	, SN_id_TA_RSA_v1_5_SHA_1	, SN_id_TA_RSA_v1_5_SHA_1	);
    if (obj != NID_undef)
        NID_id_TA_RSA_v1_5_SHA_1 = obj;

#define ASC_id_TA_RSA_v1_5_SHA_256		ASC_id_TA_RSA".2"
    obj = OBJ_create(ASC_id_TA_RSA_v1_5_SHA_256	, SN_id_TA_RSA_v1_5_SHA_256	, SN_id_TA_RSA_v1_5_SHA_256	);
    if (obj != NID_undef)
        NID_id_TA_RSA_v1_5_SHA_256 = obj;

#define ASC_id_TA_RSA_PSS_SHA_1		ASC_id_TA_RSA".3"
    obj = OBJ_create(ASC_id_TA_RSA_PSS_SHA_1	, SN_id_TA_RSA_PSS_SHA_1	, SN_id_TA_RSA_PSS_SHA_1	);
    if (obj != NID_undef)
        NID_id_TA_RSA_PSS_SHA_1 = obj;

#define ASC_id_TA_RSA_PSS_SHA_256		ASC_id_TA_RSA".4"
    obj = OBJ_create(ASC_id_TA_RSA_PSS_SHA_256	, SN_id_TA_RSA_PSS_SHA_256	, SN_id_TA_RSA_PSS_SHA_256	);
    if (obj != NID_undef)
        NID_id_TA_RSA_PSS_SHA_256 = obj;

#define ASC_id_TA_RSA_v1_5_SHA_512		ASC_id_TA_RSA".5"
    obj = OBJ_create(ASC_id_TA_RSA_v1_5_SHA_512	, SN_id_TA_RSA_v1_5_SHA_512	, SN_id_TA_RSA_v1_5_SHA_512	);
    if (obj != NID_undef)
        NID_id_TA_RSA_v1_5_SHA_512 = obj;

#define ASC_id_TA_RSA_PSS_SHA_512		ASC_id_TA_RSA".6"
    obj = OBJ_create(ASC_id_TA_RSA_PSS_SHA_512	, SN_id_TA_RSA_PSS_SHA_512	, SN_id_TA_RSA_PSS_SHA_512	);
    if (obj != NID_undef)
        NID_id_TA_RSA_PSS_SHA_512 = obj;

#define ASC_id_TA_ECDSA		ASC_id_TA".2"
    obj = OBJ_create(ASC_id_TA_ECDSA	, SN_id_TA_ECDSA	, SN_id_TA_ECDSA	);
    if (obj != NID_undef)
        NID_id_TA_ECDSA = obj;

#define ASC_id_TA_ECDSA_SHA_1		ASC_id_TA_ECDSA".1"
    obj = OBJ_create(ASC_id_TA_ECDSA_SHA_1	, SN_id_TA_ECDSA_SHA_1	, SN_id_TA_ECDSA_SHA_1	);
    if (obj != NID_undef)
        NID_id_TA_ECDSA_SHA_1 = obj;

#define ASC_id_TA_ECDSA_SHA_224		ASC_id_TA_ECDSA".2"
    obj = OBJ_create(ASC_id_TA_ECDSA_SHA_224	, SN_id_TA_ECDSA_SHA_224	, SN_id_TA_ECDSA_SHA_224	);
    if (obj != NID_undef)
        NID_id_TA_ECDSA_SHA_224 = obj;

#define ASC_id_TA_ECDSA_SHA_256		ASC_id_TA_ECDSA".3"
    obj = OBJ_create(ASC_id_TA_ECDSA_SHA_256	, SN_id_TA_ECDSA_SHA_256	, SN_id_TA_ECDSA_SHA_256	);
    if (obj != NID_undef)
        NID_id_TA_ECDSA_SHA_256 = obj;

#define ASC_id_TA_ECDSA_SHA_384		ASC_id_TA_ECDSA".4"
    obj = OBJ_create(ASC_id_TA_ECDSA_SHA_384	, SN_id_TA_ECDSA_SHA_384	, SN_id_TA_ECDSA_SHA_384	);
    if (obj != NID_undef)
        NID_id_TA_ECDSA_SHA_384 = obj;

#define ASC_id_TA_ECDSA_SHA_512		ASC_id_TA_ECDSA".5"
    obj = OBJ_create(ASC_id_TA_ECDSA_SHA_512	, SN_id_TA_ECDSA_SHA_512	, SN_id_TA_ECDSA_SHA_512	);
    if (obj != NID_undef)
        NID_id_TA_ECDSA_SHA_512 = obj;

#define ASC_id_CA		ASC_bsi_de".2.2.3"

#define ASC_id_CA_DH		ASC_id_CA".1"
    obj = OBJ_create(ASC_id_CA_DH	, SN_id_CA_DH	, SN_id_CA_DH	);
    if (obj != NID_undef)
        NID_id_CA_DH = obj;

#define ASC_id_CA_DH_3DES_CBC_CBC		ASC_id_CA_DH".1"
    obj = OBJ_create(ASC_id_CA_DH_3DES_CBC_CBC	, SN_id_CA_DH_3DES_CBC_CBC	, SN_id_CA_DH_3DES_CBC_CBC	);
    if (obj != NID_undef)
        NID_id_CA_DH_3DES_CBC_CBC = obj;

#define ASC_id_CA_DH_AES_CBC_CMAC_128		ASC_id_CA_DH".2"
    obj = OBJ_create(ASC_id_CA_DH_AES_CBC_CMAC_128	, SN_id_CA_DH_AES_CBC_CMAC_128	, SN_id_CA_DH_AES_CBC_CMAC_128	);
    if (obj != NID_undef)
        NID_id_CA_DH_AES_CBC_CMAC_128 = obj;

#define ASC_id_CA_DH_AES_CBC_CMAC_192		ASC_id_CA_DH".3"
    obj = OBJ_create(ASC_id_CA_DH_AES_CBC_CMAC_192	, SN_id_CA_DH_AES_CBC_CMAC_192	, SN_id_CA_DH_AES_CBC_CMAC_192	);
    if (obj != NID_undef)
        NID_id_CA_DH_AES_CBC_CMAC_192 = obj;

#define ASC_id_CA_DH_AES_CBC_CMAC_256		ASC_id_CA_DH".4"
    obj = OBJ_create(ASC_id_CA_DH_AES_CBC_CMAC_256	, SN_id_CA_DH_AES_CBC_CMAC_256	, SN_id_CA_DH_AES_CBC_CMAC_256	);
    if (obj != NID_undef)
        NID_id_CA_DH_AES_CBC_CMAC_256 = obj;

#define ASC_id_CA_ECDH		ASC_id_CA".2"
    obj = OBJ_create(ASC_id_CA_ECDH	, SN_id_CA_ECDH	, SN_id_CA_ECDH	);
    if (obj != NID_undef)
        NID_id_CA_ECDH = obj;

#define ASC_id_CA_ECDH_3DES_CBC_CBC		ASC_id_CA_ECDH".1"
    obj = OBJ_create(ASC_id_CA_ECDH_3DES_CBC_CBC	, SN_id_CA_ECDH_3DES_CBC_CBC	, SN_id_CA_ECDH_3DES_CBC_CBC	);
    if (obj != NID_undef)
        NID_id_CA_ECDH_3DES_CBC_CBC = obj;

#define ASC_id_CA_ECDH_AES_CBC_CMAC_128		ASC_id_CA_ECDH".2"
    obj = OBJ_create(ASC_id_CA_ECDH_AES_CBC_CMAC_128	, SN_id_CA_ECDH_AES_CBC_CMAC_128	, SN_id_CA_ECDH_AES_CBC_CMAC_128	);
    if (obj != NID_undef)
        NID_id_CA_ECDH_AES_CBC_CMAC_128 = obj;

#define ASC_id_CA_ECDH_AES_CBC_CMAC_192		ASC_id_CA_ECDH".3"
    obj = OBJ_create(ASC_id_CA_ECDH_AES_CBC_CMAC_192	, SN_id_CA_ECDH_AES_CBC_CMAC_192	, SN_id_CA_ECDH_AES_CBC_CMAC_192	);
    if (obj != NID_undef)
        NID_id_CA_ECDH_AES_CBC_CMAC_192 = obj;

#define ASC_id_CA_ECDH_AES_CBC_CMAC_256		ASC_id_CA_ECDH".4"
    obj = OBJ_create(ASC_id_CA_ECDH_AES_CBC_CMAC_256	, SN_id_CA_ECDH_AES_CBC_CMAC_256	, SN_id_CA_ECDH_AES_CBC_CMAC_256	);
    if (obj != NID_undef)
        NID_id_CA_ECDH_AES_CBC_CMAC_256 = obj;

#define ASC_id_PACE		ASC_bsi_de".2.2.4"

#define ASC_id_PACE_DH_GM		ASC_id_PACE".1"
    obj = OBJ_create(ASC_id_PACE_DH_GM	, SN_id_PACE_DH_GM	, SN_id_PACE_DH_GM	);
    if (obj != NID_undef)
        NID_id_PACE_DH_GM = obj;

#define ASC_id_PACE_DH_GM_3DES_CBC_CBC		ASC_id_PACE_DH_GM".1"
    obj = OBJ_create(ASC_id_PACE_DH_GM_3DES_CBC_CBC	, SN_id_PACE_DH_GM_3DES_CBC_CBC	, SN_id_PACE_DH_GM_3DES_CBC_CBC	);
    if (obj != NID_undef)
        NID_id_PACE_DH_GM_3DES_CBC_CBC = obj;

#define ASC_id_PACE_DH_GM_AES_CBC_CMAC_128		ASC_id_PACE_DH_GM".2"
    obj = OBJ_create(ASC_id_PACE_DH_GM_AES_CBC_CMAC_128	, SN_id_PACE_DH_GM_AES_CBC_CMAC_128	, SN_id_PACE_DH_GM_AES_CBC_CMAC_128	);
    if (obj != NID_undef)
        NID_id_PACE_DH_GM_AES_CBC_CMAC_128 = obj;

#define ASC_id_PACE_DH_GM_AES_CBC_CMAC_192		ASC_id_PACE_DH_GM".3"
    obj = OBJ_create(ASC_id_PACE_DH_GM_AES_CBC_CMAC_192	, SN_id_PACE_DH_GM_AES_CBC_CMAC_192	, SN_id_PACE_DH_GM_AES_CBC_CMAC_192	);
    if (obj != NID_undef)
        NID_id_PACE_DH_GM_AES_CBC_CMAC_192 = obj;

#define ASC_id_PACE_DH_GM_AES_CBC_CMAC_256		ASC_id_PACE_DH_GM".4"
    obj = OBJ_create(ASC_id_PACE_DH_GM_AES_CBC_CMAC_256	, SN_id_PACE_DH_GM_AES_CBC_CMAC_256	, SN_id_PACE_DH_GM_AES_CBC_CMAC_256	);
    if (obj != NID_undef)
        NID_id_PACE_DH_GM_AES_CBC_CMAC_256 = obj;

#define ASC_id_PACE_ECDH_GM		ASC_id_PACE".2"
    obj = OBJ_create(ASC_id_PACE_ECDH_GM	, SN_id_PACE_ECDH_GM	, SN_id_PACE_ECDH_GM	);
    if (obj != NID_undef)
        NID_id_PACE_ECDH_GM = obj;

#define ASC_id_PACE_ECDH_GM_3DES_CBC_CBC		ASC_id_PACE_ECDH_GM".1"
    obj = OBJ_create(ASC_id_PACE_ECDH_GM_3DES_CBC_CBC	, SN_id_PACE_ECDH_GM_3DES_CBC_CBC	, SN_id_PACE_ECDH_GM_3DES_CBC_CBC	);
    if (obj != NID_undef)
        NID_id_PACE_ECDH_GM_3DES_CBC_CBC = obj;

#define ASC_id_PACE_ECDH_GM_AES_CBC_CMAC_128		ASC_id_PACE_ECDH_GM".2"
    obj = OBJ_create(ASC_id_PACE_ECDH_GM_AES_CBC_CMAC_128	, SN_id_PACE_ECDH_GM_AES_CBC_CMAC_128	, SN_id_PACE_ECDH_GM_AES_CBC_CMAC_128	);
    if (obj != NID_undef)
        NID_id_PACE_ECDH_GM_AES_CBC_CMAC_128 = obj;

#define ASC_id_PACE_ECDH_GM_AES_CBC_CMAC_192		ASC_id_PACE_ECDH_GM".3"
    obj = OBJ_create(ASC_id_PACE_ECDH_GM_AES_CBC_CMAC_192	, SN_id_PACE_ECDH_GM_AES_CBC_CMAC_192	, SN_id_PACE_ECDH_GM_AES_CBC_CMAC_192	);
    if (obj != NID_undef)
        NID_id_PACE_ECDH_GM_AES_CBC_CMAC_192 = obj;

#define ASC_id_PACE_ECDH_GM_AES_CBC_CMAC_256		ASC_id_PACE_ECDH_GM".4"
    obj = OBJ_create(ASC_id_PACE_ECDH_GM_AES_CBC_CMAC_256	, SN_id_PACE_ECDH_GM_AES_CBC_CMAC_256	, SN_id_PACE_ECDH_GM_AES_CBC_CMAC_256	);
    if (obj != NID_undef)
        NID_id_PACE_ECDH_GM_AES_CBC_CMAC_256 = obj;

#define ASC_id_PACE_DH_IM		ASC_id_PACE".3"
    obj = OBJ_create(ASC_id_PACE_DH_IM	, SN_id_PACE_DH_IM	, SN_id_PACE_DH_IM	);
    if (obj != NID_undef)
        NID_id_PACE_DH_IM = obj;

#define ASC_id_PACE_DH_IM_3DES_CBC_CBC		ASC_id_PACE_DH_IM".1"
    obj = OBJ_create(ASC_id_PACE_DH_IM_3DES_CBC_CBC	, SN_id_PACE_DH_IM_3DES_CBC_CBC	, SN_id_PACE_DH_IM_3DES_CBC_CBC	);
    if (obj != NID_undef)
        NID_id_PACE_DH_IM_3DES_CBC_CBC = obj;

#define ASC_id_PACE_DH_IM_AES_CBC_CMAC_128		ASC_id_PACE_DH_IM".2"
    obj = OBJ_create(ASC_id_PACE_DH_IM_AES_CBC_CMAC_128	, SN_id_PACE_DH_IM_AES_CBC_CMAC_128	, SN_id_PACE_DH_IM_AES_CBC_CMAC_128	);
    if (obj != NID_undef)
        NID_id_PACE_DH_IM_AES_CBC_CMAC_128 = obj;

#define ASC_id_PACE_DH_IM_AES_CBC_CMAC_192		ASC_id_PACE_DH_IM".3"
    obj = OBJ_create(ASC_id_PACE_DH_IM_AES_CBC_CMAC_192	, SN_id_PACE_DH_IM_AES_CBC_CMAC_192	, SN_id_PACE_DH_IM_AES_CBC_CMAC_192	);
    if (obj != NID_undef)
        NID_id_PACE_DH_IM_AES_CBC_CMAC_192 = obj;

#define ASC_id_PACE_DH_IM_AES_CBC_CMAC_256		ASC_id_PACE_DH_IM".4"
    obj = OBJ_create(ASC_id_PACE_DH_IM_AES_CBC_CMAC_256	, SN_id_PACE_DH_IM_AES_CBC_CMAC_256	, SN_id_PACE_DH_IM_AES_CBC_CMAC_256	);
    if (obj != NID_undef)
        NID_id_PACE_DH_IM_AES_CBC_CMAC_256 = obj;

#define ASC_id_PACE_ECDH_IM		ASC_id_PACE".4"
    obj = OBJ_create(ASC_id_PACE_ECDH_IM	, SN_id_PACE_ECDH_IM	, SN_id_PACE_ECDH_IM	);
    if (obj != NID_undef)
        NID_id_PACE_ECDH_IM = obj;

#define ASC_id_PACE_ECDH_IM_3DES_CBC_CBC		ASC_id_PACE_ECDH_IM".1"
    obj = OBJ_create(ASC_id_PACE_ECDH_IM_3DES_CBC_CBC	, SN_id_PACE_ECDH_IM_3DES_CBC_CBC	, SN_id_PACE_ECDH_IM_3DES_CBC_CBC	);
    if (obj != NID_undef)
        NID_id_PACE_ECDH_IM_3DES_CBC_CBC = obj;

#define ASC_id_PACE_ECDH_IM_AES_CBC_CMAC_128		ASC_id_PACE_ECDH_IM".2"
    obj = OBJ_create(ASC_id_PACE_ECDH_IM_AES_CBC_CMAC_128	, SN_id_PACE_ECDH_IM_AES_CBC_CMAC_128	, SN_id_PACE_ECDH_IM_AES_CBC_CMAC_128	);
    if (obj != NID_undef)
        NID_id_PACE_ECDH_IM_AES_CBC_CMAC_128 = obj;

#define ASC_id_PACE_ECDH_IM_AES_CBC_CMAC_192		ASC_id_PACE_ECDH_IM".3"
    obj = OBJ_create(ASC_id_PACE_ECDH_IM_AES_CBC_CMAC_192	, SN_id_PACE_ECDH_IM_AES_CBC_CMAC_192	, SN_id_PACE_ECDH_IM_AES_CBC_CMAC_192	);
    if (obj != NID_undef)
        NID_id_PACE_ECDH_IM_AES_CBC_CMAC_192 = obj;

#define ASC_id_PACE_ECDH_IM_AES_CBC_CMAC_256		ASC_id_PACE_ECDH_IM".4"
    obj = OBJ_create(ASC_id_PACE_ECDH_IM_AES_CBC_CMAC_256	, SN_id_PACE_ECDH_IM_AES_CBC_CMAC_256	, SN_id_PACE_ECDH_IM_AES_CBC_CMAC_256	);
    if (obj != NID_undef)
        NID_id_PACE_ECDH_IM_AES_CBC_CMAC_256 = obj;

#define ASC_id_RI		ASC_bsi_de".2.2.5"

#define ASC_id_RI_DH		ASC_id_RI".1"
    obj = OBJ_create(ASC_id_RI_DH	, SN_id_RI_DH	, SN_id_RI_DH	);
    if (obj != NID_undef)
        NID_id_RI_DH = obj;

#define ASC_id_RI_DH_SHA_1		ASC_id_RI_DH".1"
    obj = OBJ_create(ASC_id_RI_DH_SHA_1	, SN_id_RI_DH_SHA_1	, SN_id_RI_DH_SHA_1	);
    if (obj != NID_undef)
        NID_id_RI_DH_SHA_1 = obj;

#define ASC_id_RI_DH_SHA_224		ASC_id_RI_DH".2"
    obj = OBJ_create(ASC_id_RI_DH_SHA_224	, SN_id_RI_DH_SHA_224	, SN_id_RI_DH_SHA_224	);
    if (obj != NID_undef)
        NID_id_RI_DH_SHA_224 = obj;

#define ASC_id_RI_DH_SHA_256		ASC_id_RI_DH".3"
    obj = OBJ_create(ASC_id_RI_DH_SHA_256	, SN_id_RI_DH_SHA_256	, SN_id_RI_DH_SHA_256	);
    if (obj != NID_undef)
        NID_id_RI_DH_SHA_256 = obj;

#define ASC_id_RI_DH_SHA_384		ASC_id_RI_DH".4"
    obj = OBJ_create(ASC_id_RI_DH_SHA_384	, SN_id_RI_DH_SHA_384	, SN_id_RI_DH_SHA_384	);
    if (obj != NID_undef)
        NID_id_RI_DH_SHA_384 = obj;

#define ASC_id_RI_DH_SHA_512		ASC_id_RI_DH".5"
    obj = OBJ_create(ASC_id_RI_DH_SHA_512	, SN_id_RI_DH_SHA_512	, SN_id_RI_DH_SHA_512	);
    if (obj != NID_undef)
        NID_id_RI_DH_SHA_512 = obj;

#define ASC_id_RI_ECDH		ASC_id_RI".2"
    obj = OBJ_create(ASC_id_RI_ECDH	, SN_id_RI_ECDH	, SN_id_RI_ECDH	);
    if (obj != NID_undef)
        NID_id_RI_ECDH = obj;

#define ASC_id_RI_ECDH_SHA_1		ASC_id_RI_ECDH".1"
    obj = OBJ_create(ASC_id_RI_ECDH_SHA_1	, SN_id_RI_ECDH_SHA_1	, SN_id_RI_ECDH_SHA_1	);
    if (obj != NID_undef)
        NID_id_RI_ECDH_SHA_1 = obj;

#define ASC_id_RI_ECDH_SHA_224		ASC_id_RI_ECDH".2"
    obj = OBJ_create(ASC_id_RI_ECDH_SHA_224	, SN_id_RI_ECDH_SHA_224	, SN_id_RI_ECDH_SHA_224	);
    if (obj != NID_undef)
        NID_id_RI_ECDH_SHA_224 = obj;

#define ASC_id_RI_ECDH_SHA_256		ASC_id_RI_ECDH".3"
    obj = OBJ_create(ASC_id_RI_ECDH_SHA_256	, SN_id_RI_ECDH_SHA_256	, SN_id_RI_ECDH_SHA_256	);
    if (obj != NID_undef)
        NID_id_RI_ECDH_SHA_256 = obj;

#define ASC_id_RI_ECDH_SHA_384		ASC_id_RI_ECDH".4"
    obj = OBJ_create(ASC_id_RI_ECDH_SHA_384	, SN_id_RI_ECDH_SHA_384	, SN_id_RI_ECDH_SHA_384	);
    if (obj != NID_undef)
        NID_id_RI_ECDH_SHA_384 = obj;

#define ASC_id_RI_ECDH_SHA_512		ASC_id_RI_ECDH".5"
    obj = OBJ_create(ASC_id_RI_ECDH_SHA_512	, SN_id_RI_ECDH_SHA_512	, SN_id_RI_ECDH_SHA_512	);
    if (obj != NID_undef)
        NID_id_RI_ECDH_SHA_512 = obj;

#define ASC_id_CI		ASC_bsi_de".2.2.6"
    obj = OBJ_create(ASC_id_CI	, SN_id_CI	, SN_id_CI	);
    if (obj != NID_undef)
        NID_id_CI = obj;

#define ASC_id_eIDSecurity		ASC_bsi_de".2.2.7"
    obj = OBJ_create(ASC_id_eIDSecurity	, SN_id_eIDSecurity	, SN_id_eIDSecurity	);
    if (obj != NID_undef)
        NID_id_eIDSecurity = obj;

#define ASC_id_PT		ASC_bsi_de".2.2.8"
    obj = OBJ_create(ASC_id_PT	, SN_id_PT	, SN_id_PT	);
    if (obj != NID_undef)
        NID_id_PT = obj;

#define ASC_id_ecc		ASC_bsi_de".1.1"

#define ASC_ecka_dh		ASC_id_ecc".5.2"

#define ASC_ecka_dh_SessionKDF		ASC_ecka_dh".2"
    obj = OBJ_create(ASC_ecka_dh_SessionKDF	, SN_ecka_dh_SessionKDF	, SN_ecka_dh_SessionKDF	);
    if (obj != NID_undef)
        NID_ecka_dh_SessionKDF = obj;

#define ASC_ecka_dh_SessionKDF_DES3		ASC_ecka_dh".2.1"
    obj = OBJ_create(ASC_ecka_dh_SessionKDF_DES3	, SN_ecka_dh_SessionKDF_DES3	, SN_ecka_dh_SessionKDF_DES3	);
    if (obj != NID_undef)
        NID_ecka_dh_SessionKDF_DES3 = obj;

#define ASC_ecka_dh_SessionKDF_AES128		ASC_ecka_dh".2.2"
    obj = OBJ_create(ASC_ecka_dh_SessionKDF_AES128	, SN_ecka_dh_SessionKDF_AES128	, SN_ecka_dh_SessionKDF_AES128	);
    if (obj != NID_undef)
        NID_ecka_dh_SessionKDF_AES128 = obj;

#define ASC_ecka_dh_SessionKDF_AES192		ASC_ecka_dh".2.3"
    obj = OBJ_create(ASC_ecka_dh_SessionKDF_AES192	, SN_ecka_dh_SessionKDF_AES192	, SN_ecka_dh_SessionKDF_AES192	);
    if (obj != NID_undef)
        NID_ecka_dh_SessionKDF_AES192 = obj;

#define ASC_ecka_dh_SessionKDF_AES256		ASC_ecka_dh".2.4"
    obj = OBJ_create(ASC_ecka_dh_SessionKDF_AES256	, SN_ecka_dh_SessionKDF_AES256	, SN_ecka_dh_SessionKDF_AES256	);
    if (obj != NID_undef)
        NID_ecka_dh_SessionKDF_AES256 = obj;

#define ASC_id_roles		ASC_bsi_de".3.1.2"

#define ASC_id_IS		ASC_id_roles".1"
    obj = OBJ_create(ASC_id_IS	, SN_id_IS	, SN_id_IS	);
    if (obj != NID_undef)
        NID_id_IS = obj;

#define ASC_id_AT		ASC_id_roles".2"
    obj = OBJ_create(ASC_id_AT	, SN_id_AT	, SN_id_AT	);
    if (obj != NID_undef)
        NID_id_AT = obj;

#define ASC_id_ST		ASC_id_roles".3"
    obj = OBJ_create(ASC_id_ST	, SN_id_ST	, SN_id_ST	);
    if (obj != NID_undef)
        NID_id_ST = obj;

#define ASC_id_extensions		ASC_bsi_de".3.1.3"

#define ASC_id_description		ASC_id_extensions".1"
    obj = OBJ_create(ASC_id_description	, SN_id_description	, SN_id_description	);
    if (obj != NID_undef)
        NID_id_description = obj;

#define ASC_id_plainFormat		ASC_id_description".1"
    obj = OBJ_create(ASC_id_plainFormat	, SN_id_plainFormat	, SN_id_plainFormat	);
    if (obj != NID_undef)
        NID_id_plainFormat = obj;

#define ASC_id_htmlFormat		ASC_id_description".2"
    obj = OBJ_create(ASC_id_htmlFormat	, SN_id_htmlFormat	, SN_id_htmlFormat	);
    if (obj != NID_undef)
        NID_id_htmlFormat = obj;

#define ASC_id_pdfFormat		ASC_id_description".3"
    obj = OBJ_create(ASC_id_pdfFormat	, SN_id_pdfFormat	, SN_id_pdfFormat	);
    if (obj != NID_undef)
        NID_id_pdfFormat = obj;

#define ASC_id_sector		ASC_id_extensions".2"
    obj = OBJ_create(ASC_id_sector	, SN_id_sector	, SN_id_sector	);
    if (obj != NID_undef)
        NID_id_sector = obj;

#define ASC_id_eID		ASC_bsi_de".3.2"

#define ASC_id_SecurityObject		ASC_id_eID".1"
    obj = OBJ_create(ASC_id_SecurityObject	, SN_id_SecurityObject	, SN_id_SecurityObject	);
    if (obj != NID_undef)
        NID_id_SecurityObject = obj;

#define ASC_id_AuxiliaryData		ASC_bsi_de".3.1.4"

#define ASC_id_DateOfBirth		ASC_id_AuxiliaryData".1"
    obj = OBJ_create(ASC_id_DateOfBirth	, SN_id_DateOfBirth	, SN_id_DateOfBirth	);
    if (obj != NID_undef)
        NID_id_DateOfBirth = obj;

#define ASC_id_DateOfExpiry		ASC_id_AuxiliaryData".2"
    obj = OBJ_create(ASC_id_DateOfExpiry	, SN_id_DateOfExpiry	, SN_id_DateOfExpiry	);
    if (obj != NID_undef)
        NID_id_DateOfExpiry = obj;

#define ASC_id_CommunityID		ASC_id_AuxiliaryData".3"
    obj = OBJ_create(ASC_id_CommunityID	, SN_id_CommunityID	, SN_id_CommunityID	);
    if (obj != NID_undef)
        NID_id_CommunityID = obj;

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

    objects_initialized = 1;
}
void
EAC_remove_all_objects(void)
{
    if (objects_initialized)
        OBJ_cleanup();

    objects_initialized = 0;
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
