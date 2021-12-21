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
 * @file objects.h
 * @brief Definitions of object identifiers
 *
 * @author Frank Morgner <frankmorgner@gmail.com>
 */

#ifndef OBJ_H_
#define OBJ_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <openssl/objects.h>
#include <openssl/obj_mac.h>

/** Wrappers for OpenSSL's OBJ_* functions.
 *
 * These wrappers are needed to access the possibly hidden table of OpenPACE's
 * dynamically created object identifiers.  If OpenPACE is linked statically,
 * this table is not visible to the calling application's OpenSSL, so that
 * PACE/CA/TA NIDs cannot be mapped to ASN1_OBJECTs. Using the wrappers below,
 * OpenPACE returns its internal objects. So that the calling application can
 * use this ASN1_OBJECT directly. */
ASN1_OBJECT *EAC_OBJ_nid2obj(int n);
const char *EAC_OBJ_nid2ln(int n);
const char *EAC_OBJ_nid2sn(int n);
int EAC_OBJ_obj2nid(const ASN1_OBJECT *o);
ASN1_OBJECT *EAC_OBJ_txt2obj(const char *s, int no_name);
int EAC_OBJ_txt2nid(const char *s);
int EAC_OBJ_ln2nid(const char *s);
int EAC_OBJ_sn2nid(const char *s);

#ifdef NID_id_PACE_ECDH_GM_AES_CBC_CMAC_128
#define HAVE_PATCHED_OPENSSL 1

#else

/* The following definitions are made to be compatible with OpenSSL */

#define OBJ_bsi_de		0L,4L,0L,127L,0L,7L

#define SN_standardizedDomainParameters		"standardizedDomainParameters"
extern int NID_standardizedDomainParameters;
#define OBJ_standardizedDomainParameters		OBJ_bsi_de,1L,2L

#define OBJ_id_PK		OBJ_bsi_de,2L,2L,1L

#define SN_id_PK_DH		"id-PK-DH"
extern int NID_id_PK_DH;
#define OBJ_id_PK_DH		OBJ_id_PK,1L

#define SN_id_PK_ECDH		"id-PK-ECDH"
extern int NID_id_PK_ECDH;
#define OBJ_id_PK_ECDH		OBJ_id_PK,2L

#define SN_id_TA		"id-TA"
extern int NID_id_TA;
#define OBJ_id_TA		OBJ_bsi_de,2L,2L,2L

#define SN_id_TA_RSA		"id-TA-RSA"
extern int NID_id_TA_RSA;
#define OBJ_id_TA_RSA		OBJ_id_TA,1L

#define SN_id_TA_RSA_v1_5_SHA_1		"id-TA-RSA-v1-5-SHA-1"
extern int NID_id_TA_RSA_v1_5_SHA_1;
#define OBJ_id_TA_RSA_v1_5_SHA_1		OBJ_id_TA_RSA,1L

#define SN_id_TA_RSA_v1_5_SHA_256		"id-TA-RSA-v1-5-SHA-256"
extern int NID_id_TA_RSA_v1_5_SHA_256;
#define OBJ_id_TA_RSA_v1_5_SHA_256		OBJ_id_TA_RSA,2L

#define SN_id_TA_RSA_PSS_SHA_1		"id-TA-RSA-PSS-SHA-1"
extern int NID_id_TA_RSA_PSS_SHA_1;
#define OBJ_id_TA_RSA_PSS_SHA_1		OBJ_id_TA_RSA,3L

#define SN_id_TA_RSA_PSS_SHA_256		"id-TA-RSA-PSS-SHA-256"
extern int NID_id_TA_RSA_PSS_SHA_256;
#define OBJ_id_TA_RSA_PSS_SHA_256		OBJ_id_TA_RSA,4L

#define SN_id_TA_RSA_v1_5_SHA_512		"id-TA-RSA-v1-5-SHA-512"
extern int NID_id_TA_RSA_v1_5_SHA_512;
#define OBJ_id_TA_RSA_v1_5_SHA_512		OBJ_id_TA_RSA,5L

#define SN_id_TA_RSA_PSS_SHA_512		"id-TA-RSA-PSS-SHA-512"
extern int NID_id_TA_RSA_PSS_SHA_512;
#define OBJ_id_TA_RSA_PSS_SHA_512		OBJ_id_TA_RSA,6L

#define SN_id_TA_ECDSA		"id-TA-ECDSA"
extern int NID_id_TA_ECDSA;
#define OBJ_id_TA_ECDSA		OBJ_id_TA,2L

#define SN_id_TA_ECDSA_SHA_1		"id-TA-ECDSA-SHA-1"
extern int NID_id_TA_ECDSA_SHA_1;
#define OBJ_id_TA_ECDSA_SHA_1		OBJ_id_TA_ECDSA,1L

#define SN_id_TA_ECDSA_SHA_224		"id-TA-ECDSA-SHA-224"
extern int NID_id_TA_ECDSA_SHA_224;
#define OBJ_id_TA_ECDSA_SHA_224		OBJ_id_TA_ECDSA,2L

#define SN_id_TA_ECDSA_SHA_256		"id-TA-ECDSA-SHA-256"
extern int NID_id_TA_ECDSA_SHA_256;
#define OBJ_id_TA_ECDSA_SHA_256		OBJ_id_TA_ECDSA,3L

#define SN_id_TA_ECDSA_SHA_384		"id-TA-ECDSA-SHA-384"
extern int NID_id_TA_ECDSA_SHA_384;
#define OBJ_id_TA_ECDSA_SHA_384		OBJ_id_TA_ECDSA,4L

#define SN_id_TA_ECDSA_SHA_512		"id-TA-ECDSA-SHA-512"
extern int NID_id_TA_ECDSA_SHA_512;
#define OBJ_id_TA_ECDSA_SHA_512		OBJ_id_TA_ECDSA,5L

#define OBJ_id_CA		OBJ_bsi_de,2L,2L,3L

#define SN_id_CA_DH		"id-CA-DH"
extern int NID_id_CA_DH;
#define OBJ_id_CA_DH		OBJ_id_CA,1L

#define SN_id_CA_DH_3DES_CBC_CBC		"id-CA-DH-3DES-CBC-CBC"
extern int NID_id_CA_DH_3DES_CBC_CBC;
#define OBJ_id_CA_DH_3DES_CBC_CBC		OBJ_id_CA_DH,1L

#define SN_id_CA_DH_AES_CBC_CMAC_128		"id-CA-DH-AES-CBC-CMAC-128"
extern int NID_id_CA_DH_AES_CBC_CMAC_128;
#define OBJ_id_CA_DH_AES_CBC_CMAC_128		OBJ_id_CA_DH,2L

#define SN_id_CA_DH_AES_CBC_CMAC_192		"id-CA-DH-AES-CBC-CMAC-192"
extern int NID_id_CA_DH_AES_CBC_CMAC_192;
#define OBJ_id_CA_DH_AES_CBC_CMAC_192		OBJ_id_CA_DH,3L

#define SN_id_CA_DH_AES_CBC_CMAC_256		"id-CA-DH-AES-CBC-CMAC-256"
extern int NID_id_CA_DH_AES_CBC_CMAC_256;
#define OBJ_id_CA_DH_AES_CBC_CMAC_256		OBJ_id_CA_DH,4L

#define SN_id_CA_ECDH		"id-CA-ECDH"
extern int NID_id_CA_ECDH;
#define OBJ_id_CA_ECDH		OBJ_id_CA,2L

#define SN_id_CA_ECDH_3DES_CBC_CBC		"id-CA-ECDH-3DES-CBC-CBC"
extern int NID_id_CA_ECDH_3DES_CBC_CBC;
#define OBJ_id_CA_ECDH_3DES_CBC_CBC		OBJ_id_CA_ECDH,1L

#define SN_id_CA_ECDH_AES_CBC_CMAC_128		"id-CA-ECDH-AES-CBC-CMAC-128"
extern int NID_id_CA_ECDH_AES_CBC_CMAC_128;
#define OBJ_id_CA_ECDH_AES_CBC_CMAC_128		OBJ_id_CA_ECDH,2L

#define SN_id_CA_ECDH_AES_CBC_CMAC_192		"id-CA-ECDH-AES-CBC-CMAC-192"
extern int NID_id_CA_ECDH_AES_CBC_CMAC_192;
#define OBJ_id_CA_ECDH_AES_CBC_CMAC_192		OBJ_id_CA_ECDH,3L

#define SN_id_CA_ECDH_AES_CBC_CMAC_256		"id-CA-ECDH-AES-CBC-CMAC-256"
extern int NID_id_CA_ECDH_AES_CBC_CMAC_256;
#define OBJ_id_CA_ECDH_AES_CBC_CMAC_256		OBJ_id_CA_ECDH,4L

#define OBJ_id_PACE		OBJ_bsi_de,2L,2L,4L

#define SN_id_PACE_DH_GM		"id-PACE-DH-GM"
extern int NID_id_PACE_DH_GM;
#define OBJ_id_PACE_DH_GM		OBJ_id_PACE,1L

#define SN_id_PACE_DH_GM_3DES_CBC_CBC		"id-PACE-DH-GM-3DES-CBC-CBC"
extern int NID_id_PACE_DH_GM_3DES_CBC_CBC;
#define OBJ_id_PACE_DH_GM_3DES_CBC_CBC		OBJ_id_PACE_DH_GM,1L

#define SN_id_PACE_DH_GM_AES_CBC_CMAC_128		"id-PACE-DH-GM-AES-CBC-CMAC-128"
extern int NID_id_PACE_DH_GM_AES_CBC_CMAC_128;
#define OBJ_id_PACE_DH_GM_AES_CBC_CMAC_128		OBJ_id_PACE_DH_GM,2L

#define SN_id_PACE_DH_GM_AES_CBC_CMAC_192		"id-PACE-DH-GM-AES-CBC-CMAC-192"
extern int NID_id_PACE_DH_GM_AES_CBC_CMAC_192;
#define OBJ_id_PACE_DH_GM_AES_CBC_CMAC_192		OBJ_id_PACE_DH_GM,3L

#define SN_id_PACE_DH_GM_AES_CBC_CMAC_256		"id-PACE-DH-GM-AES-CBC-CMAC-256"
extern int NID_id_PACE_DH_GM_AES_CBC_CMAC_256;
#define OBJ_id_PACE_DH_GM_AES_CBC_CMAC_256		OBJ_id_PACE_DH_GM,4L

#define SN_id_PACE_ECDH_GM		"id-PACE-ECDH-GM"
extern int NID_id_PACE_ECDH_GM;
#define OBJ_id_PACE_ECDH_GM		OBJ_id_PACE,2L

#define SN_id_PACE_ECDH_GM_3DES_CBC_CBC		"id-PACE-ECDH-GM-3DES-CBC-CBC"
extern int NID_id_PACE_ECDH_GM_3DES_CBC_CBC;
#define OBJ_id_PACE_ECDH_GM_3DES_CBC_CBC		OBJ_id_PACE_ECDH_GM,1L

#define SN_id_PACE_ECDH_GM_AES_CBC_CMAC_128		"id-PACE-ECDH-GM-AES-CBC-CMAC-128"
extern int NID_id_PACE_ECDH_GM_AES_CBC_CMAC_128;
#define OBJ_id_PACE_ECDH_GM_AES_CBC_CMAC_128		OBJ_id_PACE_ECDH_GM,2L

#define SN_id_PACE_ECDH_GM_AES_CBC_CMAC_192		"id-PACE-ECDH-GM-AES-CBC-CMAC-192"
extern int NID_id_PACE_ECDH_GM_AES_CBC_CMAC_192;
#define OBJ_id_PACE_ECDH_GM_AES_CBC_CMAC_192		OBJ_id_PACE_ECDH_GM,3L

#define SN_id_PACE_ECDH_GM_AES_CBC_CMAC_256		"id-PACE-ECDH-GM-AES-CBC-CMAC-256"
extern int NID_id_PACE_ECDH_GM_AES_CBC_CMAC_256;
#define OBJ_id_PACE_ECDH_GM_AES_CBC_CMAC_256		OBJ_id_PACE_ECDH_GM,4L

#define SN_id_PACE_DH_IM		"id-PACE-DH-IM"
extern int NID_id_PACE_DH_IM;
#define OBJ_id_PACE_DH_IM		OBJ_id_PACE,3L

#define SN_id_PACE_DH_IM_3DES_CBC_CBC		"id-PACE-DH-IM-3DES-CBC-CBC"
extern int NID_id_PACE_DH_IM_3DES_CBC_CBC;
#define OBJ_id_PACE_DH_IM_3DES_CBC_CBC		OBJ_id_PACE_DH_IM,1L

#define SN_id_PACE_DH_IM_AES_CBC_CMAC_128		"id-PACE-DH-IM-AES-CBC-CMAC-128"
extern int NID_id_PACE_DH_IM_AES_CBC_CMAC_128;
#define OBJ_id_PACE_DH_IM_AES_CBC_CMAC_128		OBJ_id_PACE_DH_IM,2L

#define SN_id_PACE_DH_IM_AES_CBC_CMAC_192		"id-PACE-DH-IM-AES-CBC-CMAC-192"
extern int NID_id_PACE_DH_IM_AES_CBC_CMAC_192;
#define OBJ_id_PACE_DH_IM_AES_CBC_CMAC_192		OBJ_id_PACE_DH_IM,3L

#define SN_id_PACE_DH_IM_AES_CBC_CMAC_256		"id-PACE-DH-IM-AES-CBC-CMAC-256"
extern int NID_id_PACE_DH_IM_AES_CBC_CMAC_256;
#define OBJ_id_PACE_DH_IM_AES_CBC_CMAC_256		OBJ_id_PACE_DH_IM,4L

#define SN_id_PACE_ECDH_IM		"id-PACE-ECDH-IM"
extern int NID_id_PACE_ECDH_IM;
#define OBJ_id_PACE_ECDH_IM		OBJ_id_PACE,4L

#define SN_id_PACE_ECDH_IM_3DES_CBC_CBC		"id-PACE-ECDH-IM-3DES-CBC-CBC"
extern int NID_id_PACE_ECDH_IM_3DES_CBC_CBC;
#define OBJ_id_PACE_ECDH_IM_3DES_CBC_CBC		OBJ_id_PACE_ECDH_IM,1L

#define SN_id_PACE_ECDH_IM_AES_CBC_CMAC_128		"id-PACE-ECDH-IM-AES-CBC-CMAC-128"
extern int NID_id_PACE_ECDH_IM_AES_CBC_CMAC_128;
#define OBJ_id_PACE_ECDH_IM_AES_CBC_CMAC_128		OBJ_id_PACE_ECDH_IM,2L

#define SN_id_PACE_ECDH_IM_AES_CBC_CMAC_192		"id-PACE-ECDH-IM-AES-CBC-CMAC-192"
extern int NID_id_PACE_ECDH_IM_AES_CBC_CMAC_192;
#define OBJ_id_PACE_ECDH_IM_AES_CBC_CMAC_192		OBJ_id_PACE_ECDH_IM,3L

#define SN_id_PACE_ECDH_IM_AES_CBC_CMAC_256		"id-PACE-ECDH-IM-AES-CBC-CMAC-256"
extern int NID_id_PACE_ECDH_IM_AES_CBC_CMAC_256;
#define OBJ_id_PACE_ECDH_IM_AES_CBC_CMAC_256		OBJ_id_PACE_ECDH_IM,4L

#define OBJ_id_RI		OBJ_bsi_de,2L,2L,5L

#define SN_id_RI_DH		"id-RI-DH"
extern int NID_id_RI_DH;
#define OBJ_id_RI_DH		OBJ_id_RI,1L

#define SN_id_RI_DH_SHA_1		"id-RI-DH-SHA-1"
extern int NID_id_RI_DH_SHA_1;
#define OBJ_id_RI_DH_SHA_1		OBJ_id_RI_DH,1L

#define SN_id_RI_DH_SHA_224		"id-RI-DH-SHA-224"
extern int NID_id_RI_DH_SHA_224;
#define OBJ_id_RI_DH_SHA_224		OBJ_id_RI_DH,2L

#define SN_id_RI_DH_SHA_256		"id-RI-DH-SHA-256"
extern int NID_id_RI_DH_SHA_256;
#define OBJ_id_RI_DH_SHA_256		OBJ_id_RI_DH,3L

#define SN_id_RI_DH_SHA_384		"id-RI-DH-SHA-384"
extern int NID_id_RI_DH_SHA_384;
#define OBJ_id_RI_DH_SHA_384		OBJ_id_RI_DH,4L

#define SN_id_RI_DH_SHA_512		"id-RI-DH-SHA-512"
extern int NID_id_RI_DH_SHA_512;
#define OBJ_id_RI_DH_SHA_512		OBJ_id_RI_DH,5L

#define SN_id_RI_ECDH		"id-RI-ECDH"
extern int NID_id_RI_ECDH;
#define OBJ_id_RI_ECDH		OBJ_id_RI,2L

#define SN_id_RI_ECDH_SHA_1		"id-RI-ECDH-SHA-1"
extern int NID_id_RI_ECDH_SHA_1;
#define OBJ_id_RI_ECDH_SHA_1		OBJ_id_RI_ECDH,1L

#define SN_id_RI_ECDH_SHA_224		"id-RI-ECDH-SHA-224"
extern int NID_id_RI_ECDH_SHA_224;
#define OBJ_id_RI_ECDH_SHA_224		OBJ_id_RI_ECDH,2L

#define SN_id_RI_ECDH_SHA_256		"id-RI-ECDH-SHA-256"
extern int NID_id_RI_ECDH_SHA_256;
#define OBJ_id_RI_ECDH_SHA_256		OBJ_id_RI_ECDH,3L

#define SN_id_RI_ECDH_SHA_384		"id-RI-ECDH-SHA-384"
extern int NID_id_RI_ECDH_SHA_384;
#define OBJ_id_RI_ECDH_SHA_384		OBJ_id_RI_ECDH,4L

#define SN_id_RI_ECDH_SHA_512		"id-RI-ECDH-SHA-512"
extern int NID_id_RI_ECDH_SHA_512;
#define OBJ_id_RI_ECDH_SHA_512		OBJ_id_RI_ECDH,5L

#define SN_id_CI		"id-CI"
extern int NID_id_CI;
#define OBJ_id_CI		OBJ_bsi_de,2L,2L,6L

#define SN_id_eIDSecurity		"id-eIDSecurity"
extern int NID_id_eIDSecurity;
#define OBJ_id_eIDSecurity		OBJ_bsi_de,2L,2L,7L

#define SN_id_PT		"id-PT"
extern int NID_id_PT;
#define OBJ_id_PT		OBJ_bsi_de,2L,2L,8L

#define OBJ_id_ecc		OBJ_bsi_de,1L,1L

#define OBJ_ecka_dh		OBJ_id_ecc,5L,2L

#define SN_ecka_dh_SessionKDF		"ecka-dh-SessionKDF"
extern int NID_ecka_dh_SessionKDF;
#define OBJ_ecka_dh_SessionKDF		OBJ_ecka_dh,2L

#define SN_ecka_dh_SessionKDF_DES3		"ecka-dh-SessionKDF-DES3"
extern int NID_ecka_dh_SessionKDF_DES3;
#define OBJ_ecka_dh_SessionKDF_DES3		OBJ_ecka_dh,2L,1L

#define SN_ecka_dh_SessionKDF_AES128		"ecka-dh-SessionKDF-AES128"
extern int NID_ecka_dh_SessionKDF_AES128;
#define OBJ_ecka_dh_SessionKDF_AES128		OBJ_ecka_dh,2L,2L

#define SN_ecka_dh_SessionKDF_AES192		"ecka-dh-SessionKDF-AES192"
extern int NID_ecka_dh_SessionKDF_AES192;
#define OBJ_ecka_dh_SessionKDF_AES192		OBJ_ecka_dh,2L,3L

#define SN_ecka_dh_SessionKDF_AES256		"ecka-dh-SessionKDF-AES256"
extern int NID_ecka_dh_SessionKDF_AES256;
#define OBJ_ecka_dh_SessionKDF_AES256		OBJ_ecka_dh,2L,4L

#define OBJ_id_roles		OBJ_bsi_de,3L,1L,2L

#define SN_id_IS		"id-IS"
extern int NID_id_IS;
#define OBJ_id_IS		OBJ_id_roles,1L

#define SN_id_AT		"id-AT"
extern int NID_id_AT;
#define OBJ_id_AT		OBJ_id_roles,2L

#define SN_id_ST		"id-ST"
extern int NID_id_ST;
#define OBJ_id_ST		OBJ_id_roles,3L

#define OBJ_id_extensions		OBJ_bsi_de,3L,1L,3L

#define SN_id_description		"id-description"
extern int NID_id_description;
#define OBJ_id_description		OBJ_id_extensions,1L

#define SN_id_plainFormat		"id-plainFormat"
extern int NID_id_plainFormat;
#define OBJ_id_plainFormat		OBJ_id_description,1L

#define SN_id_htmlFormat		"id-htmlFormat"
extern int NID_id_htmlFormat;
#define OBJ_id_htmlFormat		OBJ_id_description,2L

#define SN_id_pdfFormat		"id-pdfFormat"
extern int NID_id_pdfFormat;
#define OBJ_id_pdfFormat		OBJ_id_description,3L

#define SN_id_sector		"id-sector"
extern int NID_id_sector;
#define OBJ_id_sector		OBJ_id_extensions,2L

#define OBJ_id_eID		OBJ_bsi_de,3L,2L

#define SN_id_SecurityObject		"id-SecurityObject"
extern int NID_id_SecurityObject;
#define OBJ_id_SecurityObject		OBJ_id_eID,1L

#define OBJ_id_AuxiliaryData		OBJ_bsi_de,3L,1L,4L

#define SN_id_DateOfBirth		"id-DateOfBirth"
extern int NID_id_DateOfBirth;
#define OBJ_id_DateOfBirth		OBJ_id_AuxiliaryData,1L

#define SN_id_DateOfExpiry		"id-DateOfExpiry"
extern int NID_id_DateOfExpiry;
#define OBJ_id_DateOfExpiry		OBJ_id_AuxiliaryData,2L

#define SN_id_CommunityID		"id-CommunityID"
extern int NID_id_CommunityID;
#define OBJ_id_CommunityID		OBJ_id_AuxiliaryData,3L

#endif

#ifdef __cplusplus
}
#endif
#endif
