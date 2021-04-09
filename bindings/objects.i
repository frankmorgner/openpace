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

%{
#include <eac/objects.h>

#ifdef HAVE_PATCHED_OPENSSL

/* OpenSSL has NIDs as defines. So lets get their value into ints */

int id_PACE_DH_GM_3DES_CBC_CBC = NID_id_PACE_DH_GM_3DES_CBC_CBC;
int id_PACE_DH_GM_AES_CBC_CMAC_128 = NID_id_PACE_DH_GM_AES_CBC_CMAC_128;
int id_PACE_DH_GM_AES_CBC_CMAC_192 = NID_id_PACE_DH_GM_AES_CBC_CMAC_192;
int id_PACE_DH_GM_AES_CBC_CMAC_256 = NID_id_PACE_DH_GM_AES_CBC_CMAC_256;
int id_PACE_ECDH_GM_3DES_CBC_CBC = NID_id_PACE_ECDH_GM_3DES_CBC_CBC;
int id_PACE_ECDH_GM_AES_CBC_CMAC_128 = NID_id_PACE_ECDH_GM_AES_CBC_CMAC_128;
int id_PACE_ECDH_GM_AES_CBC_CMAC_192 = NID_id_PACE_ECDH_GM_AES_CBC_CMAC_192;
int id_PACE_ECDH_GM_AES_CBC_CMAC_256 = NID_id_PACE_ECDH_GM_AES_CBC_CMAC_256;
int id_PACE_DH_IM_3DES_CBC_CBC = NID_id_PACE_DH_IM_3DES_CBC_CBC;
int id_PACE_DH_IM_AES_CBC_CMAC_128 = NID_id_PACE_DH_IM_AES_CBC_CMAC_128;
int id_PACE_DH_IM_AES_CBC_CMAC_192 = NID_id_PACE_DH_IM_AES_CBC_CMAC_192;
int id_PACE_DH_IM_AES_CBC_CMAC_256 = NID_id_PACE_DH_IM_AES_CBC_CMAC_256;
int id_PACE_ECDH_IM_3DES_CBC_CBC = NID_id_PACE_ECDH_IM_3DES_CBC_CBC;
int id_PACE_ECDH_IM_AES_CBC_CMAC_128 = NID_id_PACE_ECDH_IM_AES_CBC_CMAC_128;
int id_PACE_ECDH_IM_AES_CBC_CMAC_192 = NID_id_PACE_ECDH_IM_AES_CBC_CMAC_192;
int id_PACE_ECDH_IM_AES_CBC_CMAC_256 = NID_id_PACE_ECDH_IM_AES_CBC_CMAC_256;

int id_CA_DH_3DES_CBC_CBC       = NID_id_CA_DH_3DES_CBC_CBC;
int id_CA_DH_AES_CBC_CMAC_128   = NID_id_CA_DH_AES_CBC_CMAC_128;
int id_CA_DH_AES_CBC_CMAC_192   = NID_id_CA_DH_AES_CBC_CMAC_192;
int id_CA_DH_AES_CBC_CMAC_256   = NID_id_CA_DH_AES_CBC_CMAC_256;
int id_CA_ECDH_3DES_CBC_CBC     = NID_id_CA_ECDH_3DES_CBC_CBC;
int id_CA_ECDH_AES_CBC_CMAC_128 = NID_id_CA_ECDH_AES_CBC_CMAC_128;
int id_CA_ECDH_AES_CBC_CMAC_192 = NID_id_CA_ECDH_AES_CBC_CMAC_192;
int id_CA_ECDH_AES_CBC_CMAC_256 = NID_id_CA_ECDH_AES_CBC_CMAC_256;

int id_RI_DH_SHA_1 = NID_id_RI_DH_SHA_1;
int id_RI_DH_SHA_224 = NID_id_RI_DH_SHA_224;
int id_RI_DH_SHA_256 = NID_id_RI_DH_SHA_256;
int id_RI_DH_SHA_384 = NID_id_RI_DH_SHA_384;
int id_RI_DH_SHA_512 = NID_id_RI_DH_SHA_512;
int id_RI_ECDH_SHA_1 = NID_id_RI_ECDH_SHA_1;
int id_RI_ECDH_SHA_224 = NID_id_RI_ECDH_SHA_224;
int id_RI_ECDH_SHA_256 = NID_id_RI_ECDH_SHA_256;
int id_RI_ECDH_SHA_384 = NID_id_RI_ECDH_SHA_384;
int id_RI_ECDH_SHA_512 = NID_id_RI_ECDH_SHA_512;

#else

/* libeac has NIDs as ints. So lets define id_* to be NID_id_* */

#define id_PACE_DH_GM_3DES_CBC_CBC NID_id_PACE_DH_GM_3DES_CBC_CBC
#define id_PACE_DH_GM_AES_CBC_CMAC_128 NID_id_PACE_DH_GM_AES_CBC_CMAC_128
#define id_PACE_DH_GM_AES_CBC_CMAC_192 NID_id_PACE_DH_GM_AES_CBC_CMAC_192
#define id_PACE_DH_GM_AES_CBC_CMAC_256 NID_id_PACE_DH_GM_AES_CBC_CMAC_256
#define id_PACE_ECDH_GM_3DES_CBC_CBC NID_id_PACE_ECDH_GM_3DES_CBC_CBC
#define id_PACE_ECDH_GM_AES_CBC_CMAC_128 NID_id_PACE_ECDH_GM_AES_CBC_CMAC_128
#define id_PACE_ECDH_GM_AES_CBC_CMAC_192 NID_id_PACE_ECDH_GM_AES_CBC_CMAC_192
#define id_PACE_ECDH_GM_AES_CBC_CMAC_256 NID_id_PACE_ECDH_GM_AES_CBC_CMAC_256
#define id_PACE_DH_IM_3DES_CBC_CBC NID_id_PACE_DH_IM_3DES_CBC_CBC
#define id_PACE_DH_IM_AES_CBC_CMAC_128 NID_id_PACE_DH_IM_AES_CBC_CMAC_128
#define id_PACE_DH_IM_AES_CBC_CMAC_192 NID_id_PACE_DH_IM_AES_CBC_CMAC_192
#define id_PACE_DH_IM_AES_CBC_CMAC_256 NID_id_PACE_DH_IM_AES_CBC_CMAC_256
#define id_PACE_ECDH_IM_3DES_CBC_CBC NID_id_PACE_ECDH_IM_3DES_CBC_CBC
#define id_PACE_ECDH_IM_AES_CBC_CMAC_128 NID_id_PACE_ECDH_IM_AES_CBC_CMAC_128
#define id_PACE_ECDH_IM_AES_CBC_CMAC_192 NID_id_PACE_ECDH_IM_AES_CBC_CMAC_192
#define id_PACE_ECDH_IM_AES_CBC_CMAC_256 NID_id_PACE_ECDH_IM_AES_CBC_CMAC_256

#define id_CA_DH_3DES_CBC_CBC NID_id_CA_DH_3DES_CBC_CBC
#define id_CA_DH_AES_CBC_CMAC_128 NID_id_CA_DH_AES_CBC_CMAC_128
#define id_CA_DH_AES_CBC_CMAC_192 NID_id_CA_DH_AES_CBC_CMAC_192
#define id_CA_DH_AES_CBC_CMAC_256 NID_id_CA_DH_AES_CBC_CMAC_256
#define id_CA_ECDH_3DES_CBC_CBC NID_id_CA_ECDH_3DES_CBC_CBC
#define id_CA_ECDH_AES_CBC_CMAC_128 NID_id_CA_ECDH_AES_CBC_CMAC_128
#define id_CA_ECDH_AES_CBC_CMAC_192 NID_id_CA_ECDH_AES_CBC_CMAC_192
#define id_CA_ECDH_AES_CBC_CMAC_256 NID_id_CA_ECDH_AES_CBC_CMAC_256

#define id_RI_DH_SHA_1 NID_id_RI_DH_SHA_1
#define id_RI_DH_SHA_224 NID_id_RI_DH_SHA_224
#define id_RI_DH_SHA_256 NID_id_RI_DH_SHA_256
#define id_RI_DH_SHA_384 NID_id_RI_DH_SHA_384
#define id_RI_DH_SHA_512 NID_id_RI_DH_SHA_512
#define id_RI_ECDH_SHA_1 NID_id_RI_ECDH_SHA_1
#define id_RI_ECDH_SHA_224 NID_id_RI_ECDH_SHA_224
#define id_RI_ECDH_SHA_256 NID_id_RI_ECDH_SHA_256
#define id_RI_ECDH_SHA_384 NID_id_RI_ECDH_SHA_384
#define id_RI_ECDH_SHA_512 NID_id_RI_ECDH_SHA_512

#endif

%}

/* export NIDs. they exist as ints */

const int id_PACE_DH_GM_3DES_CBC_CBC;
const int id_PACE_DH_GM_AES_CBC_CMAC_128;
const int id_PACE_DH_GM_AES_CBC_CMAC_192;
const int id_PACE_DH_GM_AES_CBC_CMAC_256;
const int id_PACE_ECDH_GM_3DES_CBC_CBC;
const int id_PACE_ECDH_GM_AES_CBC_CMAC_128;
const int id_PACE_ECDH_GM_AES_CBC_CMAC_192;
const int id_PACE_ECDH_GM_AES_CBC_CMAC_256;
const int id_PACE_DH_IM_3DES_CBC_CBC;
const int id_PACE_DH_IM_AES_CBC_CMAC_128;
const int id_PACE_DH_IM_AES_CBC_CMAC_192;
const int id_PACE_DH_IM_AES_CBC_CMAC_256;
const int id_PACE_ECDH_IM_3DES_CBC_CBC;
const int id_PACE_ECDH_IM_AES_CBC_CMAC_128;
const int id_PACE_ECDH_IM_AES_CBC_CMAC_192;
const int id_PACE_ECDH_IM_AES_CBC_CMAC_256;

const int id_CA_DH_3DES_CBC_CBC;
const int id_CA_DH_AES_CBC_CMAC_128;
const int id_CA_DH_AES_CBC_CMAC_192;
const int id_CA_DH_AES_CBC_CMAC_256;
const int id_CA_ECDH_3DES_CBC_CBC;
const int id_CA_ECDH_AES_CBC_CMAC_128;
const int id_CA_ECDH_AES_CBC_CMAC_192;
const int id_CA_ECDH_AES_CBC_CMAC_256;

const int id_RI_DH_SHA_1;
const int id_RI_DH_SHA_224;
const int id_RI_DH_SHA_256;
const int id_RI_DH_SHA_384;
const int id_RI_DH_SHA_512;
const int id_RI_ECDH_SHA_1;
const int id_RI_ECDH_SHA_224;
const int id_RI_ECDH_SHA_256;
const int id_RI_ECDH_SHA_384;
const int id_RI_ECDH_SHA_512;
