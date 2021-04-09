/*
 * Copyright (c) 2010-2012 Dominik Oepen
 * Copyright (c) 2013      Frank Morgner
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
 * @date 2010-01-07
 * @version 0.2
 * @author Dominik Oepen <oepen@informatik.hu-berlin.de>
 */

%module eac

%include "cstring.i"

%{
#include <eac/eac.h>
#include <openssl/bio.h>
#include <stdlib.h>
#include <string.h>

/* included in OpenPACE, but not propagated */
extern void BUF_MEM_clear_free(BUF_MEM *b);
%}

/**
 * @defgroup typemaps              Typemaps
 * @{ ************************************************************************/

#ifdef SWIGJAVA

/* Typemap to convert byte arrays to character pointer + length */
%typemap(in)     (char *BYTE, size_t LENGTH) {
    /* Functions from jni.h */
    $1 = (char *) JCALL2(GetByteArrayElements, jenv, $input, 0);
    $2 = (size_t)    JCALL1(GetArrayLength,    jenv, $input);
}
%typemap(jni)    (char *BYTE, size_t LENGTH) "jbyteArray"
%typemap(jtype)  (char *BYTE, size_t LENGTH) "byte[]"
%typemap(jstype) (char *BYTE, size_t LENGTH) "byte[]"
%typemap(javain) (char *BYTE, size_t LENGTH) "$javainput"

%apply (char *BYTE, size_t LENGTH) {(char *in, size_t in_len)};
%apply (char *BYTE, size_t LENGTH) {(char *privkey, size_t privkey_len)};
%apply (char *BYTE, size_t LENGTH) {(char *cert, size_t cert_len)};
%apply (char *BYTE, size_t LENGTH) {(char *car, size_t car_len)};
%apply (char *BYTE, size_t LENGTH) {(char *comp_pubkey, size_t comp_pubkey_len)};
%apply (char *BYTE, size_t LENGTH) {(char *pubkey, size_t pubkey_len)};
%apply (char *BYTE, size_t LENGTH) {(char *my_ta_eph_pubkey, size_t my_ta_eph_pubkey_len)};
%apply (char *BYTE, size_t LENGTH) {(char *opp_pace_eph_pubkey, size_t opp_pace_eph_pubkey_len)};
%apply (char *BYTE, size_t LENGTH) {(char *auxdata, size_t auxdata_len)};
%apply (char *BYTE, size_t LENGTH) {(char *opp_ta_comp_pubkey, size_t opp_ta_comp_pubkey_len)};
%apply (char *BYTE, size_t LENGTH) {(char *my_pace_comp_eph_pubkey, size_t my_pace_comp_eph_pubkey_len)};
%apply (char *BYTE, size_t LENGTH) {(char *signature, size_t signature_len)};
%apply (char *BYTE, size_t LENGTH) {(unsigned char *priv, size_t priv_len)};
%apply (char *BYTE, size_t LENGTH) {(unsigned char *pub, size_t pub_len)};

#endif

#if !defined(SWIG_CSTRING_UNIMPL) || defined(SWIGGO)

%apply (char *STRING, size_t LENGTH) {(char *in, size_t in_len)};
%apply (char *STRING, size_t LENGTH) {(char *privkey, size_t privkey_len)};
%apply (char *STRING, size_t LENGTH) {(char *cert, size_t cert_len)};
%apply (char *STRING, size_t LENGTH) {(char *car, size_t car_len)};
%apply (char *STRING, size_t LENGTH) {(char *comp_pubkey, size_t comp_pubkey_len)};
%apply (char *STRING, size_t LENGTH) {(char *pubkey, size_t pubkey_len)};
%apply (char *STRING, size_t LENGTH) {(char *my_ta_eph_pubkey, size_t my_ta_eph_pubkey_len)};
%apply (char *STRING, size_t LENGTH) {(char *opp_pace_eph_pubkey, size_t opp_pace_eph_pubkey_len)};
%apply (char *STRING, size_t LENGTH) {(char *auxdata, size_t auxdata_len)};
%apply (char *STRING, size_t LENGTH) {(char *opp_ta_comp_pubkey, size_t opp_ta_comp_pubkey_len)};
%apply (char *STRING, size_t LENGTH) {(char *my_pace_comp_eph_pubkey, size_t my_pace_comp_eph_pubkey_len)};
%apply (char *STRING, size_t LENGTH) {(char *signature, size_t signature_len)};

#ifndef SWIG_CSTRING_UNIMPL
%cstring_output_allocate_size(char **out, size_t *out_len, free(*$1));
#else
#endif

#endif

/** @} ***********************************************************************/

typedef unsigned short uint16_t;

#define EAC_TR_VERSION_2_01 1
#define EAC_TR_VERSION_2_02 2

%include "util.i"

%include "ca.i"
%include "cvc.i"
%include "objects.i"
%include "pace.i"
%include "ta.i"


#define EAC_ID_PACE 0
#define EAC_ID_CA 1
#define EAC_ID_TA 2
#define EAC_ID_EAC 3

%newobject EAC_CTX_new;
EAC_CTX *
EAC_CTX_new();

%delobject EAC_CTX_clear_free;
void
EAC_CTX_clear_free(EAC_CTX *ctx);

int
EAC_CTX_init_pace(EAC_CTX *ctx, int protocol, int curve);

#if !defined(SWIG_CSTRING_UNIMPL) || defined(SWIGGO) || defined(SWIGJAVA)

#if !defined(SWIGGO) && !defined(SWIGJAVA)

%begin %{
#define SWIG_PYTHON_STRICT_BYTE_CHAR
%}

%rename(EAC_encrypt) eac_encrypt;
%inline %{
    static void eac_encrypt(char **out, size_t *out_len, const EAC_CTX *ctx,
            char *in, size_t in_len) {
        BUF_MEM *out_buf = NULL, *data = NULL;

        data = get_buf(in, in_len);
        out_buf = EAC_encrypt(ctx, data);
        buf2string(out_buf, out, out_len);

        BUF_MEM_clear_free(data);
        BUF_MEM_clear_free(out_buf);
        return;
    }
%}

%rename(EAC_decrypt) eac_decrypt;
%inline %{
    static void eac_decrypt(char **out, size_t *out_len, const EAC_CTX *ctx,
            char *in, size_t in_len) {
        BUF_MEM *out_buf = NULL, *data = NULL;

        data = get_buf(in, in_len);
        out_buf = EAC_decrypt(ctx, data);
        buf2string(out_buf, out, out_len);

        BUF_MEM_clear_free(data);
        BUF_MEM_clear_free(out_buf);
    }
%}

%rename(EAC_authenticate) eac_authenticate;
%inline %{
    static void eac_authenticate(char **out, size_t *out_len, const EAC_CTX *ctx,
            char *in, size_t in_len) {
        BUF_MEM *in_buf = NULL, *out_buf = NULL;

        in_buf = get_buf(in, in_len);
        out_buf = EAC_authenticate(ctx, in_buf);
        buf2string(out_buf, out, out_len);
        BUF_MEM_clear_free(in_buf);
        BUF_MEM_clear_free(out_buf);
    }
%}

%rename(EAC_Comp) eac_comp;
%inline %{
    static void eac_comp(char **out, size_t *out_len, const EAC_CTX *ctx, int id,
            char *in, size_t in_len) {

        BUF_MEM *in_buf = NULL, *out_buf = NULL;

        in_buf = get_buf(in, in_len);
        out_buf = EAC_Comp(ctx, id, in_buf);
        buf2string(out_buf, out, out_len);
        BUF_MEM_clear_free(in_buf);
        BUF_MEM_clear_free(out_buf);
    }
%}

%rename (EAC_CTX_print_private) eac_ctx_print_private;
%inline %{
    static void eac_ctx_print_private(char **out, size_t *out_len, EAC_CTX *eac_ctx, int indent) {
        long tmp;
        BIO *bio = BIO_new(BIO_s_mem());
        if (!bio)
            goto err;

        EAC_CTX_print_private(bio, eac_ctx, indent);

        tmp = BIO_get_mem_data(bio, NULL);
        if (tmp < 0)
            goto err;
        *out = (char *) malloc(tmp);
        if (!*out)
            goto err;
        *out_len = tmp;

        if (BIO_read(bio, (void*) *out, *out_len) <= 0)
            goto err;

        BIO_free_all(bio);
        return;

err:
        *out_len = 0;
        if (*out)
            free(*out);
        if (bio)
            BIO_free_all(bio);
    }
%}

#else

%begin %{
#define SWIG_PYTHON_STRICT_BYTE_CHAR
%}

BUF_MEM *
EAC_encrypt(const EAC_CTX *ctx, const BUF_MEM *data);

BUF_MEM *
EAC_decrypt(const EAC_CTX *ctx, const BUF_MEM *data);

BUF_MEM *
EAC_authenticate(const EAC_CTX *ctx, const BUF_MEM *data);

BUF_MEM *
EAC_Comp(const EAC_CTX *ctx, int id, const BUF_MEM *pub);

int
EAC_CTX_init_ef_cardaccess(unsigned char *in, size_t in_len, EAC_CTX *ctx);

int
EAC_CTX_init_ef_cardsecurity(unsigned char *in, size_t in_len, EAC_CTX *ctx);

int
EAC_CTX_init_ta(const EAC_CTX *ctx,
    const unsigned char *privkey, size_t privkey_len,
    const unsigned char *cert, size_t cert_len);

#endif

%begin %{
#define SWIG_PYTHON_STRICT_BYTE_CHAR
%}

%rename(EAC_CTX_init_ef_cardaccess) eac_ctx_init_ef_cardaccess;
%inline %{
    static int eac_ctx_init_ef_cardaccess(char *in, size_t in_len, EAC_CTX *ctx) { /* typemap applied */
            return EAC_CTX_init_ef_cardaccess((unsigned char*) in,
                    in_len, ctx);
    }
%}

%rename(EAC_CTX_init_ef_cardsecurity) eac_ctx_init_ef_cardsecurity;
%inline %{
    static int eac_ctx_init_ef_cardsecurity(char *in, size_t in_len, EAC_CTX *ctx) { /* typemap applied */
            return EAC_CTX_init_ef_cardsecurity((unsigned char*) in,
                    in_len, ctx);
    }
%}

%rename(EAC_CTX_init_ta) eac_ctx_init_ta;
%inline %{
    static int eac_ctx_init_ta(const EAC_CTX *ctx,
            char *privkey, size_t privkey_len, char *cert, size_t cert_len) {
        return EAC_CTX_init_ta(ctx,
            (unsigned char*) privkey, privkey_len,
            (unsigned char*) cert, cert_len);

    }
%}

#else

%begin %{
#define SWIG_PYTHON_STRICT_BYTE_CHAR
%}

BUF_MEM *
EAC_encrypt(const EAC_CTX *ctx, const BUF_MEM *data);

BUF_MEM *
EAC_decrypt(const EAC_CTX *ctx, const BUF_MEM *data);

BUF_MEM *
EAC_authenticate(const EAC_CTX *ctx, const BUF_MEM *data);

BUF_MEM *
EAC_Comp(const EAC_CTX *ctx, int id, const BUF_MEM *pub);

int
EAC_CTX_init_ef_cardaccess(unsigned char *in, size_t in_len, EAC_CTX *ctx);

int
EAC_CTX_init_ef_cardsecurity(unsigned char *in, size_t in_len, EAC_CTX *ctx);

int
EAC_CTX_init_ta(const EAC_CTX *ctx,
    const unsigned char *privkey, size_t privkey_len,
    const unsigned char *cert, size_t cert_len);

#endif

int
EAC_CTX_init_ca(EAC_CTX *ctx, int protocol, int curve);

int
EAC_CTX_set_encryption_ctx(EAC_CTX *ctx, int id);

int
EAC_increment_ssc(const EAC_CTX *ctx);

int
EAC_reset_ssc(const EAC_CTX *ctx);

int
EAC_set_ssc(const EAC_CTX *ctx, unsigned long ssc);

void EAC_set_cvc_default_dir(const char *default_dir);
void EAC_set_x509_default_dir(const char *default_dir);
