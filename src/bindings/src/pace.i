/**
 * @date 2010-01-07
 * @version 0.2
 * @author Dominik Oepen <oepen@informatik.hu-berlin.de>
 */
%module pace

#ifdef SWIGPYTHON
%include "cstring.i"
#endif

%{
#include <eac/pace.h>
#include <openssl/buffer.h>
#include <stdlib.h>
#include <string.h>
%}

typedef unsigned short uint16_t;

enum s_type {
    PACE_MRZ = 1,
    PACE_CAN,
    PACE_PIN,
    PACE_PUK,
    PACE_RAW,
    PACE_SEC_UNDEF,
};

#define PACE_TR_VERSION_2_01 1
#define PACE_TR_VERSION_2_02 2

/**
 * @defgroup typemaps              Typemaps
 * @{ ************************************************************************/

#ifdef SWIGJAVA

/* Typemap to convert byte arrays to character pointer + length */
%typemap(in)     (char * BYTE, int LENGTH) {
    /* Functions from jni.h */
    $1 = (char *) JCALL2(GetByteArrayElements, jenv, $input, 0);
    $2 = (int)    JCALL1(GetArrayLength,       jenv, $input);
}
%typemap(jni)    (char *BYTE, int LENGTH) "jbyteArray"
%typemap(jtype)  (char *BYTE, int LENGTH) "byte[]"
%typemap(jstype) (char *BYTE, int LENGTH) "byte[]"
%typemap(javain) (char *BYTE, int LENGTH) "$javainput"

%apply (char *BYTE, int LENGTH) {(char *in, int in_len)};
%apply (char *BYTE, int LENGTH) {(char *privkey, int privkey_len)};
%apply (char *BYTE, int LENGTH) {(char *cert, int cert_len)};
%apply (char *BYTE, int LENGTH) {(char *car, int car_len)};
%apply (char *BYTE, int LENGTH) {(char *comp_pubkey, int comp_pubkey_len)};
%apply (char *BYTE, int LENGTH) {(char *pubkey, int pubkey_len)};

#endif

#ifdef SWIGPYTHON

%apply (char *STRING, int LENGTH) {(char *in, int in_len)};
%apply (char *STRING, int LENGTH) {(char *privkey, int privkey_len)};
%apply (char *STRING, int LENGTH) {(char *cert, int cert_len)};
%apply (char *STRING, int LENGTH) {(char *car, int car_len)};
%apply (char *STRING, int LENGTH) {(char *comp_pubkey, int comp_pubkey_len)};
%apply (char *STRING, int LENGTH) {(char *pubkey, int pubkey_len)};

%cstring_output_allocate_size(char **out, int *out_len, free(*$1));

#endif

/** @} ***********************************************************************/

%include "util.i"
%include "eac.i"
%include "ta.i"
%include "ca.i"
%include "cvc.i"

/**
 * @defgroup manage              Data Managment
 * @{ ************************************************************************/

PACE_SEC *
PACE_SEC_new(char *in, int in_len, enum s_type type); /* typemap applied */

void
PACE_SEC_clear_free(PACE_SEC *s);
/** @} ***********************************************************************/

/**
 * @defgroup protocol              Protocol steps
 * @{ ************************************************************************/

#ifdef SWIGPYTHON
%rename(PACE_STEP1_enc_nonce) enc_nonce;
%inline %{
    static void enc_nonce(char **out, int *out_len, const EAC_CTX *ctx, const PACE_SEC *pi) {

        BUF_MEM *enc_nonce = NULL;

        enc_nonce = BUF_MEM_new();
        if (!enc_nonce)
            goto err;

        if (PACE_STEP1_enc_nonce(ctx, pi, &enc_nonce)) {
            *out_len = enc_nonce->length;
            *out = malloc((size_t) *out_len);
            memcpy((void *) *out, enc_nonce->data, *out_len);
            BUF_MEM_free(enc_nonce);
            return;
        }

    err:
        if (enc_nonce)
            BUF_MEM_free(enc_nonce);
        if (*out)
            free(*out);
        *out_len = 0;
        return;
    }
%}

%rename(PACE_STEP2_dec_nonce) dec_nonce;
%inline %{
    static int dec_nonce(const EAC_CTX *ctx, const PACE_SEC *pi, char *in, int in_len) {
        BUF_MEM *in_buf = NULL;
        int ret = 0;

        in_buf = get_buf(in, in_len);
        if (!in_buf)
            return 0;

        ret = PACE_STEP2_dec_nonce(ctx, pi, in_buf);
        BUF_MEM_free(in_buf);
        return ret;
    }
%}

%rename(PACE_STEP3A_generate_mapping_data) generate_mapping_data;
%inline %{
    static void generate_mapping_data(char **out, int *out_len, const EAC_CTX *ctx) {
        BUF_MEM *out_buf = NULL;

        out_buf = PACE_STEP3A_generate_mapping_data(ctx);
        if (!out_buf)
            goto err;

        *out_len = out_buf->length;
        *out = malloc((size_t) *out_len);
        if (!*out) {
            *out_len = 0;
            goto err;
        }

        memcpy(*out, out_buf->data, *out_len);

    err:
        if(out_buf)
            BUF_MEM_free(out_buf);
        return;
    }
%}

%rename(PACE_STEP3B_generate_ephemeral_key) generate_ephemeral_pace_key;
%inline %{
    static void generate_ephemeral_pace_key(char **out, int *out_len, EAC_CTX *ctx) {
        BUF_MEM *out_buf = NULL;

        out_buf = PACE_STEP3B_generate_ephemeral_key(ctx);
        if (!out_buf)
            goto err;

        *out_len = out_buf->length;
        *out = malloc((size_t) *out_len);
        if (!*out) {
            *out_len = 0;
            goto err;
        }

        memcpy(*out, out_buf->data, *out_len);

    err:
        if(out_buf)
            BUF_MEM_free(out_buf);
        return;
    }
%}

%rename(PACE_STEP3D_compute_authentication_token) compute_authentication_token;
%inline %{
    static void compute_authentication_token(char **out, int *out_len,
            const EAC_CTX *ctx, char *in, int in_len) {
        BUF_MEM *in_buf = NULL, *out_buf = NULL;

        in_buf = get_buf(in, in_len);
        if (!in_buf)
            goto err;

        out_buf = PACE_STEP3D_compute_authentication_token(ctx, in_buf);
        if (!out_buf)
            goto err;

        *out_len = out_buf->length;
        *out = malloc((size_t) *out_len);
        if (!*out) {
            *out_len = 0;
            goto err;
        }
        memcpy(*out, out_buf->data, *out_len);

    err:
        if (in_buf)
            BUF_MEM_free(in_buf);
        if (out_buf)
            BUF_MEM_free(out_buf);
        return;
    }
%}

#else

%rename(PACE_STEP1_enc_nonce) enc_nonce;
%inline %{
    static BUF_MEM *enc_nonce(const EAC_CTX *ctx, const PACE_SEC *pi) {

        BUF_MEM *enc_nonce = NULL;

        enc_nonce = BUF_MEM_new();
        if (!enc_nonce)
            return NULL;

        if (PACE_STEP1_enc_nonce(ctx, pi, &enc_nonce))
            return enc_nonce;
        else {
            BUF_MEM_free(enc_nonce);
            return NULL;
        }
    }
%}

int
PACE_STEP2_dec_nonce(const EAC_CTX *ctx, const PACE_SEC *pi,
        const BUF_MEM *enc_nonce);

BUF_MEM *
PACE_STEP3A_generate_mapping_data(const EAC_CTX *ctx);

BUF_MEM *
PACE_STEP3B_generate_ephemeral_key(EAC_CTX *ctx);

BUF_MEM *
PACE_STEP3D_compute_authentication_token(const EAC_CTX *ctx, BUF_MEM *pub);

#endif

int
PACE_STEP3A_map_generator(const EAC_CTX *ctx, const BUF_MEM *in);
%rename(PACE_STEP3A_map_generator) map_generator;
%inline %{
    static int map_generator(const EAC_CTX *ctx, char *in, int in_len) {
        BUF_MEM *in_buf = NULL;
        int ret = 0;

        in_buf = get_buf(in, in_len);
        if (!in)
            goto err;

        ret = PACE_STEP3A_map_generator(ctx, in_buf);

    err:
        if(in_buf)
            BUF_MEM_free(in_buf);
        return ret;
    }
%}

int
PACE_STEP3B_compute_shared_secret(const EAC_CTX *ctx, const BUF_MEM *in);
%rename(PACE_STEP3B_compute_shared_secret) compute_shared_secret;
%inline %{
    static int compute_shared_secret(const EAC_CTX *ctx, char *in, int in_len) {
        BUF_MEM *in_buf = NULL;
        int ret = 0;

        in_buf = get_buf(in, in_len);
        if (!in_buf)
            return 0;

        ret = PACE_STEP3B_compute_shared_secret(ctx, in_buf);
        BUF_MEM_free(in_buf);
        return ret;
    }
%}

int
PACE_STEP3C_derive_keys(const EAC_CTX *ctx);

int
PACE_STEP3D_verify_authentication_token(const EAC_CTX *ctx, const BUF_MEM *token);
%rename(PACE_STEP3D_verify_authentication_token) verify_authentication_token;
%inline %{
    static int verify_authentication_token(const EAC_CTX *ctx, char *in, int in_len) {
        BUF_MEM *in_buf = NULL;
        int ret = 0;

        in_buf = get_buf(in, in_len);
        if (!in_buf)
            return 0;

        ret = PACE_STEP3D_verify_authentication_token(ctx, in_buf);
        BUF_MEM_free(in_buf);
        return ret;
    }
%}

/** @} ***********************************************************************/
