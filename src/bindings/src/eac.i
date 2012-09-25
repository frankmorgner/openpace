/**
 * @date 2010-01-07
 * @version 0.2
 * @author Dominik Oepen <oepen@informatik.hu-berlin.de>
 */

%{
#include <eac/eac.h>
#include <openssl/bio.h>
#include <stdlib.h>
#include <string.h>

/* included in OpenPACE, but not propagated */
extern void BUF_MEM_clear_free(BUF_MEM *b);
%}


#define EAC_ID_PACE 0
#define EAC_ID_CA 1
#define EAC_ID_TA 2
#define EAC_ID_EAC 3

EAC_CTX *
EAC_CTX_new();

void
EAC_CTX_clear_free(EAC_CTX *ctx);

int
EAC_CTX_init_pace(EAC_CTX *ctx, int protocol, int curve);

#ifdef SWIGPYTHON

%rename(EAC_encrypt) eac_encrypt;
%inline %{
    static void eac_encrypt(char **out, int *out_len, const EAC_CTX *ctx,
            unsigned long ssc, char *in, int in_len) {
        BIGNUM *bn = NULL;
        BUF_MEM *out_buf = NULL, *data = NULL;

        if (in_len < 0)
            goto err;

        bn = BN_new();
        if (!bn)
            goto err;
        BN_init(bn);
        if (!BN_set_word(bn, ssc))
            goto err;

        data = get_buf(in, in_len);
        if (!data)
            goto err;

        out_buf = EAC_encrypt(ctx, bn, data);
        if (!out_buf)
            goto err;

        *out_len = out_buf->length;
        *out = malloc(*out_len);
        if (!out) {
            *out_len = 0;
            goto err;
        }
        memcpy(*out, out_buf->data, *out_len);

    err:
        if (bn)
            BN_clear_free(bn);
        if (data)
            BUF_MEM_clear_free(data);
        if (out_buf)
            BUF_MEM_clear_free(out_buf);
        return;
    }
%}

%rename(EAC_decrypt) eac_decrypt;
%inline %{
    static void eac_decrypt(char **out, int *out_len, const EAC_CTX *ctx,
            unsigned long ssc, char *in, int in_len) {
        BIGNUM *bn = NULL;
        BUF_MEM *out_buf = NULL, *data = NULL;

        if (in_len < 0)
            goto err;

        bn = BN_new();
        if (!bn)
            goto err;
        BN_init(bn);
        if (!BN_set_word(bn, ssc))
            goto err;

        data = get_buf(in, in_len);
        if (!data)
            goto err;

        out_buf = EAC_decrypt(ctx, bn, data);
        if (!out_buf)
            goto err;

        *out_len = out_buf->length;
        *out = malloc(*out_len);
        if (!out) {
            *out_len = 0;
            goto err;
        }
        memcpy(*out, out_buf->data, *out_len);

    err:
        if (bn)
            BN_clear_free(bn);
        if (data)
            BUF_MEM_clear_free(data);
        if (out_buf)
            BUF_MEM_clear_free(out_buf);
        return;
    }
%}

%rename(EAC_authenticate) eac_authenticate;
%inline %{
    static void eac_authenticate(char **out, int *out_len, const EAC_CTX *ctx,
            unsigned long ssc, char *in, int in_len) {
        BIGNUM *bn = NULL;
        BUF_MEM *in_buf = NULL, *out_buf = NULL;

        if (in_len < 0)
            goto err;

        bn = BN_new();
        if (!bn)
            goto err;
        BN_init(bn);
        if (!BN_set_word(bn, ssc))
            goto err;

        in_buf = get_buf(in, in_len);
        if (!in_buf)
            goto err;

        out_buf = EAC_authenticate(ctx, bn, in_buf);
        if (!out_buf)
            goto err;

        *out_len = out_buf->length;
        *out = malloc(*out_len);
        if (!out) {
            *out_len = 0;
            goto err;
        }
        memcpy(*out, out_buf->data, *out_len);

    err:
        if (bn)
            BN_clear_free(bn);
        if (in_buf)
            BUF_MEM_clear_free(in_buf);
        if (out_buf)
            BUF_MEM_clear_free(out_buf);
        return;
    }
%}

%rename(EAC_Comp) eac_comp;
%inline %{
    static void eac_comp(char **out, int *out_len, const EAC_CTX *ctx, int id,
            char *in, int in_len) {

        BUF_MEM *in_buf = NULL, *out_buf = NULL;

        if (in_len < 0)
            goto err;

        in_buf = get_buf(in, in_len);
        if (!in_buf)
            goto err;

        out_buf = EAC_Comp(ctx, id, in_buf);
        if (!out_buf)
            goto err;

        *out_len = out_buf->length;
        *out = malloc(*out_len);
        if (!out) {
            *out_len = 0;
            goto err;
        }
        memcpy(*out, out_buf->data, *out_len);

    err:
        if (in_buf)
            BUF_MEM_clear_free(in_buf);
        if (out_buf)
            BUF_MEM_clear_free(out_buf);
        return;

    }
%}

%rename (EAC_CTX_print_private) print_eac_ctx;
%inline %{
    static void print_eac_ctx(char **out, int *out_len, EAC_CTX *eac_ctx, int indent) {
        BIO *bio = BIO_new(BIO_s_mem());
        if (!bio)
            goto err;

        EAC_CTX_print_private(bio, eac_ctx, indent);

        *out_len = BIO_get_mem_data(bio, NULL);
        if (*out_len <= 0)
            goto err;
        *out = malloc(*out_len);
        if (!*out)
            goto err;
        if (BIO_read(bio, (void*) *out, *out_len) <= 0)
            goto err;

        BIO_free_all(bio);
        return;

err:
        *out_len = 0;
        if (*out)
            free(*out);
        BIO_free_all(bio);
    }
%}

#else

BUF_MEM *
EAC_encrypt(const EAC_CTX *ctx, const BIGNUM *ssc, const BUF_MEM *data);

BUF_MEM *
EAC_decrypt(const EAC_CTX *ctx, const BIGNUM *ssc, const BUF_MEM *data);

BUF_MEM *
EAC_authenticate(const EAC_CTX *ctx, const BIGNUM *ssc, const BUF_MEM *data);

BUF_MEM *
EAC_Comp(const EAC_CTX *ctx, int id, const BUF_MEM *pub);

#endif

int
EAC_CTX_set_encryption_ctx(EAC_CTX *ctx, int id);


int
EAC_CTX_init_ef_cardaccess(unsigned char *in, unsigned int in_len, EAC_CTX *ctx);
%rename(EAC_CTX_init_ef_cardaccess) parse_ef_cardaccess;
%inline %{
    static int parse_ef_cardaccess(char *in, int in_len, EAC_CTX *ctx) { /* typemap applied */
        if (in_len < 0)
            return 0;
        else
            return EAC_CTX_init_ef_cardaccess((unsigned char*) in,
                    (unsigned int) in_len, ctx);
    }
%}

int
EAC_CTX_init_ta(const EAC_CTX *ctx,
    const unsigned char *privkey, size_t privkey_len,
    const unsigned char *cert, size_t cert_len,
    const unsigned char *car, size_t car_len);
%rename(EAC_CTX_init_ta) init_ta;
%inline %{
    static int init_ta(const EAC_CTX *ctx,
            char *privkey, int privkey_len, char *cert, int cert_len,
            char *car, int car_len) {
        return EAC_CTX_init_ta(ctx,
            (unsigned char*) privkey, (size_t) privkey_len,
            (unsigned char*) cert, (size_t) cert_len,
            (unsigned char*) car, (size_t) car_len);

    }
%}

int
EAC_CTX_init_ca(const EAC_CTX *ctx, int protocol, int curve,
    const unsigned char *priv, size_t priv_len,
    const unsigned char *pub, size_t pub_len);
%rename(EAC_CTX_init_ca) init_ca;
%inline %{
    static int init_ca(const EAC_CTX *ctx, int protocol, int curve,
            char *privkey, int privkey_len, /* typemap applied (see ta.i) */
            char *pubkey, int pubkey_len) {
        return EAC_CTX_init_ca(ctx, protocol, curve,
            (const unsigned char*) privkey, (size_t) privkey_len,
            (const unsigned char*) pubkey, (size_t) pubkey_len);
    }
%}

