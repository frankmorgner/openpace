/**
 * @date 2011-01-03
 * @version 0.2
 * @author Dominik Oepen <oepen@informatik.hu-berlin.de>
 */

%{
#include <eac/ta.h>
#include <openssl/buffer.h>
#include <stdlib.h>
#include <string.h>
%}

void
TA_disable_checks(EAC_CTX *ctx);

int
TA_STEP2_import_certificate(const EAC_CTX *ctx, const unsigned char *in,
        size_t in_len);
%rename(TA_STEP2_import_certificate) import_certificate;
%inline %{
    static int import_certificate(const EAC_CTX *ctx, char *in, int in_len) {
        if (in_len < 0)
            return 0;
        else
            return TA_STEP2_import_certificate(ctx, (unsigned char*) in, (size_t) in_len);
    }
%}

#ifdef SWIGPYTHON
%rename(TA_STEP3_generate_ephemeral_key) generate_ephemeral_ta_key;
%inline %{
    static void generate_ephemeral_ta_key(char **out, int *out_len, const EAC_CTX *ctx) {

        BUF_MEM *out_buf = NULL;

        out_buf = BUF_MEM_new();
        if (!out_buf)
            goto err;

        out_buf = TA_STEP3_generate_ephemeral_key(ctx);
        if (out_buf) {
            *out_len = out_buf->length;
            *out = malloc((size_t) *out_len);
            memcpy((void *) *out, out_buf->data, *out_len);
            BUF_MEM_free(out_buf);
            return;
        }

    err:
        if (out_buf)
            BUF_MEM_free(out_buf);
        if (*out)
            free(*out);
        *out_len = 0;
        return;
    }
%}

%rename(TA_STEP4_get_nonce) get_nonce;
%inline %{
    static void get_nonce(char **out, int *out_len, const EAC_CTX *ctx) {

        BUF_MEM *out_buf = NULL;

        out_buf = BUF_MEM_new();
        if (!out_buf)
            goto err;

        out_buf = TA_STEP4_get_nonce(ctx);
        if (out_buf) {
            *out_len = out_buf->length;
            *out = malloc((size_t) *out_len);
            memcpy((void *) *out, out_buf->data, *out_len);
            BUF_MEM_free(out_buf);
            return;
        }

    err:
        if (out_buf)
            BUF_MEM_free(out_buf);
        if (*out)
            free(*out);
        *out_len = 0;
        return;
    }
%}
#else

BUF_MEM *
TA_STEP3_generate_ephemeral_key(const EAC_CTX *ctx);

BUF_MEM *
TA_STEP4_get_nonce(const EAC_CTX *ctx);

#endif

int
TA_STEP6_verify(const EAC_CTX *ctx, const BUF_MEM *opp_ta_comp_pubkey,
        const BUF_MEM *my_pace_comp_eph_pubkey, const BUF_MEM *auxdata,
        const BUF_MEM *signature);
