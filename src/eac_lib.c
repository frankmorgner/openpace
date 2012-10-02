/*
 * Copyright (c) 2010-2012 Frank Morgner and Dominik Oepen
 *
 * This file is part of OpenPACE.
 *
 * OpenPACE is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * OpenPACE is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with FFmpeg; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

/**
 * @file eac_lib.c
 * @brief Data management functions
 *
 * @author Frank Morgner <morgner@informatik.hu-berlin.de>
 * @author Dominik Oepen <oepen@informatik.hu-berlin.de>
 */

#include "ca_lib.h"
#include "eac_dh.h"
#include "eac_ecdh.h"
#include "eac_err.h"
#include "eac_lib.h"
#include "eac_util.h"
#include "misc.h"
#include "pace_lib.h"
#include "ta_lib.h"
#include <eac/ca.h>
#include <eac/cv_cert.h>
#include <eac/eac.h>
#include <eac/pace.h>
#include <eac/ri.h>
#include <eac/ta.h>
#include <openssl/buffer.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <string.h>

static unsigned char DECVCAeID00102[] = {
    0x7f, 0x21, 0x82, 0x01, 0xb6, 0x7f, 0x4e, 0x82, 0x01, 0x6e, 0x5f, 0x29, 0x01, 0x00, 0x42, 0x0e, /*.!....N..n_)..B.*/
    0x44, 0x45, 0x43, 0x56, 0x43, 0x41, 0x65, 0x49, 0x44, 0x30, 0x30, 0x31, 0x30, 0x32, 0x7f, 0x49, /*DECVCAeID00102.I*/
    0x82, 0x01, 0x1d, 0x06, 0x0a, 0x04, 0x00, 0x7f, 0x00, 0x07, 0x02, 0x02, 0x02, 0x02, 0x03, 0x81, /*................*/
    0x20, 0xa9, 0xfb, 0x57, 0xdb, 0xa1, 0xee, 0xa9, 0xbc, 0x3e, 0x66, 0x0a, 0x90, 0x9d, 0x83, 0x8d, /* ..W.....>f.....*/
    0x72, 0x6e, 0x3b, 0xf6, 0x23, 0xd5, 0x26, 0x20, 0x28, 0x20, 0x13, 0x48, 0x1d, 0x1f, 0x6e, 0x53, /*rn;.#.& ( .H..nS*/
    0x77, 0x82, 0x20, 0x7d, 0x5a, 0x09, 0x75, 0xfc, 0x2c, 0x30, 0x57, 0xee, 0xf6, 0x75, 0x30, 0x41, /*w. }Z.u.,0W..u0A*/
    0x7a, 0xff, 0xe7, 0xfb, 0x80, 0x55, 0xc1, 0x26, 0xdc, 0x5c, 0x6c, 0xe9, 0x4a, 0x4b, 0x44, 0xf3, /*z....U.&.\l.JKD.*/
    0x30, 0xb5, 0xd9, 0x83, 0x20, 0x26, 0xdc, 0x5c, 0x6c, 0xe9, 0x4a, 0x4b, 0x44, 0xf3, 0x30, 0xb5, /*0... &.\l.JKD.0.*/
    0xd9, 0xbb, 0xd7, 0x7c, 0xbf, 0x95, 0x84, 0x16, 0x29, 0x5c, 0xf7, 0xe1, 0xce, 0x6b, 0xcc, 0xdc, /*...|....)\...k..*/
    0x18, 0xff, 0x8c, 0x07, 0xb6, 0x84, 0x41, 0x04, 0x8b, 0xd2, 0xae, 0xb9, 0xcb, 0x7e, 0x57, 0xcb, /*......A......~W.*/
    0x2c, 0x4b, 0x48, 0x2f, 0xfc, 0x81, 0xb7, 0xaf, 0xb9, 0xde, 0x27, 0xe1, 0xe3, 0xbd, 0x23, 0xc2, /*,KH/......'...#.*/
    0x3a, 0x44, 0x53, 0xbd, 0x9a, 0xce, 0x32, 0x62, 0x54, 0x7e, 0xf8, 0x35, 0xc3, 0xda, 0xc4, 0xfd, /*:DS...2bT~.5....*/
    0x97, 0xf8, 0x46, 0x1a, 0x14, 0x61, 0x1d, 0xc9, 0xc2, 0x77, 0x45, 0x13, 0x2d, 0xed, 0x8e, 0x54, /*..F..a...wE.-..T*/
    0x5c, 0x1d, 0x54, 0xc7, 0x2f, 0x04, 0x69, 0x97, 0x85, 0x20, 0xa9, 0xfb, 0x57, 0xdb, 0xa1, 0xee, /*\.T./.i.. ..W...*/
    0xa9, 0xbc, 0x3e, 0x66, 0x0a, 0x90, 0x9d, 0x83, 0x8d, 0x71, 0x8c, 0x39, 0x7a, 0xa3, 0xb5, 0x61, /*..>f.....q.9z..a*/
    0xa6, 0xf7, 0x90, 0x1e, 0x0e, 0x82, 0x97, 0x48, 0x56, 0xa7, 0x86, 0x41, 0x04, 0x33, 0x47, 0xec, /*.......HV..A.3G.*/
    0xf9, 0x6f, 0xfb, 0x4b, 0xd9, 0xb8, 0x55, 0x4e, 0xfb, 0xcc, 0xfc, 0x7d, 0x0b, 0x24, 0x2f, 0x10, /*.o.K..UN...}.$/.*/
    0x71, 0xe2, 0x9b, 0x4c, 0x9c, 0x62, 0x2c, 0x79, 0xe3, 0x39, 0xd8, 0x40, 0xaf, 0x67, 0xbe, 0xb9, /*q..L.b,y.9.@.g..*/
    0xb9, 0x12, 0x69, 0x22, 0x65, 0xd9, 0xc1, 0x6c, 0x62, 0x57, 0x3f, 0x45, 0x79, 0xff, 0xd4, 0xde, /*..i"e..lbW?Ey...*/
    0x2d, 0xe9, 0x2b, 0xab, 0x40, 0x9d, 0xd5, 0xc5, 0xd4, 0x82, 0x44, 0xa9, 0xf7, 0x87, 0x01, 0x01, /*-.+.@.....D.....*/
    0x5f, 0x20, 0x0e, 0x44, 0x45, 0x43, 0x56, 0x43, 0x41, 0x65, 0x49, 0x44, 0x30, 0x30, 0x31, 0x30, /*_ .DECVCAeID0010*/
    0x32, 0x7f, 0x4c, 0x12, 0x06, 0x09, 0x04, 0x00, 0x7f, 0x00, 0x07, 0x03, 0x01, 0x02, 0x02, 0x53, /*2.L............S*/
    0x05, 0xfe, 0x0f, 0x01, 0xff, 0xff, 0x5f, 0x25, 0x06, 0x01, 0x00, 0x01, 0x00, 0x01, 0x08, 0x5f, /*......_%......._*/
    0x24, 0x06, 0x01, 0x03, 0x01, 0x00, 0x01, 0x08, 0x5f, 0x37, 0x40, 0x50, 0x67, 0x14, 0x5c, 0x68, /*$......._7@Pg.\h*/
    0xca, 0xe9, 0x52, 0x0f, 0x5b, 0xb3, 0x48, 0x17, 0xf1, 0xca, 0x9c, 0x43, 0x59, 0x3d, 0xb5, 0x64, /*..R.[.H....CY=.d*/
    0x06, 0xc6, 0xa3, 0xb0, 0x06, 0xcb, 0xf3, 0xf3, 0x14, 0xe7, 0x34, 0x9a, 0xcf, 0x0c, 0xc6, 0xbf, /*..........4.....*/
    0xeb, 0xcb, 0xde, 0xfd, 0x10, 0xb4, 0xdc, 0xf0, 0xf2, 0x31, 0xda, 0x56, 0x97, 0x7d, 0x88, 0xf9, /*.........1.V.}..*/
    0xf9, 0x01, 0x82, 0xd1, 0x99, 0x07, 0x6a, 0x56, 0x50, 0x64, 0x51,                               /*......jVPdQ*/
};
static unsigned char DECVCAEPASS00102[] = {
    0x7f, 0x21, 0x82, 0x01, 0xb6, 0x7f, 0x4e, 0x82, 0x01, 0x6e, 0x5f, 0x29, 0x01, 0x00, 0x42, 0x10, /*.!....N..n_)..B.*/
    0x44, 0x45, 0x43, 0x56, 0x43, 0x41, 0x45, 0x50, 0x41, 0x53, 0x53, 0x30, 0x30, 0x31, 0x30, 0x32, /*DECVCAEPASS00102*/
    0x7f, 0x49, 0x82, 0x01, 0x1d, 0x06, 0x0a, 0x04, 0x00, 0x7f, 0x00, 0x07, 0x02, 0x02, 0x02, 0x02, /*.I..............*/
    0x03, 0x81, 0x20, 0xa9, 0xfb, 0x57, 0xdb, 0xa1, 0xee, 0xa9, 0xbc, 0x3e, 0x66, 0x0a, 0x90, 0x9d, /*.., 0x..W.....>f...*/
    0x83, 0x8d, 0x72, 0x6e, 0x3b, 0xf6, 0x23, 0xd5, 0x26, 0x20, 0x28, 0x20, 0x13, 0x48, 0x1d, 0x1f, /*..rn;.#.&, 0x(, 0x.H..*/
    0x6e, 0x53, 0x77, 0x82, 0x20, 0x7d, 0x5a, 0x09, 0x75, 0xfc, 0x2c, 0x30, 0x57, 0xee, 0xf6, 0x75, /*nSw., 0x}Z.u.,0W..u*/
    0x30, 0x41, 0x7a, 0xff, 0xe7, 0xfb, 0x80, 0x55, 0xc1, 0x26, 0xdc, 0x5c, 0x6c, 0xe9, 0x4a, 0x4b, /*0Az....U.&.\l.JK*/
    0x44, 0xf3, 0x30, 0xb5, 0xd9, 0x83, 0x20, 0x26, 0xdc, 0x5c, 0x6c, 0xe9, 0x4a, 0x4b, 0x44, 0xf3, /*D.0..., 0x&.\l.JKD.*/
    0x30, 0xb5, 0xd9, 0xbb, 0xd7, 0x7c, 0xbf, 0x95, 0x84, 0x16, 0x29, 0x5c, 0xf7, 0xe1, 0xce, 0x6b, /*0....|....)\...k*/
    0xcc, 0xdc, 0x18, 0xff, 0x8c, 0x07, 0xb6, 0x84, 0x41, 0x04, 0x8b, 0xd2, 0xae, 0xb9, 0xcb, 0x7e, /*........A......~*/
    0x57, 0xcb, 0x2c, 0x4b, 0x48, 0x2f, 0xfc, 0x81, 0xb7, 0xaf, 0xb9, 0xde, 0x27, 0xe1, 0xe3, 0xbd, /*W.,KH/......'...*/
    0x23, 0xc2, 0x3a, 0x44, 0x53, 0xbd, 0x9a, 0xce, 0x32, 0x62, 0x54, 0x7e, 0xf8, 0x35, 0xc3, 0xda, /*#.:DS...2bT~.5..*/
    0xc4, 0xfd, 0x97, 0xf8, 0x46, 0x1a, 0x14, 0x61, 0x1d, 0xc9, 0xc2, 0x77, 0x45, 0x13, 0x2d, 0xed, /*....F..a...wE.-.*/
    0x8e, 0x54, 0x5c, 0x1d, 0x54, 0xc7, 0x2f, 0x04, 0x69, 0x97, 0x85, 0x20, 0xa9, 0xfb, 0x57, 0xdb, /*.T\.T./.i.., 0x..W.*/
    0xa1, 0xee, 0xa9, 0xbc, 0x3e, 0x66, 0x0a, 0x90, 0x9d, 0x83, 0x8d, 0x71, 0x8c, 0x39, 0x7a, 0xa3, /*....>f.....q.9z.*/
    0xb5, 0x61, 0xa6, 0xf7, 0x90, 0x1e, 0x0e, 0x82, 0x97, 0x48, 0x56, 0xa7, 0x86, 0x41, 0x04, 0x43, /*.a.......HV..A.C*/
    0x3e, 0xdc, 0xc9, 0x3e, 0x73, 0xe8, 0xe2, 0x92, 0xf4, 0xd9, 0x41, 0xed, 0x06, 0x58, 0x0e, 0x56, /*>..>s.....A..X.V*/
    0x8f, 0x7f, 0x09, 0xfc, 0x5e, 0xc3, 0x4e, 0x90, 0x6e, 0x5a, 0x61, 0xae, 0x83, 0x10, 0x8f, 0xa2, /*....^.N.nZa.....*/
    0x76, 0x95, 0x2f, 0xbd, 0xa1, 0x4f, 0xfe, 0x47, 0xfd, 0x08, 0xec, 0x42, 0xa8, 0x20, 0xc7, 0x73, /*v./..O.G...B., 0x.s*/
    0xb2, 0x27, 0x02, 0xfc, 0x47, 0xbf, 0xf1, 0xa1, 0xd3, 0x41, 0x60, 0xb6, 0x46, 0x23, 0xd7, 0x87, /*.'..G....A`.F#..*/
    0x01, 0x01, 0x5f, 0x20, 0x10, 0x44, 0x45, 0x43, 0x56, 0x43, 0x41, 0x45, 0x50, 0x41, 0x53, 0x53, /*.._, 0x.DECVCAEPASS*/
    0x30, 0x30, 0x31, 0x30, 0x32, 0x7f, 0x4c, 0x0e, 0x06, 0x09, 0x04, 0x00, 0x7f, 0x00, 0x07, 0x03, /*00102.L.........*/
    0x01, 0x02, 0x01, 0x53, 0x01, 0xc1, 0x5f, 0x25, 0x06, 0x01, 0x00, 0x01, 0x00, 0x01, 0x08, 0x5f, /*...S.._%......._*/
    0x24, 0x06, 0x01, 0x03, 0x01, 0x00, 0x01, 0x08, 0x5f, 0x37, 0x40, 0x90, 0xd5, 0xe1, 0x71, 0xeb, /*$......._7@...q.*/
    0xb2, 0xce, 0x74, 0x9f, 0xb3, 0x15, 0xb3, 0x13, 0x29, 0x9f, 0xa9, 0x04, 0x24, 0x1d, 0xde, 0x27, /*..t.....)...$..'*/
    0x1b, 0xf5, 0xc6, 0x81, 0x9c, 0x8f, 0xcd, 0xe7, 0xbb, 0x4c, 0xb4, 0x77, 0x62, 0x3f, 0x1c, 0xcd, /*.........L.wb?..*/
    0xd7, 0x1a, 0xd3, 0xda, 0x90, 0xfa, 0x4c, 0x48, 0xe5, 0x8a, 0x96, 0xc7, 0x4f, 0xea, 0xdc, 0xe3, /*......LH....O...*/
    0x85, 0xe4, 0xa2, 0x77, 0x98, 0x22, 0xb4, 0x79, 0xfa, 0x4a, 0xe4,                               /*...w.".y.J.*/
};
struct certificates {
    char *chr;
    unsigned char *cert;
    size_t cert_len;
};
static struct certificates certs[] = {
    {"DECVCAeID00102", DECVCAeID00102, sizeof DECVCAeID00102},
    {"DECVCAEPASS00102", DECVCAEPASS00102, sizeof DECVCAEPASS00102},
};

EAC_CTX *
EAC_CTX_new(void)
{
    EAC_CTX *ctx = OPENSSL_malloc(sizeof(EAC_CTX));
    if (!ctx)
        return NULL;

    ctx->bn_ctx = BN_CTX_new();
    ctx->pace_ctx = PACE_CTX_new();
    ctx->md_ctx = EVP_MD_CTX_create();
    ctx->ta_ctx = TA_CTX_new();
    ctx->ca_ctx = CA_CTX_new();
    ctx->cipher_ctx = EVP_CIPHER_CTX_new();
    ctx->ri_ctx = RI_CTX_new();

    if (!ctx->bn_ctx || !ctx->md_ctx || !ctx->pace_ctx || !ctx->ta_ctx
                       || !ctx->ca_ctx || !ctx->cipher_ctx || !ctx->ri_ctx)
        goto err;

    ctx->tr_version = EAC_TR_VERSION_2_02;
    BN_CTX_init(ctx->bn_ctx);
    EVP_CIPHER_CTX_init(ctx->cipher_ctx);
    ctx->key_ctx = NULL;

    return ctx;

err:
    EAC_CTX_clear_free(ctx);
    return NULL;
}

int
EAC_CTX_init_pace(EAC_CTX *ctx, int protocol, int curve)
{
    if (!ctx || !ctx->pace_ctx) {
        log_err("Invalid arguments");
        return 0;
    }

    if (!PACE_CTX_set_protocol(ctx->pace_ctx, protocol, ctx->tr_version)
                || !EVP_PKEY_set_std_dp(ctx->pace_ctx->static_key, curve))
        return 0;

    return 1;
}

CVC_CERT *
cert_from_car(const unsigned char *car, size_t car_len)
{
    size_t i;
    const unsigned char *p;

    check_return((car && car_len), "Invalid arguments");

    for (i = 0; i < (sizeof certs)/sizeof *certs; i++) {
        if (strlen(certs[i].chr) == car_len
                && memcmp(certs[i].chr, car, car_len) == 0) {
            p = certs[i].cert;
            return CVC_d2i_CVC_CERT(NULL, &p, certs[i].cert_len);
        }
    }

    return NULL;
}

int
EAC_CTX_init_ta(const EAC_CTX *ctx,
           const unsigned char *privkey, size_t privkey_len,
           const unsigned char *cert, size_t cert_len,
           const unsigned char *car, size_t car_len)
{
    CVC_CERT *ta_cert = NULL;
    int r = 0;

    check(ctx, "Invalid arguments");

    if (privkey && privkey_len) {
        if (ctx->ta_ctx->priv_key)
            EVP_PKEY_free(ctx->ta_ctx->priv_key);
        ctx->ta_ctx->priv_key = d2i_AutoPrivateKey(&ctx->ta_ctx->priv_key,
                &privkey, privkey_len);
        if (!ctx->ta_ctx->priv_key)
            goto err;
    }

    if (cert && cert_len) {
        ta_cert = CVC_d2i_CVC_CERT(&ta_cert, &cert, cert_len);
        if (car && car_len && ta_cert) {
            if (!ta_cert->body || !ta_cert->body->certificate_holder_reference
                    || ta_cert->body->certificate_holder_reference->length != car_len
                    || memcmp(ta_cert->body->certificate_holder_reference->data, car, car_len) != 0)
                goto err;
        }
    } else
        ta_cert = cert_from_car(car, car_len);
    r = TA_CTX_import_certificate(ctx->ta_ctx, ta_cert, ctx->bn_ctx);

err:
    if (ta_cert)
        CVC_CERT_free(ta_cert);

    return r;
}

int
EAC_CTX_init_ca(const EAC_CTX *ctx, int protocol, int curve,
                const unsigned char *priv, size_t priv_len,
                const unsigned char *pub, size_t pub_len)
{
    if (!ctx || !ctx->ca_ctx || !ctx->ca_ctx->ka_ctx
               || (!priv && pub)) {
        log_err("Invalid arguments");
        return 0;
    }

    if (protocol) {
        if (!CA_CTX_set_protocol(ctx->ca_ctx, protocol)
                || !EVP_PKEY_set_std_dp(ctx->ca_ctx->ka_ctx->key, curve))
            return 0;
    }

    if (priv && !pub) {
        if (!d2i_AutoPrivateKey(&ctx->ca_ctx->ka_ctx->key, &priv, priv_len))
            return 0;
    }

    if (priv && pub)
        return EVP_PKEY_set_keys(ctx->ca_ctx->ka_ctx->key, priv, priv_len,
                   pub, pub_len, ctx->bn_ctx);

    return 1;
}

int
EAC_CTX_init_ri(EAC_CTX *ctx, int protocol, int stnd_dp)
{

    BUF_MEM *pubkey = NULL;

    if (!ctx || !ctx->ri_ctx) {
        log_err("Invalid arguments");
        return 0;
    }

    if (!RI_CTX_set_protocol(ctx->ri_ctx, protocol)
               || !EVP_PKEY_set_std_dp(ctx->ri_ctx->static_key, stnd_dp))
            return 0;

    if (!ctx->ri_ctx->generate_key)
        return 0;

    pubkey = ctx->ri_ctx->generate_key(ctx->ri_ctx->static_key, ctx->bn_ctx);
    if (!pubkey)
        return 0;
    else /* We do not need the buffered public key and throw it away immediately */
        BUF_MEM_clear_free(pubkey);

    return 1;
}

void
EAC_CTX_clear_free(EAC_CTX *ctx) {
    if (ctx) {
        if (ctx->bn_ctx)
            BN_CTX_free(ctx->bn_ctx);
        if (ctx->md_ctx)
            EVP_MD_CTX_destroy(ctx->md_ctx);
        if (ctx->cipher_ctx)
            EVP_CIPHER_CTX_free(ctx->cipher_ctx);
        if (ctx->pace_ctx)
            PACE_CTX_clear_free(ctx->pace_ctx);
        if (ctx->ta_ctx)
            TA_CTX_clear_free(ctx->ta_ctx);
        if (ctx->ca_ctx)
            CA_CTX_clear_free(ctx->ca_ctx);
        if (ctx->key_ctx)
            KA_CTX_clear_free(ctx->key_ctx);
        if (ctx->ri_ctx)
            RI_CTX_clear_free(ctx->ri_ctx);
        OPENSSL_free(ctx);
    }
}

KA_CTX *
KA_CTX_new(void)
{
    KA_CTX * out = OPENSSL_malloc(sizeof(KA_CTX));
    if (!out)
        goto err;

    out->key = EVP_PKEY_new();
    if (!out->key)
        goto err;

    out->md = NULL;
    out->md_engine = NULL;
    out->cmac_ctx = NULL;
    out->cipher = NULL;
    out->cipher_engine = NULL;
    out->iv = NULL;
    out->generate_key = NULL;
    out->compute_key = NULL;
    out->mac_keylen = 0;
    out->enc_keylen = 0;
    out->shared_secret = NULL;
    out->k_enc = NULL;
    out->k_mac = NULL;

    return out;

err:
    if (out) {
        if (out->key)
            EVP_PKEY_free(out->key);
        OPENSSL_free(out);
    }
    return NULL;
}

KA_CTX *
KA_CTX_dup(const KA_CTX *ka_ctx)
{
    KA_CTX *out = NULL;

    check(ka_ctx, "Invalid arguments");

    out = OPENSSL_malloc(sizeof(KA_CTX));
    if (!out)
        goto err;

    out->key = EVP_PKEY_dup(ka_ctx->key);
    if (!out->key && ka_ctx->key)
        goto err;

    out->md = ka_ctx->md;
    out->md_engine = ka_ctx->md_engine;
    out->cmac_ctx = NULL;
    out->cipher = ka_ctx->cipher;
    out->cipher_engine = ka_ctx->cipher_engine;
    out->iv = NULL;
    out->generate_key = ka_ctx->generate_key;
    out->compute_key = ka_ctx->compute_key;
    out->mac_keylen = ka_ctx->mac_keylen;
    out->enc_keylen = ka_ctx->enc_keylen;
    if (ka_ctx->k_enc) {
        out->k_enc = BUF_MEM_create_init(ka_ctx->k_enc->data, ka_ctx->k_enc->length);
        if (!out->k_enc)
            goto err;
    } else
        out->k_enc = NULL;
    if (ka_ctx->k_mac) {
        out->k_mac = BUF_MEM_create_init(ka_ctx->k_mac->data, ka_ctx->k_mac->length);
        if (!out->k_mac)
            goto err;
    } else
        out->k_mac = NULL;
    if (ka_ctx->shared_secret) {
        out->shared_secret = BUF_MEM_create_init(ka_ctx->shared_secret->data, ka_ctx->shared_secret->length);
        if (!out->shared_secret)
            goto err;
    } else
        out->shared_secret = NULL;

    return out;

err:
    KA_CTX_clear_free(out);

    return NULL;
}

void
KA_CTX_clear_free(KA_CTX *ctx)
{
    if (ctx) {
        if (ctx->cmac_ctx) /* FIXME: Segfaults if CMAC_Init has not been called */
            CMAC_CTX_free(ctx->cmac_ctx);
        if (ctx->key)
            EVP_PKEY_free(ctx->key);
        if (ctx->shared_secret) {
            OPENSSL_cleanse(ctx->shared_secret->data, ctx->shared_secret->max);
            BUF_MEM_free(ctx->shared_secret);
        }
        if (ctx->k_mac) {
            OPENSSL_cleanse(ctx->k_mac->data, ctx->k_mac->max);
            BUF_MEM_free(ctx->k_mac);
        }
        if (ctx->k_enc) {
            OPENSSL_cleanse(ctx->k_enc->data, ctx->k_enc->max);
            BUF_MEM_free(ctx->k_enc);
        }
        free(ctx->iv);
        OPENSSL_free(ctx);
    }
}

int
KA_CTX_set_protocol(KA_CTX *ctx, int protocol)
{
    if (!ctx) {
        log_err("Invalid arguments");
        return 0;
    }

    switch (protocol) {
        case NID_id_CA_DH_3DES_CBC_CBC:
        case NID_id_PACE_DH_GM_3DES_CBC_CBC:
        case NID_id_PACE_DH_IM_3DES_CBC_CBC:
            ctx->generate_key = dh_generate_key;
            ctx->compute_key = dh_compute_key;
            ctx->mac_keylen = 16;
            ctx->md = EVP_sha1();
            ctx->cipher = EVP_des_ede_cbc();
            ctx->enc_keylen = ctx->cipher->key_len;
            break;

        case NID_id_CA_DH_AES_CBC_CMAC_128:
        case NID_id_PACE_DH_GM_AES_CBC_CMAC_128:
        case NID_id_PACE_DH_IM_AES_CBC_CMAC_128:
            ctx->generate_key = dh_generate_key;
            ctx->compute_key = dh_compute_key;
            ctx->mac_keylen = 16;
            ctx->cmac_ctx = NULL; /* We don't set cmac_ctx, because of potential segfaults */
            ctx->md = EVP_sha1();
            ctx->cipher = EVP_aes_128_cbc();
            ctx->enc_keylen = ctx->cipher->key_len;
            break;

        case NID_id_CA_DH_AES_CBC_CMAC_192:
        case NID_id_PACE_DH_GM_AES_CBC_CMAC_192:
        case NID_id_PACE_DH_IM_AES_CBC_CMAC_192:
            ctx->generate_key = dh_generate_key;
            ctx->compute_key = dh_compute_key;
            ctx->mac_keylen = 24;
            ctx->cmac_ctx = NULL; /* We don't set cmac_ctx, because of potential segfaults */
            ctx->md = EVP_sha256();
            ctx->cipher = EVP_aes_192_cbc();
            ctx->enc_keylen = ctx->cipher->key_len;
            break;

        case NID_id_CA_DH_AES_CBC_CMAC_256:
        case NID_id_PACE_DH_GM_AES_CBC_CMAC_256:
        case NID_id_PACE_DH_IM_AES_CBC_CMAC_256:
            ctx->generate_key = dh_generate_key;
            ctx->compute_key = dh_compute_key;
            ctx->mac_keylen = 32;
            ctx->cmac_ctx = NULL; /* We don't set cmac_ctx, because of potential segfaults */
            ctx->md = EVP_sha256();
            ctx->cipher = EVP_aes_256_cbc();
            ctx->enc_keylen = ctx->cipher->key_len;
            break;

        case NID_id_CA_ECDH_3DES_CBC_CBC:
        case NID_id_PACE_ECDH_GM_3DES_CBC_CBC:
        case NID_id_PACE_ECDH_IM_3DES_CBC_CBC:
            ctx->generate_key = ecdh_generate_key;
            ctx->compute_key = ecdh_compute_key;
            ctx->mac_keylen = 16;
            ctx->md = EVP_sha1();
            ctx->cipher = EVP_des_ede_cbc();
            ctx->enc_keylen = ctx->cipher->key_len;
            break;

        case NID_id_CA_ECDH_AES_CBC_CMAC_128:
        case NID_id_PACE_ECDH_GM_AES_CBC_CMAC_128:
        case NID_id_PACE_ECDH_IM_AES_CBC_CMAC_128:
            ctx->generate_key = ecdh_generate_key;
            ctx->compute_key = ecdh_compute_key;
            ctx->mac_keylen = 16;
            ctx->cmac_ctx = NULL; /* We don't set cmac_ctx, because of potential segfaults */
            ctx->md = EVP_sha1();
            ctx->cipher = EVP_aes_128_cbc();
            ctx->enc_keylen = ctx->cipher->key_len;
            break;

        case NID_id_CA_ECDH_AES_CBC_CMAC_192:
        case NID_id_PACE_ECDH_GM_AES_CBC_CMAC_192:
        case NID_id_PACE_ECDH_IM_AES_CBC_CMAC_192:
            ctx->generate_key = ecdh_generate_key;
            ctx->compute_key = ecdh_compute_key;
            ctx->mac_keylen = 24;
            ctx->cmac_ctx = NULL; /* We don't set cmac_ctx, because of potential segfaults */
            ctx->md = EVP_sha256();
            ctx->cipher = EVP_aes_192_cbc();
            ctx->enc_keylen = ctx->cipher->key_len;
            break;

        case NID_id_CA_ECDH_AES_CBC_CMAC_256:
        case NID_id_PACE_ECDH_GM_AES_CBC_CMAC_256:
        case NID_id_PACE_ECDH_IM_AES_CBC_CMAC_256:
            ctx->generate_key = ecdh_generate_key;
            ctx->compute_key = ecdh_compute_key;
            ctx->mac_keylen = 32;
            ctx->cmac_ctx = NULL; /* We don't set cmac_ctx, because of potential segfaults */
            ctx->md = EVP_sha256();
            ctx->cipher = EVP_aes_256_cbc();
            ctx->enc_keylen = ctx->cipher->key_len;
            break;

        default:
            log_err("Unknown protocol");
            return 0;
    }

    return 1;
}
