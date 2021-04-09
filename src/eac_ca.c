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
 * @file eac_ca.c
 * @brief Chip Authentication implementation
 *
 * @author Frank Morgner <frankmorgner@gmail.com>
 * @author Dominik Oepen <oepen@informatik.hu-berlin.de>
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "eac_asn1.h"
#include "eac_err.h"
#include "eac_lib.h"
#include "eac_util.h"
#include <eac/ca.h>
#include <eac/pace.h>
#include <openssl/crypto.h>
#include <openssl/dh.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>
#include <string.h>

static int CA_passive_authentication(const EAC_CTX *ctx, PKCS7 *ef_cardsecurity);

BUF_MEM *
CA_STEP1_get_pubkey(const EAC_CTX *ctx)
{
    check_return(ctx && ctx->ca_ctx && ctx->ca_ctx->ka_ctx,
            "Invalid arguments");

    return asn1_pubkey(ctx->ca_ctx->protocol, ctx->ca_ctx->ka_ctx->key,
            ctx->bn_ctx, ctx->tr_version);
}

BUF_MEM *
CA_STEP2_get_eph_pubkey(const EAC_CTX *ctx)
{
    check_return(ctx && ctx->ca_ctx && ctx->ca_ctx->ka_ctx,
            "Invalid arguments");

    return get_pubkey(ctx->ca_ctx->ka_ctx->key, ctx->bn_ctx);
}

int
CA_STEP3_check_pcd_pubkey(const EAC_CTX *ctx,
        const BUF_MEM *comp_pubkey, const BUF_MEM *pubkey)
{
    BUF_MEM *my_comp_pubkey = NULL;
    int r = -1;

    check((ctx && ctx->ca_ctx && comp_pubkey && ctx->ca_ctx->ka_ctx),
           "Invalid arguments");

    /* Compress own public key */
    my_comp_pubkey = Comp(ctx->ca_ctx->ka_ctx->key, pubkey, ctx->bn_ctx, ctx->md_ctx);
    check(my_comp_pubkey, "Failed to compress public key");

    /* Check whether or not the received data fits the own data */
    if (my_comp_pubkey->length != comp_pubkey->length
            || memcmp(my_comp_pubkey->data, comp_pubkey->data, comp_pubkey->length) != 0) {
        log_err("Wrong public key");
        r = 0;
    } else
        r = 1;

err:
    if (my_comp_pubkey)
        BUF_MEM_free(my_comp_pubkey);

    return r;
}

int
CA_STEP4_compute_shared_secret(const EAC_CTX *ctx, const BUF_MEM *pubkey)
{
    if (!ctx || !ctx->ca_ctx
            || !KA_CTX_compute_key(ctx->ca_ctx->ka_ctx, pubkey, ctx->bn_ctx)) {
        log_err("Invalid arguments");
        return 0;
    }

    return 1;
}

int
CA_passive_authentication(const EAC_CTX *ctx, PKCS7 *ef_cardsecurity)
{
    X509 *ds_cert;
    X509_STORE *store;
    STACK_OF(X509) *ds_certs = NULL;
    unsigned long issuer_name_hash;
    int ret = 0;

    check(ef_cardsecurity && ctx && ctx->ca_ctx && ctx->ca_ctx->lookup_csca_cert, "Invalid arguments");

    /* Extract the DS certificates from the EF.CardSecurity */
    ds_certs = PKCS7_get0_signers(ef_cardsecurity, NULL, 0);
    check(ds_certs, "Failed to retrieve certificates from EF.CardSecurity");

    /* NOTE: The following code assumes that there is only one certificate in
     * PKCS7 structure. ds_cert is implicitly freed together with ds_certs. */
    ds_cert = sk_X509_pop(ds_certs);
    check(ds_cert, "Failed to retrieve DS certificate from EF.CardSecurity");

    /* Get the trust store with at least the csca certificate */
    issuer_name_hash = X509_issuer_name_hash(ds_cert);
    store = ctx->ca_ctx->lookup_csca_cert(issuer_name_hash);
    check (store, "Failed to retrieve CSCA truststore");

    /* Verify the signature and the certificate chain */
    ret = PKCS7_verify(ef_cardsecurity, ds_certs, store, NULL, NULL, 0);

err:
    if (ds_certs)
        sk_X509_free(ds_certs);

    return ret;
}

int
EAC_CTX_init_ef_cardsecurity(const unsigned char *ef_cardsecurity,
            size_t ef_cardsecurity_len, EAC_CTX *ctx)
{
	PKCS7 *p7 = NULL, *signed_data;
    ASN1_OCTET_STRING *os;
    int r = 0;

    check(ef_cardsecurity, "Invalid arguments");

    if (!d2i_PKCS7(&p7, &ef_cardsecurity, ef_cardsecurity_len)
            || !PKCS7_type_is_signed(p7))
        goto err;

    if (ctx && ctx->ca_ctx &&
            !(ctx->ca_ctx->flags & CA_FLAG_DISABLE_PASSIVE_AUTH))
        check((CA_passive_authentication(ctx, p7) == 1),
                "Failed to perform passive authentication");

    signed_data = p7->d.sign->contents;
    if (OBJ_obj2nid(signed_data->type) != NID_id_SecurityObject
            || ASN1_TYPE_get(signed_data->d.other) != V_ASN1_OCTET_STRING)
        goto err;
    os = signed_data->d.other->value.octet_string;

    if (!EAC_CTX_init_ef_cardaccess(os->data, os->length, ctx)
            || !ctx || !ctx->ca_ctx || !ctx->ca_ctx->ka_ctx)
        goto err;

    r = 1;

err:
    if (p7)
        PKCS7_free(p7);

    return r;
}

BUF_MEM *
CA_get_pubkey(const EAC_CTX *ctx,
        const unsigned char *ef_cardsecurity,
        size_t ef_cardsecurity_len)
{
    BUF_MEM *pubkey = NULL;
    EAC_CTX *signed_ctx = EAC_CTX_new();
    check(ctx && ctx->ca_ctx, "Invalid arguments");

    if (ctx->ca_ctx->flags & CA_FLAG_DISABLE_PASSIVE_AUTH)
        CA_disable_passive_authentication(signed_ctx);

    check(EAC_CTX_init_ef_cardsecurity(ef_cardsecurity, ef_cardsecurity_len,
                signed_ctx)
            && signed_ctx && signed_ctx->ca_ctx && signed_ctx->ca_ctx->ka_ctx,
            "Could not parse EF.CardSecurity");

    pubkey = get_pubkey(signed_ctx->ca_ctx->ka_ctx->key, signed_ctx->bn_ctx);

err:
    EAC_CTX_clear_free(signed_ctx);

    return pubkey;
}

int
CA_set_key(const EAC_CTX *ctx,
        const unsigned char *priv, size_t priv_len,
        const unsigned char *pub, size_t pub_len)
{
    int r = 0;
    const unsigned char *p = priv;
    EVP_PKEY *key = NULL;

    check(ctx && ctx->ca_ctx && ctx->ca_ctx->ka_ctx,
            "Invalid arguments");

    /* always try d2i_AutoPrivateKey as priv may contain domain parameters */
    if (priv && d2i_AutoPrivateKey(&key, &p, priv_len)) {
        EVP_PKEY_free(ctx->ca_ctx->ka_ctx->key);
        ctx->ca_ctx->ka_ctx->key = key;
        if (pub) {
            /* it's OK if import of public key fails */
            EVP_PKEY_set_keys(key, NULL, 0, pub, pub_len, ctx->bn_ctx);
        }
    } else {
        /* wipe errors from d2i_AutoPrivateKey() */
        ERR_clear_error();
        check(EVP_PKEY_set_keys(ctx->ca_ctx->ka_ctx->key, priv, priv_len, pub,
                    pub_len, ctx->bn_ctx),
                "no valid keys given");
    }
    r = 1;

err:
    return r;
}

/* Nonce for CA is always 8 bytes long */
#define CA_NONCE_SIZE 8
int
CA_STEP5_derive_keys(const EAC_CTX *ctx, const BUF_MEM *pub,
                   BUF_MEM **nonce, BUF_MEM **token)
{
    BUF_MEM *r = NULL;
    BUF_MEM *authentication_token = NULL;

    check((ctx && ctx->ca_ctx && ctx->ca_ctx->ka_ctx && nonce && token),
            "Invalid arguments");

    /* Generate nonce  and derive k_mac and k_enc*/
    r = randb(CA_NONCE_SIZE);
    if (!r || !KA_CTX_derive_keys(ctx->ca_ctx->ka_ctx, r, ctx->md_ctx))
        goto err;

    /* Compute authentication token */
    authentication_token = get_authentication_token(ctx->ca_ctx->protocol,
            ctx->ca_ctx->ka_ctx, ctx->bn_ctx, ctx->tr_version,
            pub);
    check(authentication_token, "Failed to compute authentication token");

    *nonce = r;
    *token = authentication_token;

    return 1;

err:
    BUF_MEM_clear_free(r);

    return 0;
}

int
CA_STEP6_derive_keys(EAC_CTX *ctx, const BUF_MEM *nonce, const BUF_MEM *token)
{
    int rv = -1;

    check((ctx && ctx->ca_ctx), "Invalid arguments");

    if (!KA_CTX_derive_keys(ctx->ca_ctx->ka_ctx, nonce, ctx->md_ctx))
        goto err;

    rv = verify_authentication_token(ctx->ca_ctx->protocol,
            ctx->ca_ctx->ka_ctx,
            ctx->bn_ctx, ctx->tr_version, token);
    check(rv >= 0, "Failed to verify authentication token");

    /* PACE, TA and CA were successful. Update the trust anchor! */
    if (rv) {
        if (ctx->ta_ctx->new_trust_anchor) {
            CVC_CERT_free(ctx->ta_ctx->trust_anchor);
            ctx->ta_ctx->trust_anchor = ctx->ta_ctx->new_trust_anchor;
            ctx->ta_ctx->new_trust_anchor = NULL;
        }
    }

err:
    return rv;
}

void
CA_disable_passive_authentication (EAC_CTX *ctx)
{
    if (!ctx || !ctx->ca_ctx)
        return;
    ctx->ca_ctx->flags |= CA_FLAG_DISABLE_PASSIVE_AUTH;
    return;
}
