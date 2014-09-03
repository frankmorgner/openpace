/*
 * Copyright (c) 2014 Frank Morgner
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
 */

/**
 * @file cvc-create.c
 * @brief Create Card Verifiable Certificates and their Description
 *
 * @author Frank Morgner <morgner@informatik.hu-berlin.de>
 */

#include "cvc-create-cmdline.h"
#include "misc.h"
#include "eac_util.h"
#include "eac_asn1.h"
#include "read_file.h"
#include <eac/eac.h>
#include <eac/cv_cert.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <stdio.h>
#include <string.h>

#define err(s) { puts(s); ERR_print_errors_fp(stdout); goto err; }

static int write_file(const char *filename, unsigned char *data, size_t length)
{
    FILE *fp = NULL;
    int fail = 1;
    unsigned char *p;

    fp = fopen(filename, "wb");
    if (!fp) {
        perror("Could not open file");
        goto err;
    }

    if (length != fwrite(data, sizeof(unsigned char), length, fp)) {
        perror("Failed to write file");
        goto err;
    }

    fail = 0;

err:
    if (fp)
        fclose(fp);

    return fail;
}

static EVP_PKEY *read_evp_pkey(const char *filename)
{
    unsigned char *key = NULL;
    const unsigned char *p;
    size_t key_len = 0;
    EVP_PKEY *pkey = NULL;

    if (0 != read_file(filename, &key, &key_len)) {
        goto err;
    }

    p = key;
    if (!d2i_AutoPrivateKey(&pkey, &p, key_len)) {
        err("Could not read private key");
    }

err:
    free(key);

    return pkey;
}

static CVC_CERT *read_cvc_cert(const char *filename)
{
    unsigned char *cert = NULL;
    const unsigned char *p;
    size_t cert_len = 0;
    CVC_CERT *cvc = NULL;

    if (0 != read_file(filename, &cert, &cert_len)) {
        goto err;
    }

    p = cert;
    if (!CVC_d2i_CVC_CERT(&cvc, &p, cert_len)) {
        err("Could not read certificate");
    }

err:
    free(cert);

    return cvc;
}

int cvc_role_set(const struct gengetopt_args_info *cmdline, unsigned char *out)
{
    int ok = 0;

    if (!cmdline || !out)
        goto err;

    switch (cmdline->role_arg) {
        case role_arg_cvca:
            *out = CVC_CVCA<<6;
            break;
        case role_arg_dv_domestic:
            *out = CVC_DV<<6;
            break;
        case role_arg_dv_foreign:
            *out = CVC_DocVer<<6;
            break;
        case role_arg_terminal:
            *out = CVC_Terminal<<6;
            break;
        default:
            err("unhandled type of terminal");
    }
    ok = 1;
err:
    return ok;
}

ASN1_OCTET_STRING *get_at_authorizations(const struct gengetopt_args_info *cmdline)
{
    ASN1_OCTET_STRING *out = NULL;
    unsigned char authorization[EAC_AT_CHAT_BYTES];

    memset(authorization, 0, sizeof authorization);

    if (!cvc_role_set(cmdline, authorization))
        goto err;

    if (cmdline->verify_age_flag)
        authorization[4] |= 1<<0;
    if (cmdline->verify_community_flag)
        authorization[4] |= 1<<1;
    if (cmdline->rid_flag)
        authorization[4] |= 1<<2;
    if (cmdline->privileged_flag)
        authorization[4] |= 1<<3;
    if (cmdline->can_allowed_flag)
        authorization[4] |= 1<<4;
    if (cmdline->pin_management_flag)
        authorization[4] |= 1<<5;
    if (cmdline->install_cert_flag)
        authorization[4] |= 1<<6;
    if (cmdline->install_qual_cert_flag)
        authorization[4] |= 1<<7;
    if (cmdline->read_dg1_flag)
        authorization[3] |= 1<<0;
    if (cmdline->read_dg2_flag)
        authorization[3] |= 1<<1;
    if (cmdline->read_dg3_flag)
        authorization[3] |= 1<<2;
    if (cmdline->read_dg4_flag)
        authorization[3] |= 1<<3;
    if (cmdline->read_dg5_flag)
        authorization[3] |= 1<<4;
    if (cmdline->read_dg6_flag)
        authorization[3] |= 1<<5;
    if (cmdline->read_dg7_flag)
        authorization[3] |= 1<<6;
    if (cmdline->read_dg8_flag)
        authorization[3] |= 1<<7;
    if (cmdline->read_dg9_flag)
        authorization[2] |= 1<<0;
    if (cmdline->read_dg10_flag)
        authorization[2] |= 1<<1;
    if (cmdline->read_dg11_flag)
        authorization[2] |= 1<<2;
    if (cmdline->read_dg12_flag)
        authorization[2] |= 1<<3;
    if (cmdline->read_dg13_flag)
        authorization[2] |= 1<<4;
    if (cmdline->read_dg14_flag)
        authorization[2] |= 1<<5;
    if (cmdline->read_dg15_flag)
        authorization[2] |= 1<<6;
    if (cmdline->read_dg16_flag)
        authorization[2] |= 1<<7;
    if (cmdline->read_dg17_flag)
        authorization[1] |= 1<<0;
    if (cmdline->read_dg18_flag)
        authorization[1] |= 1<<1;
    if (cmdline->read_dg19_flag)
        authorization[1] |= 1<<2;
    if (cmdline->read_dg20_flag)
        authorization[1] |= 1<<3;
    if (cmdline->read_dg21_flag)
        authorization[1] |= 1<<4;
    if (cmdline->at_rfu29_flag)
        authorization[1] |= 1<<5;
    if (cmdline->at_rfu30_flag)
        authorization[1] |= 1<<6;
    if (cmdline->at_rfu31_flag)
        authorization[1] |= 1<<7;
    if (cmdline->at_rfu32_flag)
        authorization[0] |= 1<<0;
    if (cmdline->write_dg21_flag)
        authorization[0] |= 1<<1;
    if (cmdline->write_dg20_flag)
        authorization[0] |= 1<<2;
    if (cmdline->write_dg19_flag)
        authorization[0] |= 1<<3;
    if (cmdline->write_dg18_flag)
        authorization[0] |= 1<<4;
    if (cmdline->write_dg17_flag)
        authorization[0] |= 1<<5;

    out = ASN1_OCTET_STRING_new();
    if (!out || !M_ASN1_OCTET_STRING_set(out,
                authorization, sizeof authorization))
        goto err;

err:
    return out;
}

ASN1_OCTET_STRING *get_is_authorizations(const struct gengetopt_args_info *cmdline)
{
    ASN1_OCTET_STRING *out = NULL;
    unsigned char authorization[EAC_IS_CHAT_BYTES];

    memset(authorization, 0, sizeof authorization);

    if (!cvc_role_set(cmdline, authorization))
        goto err;

    if (cmdline->read_finger_flag)
        authorization[0] |= 1<<0;
    if (cmdline->read_iris_flag)
        authorization[0] |= 1<<1;
    if (cmdline->is_rfu2_flag)
        authorization[0] |= 1<<2;
    if (cmdline->is_rfu3_flag)
        authorization[0] |= 1<<3;
    if (cmdline->is_rfu4_flag)
        authorization[0] |= 1<<4;
    if (cmdline->read_eid_flag)
        authorization[0] |= 1<<5;

    out = ASN1_OCTET_STRING_new();
    if (!out || !M_ASN1_OCTET_STRING_set(out,
                authorization, sizeof authorization))
        goto err;

err:
    return out;
}

ASN1_OCTET_STRING *get_st_authorizations(const struct gengetopt_args_info *cmdline)
{
    ASN1_OCTET_STRING *out = NULL;
    unsigned char authorization[EAC_ST_CHAT_BYTES];

    memset(authorization, 0, sizeof authorization);

    if (!cvc_role_set(cmdline, authorization))
        goto err;

    if (cmdline->gen_sig_flag)
        authorization[0] |= 1<<0;
    if (cmdline->gen_qualified_sig_flag)
        authorization[0] |= 1<<1;
    if (cmdline->st_rfu2_flag)
        authorization[0] |= 1<<2;
    if (cmdline->st_rfu3_flag)
        authorization[0] |= 1<<3;
    if (cmdline->st_rfu4_flag)
        authorization[0] |= 1<<4;
    if (cmdline->st_rfu5_flag)
        authorization[0] |= 1<<5;

    out = ASN1_OCTET_STRING_new();
    if (!out || !M_ASN1_OCTET_STRING_set(out,
                authorization, sizeof authorization))
        goto err;

err:
    return out;
}

static CVC_CHAT *get_chat(const struct gengetopt_args_info *cmdline, CVC_CERT *signer)
{
    CVC_CHAT *chat = NULL;
    int terminal_type = NID_undef;

    if (!cmdline)
        goto err;

    chat = CVC_CHAT_new();
    if (!chat)
        goto err;

    switch (cmdline->type_arg) {
        case type_arg_at:
            terminal_type = NID_id_AT;
            break;
        case type_arg_is:
            terminal_type = NID_id_IS;
            break;
        case type_arg_st:
            terminal_type = NID_id_ST;
            break;
        case type_arg_derived_from_signer:
            if (!signer || !signer->body || !signer->body->chat
                    || !signer->body->chat->terminal_type)
                err("type of signer is missing");
            terminal_type = OBJ_obj2nid(signer->body->chat->terminal_type);
            break;
        default:
            err("unhandled type of terminal");
    }

    switch (terminal_type) {
        case NID_id_AT:
            chat->relative_authorization = get_at_authorizations(cmdline);
            break;
        case NID_id_IS:
            chat->relative_authorization = get_is_authorizations(cmdline);
            break;
        case NID_id_ST:
            chat->relative_authorization = get_st_authorizations(cmdline);
            break;
        default:
            /* TODO implement the rest */
            err("unhandled type of terminal");
    }
    chat->terminal_type = OBJ_nid2obj(terminal_type);
    if (!chat->terminal_type)
        goto err;

err:
    return chat;
}

/* TODO merge with asn1_pubkey */
static int CVC_set_ec_pubkey(const struct gengetopt_args_info *cmdline,
        EC_KEY *ec, CVC_PUBKEY *out)
{
    const EC_GROUP *group;
    int ok = 0;
    BN_CTX *bn_ctx = NULL;
    BIGNUM *a_bn = NULL, *b_bn = NULL, *bn = NULL;
    BUF_MEM *Y_buf = NULL, *G_buf = NULL;

    if (!cmdline || !out || !ec)
        goto err;

    bn_ctx = BN_CTX_new();
    group = EC_KEY_get0_group(ec);
    if (!bn_ctx || !group)
        goto err;
    BN_CTX_start(bn_ctx);

    /* Public point */
    Y_buf = EC_POINT_point2buf(ec, bn_ctx, EC_KEY_get0_public_key(ec));
    out->public_point = ASN1_OCTET_STRING_new();
    if (!Y_buf || !out->public_point ||
            !M_ASN1_OCTET_STRING_set(out->public_point, Y_buf->data,
                Y_buf->length))
        goto err;

    /* If cert is not a CVCA certificate it MUST NOT contain any domain
     * parameters. It only carries the public key. */
    if (cmdline->role_arg == role_arg_cvca) {
        /* If cert is a CVCA certificate it MUST contain all domain parameters. */
        bn = BN_CTX_get(bn_ctx);
        a_bn = BN_CTX_get(bn_ctx);
        b_bn = BN_CTX_get(bn_ctx);
        if (!EC_GROUP_get_curve_GFp(group, bn, a_bn, b_bn, bn_ctx))
            goto err;

        /* Prime modulus */
        out->modulus = BN_to_ASN1_UNSIGNED_INTEGER(bn, out->modulus);

        /* First coefficient */
        out->a = BN_to_ASN1_UNSIGNED_INTEGER(a_bn, out->a);

        /* Second coefficient */
        out->b = BN_to_ASN1_UNSIGNED_INTEGER(b_bn, out->b);

        /* Base Point */
        G_buf = EC_POINT_point2buf(ec, bn_ctx,
                EC_GROUP_get0_generator(group));
        out->base = ASN1_OCTET_STRING_new();
        if (!out->base
                || !M_ASN1_OCTET_STRING_set(
                    out->base, G_buf->data, G_buf->length))
            goto err;

        /* Order of the base point */
        if (!EC_GROUP_get_order(group, bn, bn_ctx))
            goto err;
        out->base_order = BN_to_ASN1_UNSIGNED_INTEGER(bn, out->base_order);

        /* Cofactor */
        if (!EC_GROUP_get_cofactor(group, bn, bn_ctx))
            goto err;
        out->cofactor = BN_to_ASN1_UNSIGNED_INTEGER(bn, out->cofactor);

        if (!out->modulus || !out->a || !out->b || !out->base_order || !out->cofactor)
            goto err;
    }

    ok = 1;

err:
    if (bn)
        BN_free(bn);
    if (a_bn)
        BN_free(a_bn);
    if (b_bn)
        BN_free(b_bn);
    if (Y_buf)
        BUF_MEM_free(Y_buf);
    if (G_buf)
        BUF_MEM_free(G_buf);
    if (bn_ctx)
        BN_CTX_free(bn_ctx);

    return ok;
}

/* TODO merge with asn1_pubkey */
static int CVC_set_rsa_pubkey(RSA *rsa, CVC_PUBKEY *out)
{
    int ok = 0;

    if (!out) {
        goto err;
    }

    out->modulus = BN_to_ASN1_UNSIGNED_INTEGER(rsa->n, out->modulus);
    out->a = BN_to_ASN1_UNSIGNED_INTEGER(rsa->e, out->a);
    /* FIXME what about the public_point ??? */
    if (!out->modulus || !out->a)
        goto err;

    ok = 1;

err:
    return ok;
}

static CVC_PUBKEY *get_cvc_pubkey(const struct gengetopt_args_info *cmdline, EVP_PKEY *key)
{
    CVC_PUBKEY *pubkey = NULL;
    EC_KEY *ec = NULL;
    RSA *rsa = NULL;

    if (!cmdline || !key)
        goto err;

    pubkey = CVC_PUBKEY_new();
    if (!pubkey)
        goto err;

    switch (cmdline->scheme_arg) {
        case scheme_arg_ECDSA_SHA_1:
            pubkey->oid = OBJ_nid2obj(NID_id_TA_ECDSA_SHA_1);
            break;
        case scheme_arg_ECDSA_SHA_224:
            pubkey->oid = OBJ_nid2obj(NID_id_TA_ECDSA_SHA_224);
            break;
        case scheme_arg_ECDSA_SHA_256:
            pubkey->oid = OBJ_nid2obj(NID_id_TA_ECDSA_SHA_256);
            break;
        case scheme_arg_ECDSA_SHA_384:
            pubkey->oid = OBJ_nid2obj(NID_id_TA_ECDSA_SHA_384);
            break;
        case scheme_arg_ECDSA_SHA_512:
            pubkey->oid = OBJ_nid2obj(NID_id_TA_ECDSA_SHA_512);
            break;
        case scheme_arg_RSA_v1_5_SHA_1:
            pubkey->oid = OBJ_nid2obj(NID_id_TA_RSA_v1_5_SHA_1);
            break;
        case scheme_arg_RSA_v1_5_SHA_256:
            pubkey->oid = OBJ_nid2obj(NID_id_TA_RSA_v1_5_SHA_256);
            break;
        case scheme_arg_RSA_v1_5_SHA_512:
            pubkey->oid = OBJ_nid2obj(NID_id_TA_RSA_v1_5_SHA_512);
            break;
        case scheme_arg_RSA_PSS_SHA_1:
            pubkey->oid = OBJ_nid2obj(NID_id_TA_RSA_PSS_SHA_1);
            break;
        case scheme_arg_RSA_PSS_SHA_256:
            pubkey->oid = OBJ_nid2obj(NID_id_TA_RSA_PSS_SHA_256);
            break;
        case scheme_arg_RSA_PSS_SHA_512:
            pubkey->oid = OBJ_nid2obj(NID_id_TA_RSA_PSS_SHA_512);
            break;
        default:
            err("unhandled signature scheme");
    }

    switch (EVP_PKEY_type(key->type)) {
        case EVP_PKEY_EC:
            ec = EVP_PKEY_get1_EC_KEY(key);
            if (!CVC_set_ec_pubkey(cmdline, ec, pubkey))
                goto err;
            break;
        case EVP_PKEY_RSA:
            rsa = EVP_PKEY_get1_RSA(key);
            if (!CVC_set_rsa_pubkey(rsa, pubkey))
                goto err;
            break;
        default:
            err("unhandled type of key");
    }

err:
    if (rsa)
        RSA_free(rsa);
    if (ec)
        EC_KEY_free(ec);

    return pubkey;
}

int to_bcd(char *ascii, unsigned char *out, size_t out_len)
{
    int ok = 0, i;

    if (out_len != strlen(ascii)) {
        err("invalid data given");
    }

    for (i = 0; i < out_len; i++) {
        out[i] = ascii[i] - 0x30;
    }

    ok = 1;

err:
    return ok;
}

#define CVC_CERT_EXT ".cvcert"
#define PKCS8_EXT    ".pkcs8"

int main(int argc, char *argv[])
{
    CVC_CERT *cert = NULL;
    CVC_CERT *sign_as_cert = NULL;
    CVC_CERT_BODY *body = NULL;
    int fail = 1;
    struct gengetopt_args_info cmdline;
    const unsigned char *car = NULL;
    unsigned char *body_p = NULL, *cert_buf = NULL, *term_key_buf = NULL;
    size_t car_len = 0, body_len = 0, cert_len = 0, term_key_len = 0;
    time_t loc;
    const struct tm *utc_tm;
    char string[80];
    BUF_MEM *body_buf = NULL, *signature = NULL;
    EVP_PKEY *signer_key = NULL, *term_key = NULL;
    EVP_PKEY_CTX *term_key_ctx = NULL;
    int signature_scheme = NID_undef;

    EAC_init();

    /* Parse command line */
    if (cmdline_parser (argc, argv, &cmdline) != 0)
        goto err;

    body = CVC_CERT_BODY_new();
    cert = CVC_CERT_new();
    if (!cert || !body)
        goto err;
    cert->body = body;


    /* write profile identifier fixed to 0 ("version 1") */
    body->certificate_profile_identifier = ASN1_INTEGER_new();
    if (!body->certificate_profile_identifier
            || !ASN1_INTEGER_set(body->certificate_profile_identifier, 0))
        goto err;


    /* write CAR */
    if (cmdline.sign_as_given) {
        /* sign as with a different cv certificate */
        sign_as_cert = read_cvc_cert(cmdline.sign_as_arg);
        if (!sign_as_cert)
            goto err;
        car = sign_as_cert->body->certificate_holder_reference->data;
        car_len = sign_as_cert->body->certificate_holder_reference->length;
        signature_scheme = OBJ_obj2nid(sign_as_cert->body->public_key->oid);
    } else {
        /* self signed certificate */
        car = (unsigned char *) cmdline.chr_arg;
        car_len = strlen(cmdline.chr_arg);
        signature_scheme = OBJ_obj2nid(cert->body->public_key->oid);
    }
    body->certificate_authority_reference = ASN1_UTF8STRING_new();
    if (!body->certificate_authority_reference
            || !M_ASN1_OCTET_STRING_set(body->certificate_authority_reference, car, car_len))
        goto err;


    /* write CHR */
    body->certificate_holder_reference = ASN1_UTF8STRING_new();
    if (!body->certificate_holder_reference
            || !M_ASN1_OCTET_STRING_set(body->certificate_holder_reference,
                (unsigned char *) cmdline.chr_arg, strlen(cmdline.chr_arg)))
        goto err;


    /* read signer key */
    signer_key = read_evp_pkey(cmdline.sign_with_arg);
    if (!signer_key)
        goto err;


    /* get terminal's key */
    if (cmdline.key_given) {
        term_key = read_evp_pkey(cmdline.sign_with_arg);
        if (!term_key)
            goto err;
    } else {
        term_key_ctx = EVP_PKEY_CTX_new(signer_key, NULL);
        if (!term_key_ctx
                || !EVP_PKEY_keygen_init(term_key_ctx)
                || !EVP_PKEY_keygen(term_key_ctx, &term_key))
            goto err;

        /* export key */
        term_key_len = i2d_PrivateKey(term_key, &term_key_buf);
        if (term_key_len <= 0)
            goto err;
        memset(string, 0, sizeof string);
        memcpy(string, cert->body->certificate_holder_reference->data,
                cert->body->certificate_holder_reference->length < sizeof string ?
                cert->body->certificate_holder_reference->length : sizeof string);
        if (cert->body->certificate_holder_reference->length + strlen(PKCS8_EXT) > sizeof string) {
            strcat(string + sizeof string - strlen(PKCS8_EXT) - 1, PKCS8_EXT);
        } else {
            strcat(string, PKCS8_EXT);
        }
        if (0 != write_file(string, term_key_buf, term_key_len))
            err("Could not write terminal key");
        printf("Created %s\n", string);
    }


    /* write public key */
    body->public_key = get_cvc_pubkey(&cmdline, term_key);
    if (!body->public_key)
        goto err;


    /* write effective date */
    if (!cmdline.issued_given) {
        time(&loc);
        utc_tm = gmtime(&loc);
        if (!utc_tm || utc_tm->tm_year < 100 || utc_tm->tm_year > 2000
                || utc_tm->tm_mon < 0 || utc_tm->tm_mon > 11
                || utc_tm->tm_mday < 0 || utc_tm->tm_mday > 31)
            goto err;
        string[0] = (char) (utc_tm->tm_year-100)/10;
        string[1] = (char) utc_tm->tm_year%10;
        string[2] = (char) utc_tm->tm_mon/10;
        string[3] = (char) utc_tm->tm_mon%10+1;
        string[4] = (char) utc_tm->tm_mday/10;
        string[5] = (char) utc_tm->tm_mday%10;
    } else {
        if (!to_bcd(cmdline.issued_arg, (unsigned char *) string, 6))
            goto err;
    }
    body->certificate_effective_date = ASN1_OCTET_STRING_new();
    if (!body->certificate_effective_date
            || !M_ASN1_OCTET_STRING_set(body->certificate_effective_date,
                (unsigned char *) string, 6))
        goto err;


    /* write expiration date */
    body->certificate_expiration_date = ASN1_OCTET_STRING_new();
    if (!body->certificate_expiration_date
            || !to_bcd(cmdline.expires_arg, (unsigned char *) string, 6)
            || !M_ASN1_OCTET_STRING_set(body->certificate_expiration_date,
                (unsigned char *) string, 6))
        goto err;


    /* write chat */
    body->chat = get_chat(&cmdline, sign_as_cert);
    if (!body->chat)
        goto err;


    /* sign body */
    body_len = i2d_CVC_CERT_BODY(body, &body_p);
    if (body_len <= 0)
        goto err;
    body_buf = BUF_MEM_create_init(body_p, (size_t) body_len);
    signature = EAC_sign(signature_scheme, signer_key, body_buf);
    if (!signature)
        goto err;


    /* assamble everything */
    cert->signature = ASN1_OCTET_STRING_new();
    if (!cert->signature
            || !M_ASN1_OCTET_STRING_set(cert->signature,
                signature->data, signature->length))
        goto err;

    /* write certificate */
    cert_len = i2d_CVC_CERT(cert, &cert_buf);
    if (cert_len <= 0)
        goto err;
    memset(string, 0, sizeof string);
    memcpy(string, cert->body->certificate_holder_reference->data,
            cert->body->certificate_holder_reference->length < sizeof string ?
            cert->body->certificate_holder_reference->length : sizeof string);
    if (cert->body->certificate_holder_reference->length + strlen(CVC_CERT_EXT) > sizeof string) {
        strcat(string + sizeof string - strlen(CVC_CERT_EXT) - 1, CVC_CERT_EXT);
    } else {
        strcat(string, CVC_CERT_EXT);
    }
    if (0 != write_file(string, cert_buf, cert_len))
        err("Could not write certificate");
    printf("Created %s\n", string);


    fail = 0;

err:
    if (cert) {
        CVC_CERT_free(cert);
    } else {
        if (body)
            CVC_CERT_BODY_free(body);
    }
    if (sign_as_cert)
        CVC_CERT_free(sign_as_cert);
    free(cert_buf);
    free(body_p);
    free(term_key_buf);
    if (body_buf)
        BUF_MEM_free(body_buf);
    if (signature)
        BUF_MEM_free(signature);
    if (signer_key)
        EVP_PKEY_free(signer_key);
    if (term_key)
        EVP_PKEY_free(term_key);
    if (term_key_ctx)
        EVP_PKEY_CTX_free(term_key_ctx);

    EAC_cleanup();

    return fail;
}
