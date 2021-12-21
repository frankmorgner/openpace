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
 * @file cvc-create.c
 * @brief Create Card Verifiable Certificates and their Description
 *
 * @author Frank Morgner <frankmorgner@gmail.com>
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "cvc-create-cmdline.h"
#include "eac_asn1.h"
#include "eac_util.h"
#include "misc.h"
#include "read_file.h"
#include "ssl_compat.h"
#include <eac/eac.h>
#include <eac/cv_cert.h>
#include <eac/objects.h>
#include <openssl/asn1.h>
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

static CVC_CERT_REQUEST *read_request(const char *filename)
{
    unsigned char *request = NULL;
    const unsigned char *p;
    size_t request_len = 0;
    CVC_CERT_REQUEST *cvc_request = NULL;

    if (0 != read_file(filename, &request, &request_len)) {
        goto err;
    }

    p = request;
    if (!d2i_CVC_CERT_REQUEST(&cvc_request, &p, request_len))
        goto err;

err:
    free(request);

    return cvc_request;
}

static CVC_CERT_AUTHENTICATION_REQUEST *read_authentication(const char *filename)
{
    unsigned char *authentication = NULL;
    const unsigned char *p;
    size_t authentication_len = 0;
    CVC_CERT_AUTHENTICATION_REQUEST *cvc_authentication = NULL;

    if (0 != read_file(filename, &authentication, &authentication_len)) {
        goto err;
    }

    p = authentication;
    if (!d2i_CVC_CERT_AUTHENTICATION_REQUEST(&cvc_authentication, &p, authentication_len))
        goto err;

err:
    free(authentication);

    return cvc_authentication;
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
    if (!out || !ASN1_OCTET_STRING_set(out,
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
    if (!out || !ASN1_OCTET_STRING_set(out,
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
    if (!out || !ASN1_OCTET_STRING_set(out,
                authorization, sizeof authorization))
        goto err;

err:
    return out;
}

ASN1_OCTET_STRING *get_raw_authorizations(const struct gengetopt_args_info *cmdline)
{
    int ok = 0;
    size_t i, hex_len, binary_len;
    unsigned char *binary = NULL;
    char *hex = cmdline->chat_arg;
    ASN1_OCTET_STRING *out = NULL;

    hex_len = strlen(hex);
    if (hex_len % 2) {
        err("hex string needs even number of bytes");
    }
    binary_len = hex_len / 2;

    binary = calloc(sizeof *binary, binary_len);
    if (!binary)
        goto err;

    for (i = 0; i < hex_len; i++) {
        char c = *hex;
        if (c == 0)
            break;
        if ((c >= '0') && (c <= '9'))
            c -= '0';
        else if ((c >= 'A') && (c <= 'F'))
            c = c - 'A' + 10;
        else if ((c >= 'a') && (c <= 'f'))
            c = c - 'a' + 10;
        else {
            err("non-hex digit");
        }
        if (i & 1)
            binary[i / 2] |= c;
        else
            binary[i / 2] = (c << 4);
        hex++;
    }

    out = ASN1_OCTET_STRING_new();
    if (!out || !ASN1_OCTET_STRING_set(out,
                binary, binary_len))
        goto err;

err:
    free(binary);

    return out;
}

static CVC_CHAT *get_chat(const struct gengetopt_args_info *cmdline, CVC_CERT *signer)
{
    CVC_CHAT *chat = NULL;
    int terminal_type = NID_undef;
    size_t type_arg_len;

    if (!cmdline)
        goto err;
    type_arg_len = strlen(cmdline->type_arg);

    chat = CVC_CHAT_new();
    if (!chat)
        goto err;

    if (strlen("at") == type_arg_len
            && 0 == strcmp(cmdline->type_arg, "at")) {
        terminal_type = NID_id_AT;
        chat->terminal_type = EAC_OBJ_nid2obj(NID_id_AT);
    } else if (strlen("is") == type_arg_len
            && 0 == strcmp(cmdline->type_arg, "is")) {
            terminal_type = NID_id_IS;
            chat->terminal_type = EAC_OBJ_nid2obj(NID_id_IS);
    } else if (strlen("st") == type_arg_len
            && 0 == strcmp(cmdline->type_arg, "st")) {
            terminal_type = NID_id_ST;
            chat->terminal_type = EAC_OBJ_nid2obj(NID_id_ST);
    } else if (strlen("derived_from_signer") == type_arg_len
            && 0 == strcmp(cmdline->type_arg, "derived_from_signer")) {
        if (!signer || !signer->body || !signer->body->chat
                || !signer->body->chat->terminal_type)
            err("type of signer is missing");
        terminal_type = EAC_OBJ_obj2nid(signer->body->chat->terminal_type);
        chat->terminal_type = OBJ_dup(signer->body->chat->terminal_type);
    } else {
        terminal_type = EAC_OBJ_txt2nid(cmdline->type_arg);
        chat->terminal_type = EAC_OBJ_txt2obj(cmdline->type_arg, 0);
    }

    if (chat->relative_authorization)
        ASN1_OCTET_STRING_free(chat->relative_authorization);

    if        (terminal_type == NID_id_AT) {
        chat->relative_authorization = get_at_authorizations(cmdline);
    } else if (terminal_type == NID_id_IS) {
        chat->relative_authorization = get_is_authorizations(cmdline);
    } else if (terminal_type == NID_id_ST) {
        chat->relative_authorization = get_st_authorizations(cmdline);
    }

    if (cmdline->chat_arg) {
        if (chat->relative_authorization) {
            ASN1_OCTET_STRING_free(chat->relative_authorization);
            chat->relative_authorization = get_raw_authorizations(cmdline);
        }
    }


err:
    return chat;
}

static CVC_PUBKEY *get_cvc_pubkey(const struct gengetopt_args_info *cmdline,
        EVP_PKEY *key)
{
    CVC_PUBKEY *pubkey = NULL;
    int protocol;

    if (!cmdline)
        goto err;

    switch (cmdline->scheme_arg) {
        case scheme_arg_ECDSA_SHA_1:
            protocol = NID_id_TA_ECDSA_SHA_1;
            break;
        case scheme_arg_ECDSA_SHA_224:
            protocol = NID_id_TA_ECDSA_SHA_224;
            break;
        case scheme_arg_ECDSA_SHA_256:
            protocol = NID_id_TA_ECDSA_SHA_256;
            break;
        case scheme_arg_ECDSA_SHA_384:
            protocol = NID_id_TA_ECDSA_SHA_384;
            break;
        case scheme_arg_ECDSA_SHA_512:
            protocol = NID_id_TA_ECDSA_SHA_512;
            break;
        case scheme_arg_RSA_v1_5_SHA_1:
            protocol = NID_id_TA_RSA_v1_5_SHA_1;
            break;
        case scheme_arg_RSA_v1_5_SHA_256:
            protocol = NID_id_TA_RSA_v1_5_SHA_256;
            break;
        case scheme_arg_RSA_v1_5_SHA_512:
            protocol = NID_id_TA_RSA_v1_5_SHA_512;
            break;
        case scheme_arg_RSA_PSS_SHA_1:
            protocol = NID_id_TA_RSA_PSS_SHA_1;
            break;
        case scheme_arg_RSA_PSS_SHA_256:
            protocol = NID_id_TA_RSA_PSS_SHA_256;
            break;
        case scheme_arg_RSA_PSS_SHA_512:
            protocol = NID_id_TA_RSA_PSS_SHA_512;
            break;
        default:
            err("unhandled signature scheme");
    }
    pubkey = CVC_pkey2pubkey(cmdline->role_arg == role_arg_cvca ? 1 : 0,
            protocol, key, NULL, NULL);

err:
    return pubkey;
}

int to_bcd(char *ascii, unsigned char *out, size_t out_len)
{
    int ok = 0;
    size_t i;

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

#define TXT_EXT    ".txt"
#define HTML_EXT    ".html"
#define PDF_EXT    ".pdf"

CVC_CERTIFICATE_DESCRIPTION *create_certificate_description(const struct gengetopt_args_info *cmdline)
{
    CVC_CERTIFICATE_DESCRIPTION *desc = NULL;
    const char *ext = NULL;
    unsigned char *desc_data = NULL;
    size_t len = 0, ext_len = 0, desc_data_len = 0;
    int desc_type = NID_undef;

    if (cmdline->cert_desc_arg) {
        len = strlen(cmdline->cert_desc_arg);
        ext_len = strlen(TXT_EXT);
        ext = cmdline->cert_desc_arg+len-ext_len;
        if (len > ext_len && strcmp(ext, TXT_EXT) == 0) {
            desc_type = NID_id_plainFormat;
        } else {
            ext_len = strlen(HTML_EXT);
            ext = cmdline->cert_desc_arg+len-ext_len;
            if (len > ext_len && strcmp(ext, HTML_EXT) == 0) {
                desc_type = NID_id_htmlFormat;
            } else {
                ext_len = strlen(PDF_EXT);
                ext = cmdline->cert_desc_arg+len-ext_len;
                if (len > ext_len && strcmp(ext, PDF_EXT) == 0) {
                    desc_type = NID_id_pdfFormat;
                } else {
                    err("unknown type of certificate description");
                }
            }
        }
        desc = CVC_CERTIFICATE_DESCRIPTION_new();
        if (!desc)
            goto err;
        desc->descriptionType = EAC_OBJ_nid2obj(desc_type);

        if (0 != read_file(cmdline->cert_desc_arg, &desc_data, &desc_data_len)) {
            goto err;
        }
        desc->termsOfUsage = ASN1_OCTET_STRING_new();
        if (!desc->termsOfUsage || !ASN1_OCTET_STRING_set(
                    desc->termsOfUsage, desc_data, desc_data_len))
            goto err;

        if (cmdline->issuer_name_arg) {
            if (!desc->issuerName)
                desc->issuerName = ASN1_UTF8STRING_new();
            if (!desc->issuerName
                    || !ASN1_OCTET_STRING_set(desc->issuerName,
                         (const unsigned char *) cmdline->issuer_name_arg,
                         strlen(cmdline->issuer_name_arg)))
                goto err;
        }

        if (cmdline->issuer_url_arg) {
            desc->issuerURL = ASN1_PRINTABLESTRING_new();
            if (!desc->issuerURL
                    || !ASN1_OCTET_STRING_set(desc->issuerURL,
                         (const unsigned char *) cmdline->issuer_url_arg,
                         strlen(cmdline->issuer_url_arg)))
                goto err;
        }

        if (cmdline->subject_name_arg) {
            desc->subjectName = ASN1_UTF8STRING_new();
            if (!desc->subjectName
                    || !ASN1_OCTET_STRING_set(desc->subjectName,
                         (const unsigned char *) cmdline->subject_name_arg,
                         strlen(cmdline->subject_name_arg)))
                goto err;
        }

        if (cmdline->subject_url_arg) {
            desc->subjectURL = ASN1_PRINTABLESTRING_new();
            if (!desc->subjectURL
                    || !ASN1_OCTET_STRING_set(desc->subjectURL,
                         (const unsigned char *) cmdline->subject_url_arg,
                         strlen(cmdline->subject_url_arg)))
                goto err;
        }
    }

err:
    free(desc_data);

    return desc;
}

#define CVC_CERT_EXT ".cvcert"
#define PKCS8_EXT    ".pkcs8"
#define DESC_EXT    ".desc"

int main(int argc, char *argv[])
{
    CVC_CERT *cert = NULL;
    CVC_CERT *sign_as_cert = NULL;
    CVC_CERTIFICATE_DESCRIPTION *desc = NULL;
    CVC_CERT_REQUEST *request = NULL;
    CVC_CERT_AUTHENTICATION_REQUEST *authentication = NULL;
    CVC_DISCRETIONARY_DATA_TEMPLATE *template = NULL;
    int fail = 1, body_len = 0, desc_buf_len = 0, term_key_len = 0;
    struct gengetopt_args_info cmdline;
    const unsigned char *car = NULL;
    unsigned char *body_p = NULL, *cert_buf = NULL, *term_key_buf = NULL, *desc_buf = NULL;
    size_t car_len = 0, cert_len = 0;
    time_t loc;
    struct tm utc_tm;
    char string[80];
    const char *out = NULL;
    char basename[70];
    BUF_MEM *body_buf = NULL, *signature = NULL, *desc_hash = NULL;
    EVP_PKEY *signer_key = NULL, *term_key = NULL;
    EVP_PKEY_CTX *term_key_ctx = NULL;

    EAC_init();

    /* Parse command line */
    if (cmdline_parser (argc, argv, &cmdline) != 0) {
        return 1;
    }

    cert = CVC_CERT_new();
    if (!cert)
        goto err;
    if (!cert->body) {
        cert->body = CVC_CERT_BODY_new();
        if (!cert->body)
            goto err;
    }


    /* read certificate signing request */
    if (cmdline.csr_given) {
        request = read_request(cmdline.csr_arg);
        if (!request) {
            authentication = read_authentication(cmdline.csr_arg);
            if (!authentication)
                err("could not parse certificate request");
            request = authentication->request;
        }
    }
    if (!cmdline.manual_mode_counter
            && (!request || !request->body))
        err("bad format of certificate request");


    /* write profile identifier fixed to 0 ("version 1") */
    if (!cert->body->certificate_profile_identifier)
        cert->body->certificate_profile_identifier = ASN1_INTEGER_new();
    if (!cert->body->certificate_profile_identifier
            || !ASN1_INTEGER_set(cert->body->certificate_profile_identifier, 0))
        goto err;


    if (cmdline.manual_mode_counter
            || !request->body->certificate_authority_reference) {
        /* write CAR */
        if (cmdline.sign_as_given) {
            /* sign as with a different cv certificate */
            sign_as_cert = read_cvc_cert(cmdline.sign_as_arg);
            if (!sign_as_cert)
                goto err;
            car = sign_as_cert->body->certificate_holder_reference->data;
            car_len = sign_as_cert->body->certificate_holder_reference->length;
        } else {
            /* self signed certificate */
            if (cmdline.manual_mode_counter) {
                car = (unsigned char *) cmdline.chr_arg;
                car_len = strlen(cmdline.chr_arg);
            } else {
                car = request->body->certificate_holder_reference->data;
                car_len = request->body->certificate_holder_reference->length;
            }
        }
        if (!cert->body->certificate_authority_reference)
            cert->body->certificate_authority_reference = ASN1_UTF8STRING_new();
        if (!cert->body->certificate_authority_reference
                || !ASN1_OCTET_STRING_set(cert->body->certificate_authority_reference, car, car_len))
            goto err;
    } else {
        cert->body->certificate_authority_reference = (ASN1_UTF8STRING *) ASN1_STRING_dup((ASN1_STRING *) request->body->certificate_authority_reference);
        if (!cert->body->certificate_authority_reference)
            goto err;
    }


    /* write CHR */
    if (cmdline.manual_mode_counter) {
        if (!cert->body->certificate_holder_reference)
            cert->body->certificate_holder_reference = ASN1_UTF8STRING_new();
        if (!cert->body->certificate_holder_reference
                || !ASN1_OCTET_STRING_set(cert->body->certificate_holder_reference,
                    (unsigned char *) cmdline.chr_arg, strlen(cmdline.chr_arg)))
            goto err;
        strncpy(basename, cmdline.chr_arg, (sizeof basename) - 1);
        basename[sizeof basename - 1] = '\0';
    } else {
        cert->body->certificate_holder_reference = (ASN1_UTF8STRING *) ASN1_STRING_dup((ASN1_STRING *) request->body->certificate_holder_reference);
        if (!cert->body->certificate_holder_reference)
            goto err;
        memcpy(basename, (char *) request->body->certificate_holder_reference->data,
                sizeof basename < request->body->certificate_holder_reference->length ?
                sizeof basename : request->body->certificate_holder_reference->length);
        basename[
            sizeof basename - 1 < request->body->certificate_holder_reference->length ?
            sizeof basename - 1 : request->body->certificate_holder_reference->length] = '\0';
    }


    /* read signer key */
    signer_key = read_evp_pkey(cmdline.sign_with_arg);
    if (!signer_key)
        goto err;


    /* get terminal's key */
    if (cmdline.manual_mode_counter) {
        if (cmdline.key_given) {
            term_key = read_evp_pkey(cmdline.key_arg);
            if (!term_key)
                goto err;
        } else {
            if (cmdline.sign_as_given) {
                term_key_ctx = EVP_PKEY_CTX_new(signer_key, NULL);
                if (!term_key_ctx
                        || !EVP_PKEY_keygen_init(term_key_ctx))
                    goto err;
                if (EVP_PKEY_base_id(signer_key) == EVP_PKEY_RSA) {
                    /* RSA keys set the key length during key generation
                     * rather than parameter generation! */
                    if (!EVP_PKEY_CTX_set_rsa_keygen_bits(term_key_ctx,
                                EVP_PKEY_bits(signer_key)))
                        goto err;
                }
                if (!EVP_PKEY_keygen(term_key_ctx, &term_key))
                    goto err;

                /* export key */
                term_key_len = i2d_PrivateKey(term_key, &term_key_buf);
                if (term_key_len <= 0)
                    goto err;
                if (!cmdline.out_key_given) {
                    strcpy(string, basename);
                    strcat(string, PKCS8_EXT);
                    out = string;
                } else {
                    out = cmdline.out_key_arg;
                }
                if (0 != write_file(out, term_key_buf, term_key_len))
                    err("Could not write terminal key");
                printf("Created %s\n", out);
            } else {
                /* self signed certificate */
                term_key = EVP_PKEY_dup(signer_key);
            }
        }


        /* write public key */
        if (cert->body->public_key)
            CVC_PUBKEY_free(cert->body->public_key);
        cert->body->public_key = get_cvc_pubkey(&cmdline, term_key);
    } else {
        /* write public key */
        if (cert->body->public_key)
            CVC_PUBKEY_free(cert->body->public_key);
        if (cmdline.role_arg == role_arg_cvca) {
            cert->body->public_key = CVC_PUBKEY_dup(request->body->public_key);
        } else {
            int nid = EAC_OBJ_obj2nid(request->body->public_key->oid);
            if (       nid == NID_id_TA_ECDSA_SHA_1
                    || nid == NID_id_TA_ECDSA_SHA_224
                    || nid == NID_id_TA_ECDSA_SHA_256
                    || nid == NID_id_TA_ECDSA_SHA_384
                    || nid == NID_id_TA_ECDSA_SHA_512) {
                cert->body->public_key = CVC_PUBKEY_new();
                if (!cert->body->public_key)
                    goto err;
                /* copy only the public key without explicit parameters */
                cert->body->public_key->oid = OBJ_dup(request->body->public_key->oid);
                cert->body->public_key->cont6 = ASN1_OCTET_STRING_dup(request->body->public_key->cont6);
                if (!cert->body->public_key->oid
                        || !cert->body->public_key->cont6)
                    goto err;
            } else if (nid == NID_id_TA_RSA_v1_5_SHA_1
                    || nid == NID_id_TA_RSA_v1_5_SHA_256
                    || nid == NID_id_TA_RSA_v1_5_SHA_512
                    || nid == NID_id_TA_RSA_PSS_SHA_1
                    || nid == NID_id_TA_RSA_PSS_SHA_256
                    || nid == NID_id_TA_RSA_PSS_SHA_512) {
                /* copy only the public key without explicit parameters */
                cert->body->public_key->oid = OBJ_dup(request->body->public_key->oid);
                cert->body->public_key->cont1 = ASN1_OCTET_STRING_dup(request->body->public_key->cont1);
                cert->body->public_key->cont2 = ASN1_OCTET_STRING_dup(request->body->public_key->cont2);
                if (!cert->body->public_key->oid
                        || !cert->body->public_key->cont1
                        || !cert->body->public_key->cont2)
                    goto err;
            } else {
                /* unknown mechanism, just copy everything */
                cert->body->public_key = CVC_PUBKEY_dup(request->body->public_key);
            }
        }
    }
    if (!cert->body->public_key)
        goto err;


    /* write effective date */
    if (!cmdline.issued_given) {
        time(&loc);
#ifdef _WIN32
		if (0 != gmtime_s(&utc_tm, &loc))
			goto err;
#else
		if (NULL == gmtime_r(&loc, &utc_tm))
			goto err;
#endif
        if (utc_tm.tm_year < 100 || utc_tm.tm_year > 2000
                || utc_tm.tm_mon < 0 || utc_tm.tm_mon > 11
                || utc_tm.tm_mday < 0 || utc_tm.tm_mday > 31)
            goto err;
        string[0] = (char) (utc_tm.tm_year-100)/10;
        string[1] = (char) utc_tm.tm_year%10;
        string[2] = (char) (utc_tm.tm_mon+1)/10;
        string[3] = (char) (utc_tm.tm_mon+1)%10;
        string[4] = (char) utc_tm.tm_mday/10;
        string[5] = (char) utc_tm.tm_mday%10;
    } else {
        if (!to_bcd(cmdline.issued_arg, (unsigned char *) string, 6))
            goto err;
    }
    if (!cert->body->certificate_effective_date)
        cert->body->certificate_effective_date = ASN1_OCTET_STRING_new();
    if (!cert->body->certificate_effective_date
            || !ASN1_OCTET_STRING_set(cert->body->certificate_effective_date,
                (unsigned char *) string, 6))
        goto err;


    /* write expiration date */
    if (!cert->body->certificate_expiration_date)
        cert->body->certificate_expiration_date = ASN1_OCTET_STRING_new();
    if (!cert->body->certificate_expiration_date
            || !to_bcd(cmdline.expires_arg, (unsigned char *) string, 6)
            || !ASN1_OCTET_STRING_set(cert->body->certificate_expiration_date,
                (unsigned char *) string, 6))
        goto err;


    /* write chat */
    if (cert->body->chat)
        CVC_CHAT_free(cert->body->chat);
    cert->body->chat = get_chat(&cmdline, sign_as_cert);
    if (!cert->body->chat)
        goto err;


    /* write certificate description */
    desc = create_certificate_description(&cmdline);
    if (desc) {
        desc_buf_len = i2d_CVC_CERTIFICATE_DESCRIPTION(desc, &desc_buf);
        if (desc_buf_len <= 0)
            goto err;
        desc_hash = CVC_hash_description(cert, desc_buf, desc_buf_len);
        if (!cert->body->certificate_extensions)
            cert->body->certificate_extensions = (void *) sk_new_null();
        template = CVC_DISCRETIONARY_DATA_TEMPLATE_new();
        if (!desc_hash || !cert->body->certificate_extensions || !template)
            goto err;
        template->type = EAC_OBJ_nid2obj(NID_id_description);
        template->discretionary_data1 = ASN1_OCTET_STRING_new();
        if (!template->type || !template->discretionary_data1
                || !ASN1_OCTET_STRING_set(template->discretionary_data1,
                    (unsigned char *) desc_hash->data, desc_hash->length)
                || !sk_push((_STACK *) cert->body->certificate_extensions, template))
            goto err;
        if (!cmdline.out_desc_given) {
            strcpy(string, basename);
            strcat(string, DESC_EXT);
            out = string;
        } else {
            out = cmdline.out_desc_arg;
        }
        if (0 != write_file(out, desc_buf, desc_buf_len))
            err("Could not write certificate description");
        printf("Created %s\n", out);
    }


    /* sign body */
    body_len = i2d_CVC_CERT_BODY(cert->body, &body_p);
    if (body_len <= 0)
        goto err;
    body_buf = BUF_MEM_create_init(body_p, (size_t) body_len);
    if (cmdline.sign_as_given) {
        if (!sign_as_cert)
            err("no valid certificate found");
        signature = EAC_sign(EAC_OBJ_obj2nid(sign_as_cert->body->public_key->oid),
                signer_key, body_buf);
    } else {
        signature = EAC_sign(EAC_OBJ_obj2nid(cert->body->public_key->oid),
                signer_key, body_buf);
    }
    if (!signature)
        goto err;


    /* assamble everything */
    if (!cert->signature)
        cert->signature = ASN1_OCTET_STRING_new();
    if (!cert->signature
            || !ASN1_OCTET_STRING_set(cert->signature,
                (unsigned char *) signature->data, signature->length))
        goto err;

    /* write certificate */
    cert_len = i2d_CVC_CERT(cert, &cert_buf);
    if (cert_len <= 0)
        goto err;
    if (!cmdline.out_cert_given) {
        strcpy(string, basename);
        strcat(string, CVC_CERT_EXT);
        out = string;
    } else {
        out = cmdline.out_cert_arg;
    }
    if (0 != write_file(out, cert_buf, cert_len))
        err("Could not write certificate");
    printf("Created %s\n", out);


    fail = 0;

err:
    cmdline_parser_free (&cmdline);
    if (cert) {
        CVC_CERT_free(cert);
    }
    if (sign_as_cert)
        CVC_CERT_free(sign_as_cert);
    OPENSSL_free(cert_buf);
    OPENSSL_free(body_p);
    OPENSSL_free(term_key_buf);
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
    if (desc)
        CVC_CERTIFICATE_DESCRIPTION_free(desc);
    if (authentication) {
        CVC_CERT_AUTHENTICATION_REQUEST_free(authentication);
        request = NULL;
    }
    if (request)
        CVC_CERT_REQUEST_free(request);
    OPENSSL_free(desc_buf);
    if (desc_hash)
        BUF_MEM_free(desc_hash);

    EAC_cleanup();

    return fail;
}
