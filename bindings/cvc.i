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

%{
#include <eac/cv_cert.h>
#include <openssl/bio.h>
#include <stdlib.h>
#include <string.h>
%}

%newobject CVC_CERT_new;
CVC_CERT *
CVC_CERT_new(void);

%delobject CVC_CERT_free;
void
CVC_CERT_free(CVC_CERT *a);

%newobject CVC_CERT_dup;
CVC_CERT *
CVC_CERT_dup(CVC_CERT *x)
{
    ASN1_dup_of(CVC_CERT, i2d_CVC_CERT, CVC_d2i_CVC_CERT, x);
}

short
CVC_get_profile_identifier(const CVC_CERT *cert);

%newobject CVC_get_car;
char *
CVC_get_car(const CVC_CERT *cert);

%newobject CVC_get_chr;
char *
CVC_get_chr(const CVC_CERT *cert);

%newobject CVC_get_effective_date;
char *
CVC_get_effective_date(const CVC_CERT *cert);

%newobject CVC_get_expiration_date;
char *
CVC_get_expiration_date(const CVC_CERT *cert);

%newobject CVC_CERTIFICATE_DESCRIPTION_new;
CVC_CERTIFICATE_DESCRIPTION *
CVC_CERTIFICATE_DESCRIPTION_new(void);

%delobject CVC_CERTIFICATE_DESCRIPTION_free;
void
CVC_CERTIFICATE_DESCRIPTION_free(CVC_CERTIFICATE_DESCRIPTION *a);

%rename (cvc_chat_print) CVC_CHAT_PRINT;
%inline %{
    static void CVC_CHAT_PRINT(CVC_CHAT *chat, int indent) {
        BIO *bio_stdout = BIO_new_fp(stdout, BIO_NOCLOSE);
        if (!bio_stdout)
            return;
        cvc_chat_print(bio_stdout, chat, indent);
        BIO_free_all(bio_stdout);
    }
%}

#if !defined(SWIG_CSTRING_UNIMPL) || defined(SWIGGO) || defined(SWIGJAVA)

%begin %{
#define SWIG_PYTHON_STRICT_BYTE_CHAR
%}

%newobject CVC_d2i_CVC_CERT;
%rename (CVC_d2i_CVC_CERT) cvc_d2i_cvc_cert;
%inline %{ /* typemap applied */
    static CVC_CERT *cvc_d2i_cvc_cert(char *in, size_t in_len) {
        CVC_CERT *cvc = NULL;
        const unsigned char **p = (const unsigned char **) &in;
        cvc = CVC_d2i_CVC_CERT(NULL, p, in_len);
        return cvc;
    }
%}

%newobject d2i_CVC_CERTIFICATE_DESCRIPTION;
%rename (d2i_CVC_CERTIFICATE_DESCRIPTION) d2i_cvc_certificate_description;
%inline %{ /* typemap applied */
    static CVC_CERTIFICATE_DESCRIPTION *d2i_cvc_certificate_description(char *in, size_t in_len) {
        CVC_CERTIFICATE_DESCRIPTION *description = NULL;
        const unsigned char **p = (const unsigned char **) &in;
        description = d2i_CVC_CERTIFICATE_DESCRIPTION(NULL, p, in_len);
        return description;
    }
%}

#if !defined(SWIGGO) && !defined(SWIGJAVA)

%inline %{
    static void get_termsOfUsage(CVC_CERTIFICATE_DESCRIPTION *desc, char **out,
            size_t *out_len) {
    
        *out = NULL;
        *out_len = 0;

        if (!desc)
            goto err;

        /* TODO check for OID */
        if (!desc->termsOfUsage) {
            goto err;
        }

        *out = (char *) malloc(desc->termsOfUsage->length);
        if (!*out)
            goto err;
        *out_len = desc->termsOfUsage->length;
        memcpy(*out, desc->termsOfUsage->data, *out_len);

err:
        /* need to have something behind a label */
        ;
    }
%}

%inline %{
    static void get_issuer_name(char **out, size_t *out_len, CVC_CERTIFICATE_DESCRIPTION *desc) {
        if (!desc || !desc->issuerName)
            return;

        *out_len = desc->issuerName->length;
        *out = (char *) malloc (*out_len);
        if (!*out)
            return;

        memcpy(*out, desc->issuerName->data, *out_len);
        return;
    }
%}

%inline %{
    static void get_subject_name(char **out, size_t *out_len, CVC_CERTIFICATE_DESCRIPTION *desc) {
        if (!desc || !desc->issuerName)
            return;

        *out_len = desc->subjectName->length;
        *out = (char *) malloc (*out_len);
        if (!*out)
            return;

        memcpy(*out, desc->subjectName->data, *out_len);
        return;
    }
%}

%inline %{
    static void get_subject_url(char **out, size_t *out_len, CVC_CERTIFICATE_DESCRIPTION *desc) {
        if (!desc || !desc->subjectURL)
            return;

        *out_len = desc->subjectURL->length;
        *out = (char *) malloc (*out_len);
        if (!*out)
            return;

        memcpy(*out, desc->subjectURL->data, *out_len);
        return;
    }
%}

%inline %{
    static void get_issuer_url(char **out, size_t *out_len, CVC_CERTIFICATE_DESCRIPTION *desc) {
        if (!desc || !desc->issuerURL)
            return;

        *out_len = desc->issuerURL->length;
        *out = (char *) malloc (*out_len);
        if (!*out)
            return;

        memcpy(*out, desc->issuerURL->data, *out_len);
        return;
    }
%}

#endif

%begin %{
#define SWIG_PYTHON_STRICT_BYTE_CHAR
%}

%newobject d2i_CVC_CHAT;
%rename (d2i_CVC_CHAT) d2i_cvc_chat;
%inline %{ /* typemap applied */
    static CVC_CHAT *d2i_cvc_chat(char *in, size_t in_len) {
        CVC_CHAT *chat = NULL;
        const unsigned char **p = (const unsigned char **) &in;
        chat = d2i_CVC_CHAT(NULL, p, (long) in_len);
        return chat;
    }
%}

%inline %{
    static void print_binary_chat(char *in, size_t in_len) {
        CVC_CHAT *chat = NULL;
        const unsigned char **p;

        if (!in || (in_len <= 0))
            return;

        p = (const unsigned char**)&in;

        /* Convert string to CHAT structure */
        chat = d2i_CVC_CHAT(NULL, p, in_len);
        if (!chat)
            return;

        /* Print CHAT structure */
        CVC_CHAT_PRINT(chat, 0);

        /* Free memory */
        OPENSSL_free(chat);
        return;
    }
%}

%rename (i2d_CVC_CHAT) i2d_cvc_chat;
%inline %{ /* typemap applied */
    void i2d_cvc_chat(CVC_CHAT *chat, char **out, size_t *out_len) {
        unsigned char *tmp;
        int new_len;

        if (!chat)
            return;

        new_len = i2d_CVC_CHAT(chat, NULL);
        if (new_len < 0) {
            *out_len = 0;
            return;
        }
        *out = (char *) malloc(new_len);
        if (!*out)
            return;

        tmp = (unsigned char *) *out;
        *out_len = i2d_CVC_CHAT(chat, &tmp);
        return;
    }
%}

%inline %{
    static void get_binary_chat(CVC_CHAT *chat, char **out, size_t *out_len) {

        if (!chat || !chat->relative_authorization) {
            /* Return a NULL pointer on error */
            *out = NULL;
            *out_len = 0;
            return;
        }

        *out_len = chat->relative_authorization->length;
        *out = (char *) malloc(*out_len);
        memcpy(*out, chat->relative_authorization->data, *out_len);
        return;

    }
%}

%inline %{
    static void get_chat_role(CVC_CHAT *chat, char **out, size_t *out_len) {
        int role = 0;

        if (!chat || !out || !out_len)
            goto err;

        role = CVC_get_role(chat);
        switch(role) {
            case CVC_Terminal:
                *out_len = 21;
                *out = (char *) malloc(*out_len);
                if (!*out)
                    goto err;
                strncpy(*out, "Terminal certificate", *out_len);
                break;
            case CVC_DV:
                *out_len = 15;
                *out = (char *) malloc(*out_len);
                if (!*out)
                    goto err;
                strncpy(*out, "DV certificate", *out_len);
                break;
            case CVC_DocVer:
                *out_len = 15;
                *out = (char *) malloc(*out_len);
                if (!*out)
                    goto err;
                strncpy(*out, "DV certificate", *out_len);
                break;
            case CVC_CVCA:
                *out_len = 17;
                *out = (char *) malloc(*out_len);
                if (!*out)
                    goto err;
                strncpy(*out, "CVCA certificate", *out_len);
                break;
            default:
                goto err;
        }

        return;

    err:
        if (out) {
            free(*out);
            *out = NULL;
        }
        if (out_len)
            *out_len = 0;
        return;
    }
%}

%inline %{
    static void get_chat_terminal_type(CVC_CHAT *chat, char **out, size_t *out_len) {
        const char *terminal_type = NULL;

        if (!chat || !out || !out_len)
            goto err;

        terminal_type = OBJ_nid2sn(OBJ_obj2nid(chat->terminal_type));
        if (!terminal_type)
            goto err;

        *out_len = strlen(terminal_type) + 1;
        *out = (char *) malloc(*out_len);
        if (!*out)
            goto err;

        strcpy(*out, terminal_type);
        return;

    err:
        if (out) {
            free(*out);
            *out = NULL;
        }
        if (out_len)
            *out_len = 0;
        return;
    }
%}

%inline %{
    /**
     * @brief Get a string representation of a CHAT.
     */
    static void get_chat_rel_auth(CVC_CHAT *chat, char **out, size_t *out_len) {
        BIO *bio = NULL;
        long tmp;

        if (!out || !out_len)
            goto err;

        bio = BIO_new(BIO_s_mem());
        if (!bio)
            goto err;

        cvc_chat_print_authorizations(bio, chat, 0);

        tmp = BIO_ctrl_pending(bio);
        if (tmp < 0)
            goto err;
        *out = (char *) malloc(tmp);
        if (!*out)
            goto err;
        *out_len = tmp;

        if (BIO_read(bio, (void *) *out, *out_len) != tmp)
            goto err;

        BIO_free_all(bio);
        return;

    err:
        if (bio)
            BIO_free_all(bio);
        if (out) {
            free(*out);
            *out = NULL;
        }
        if (out_len)
            *out_len = 0;
        return;
    }
%}

%inline %{
    /**
     * @brief Get a string representation of a CHAT.
     */
    static void get_chat_repr(CVC_CHAT *chat, char **out, size_t *out_len) {
        BIO *bio =  NULL;
        long tmp;

        if (!out || !out_len)
            goto err;

        bio = BIO_new(BIO_s_mem());
        if (!bio)
            return;

        cvc_chat_print(bio, chat, 0);

        tmp = BIO_ctrl_pending(bio);
        if (tmp < 0)
            goto err;
        *out = (char *) malloc(tmp);
        if (!*out)
            goto err;
        *out_len = tmp;

        if (BIO_read(bio, (void *) *out, *out_len) != tmp)
            goto err;

        BIO_free_all(bio);
        return;

    err:
        if (bio)
            BIO_free_all(bio);
        if (out) {
            free(*out);
            *out = NULL;
        }
        if (out_len)
            *out_len = 0;
        return;
    }
%}

%inline %{
    /**
     * @brief Get a string representation of a CHAT.
     */
    static void get_cvc_repr(CVC_CERT *chat, char **out, size_t *out_len) {
        BIO *bio =  NULL;
        long tmp;

        if (!out || !out_len)
            goto err;

        bio = BIO_new(BIO_s_mem());
        if (!bio)
            return;

        CVC_print(bio, chat, 0);

        tmp = BIO_ctrl_pending(bio);
        if (tmp < 0)
            goto err;
        *out = (char *) malloc(tmp);
        if (!*out)
            goto err;
        *out_len = tmp;

        if (BIO_read(bio, (void *) *out, *out_len) != tmp)
            goto err;

        BIO_free_all(bio);
        return;

    err:
        if (bio)
            BIO_free_all(bio);
        if (out) {
            free(*out);
            *out = NULL;
        }
        if (out_len)
            *out_len = 0;
        return;
    }
%}

#endif

%delobject CVC_CHAT_free;
void
CVC_CHAT_free(CVC_CHAT *);

CVC_CHAT *
cvc_get_chat(CVC_CERT *cvc);

%newobject CVC_CHAT_dup;
CVC_CHAT *
CVC_CHAT_dup(CVC_CHAT *x)
{
    ASN1_dup_of(CVC_CHAT, i2d_CVC_CHAT, d2i_CVC_CHAT, x);
}

/** @} ***********************************************************************/

