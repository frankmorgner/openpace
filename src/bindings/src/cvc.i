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

/*int i2d_CVC_CERT(CVC_CERT *a, unsigned char **out);*/

CVC_CERT *
CVC_CERT_new(void);

void
CVC_CERT_free(CVC_CERT *a);

CVC_CERT
*CVC_d2i_CVC_CERT(CVC_CERT **cert, const unsigned char **in, long len);

%rename (CVC_d2i_CVC_CERT) str_to_cv_cert;
%inline %{ /* typemap applied */
    static CVC_CERT *str_to_cv_cert(char *in, int in_len) {
        CVC_CERT *cvc = NULL;
        const unsigned char **p = (const unsigned char **) &in;
        cvc = CVC_d2i_CVC_CERT(NULL, p, in_len);
        return cvc;
    }
%}

/*int i2d_CVC_CERTIFICATE_DESCRIPTION(CVC_CERTIFICATE_DESCRPTION *a,
        unsigned char **out);*/

CVC_CERTIFICATE_DESCRIPTION *
CVC_CERTIFICATE_DESCRIPTION_new(void);

void
CVC_CERTIFICATE_DESCRIPTION_free(CVC_CERTIFICATE_DESCRIPTION *a);


CVC_CERT *
d2i_CVC_CERTIFICATE_DESCRIPTION(CVC_CERTIFICATE_DESCRIPTION **desc,
        const unsigned char **in, long len);
%rename (d2i_CVC_CERTIFICATE_DESCRIPTION) str_to_cert_desc;
%inline %{ /* typemap applied */
    static CVC_CERTIFICATE_DESCRIPTION *str_to_cert_desc(char *in, int in_len) {
        CVC_CERTIFICATE_DESCRIPTION *description = NULL;
        const unsigned char **p = (const unsigned char **) &in;
        description = d2i_CVC_CERTIFICATE_DESCRIPTION(NULL, p, in_len);
        return description;
    }
%}

#ifdef SWIGPYTHON

%inline %{
    static void get_termsOfUsage(CVC_CERTIFICATE_DESCRIPTION *desc, char **out,
            int *out_len) {

        /*XXX: We only deal with plain text TOUs. What should we do with pdf or
               HTML? */
        /*TODO: Check OID */
        if (!desc || !desc->termsOfUsage.plainTerms) {
            /* Return a NULL pointer on error */
            *out = NULL;
            *out_len = 0;
            return;
        }

        *out_len = desc->termsOfUsage.plainTerms->length;
        *out = malloc(*out_len);
        memcpy(*out, desc->termsOfUsage.plainTerms->data, *out_len);
        return;
    }
%}

%inline %{
    static void get_issuer_name(char **out, int *out_len, CVC_CERTIFICATE_DESCRIPTION *desc) {
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
    static void get_subject_name(char **out, int *out_len, CVC_CERTIFICATE_DESCRIPTION *desc) {
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
    static void get_subject_url(char **out, int *out_len, CVC_CERTIFICATE_DESCRIPTION *desc) {
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
    static void get_issuer_url(char **out, int *out_len, CVC_CERTIFICATE_DESCRIPTION *desc) {
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

/**
 * @defgroup cvc            CHAT functions
 * @{ ************************************************************************/

CVC_CHAT *
d2i_CVC_CHAT(CVC_CHAT **chat, const unsigned char **in, long len);
%rename (d2i_CVC_CHAT) str_to_chat;
%inline %{ /* typemap applied */
    static CVC_CHAT *str_to_chat(char *in, int in_len) {
        CVC_CHAT *chat = NULL;
        const unsigned char **p = (const unsigned char **) &in;
        chat = d2i_CVC_CHAT(NULL, p, (long) in_len);
        return chat;
    }
%}

void
CVC_CHAT_free(CVC_CHAT *);

CVC_CHAT *
cvc_get_chat(CVC_CERT *cvc);

void cvc_chat_print(BIO *bio, CVC_CHAT *chat, int indent);
%rename (cvc_chat_print) print_chat;
%inline %{
    static void print_chat(CVC_CHAT *chat, int indent) {
        BIO *bio_stdout = BIO_new_fp(stdout, BIO_NOCLOSE);
        if (!bio_stdout)
            return;
        cvc_chat_print(bio_stdout, chat, indent);
        BIO_free_all(bio_stdout);
    }
%}

%inline %{
    static void print_binary_chat(char *in, int in_len) {
        CVC_CHAT *chat = NULL;
        if (!in || (in_len <= 0))
            return;

        const unsigned char **p = (const unsigned char**)&in;

        /* Convert string to CHAT structure */
        chat = d2i_CVC_CHAT(NULL, p, in_len);
        if (!chat)
            return;

        /* Print CHAT structure */
        print_chat(chat, 0);

        /* Free memory */
        free(chat);
        return;
    }
%}

#ifdef SWIGPYTHON

%inline %{
    static void get_binary_chat(CVC_CHAT *chat, char **out, int *out_len) {

        if (!chat || !chat->relative_authorization) {
            /* Return a NULL pointer on error */
            *out = NULL;
            *out_len = 0;
            return;
        }

        *out_len = chat->relative_authorization->length;
        *out = malloc(*out_len);
        memcpy(*out, chat->relative_authorization->data, *out_len);
        return;

    }
%}


%inline %{
    static void get_chat_role(CVC_CHAT *chat, char **out, int *out_len) {
        int role = 0;

        if (!chat || !out || !out_len)
            goto err;

        role = CVC_get_role(chat);
        switch(role) {
            case CVC_Terminal:
                *out_len = 21;
                *out = malloc(*out_len);
                if (!*out)
                    goto err;
                strncpy(*out, "Terminal certificate", *out_len);
                break;
            case CVC_DV:
                *out_len = 15;
                *out = malloc(*out_len);
                if (!*out)
                    goto err;
                strncpy(*out, "DV certificate", *out_len);
                break;
            case CVC_DocVer:
                *out_len = 15;
                *out = malloc(*out_len);
                if (!*out)
                    goto err;
                strncpy(*out, "DV certificate", *out_len);
                break;
            case CVC_CVCA:
                *out_len = 17;
                *out = malloc(*out_len);
                if (!*out)
                    goto err;
                strncpy(*out, "CVCA certificate", *out_len);
                break;
            default:
                goto err;
        }

        return;

    err:
        if (*out) {
            free(*out);
            *out = NULL;
        }
        out = NULL;
        *out_len = 0;
        return;
    }
%}

%inline %{
    static void get_chat_terminal_type(CVC_CHAT *chat, char **out, int *out_len) {
        const char *terminal_type = NULL;

        if (!chat || !out || !out_len)
            goto err;

        terminal_type = OBJ_nid2sn(OBJ_obj2nid(chat->terminal_type));
        if (!terminal_type)
            goto err;

        *out_len = strlen(terminal_type) + 1; 
        *out = malloc(*out_len);
        if (!*out)
            goto err;

        strcpy(*out, terminal_type);
        return;

    err:
        if (*out) {
            free(*out);
            *out = NULL;
        }
        out = NULL;
        *out_len = 0;
        return;
    }
%}

%inline %{
    /**
     * @brief Get a string representation of a CHAT.
     */
    static void get_chat_rel_auth(CVC_CHAT *chat, char **out, int *out_len) {
        BIO *bio =  NULL;

        if (!out || !out_len)
            goto err;

        bio = BIO_new(BIO_s_mem());
        if (!bio)
            return;

        cvc_chat_print_authorizations(bio, chat, 0);

        *out_len = BIO_ctrl_pending(bio);
        *out = malloc(*out_len);
        if (!*out)
            goto err;

        if (BIO_read(bio, (void *) *out, *out_len) != *out_len)
            goto err;

        BIO_free_all(bio);
        return;

    err:
        if (bio)
            BIO_free_all(bio);
        if (*out) {
            free(*out);
            *out = NULL;
        }
        out = NULL;
        *out_len = 0;
        return;
    }
%}

%inline %{
    /**
     * @brief Get a string representation of a CHAT.
     */
    static void get_chat_repr(CVC_CHAT *chat, char **out, int *out_len) {
        BIO *bio =  NULL;

        if (!out || !out_len)
            goto err;

        bio = BIO_new(BIO_s_mem());
        if (!bio)
            return;

        cvc_chat_print(bio, chat, 0);

        *out_len = BIO_ctrl_pending(bio);
        *out = malloc(*out_len);
        if (!*out)
            goto err;

        if (BIO_read(bio, (void *) *out, *out_len) != *out_len)
            goto err;

        BIO_free_all(bio);
        return;

    err:
        if (bio)
            BIO_free_all(bio);
        if (*out) {
            free(*out);
            *out = NULL;
        }
        out = NULL;
        *out_len = 0;
        return;
    }
%}

#endif


/** @} ***********************************************************************/

