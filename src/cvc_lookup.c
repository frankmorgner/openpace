/*
 * Copyright (c) 2010-2012 Frank Morgner
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
 * @file cvc_lookup.c
 * @brief
 *
 * @author Frank Morgner <frankmorgner@gmail.com>
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "eac_err.h"
#include "eac_util.h"
#include <eac/cv_cert.h>
#include <eac/eac.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#ifndef PATH_MAX
#define PATH_MAX 1024 /* # chars in a path name including nul */
#endif

/** @brief Directory for \c EAC_get_default_cvca_lookup() */
static char cvc_default_dir[PATH_MAX];

void EAC_set_cvc_default_dir(const char *default_dir)
{
    if (default_dir) {
        strncpy(cvc_default_dir, default_dir, (sizeof cvc_default_dir) - 1);
        cvc_default_dir[(sizeof cvc_default_dir) - 1] = '\0';
    }
}

static int CVC_find_chr_in_file(const unsigned char *chr, size_t chr_len,
        const char *file, CVC_CERT **cv_certificate)
{
    BIO *in = NULL;
    CVC_CERT *cvc;
    int ok = 0;

    if (!chr)
        goto err;

    in = BIO_new(BIO_s_file());
    if (!in || !BIO_read_filename(in, file))
        goto err;

    while (1) {
        if (!d2i_CVC_CERT_bio(in, cv_certificate)) {
            ERR_clear_error();
            break;
        }
        cvc = *cv_certificate;
        if (cvc && cvc->body && cvc->body->certificate_holder_reference
                && cvc->body->certificate_holder_reference->length == chr_len
                && 0 == memcmp(cvc->body->certificate_holder_reference->data,
                    chr, chr_len)) {
            ok = 1;
            break;
        }
    }

err:
    if(in)
        BIO_free(in);

    return ok;
}

static int CVC_find_chr_in_directory(const unsigned char *chr, size_t chr_len,
        const char *dir, CVC_CERT **cv_certificate)
{
    int ok = 0, r;
    char path[1024];

    if (!is_chr(chr, chr_len))
        goto err;

    if(strlen(dir)+1+chr_len+5 > sizeof path)
        goto err;

    r = BIO_snprintf(path, sizeof path, "%s/%s", dir, chr);
    if (r <= 0)
        goto err;

    if(!CVC_find_chr_in_file(chr, chr_len, path, cv_certificate))
        goto err;

    ok = 1;

err:
    return ok;
}

CVC_CERT *CVC_default_lookup(const unsigned char *chr, size_t chr_len)
{
    CVC_CERT *cvc = NULL;

    if (!CVC_find_chr_in_directory(chr, chr_len, cvc_default_dir, &cvc)) {
        CVC_CERT_free(cvc);
        cvc = NULL;
    }

    return cvc;
}

CVC_lookup_cvca_cert EAC_get_default_cvca_lookup(void)
{
    return CVC_default_lookup;
}

int EAC_CTX_set_cvca_lookup(EAC_CTX *ctx, CVC_lookup_cvca_cert lookup_cvca_cert)
{
    int ok = 0;

    check (ctx && ctx->ta_ctx, "Invalid EAC context");
    ctx->ta_ctx->lookup_cvca_cert = lookup_cvca_cert;
    ok = 1;

err:
    return ok;
}

int EAC_CTX_get_cvca_lookup(const EAC_CTX *ctx, CVC_lookup_cvca_cert *lookup_cvca_cert)
{
    int ok = 0;

    check (lookup_cvca_cert && ctx && ctx->ta_ctx, "Invalid parameters");
    *lookup_cvca_cert = ctx->ta_ctx->lookup_cvca_cert;
    ok = 1;

err:
    return ok;
}
