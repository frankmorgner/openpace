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
 */

/**
 * @file x509_lookup.c
 * @brief
 *
 * @author Frank Morgner <morgner@informatik.hu-berlin.de>
 */

#include "eac_err.h"
#include <eac/cv_cert.h>
#include <eac/eac.h>
#include <openssl/bio.h>
#include <openssl/x509.h>

static int X509_find_issuer_in_file(unsigned long issuer_name_hash,
        const char *file, X509 **x509_certificate)
{
    BIO *in = NULL;
    X509 *x509;
    int ok = 0;

    in = BIO_new(BIO_s_file_internal());
    if (!in || !BIO_read_filename(in, file))
        goto err;

    while (1) {
        if (!d2i_X509_bio(in, x509_certificate)) {
            ERR_clear_error();
            break;
        }
        x509 = *x509_certificate;
        if (issuer_name_hash = X509_issuer_name_hash(x509)) {
            ok = 1;
            break;
        }
    }

err:
    if(in)
        BIO_free(in);

    return ok;
}

static int X509_find_issuer_in_directory(unsigned long issuer_name_hash,
        const char *dir, X509 **x509_certificate)
{
    int ok = 0, r;
    char path[1024];

    if(strlen(dir)+1+8+5 > sizeof path)
        goto err;

    r = BIO_snprintf(path, sizeof path, "%s/%08x.cer", dir, issuer_name_hash);
    if (r <= 0)
        goto err;

    if(!X509_find_issuer_in_file(issuer_name_hash, path, x509_certificate))
        goto err;

    ok = 1;

err:
    return ok;
}

/* FIXME X509_default_lookup is not thread safe */
static X509_STORE *X509_default_lookup(unsigned long issuer_name_hash)
{
    static X509_STORE *store = NULL;
    static X509 *csca_cert = NULL;

    if (!store)
       store = X509_STORE_new();
    check(store, "Failed to create trust store");

    check(X509_find_issuer_in_directory(issuer_name_hash, ETC_EAC, &csca_cert),
            "Could not find issuer's certificate");
    check(X509_STORE_add_cert(store, csca_cert),
            "Could not initialize trust store");

err:
    return store;
}

X509_lookup_csca_cert EAC_get_default_csca_lookup(void)
{
    return X509_default_lookup;
}

int EAC_CTX_set_csca_lookup(EAC_CTX *ctx, X509_lookup_csca_cert lookup_csca_cert)
{
    int ok = 0;

    check (ctx && ctx->ca_ctx, "Invalid EAC context");
    ctx->ca_ctx->lookup_csca_cert = lookup_csca_cert;
    ok = 1;

err:
    return ok;
}

int EAC_CTX_get_csca_lookup(const EAC_CTX *ctx, X509_lookup_csca_cert *lookup_csca_cert)
{
    int ok = 0;

    check (lookup_csca_cert && ctx && ctx->ca_ctx, "Invalid parameters");
    *lookup_csca_cert = ctx->ca_ctx->lookup_csca_cert;
    ok = 1;

err:
    return ok;
}
