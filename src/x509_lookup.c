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
 * @file x509_lookup.c
 * @brief
 *
 * @author Frank Morgner <frankmorgner@gmail.com>
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "eac_err.h"
#include <eac/cv_cert.h>
#include <eac/eac.h>
#include <openssl/bio.h>
#include <openssl/x509.h>

#ifndef PATH_MAX
#define PATH_MAX 1024 /* # chars in a path name including nul */
#endif

/** @brief Directory for \c EAC_get_default_csca_lookup() */
static char x509_default_dir[PATH_MAX];

void EAC_set_x509_default_dir(const char *default_dir)
{
    if (default_dir) {
        strncpy(x509_default_dir, default_dir, (sizeof x509_default_dir) - 1);
        x509_default_dir[(sizeof x509_default_dir) - 1] = '\0';
    }
}

static X509_STORE *X509_default_lookup(unsigned long issuer_name_hash)
{
    static X509_STORE *store = NULL;

    if (!store)
       store = X509_STORE_new();
    check(store, "Failed to create trust store");

    if (!X509_STORE_load_locations(store, NULL, x509_default_dir)) {
            log_err("Failed to load trusted certificates");
            X509_STORE_free(store);
            store = NULL;
    }

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
