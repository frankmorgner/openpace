/*
 * Copyright (c) 2010-2012 Dominik Oepen and Frank Morgner
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
 * @file cvcprint.c
 * @brief Print a Card Verifiable Certificate and its Description
 *
 * @author Dominik Oepen <oepen@informatik.hu-berlin.de>
 * @author Frank Morgner <morgner@informatik.hu-berlin.de>
 */

#include "cvc-print-cmdline.h"
#include "read_file.h"
#include <eac/cv_cert.h>
#include <eac/eac.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>

#define err(s) { puts(s); ERR_print_errors_fp(stdout); goto err; }

static int print_cvc(const unsigned char *cvc_data, const size_t cvc_len,
        const unsigned char *desc_data, const size_t desc_len,
        const unsigned char *csr_data, const size_t csr_len)
{
    BIO *bio_stdout = NULL;
    CVC_CERT *cvc = NULL;
    CVC_CERTIFICATE_DESCRIPTION *desc = NULL;
    CVC_CERT_REQUEST *request = NULL;
    CVC_CERT_AUTHENTICATION_REQUEST *authentication = NULL;
    const unsigned char *p;
    int fail = 1;

    bio_stdout = BIO_new_fp(stdout, BIO_NOCLOSE);
    if (!bio_stdout)
        err("could not get output buffer");

    if (cvc_data && cvc_len) {
        p = cvc_data;
        if (!CVC_d2i_CVC_CERT(&cvc, &p, cvc_len))
            err("could not parse card verifiable certificate");

        puts("Certificate:");
        if (!CVC_print(bio_stdout, cvc, 2))
            err("could not print card verifiable certificate");
    }

    /* FIXME: CVC_CERT_print_ctx -> segfault */
    /* CVC_CERT_print_ctx(bio_stdout, cvc, 1, NULL); */

    if (desc_data && desc_len) {
        p = desc_data;
        if (!d2i_CVC_CERTIFICATE_DESCRIPTION(&desc, &p, desc_len))
            err("could not parse certificate description");

        puts("Description:");
        if (!certificate_description_print(bio_stdout, desc, 0))
            err("could not print certificate description");
    }

    if (cvc && desc_data && desc_len) {
        if (!CVC_check_description(cvc, desc_data, desc_len)) {
            puts("certificate description doesn't match certificate");
        } else {
            puts("certificate description matches certificate");
        }
    }

    if (csr_data && csr_len) {
        p = csr_data;
        if (d2i_CVC_CERT_REQUEST(&request, &p, csr_len)) {
            puts("Certificate Request:");
            if (!certificate_request_print(bio_stdout, request, 2))
                err("could not print certificate request");
        } else {
            /* try using an authentication request */
            p = csr_data;
            if (!d2i_CVC_CERT_AUTHENTICATION_REQUEST(&authentication, &p, desc_len))
                err("could not parse certificate request");

            puts("Certificate Authentication Request:");
            if (!certificate_authentication_request_print(bio_stdout, authentication, 2))
                err("could not print certificate authentication request");
        }
    }

    fail = 0;

err:
    if (desc)
        CVC_CERTIFICATE_DESCRIPTION_free(desc);
    if (cvc)
        CVC_CERT_free(cvc);
    if (authentication)
        CVC_CERT_AUTHENTICATION_REQUEST_free(authentication);
    if (request)
        CVC_CERT_REQUEST_free(request);
    if (bio_stdout)
        BIO_free_all(bio_stdout);

    return fail;
}

int main(int argc, char *argv[])
{
    int fail = 1;
    unsigned char *cvc_data = NULL, *desc_data = NULL, *csr_data = NULL;
    size_t cvc_len = 0, desc_len = 0, csr_len = 0;
    struct gengetopt_args_info cmdline;

    /* Parse command line */
    if (cmdline_parser (argc, argv, &cmdline) != 0) {
        return fail;
    }

    if (cmdline.cvc_arg) {
        fail = read_file(cmdline.cvc_arg, &cvc_data, &cvc_len);
        if (fail) {
            fprintf(stderr, "failed to read %s\n", cmdline.cvc_arg);
            goto err;
        }
    }

    if (cmdline.description_arg) {
        fail = read_file(cmdline.description_arg, &desc_data, &desc_len);
        if (fail) {
            fprintf(stderr, "failed to read %s\n", cmdline.description_arg);
            goto err;
        }
    }

    if (cmdline.csr_arg) {
        fail = read_file(cmdline.csr_arg, &csr_data, &csr_len);
        if (fail) {
            fprintf(stderr, "failed to read %s\n", cmdline.csr_arg);
            goto err;
        }
    }

    EAC_init();
    fail = print_cvc(cvc_data, cvc_len, desc_data, desc_len, csr_data, csr_len);

err:
    cmdline_parser_free (&cmdline);
    free(cvc_data);
    free(desc_data);
    EAC_cleanup();

    return fail;
}
