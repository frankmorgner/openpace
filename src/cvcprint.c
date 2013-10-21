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

#include <eac/cv_cert.h>
#include <eac/eac.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>

#define err(s) { puts(s); ERR_print_errors_fp(stdout); goto err; }

static int print_cvc(const unsigned char *cvc_data, const size_t cvc_len,
        const unsigned char *desc_data, const size_t desc_len) {
    BIO *bio_stdout = NULL;
    CVC_CERT *cvc = NULL;
    CVC_CERTIFICATE_DESCRIPTION *desc = NULL;
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

    fail = 0;

err:
    if (desc)
        CVC_CERTIFICATE_DESCRIPTION_free(desc);
    if (cvc)
        CVC_CERT_free(cvc);
    if (bio_stdout)
        BIO_free_all(bio_stdout);

    return fail;
}

static int read_file(const char *filename, unsigned char **out, size_t *outlen)
{
    FILE *fp = NULL;
    int fail = 1;
    size_t filesize;
    unsigned char *p;

    fp = fopen(filename, "rb");
    if (!fp)
        err("Could not open file");

    if (0 > fseek(fp, 0L, SEEK_END))
        err("count not seek file");
    filesize = ftell(fp);
    fseek(fp, 0L, SEEK_SET);

    p = (unsigned char*) realloc(*out, filesize);
    if (!p)
        err("Failed to allocate memory");
    *out = p;
    *outlen = filesize;

    if (filesize != fread(p, sizeof(unsigned char), filesize, fp))
        err("Failed to read file");

    fail = 0;

err:
    if (fp)
        fclose(fp);

    return fail;
}

int main(int argc, char *argv[])
{
    int fail = 1, i;
    char *cvc_filename = NULL;
    char *desc_filename = NULL;
    unsigned char *cvc_data = NULL, *desc_data = NULL;
    size_t cvc_len = 0, desc_len = 0;

    for (i=1; i<argc; i++)
    {
        if ((strcmp(argv[i], "--cvc") == 0)
                || (strcmp(argv[i], "-c") == 0)) {
            if (i++>=argc) {
                fprintf(stderr, "-c,--cvc requires an argument\n");
                return fail;
            }
            cvc_filename = argv[i];
            continue;
        }
        if ((strcmp(argv[i], "--description") == 0)
                || (strcmp(argv[i], "-d") == 0)) {
            if (i++>=argc) {
                fprintf(stderr, "-d,--description requires an argument\n");
                return fail;
            }
            desc_filename = argv[i];
            continue;
        }
        if ((strcmp(argv[i], "--help") == 0)
                || (strcmp(argv[i], "-h") == 0)) {
            printf(
                    "%s Prints card verifiable certificate and its description\n"
                    "\n"
                    "Usage: %s [Options]\n"
                    "\n"
                    "Options:\n"
                    "  -c,--cvc          file with card Verifiable certificate\n"
                    "  -d,--description  file with certificate description\n"
                    "  -h,--help         show this help message and exit\n"
                    "     --version      print version information and exit\n"
                    , argv[0], argv[0]
            );
            fail = 0;
            goto err;
        }
        if (strcmp(argv[i], "--version") == 0) {
            fprintf(stderr,
                    "%s 0.1\n"
                    "\n"
                    "Written by Frank Morgner and Dominik Oepen.\n"
                    , argv[0]
            );
            fail = 0;
            goto err;
        }

        fprintf(stderr, "unrecognized option \"%s\"\n", argv[i]);
        goto err;
    }

    if (cvc_filename) {
        fail = read_file(cvc_filename, &cvc_data, &cvc_len);
        if (fail) {
            fprintf(stderr, "failed to read %s\n", cvc_filename);
            goto err;
        }
    }

    if (desc_filename) {
        fail = read_file(desc_filename, &desc_data, &desc_len);
        if (fail) {
            fprintf(stderr, "failed to read %s\n", desc_filename);
            goto err;
        }
    }

    EAC_init();
    fail = print_cvc(cvc_data, cvc_len, desc_data, desc_len);

err:
    free(cvc_data);
    free(desc_data);
    EAC_cleanup();

    return fail;
}
