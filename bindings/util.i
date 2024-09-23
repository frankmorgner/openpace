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
 * @date 2012-02-08
 * @version 0.2
 * @author Dominik Oepen <oepen@informatik.hu-berlin.de>
 */

%{
#include <eac/eac.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <stdlib.h>
#include <string.h>

/* included in OpenPACE, but not propagated */
extern BUF_MEM *BUF_MEM_create_init(const void *buf, size_t len);
%}

%delobject BUF_MEM_clear_free;
void BUF_MEM_clear_free(BUF_MEM *b);

%begin %{
#define SWIG_PYTHON_STRICT_BYTE_CHAR
%}
int OBJ_txt2nid(char *in);

void EAC_init(void);

void EAC_cleanup(void);

%inline %{
    /*Dumps a BUF_MEM structure to stdout for debugging purposes */
    static void hexdump(const char *title, const BUF_MEM *s) {
        unsigned int n=0;

        if (!s) return;

        fprintf(stdout,"%s",title);
        for(; n < s->length; ++n) {
            if((n%16) == 0)
            fprintf(stdout,"\n    ");
            fprintf(stdout,"%02x:",(unsigned char) s->data[n]);
        }
        fprintf(stdout,"\n");
    }
%}

%inline %{
    static void set_tr_version(EAC_CTX *ctx, int version) {
        switch (version) {
            case 1:
                ctx->tr_version = EAC_TR_VERSION_2_01;
                break;
            case 2:
                ctx->tr_version = EAC_TR_VERSION_2_02;
                break;
            default:
                ctx->tr_version = EAC_TR_VERSION;
                break;
        }
        return;
    }
%}

%inline %{
    /* Converts a binary string and a length into a BUF_MEM structure */
    static BUF_MEM * get_buf(char *in, size_t in_len) {
        BUF_MEM *buf = NULL;
        if (in_len > 0)
            buf = BUF_MEM_create_init(in, in_len);
        else
            buf = BUF_MEM_create_init("", 0);
        return buf;
    }
%}

%inline %{
    /* Print the OpenSSL error stack to stdout */
    static void print_ossl_err(void) {
        /* Might be better to load the strings once on program startup */
        ERR_load_crypto_strings();
        ERR_print_errors_fp(stdout);
        ERR_free_strings();
        return;
    }
%}

#if !defined(SWIG_CSTRING_UNIMPL)

%inline %{
    static void buf2string(BUF_MEM *buf, char **out, size_t *out_len) {
        if (!buf) { /* Return a NULL pointer on error */
            *out = NULL;
            out_len = 0;
            return;
        } else {
            *out_len = buf->length;
            *out = (char *) malloc(*out_len);

            if (!*out) {
                *out_len = 0;
                return;
            }

            memcpy(*out, buf->data, *out_len);
            return;
        }
    }
%}

#endif
