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
 * @file read_file.c
 *
 * @author Frank Morgner <frankmorgner@gmail.com>
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

int read_file(const char *filename, unsigned char **out, size_t *outlen)
{
    FILE *fp = NULL;
    int fail = 1;
    int filesize;
    unsigned char *p;

    fp = fopen(filename, "rb");
    if (!fp) {
        perror("Could not open file");
        goto err;
    }

    if (0 > fseek(fp, 0L, SEEK_END)) {
        perror("count not seek file");
        goto err;
    }
    filesize = ftell(fp);
    if (0 > filesize) {
        perror("count not tell file");
        goto err;
    }
    fseek(fp, 0L, SEEK_SET);

    p = (unsigned char*) realloc(*out, filesize);
    if (!p) {
        puts("Failed to allocate memory");
        goto err;
    }
    *out = p;
    *outlen = filesize;

    if (filesize != fread(p, sizeof(unsigned char), filesize, fp)) {
        perror("Failed to read file");
        goto err;
    }

    fail = 0;

err:
    if (fp)
        fclose(fp);

    return fail;
}
