#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "eac_dh.h"
#include <openssl/crypto.h>
#include <openssl/dh.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <string.h>

#ifndef HAVE_DH_SET0_KEY
int DH_set0_key(DH *dh, BIGNUM *pub_key, BIGNUM *priv_key)
{
    /* If the field pub_key in dh is NULL, the corresponding input
     * parameters MUST be non-NULL.  The priv_key field may
     * be left NULL.
     */
    if (dh->pub_key == NULL && pub_key == NULL)
        return 0;

    if (pub_key != NULL) {
        BN_free(dh->pub_key);
        dh->pub_key = pub_key;
    }
    if (priv_key != NULL) {
        BN_free(dh->priv_key);
        dh->priv_key = priv_key;
    }

    return 1;
}
#endif

#ifndef HAVE_DH_GET0_KEY
void DH_get0_key(const DH *dh, const BIGNUM **pub_key, const BIGNUM **priv_key)
{
    if (pub_key != NULL)
        *pub_key = dh->pub_key;
    if (priv_key != NULL)
        *priv_key = dh->priv_key;
}
#endif

#ifndef HAVE_DH_GET0_PQG
void DH_get0_pqg(const DH *dh,
        const BIGNUM **p, const BIGNUM **q, const BIGNUM **g)
{
    if (p != NULL)
        *p = dh->p;
    if (q != NULL)
        *q = dh->q;
    if (g != NULL)
        *g = dh->g;
}
#endif

#ifndef HAVE_DH_SET0_PQG
int DH_set0_pqg(DH *dh, BIGNUM *p, BIGNUM *q, BIGNUM *g)
{
    /* If the fields p and g in d are NULL, the corresponding input
     * parameters MUST be non-NULL.  q may remain NULL.
     */
    if ((dh->p == NULL && p == NULL)
            || (dh->g == NULL && g == NULL))
        return 0;

    if (p != NULL) {
        BN_free(dh->p);
        dh->p = p;
    }
    if (q != NULL) {
        BN_free(dh->q);
        dh->q = q;
    }
    if (g != NULL) {
        BN_free(dh->g);
        dh->g = g;
    }

    if (q != NULL) {
        dh->length = BN_num_bits(q);
    }

    return 1;
}
#endif

#ifndef HAVE_RSA_SET0_KEY
int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d)
{
    /* If the fields n and e in r are NULL, the corresponding input
     * parameters MUST be non-NULL for n and e.  d may be
     * left NULL (in case only the public key is used).
     */
    if ((r->n == NULL && n == NULL)
            || (r->e == NULL && e == NULL))
        return 0;

    if (n != NULL) {
        BN_free(r->n);
        r->n = n;
    }
    if (e != NULL) {
        BN_free(r->e);
        r->e = e;
    }
    if (d != NULL) {
        BN_free(r->d);
        r->d = d;
    }

    return 1;
}
#endif

#ifndef HAVE_RSA_GET0_KEY
void RSA_get0_key(const RSA *r,
        const BIGNUM **n, const BIGNUM **e, const BIGNUM **d)
{
    if (n != NULL)
        *n = r->n;
    if (e != NULL)
        *e = r->e;
    if (d != NULL)
        *d = r->d;
}
#endif

#ifndef HAVE_ECDSA_SIG_SET0
int ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s)
{
    if (r == NULL || s == NULL)
        return 0;
    BN_clear_free(sig->r);
    BN_clear_free(sig->s);
    sig->r = r;
    sig->s = s;
    return 1;
}
#endif

#ifndef HAVE_ECDSA_SIG_GET0
void ECDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps)
{
    if (pr != NULL)
        *pr = sig->r;
    if (ps != NULL)
        *ps = sig->s;
}
#endif

#ifndef HAVE_ASN1_STRING_GET0_DATA
const unsigned char *ASN1_STRING_get0_data(const ASN1_STRING *x)
{
    return x->data;
}
#endif

#if !defined(HAVE_DECL_OPENSSL_ZALLOC) || HAVE_DECL_OPENSSL_ZALLOC == 0
void *OPENSSL_zalloc(size_t num)
{
    void *out = OPENSSL_malloc(num);

    if (out != NULL)
        memset(out, 0, num);

    return out;
}
#endif

#ifndef HAVE_EC_POINT_GET_AFFINE_COORDINATES
int EC_POINT_get_affine_coordinates(const EC_GROUP *group, const EC_POINT *p, BIGNUM *x, BIGNUM *y, BN_CTX *ctx)
{
    return EC_POINT_get_affine_coordinates_GF2m(group, p, x, y, ctx);
}
#endif

#ifndef HAVE_EC_POINT_SET_AFFINE_COORDINATES
int EC_POINT_set_affine_coordinates(const EC_GROUP *group, EC_POINT *p, const BIGNUM *x, const BIGNUM *y, BN_CTX *ctx)
{
    return EC_POINT_set_affine_coordinates_GFp(group, p, x, y, ctx);
}
#endif

#ifndef HAVE_EVP_PKEY_DUP
EVP_PKEY *
EVP_PKEY_dup(EVP_PKEY *key)
{
    EVP_PKEY *out = NULL;
    DH *dh_in = NULL, *dh_out = NULL;
    EC_KEY *ec_in = NULL, *ec_out = NULL;
    RSA *rsa_in = NULL, *rsa_out = NULL;

    out = EVP_PKEY_new();

    if (!key || !out)
        goto err;

    switch (EVP_PKEY_base_id(key)) {
        case EVP_PKEY_DH:
        case EVP_PKEY_DHX:
            dh_in = EVP_PKEY_get1_DH(key);
            if (!dh_in)
                goto err;

            dh_out = DHparams_dup_with_q(dh_in);
            if (!dh_out)
                goto err;

            EVP_PKEY_set1_DH(out, dh_out);
            DH_free(dh_out);
            DH_free(dh_in);
            break;

        case EVP_PKEY_EC:
            ec_in = EVP_PKEY_get1_EC_KEY(key);
            if (!ec_in)
                goto err;

            ec_out = EC_KEY_dup(ec_in);
            if (!ec_out)
                goto err;

            EVP_PKEY_set1_EC_KEY(out, ec_out);
            EC_KEY_free(ec_out);
            EC_KEY_free(ec_in);
            break;

        case EVP_PKEY_RSA:
            rsa_in = EVP_PKEY_get1_RSA(key);
            if (!rsa_in)
                goto err;

            rsa_out = RSAPrivateKey_dup(rsa_in);
            if (!rsa_out)
                goto err;

            EVP_PKEY_set1_RSA(out, rsa_out);
            RSA_free(rsa_out);
            RSA_free(rsa_in);
            break;

        default:
            goto err;
    }

    return out;

err:
    if (dh_in)
        DH_free(dh_in);
    if (ec_in)
        EC_KEY_free(ec_in);
    if (rsa_in)
        RSA_free(rsa_in);
    if (out)
        EVP_PKEY_free(out);

    return NULL;
}
#endif
