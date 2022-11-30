#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <openssl/crypto.h>
#include <openssl/dh.h>
#include <openssl/ecdsa.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>

#ifndef HAVE_DH_SET0_KEY
int DH_set0_key(DH *dh, BIGNUM *pub_key, BIGNUM *priv_key);
#endif

#ifndef HAVE_DH_GET0_KEY
void DH_get0_key(const DH *dh, const BIGNUM **pub_key, const BIGNUM **priv_key);
#endif

#ifndef HAVE_DH_GET0_PQG
void DH_get0_pqg(const DH *dh, const BIGNUM **p, const BIGNUM **q, const BIGNUM **g);
#endif

#ifndef HAVE_DH_SET0_PQG
int DH_set0_pqg(DH *dh, BIGNUM *p, BIGNUM *q, BIGNUM *g);
#endif

#ifndef HAVE_RSA_SET0_KEY
int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d);
#endif

#ifndef HAVE_RSA_GET0_KEY
void RSA_get0_key(const RSA *r, const BIGNUM **n, const BIGNUM **e, const BIGNUM **d);
#endif

#ifndef HAVE_BN_IS_PRIME_EX
int BN_is_prime_ex(const BIGNUM *a, int checks, BN_CTX *ctx_passed, BN_GENCB *cb);
#endif

#ifndef HAVE_ECDSA_SIG_SET0
int ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s);
#endif

#ifndef HAVE_ECDSA_SIG_GET0
void ECDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps);
#endif

#ifndef HAVE_ASN1_STRING_GET0_DATA
const unsigned char *ASN1_STRING_get0_data(const ASN1_STRING *x);
#endif

#if !defined(HAVE_DECL_OPENSSL_ZALLOC) || HAVE_DECL_OPENSSL_ZALLOC == 0
void *OPENSSL_zalloc(size_t num);
#endif

#ifndef HAVE_EC_POINT_GET_AFFINE_COORDINATES
int EC_POINT_get_affine_coordinates(const EC_GROUP *group, const EC_POINT *p, BIGNUM *x, BIGNUM *y, BN_CTX *ctx);
#endif

#ifndef HAVE_EC_POINT_SET_AFFINE_COORDINATES
int EC_POINT_set_affine_coordinates(const EC_GROUP *group, EC_POINT *p, const BIGNUM *x, const BIGNUM *y, BN_CTX *ctx);
#endif

#ifndef HAVE_EVP_PKEY_DUP
EVP_PKEY *
EVP_PKEY_dup(EVP_PKEY *key);
#endif
