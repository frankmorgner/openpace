#!/bin/sh

# CI script to test on unix like systems

set -ex -o xtrace

chmod a+x *.com
./eactest.com
openssl ecparam -out ZZATCVCA00001.pem -name prime192v1 -genkey -param_enc explicit
openssl pkcs8 -topk8 -nocrypt -in ZZATCVCA00001.pem -outform DER -out ZZATCVCA00001.pkcs8
./cvc-create.com --role=cvca --type=at --chr=ZZATCVCA00001 --expires=991231 --sign-with=ZZATCVCA00001.pkcs8 --scheme=ECDSA_SHA_256 --rid
./cvc-print.com --cvc=ZZATCVCA00001.cvcert --disable-cvc-verification
