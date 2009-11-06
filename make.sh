#!/bin/sh

wget http://www.openssl.org/source/openssl-1.0.0-beta3.tar.gz
wget "http://marc.info/?l=openssl-dev&m=125730780821132&q=p3" -O ibm4.patch
tar -xzf openssl-1.0.0-beta3.tar.gz

cd openssl-1.0.0-beta3
patch --strip 1 < ../ibm4.patch
patch --strip 1 < ../openpace.patch
ln crypto/cmac/cmac.h include/openssl/
ln crypto/pace/pace.h include/openssl/

sleep 1
./config && make
make -C crypto/pace
make
