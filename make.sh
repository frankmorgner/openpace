#!/bin/sh

wget http://www.openssl.org/source/openssl-1.0.0-beta2.tar.gz
wget "http://marc.info/?l=openssl-dev&m=124340739803855&q=p3" -O ibm3.patch
tar -xzf openssl-1.0.0-beta2.tar.gz

cd openssl-1.0.0-beta2
patch -p1 < ../ibm3.patch
patch -R -p1 < ../openpace.patch
ln crypto/cmac/cmac.h include/openssl/
ln crypto/pace/pace.h include/openssl/

./config
make
make -C crypto/pace
make
