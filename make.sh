#!/bin/sh

# downloading and extracting
wget http://www.openssl.org/source/openssl-1.0.0-beta3.tar.gz
#wget "http://marc.info/?l=openssl-dev&m=125730780821132&q=p3" -O ibm4.patch
tar -xzf openssl-1.0.0-beta3.tar.gz

# datching
cd openssl-1.0.0-beta3
patch --strip 1 < ../ibm4.patch
patch --strip 1 < ../BP.patch
patch --strip 1 < ../OpenPACE.patch

# symbolic linking
(cd include/openssl/ ;\
ln -v -s ../../crypto/cmac/cmac.h \
         ../../crypto/pace/pace.h \
         .                    )
# compile
sleep 1
./config && make
