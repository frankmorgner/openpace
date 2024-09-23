#!/bin/sh

# CI script to build for "ubuntu", "macos", "ape", "coverity"

set -ex -o xtrace

DEPS="gengetopt help2man automake libtool"

case "$1" in
    ubuntu|coverity)
        DEPS="$DEPS gccgo golang-go openjdk-8-jdk openjdk-8-jre-headless python-dev ruby-dev swig xutils-dev doxygen"
        ;;
    macos)
        DEPS="$DEPS openssl"
        ;;
esac

case "$1" in
    ubuntu|coverity|ape)
        sudo apt-get update
        sudo apt-get install -y $DEPS
        ;;
    macos)
        brew install $DEPS
        ;;
esac

case "$1" in
    ubuntu)
        # full documentation is only built on ubuntu
        #pip install -r sphinx sphinx-bootstrap-theme breathe sphinxcontrib-programoutput
        pip install -r src/docs/requirements.txt
        ;;
esac

case "$1" in
    ape)
        sudo sh -c "echo ':APE:M::MZqFpD::/bin/sh:' >/proc/sys/fs/binfmt_misc/register"
        sudo mkdir -p /opt
        sudo chmod 1777 /opt
        test -d /opt/cosmo || (wget https://cosmo.zip/pub/cosmocc/cosmocc-3.3.1.zip && sudo unzip cosmocc-3.3.1.zip -d /opt/cosmo)
        test -d openssl || git clone --depth=1 https://github.com/openssl/openssl.git -b openssl-3.0 openssl
        # see also https://github.com/ahgamut/superconfigure/blob/main/lib/openssl/BUILD.mk
        cd openssl
        git apply ../.github/openssl_getrandom.diff
        ./Configure linux-aarch64 --with-rand-seed=getrandom no-asm no-shared no-dso no-engine no-dynamic-engine no-pic no-autoalginit no-autoerrinit no-tests -DPURIFY CC="/opt/cosmo/bin/cosmocc -I/opt/cosmo/include -L/opt/cosmo/lib" AR=/opt/cosmo/bin/cosmoar
        make
        cd -
        ;;
esac

autoreconf -vis

case "$1" in
    ubuntu|coverity)
        export GCCGOFLAGS="-static-libgcc $CFLAGS"
        ./configure --enable-python --enable-java --enable-ruby --enable-go
        ;;
    ape)
        ./configure CC=/opt/cosmo/bin/cosmocc INSTALL="/opt/cosmo/bin/cosmoinstall" AR="/opt/cosmo/bin/cosmoar" CRYPTO_CFLAGS="-I$PWD/openssl/include" CRYPTO_LIBS="-L$PWD/openssl -lcrypto" --disable-shared
        ;;
    macos)
        ./configure
        ;;
esac

case "$1" in
    ubuntu)
        make
        make check
        sudo make install
        make distcheck
        sudo make uninstall
        ;;
    ape|macos)
        make
        ;;
esac

case "$1" in
    ape)
        mkdir -p openpace-bin
        for file in src/eactest src/cvc-create src/cvc-print
        do
            #objcopy -SO binary $file openpace-bin/${file##*/}.com
            cp $file openpace-bin/${file##*/}.com
        done
        cp -r docs openpace-bin
        ;;
esac
