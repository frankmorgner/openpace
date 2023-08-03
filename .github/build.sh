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
        pip install -U sphinx sphinx-bootstrap-theme breathe sphinxcontrib-programoutput
        ;;
esac

case "$1" in
    ape)
        sudo sh -c "echo ':APE:M::MZqFpD::/bin/sh:' >/proc/sys/fs/binfmt_misc/register"
        sudo mkdir -p /opt
        sudo chmod 1777 /opt
        test -d /opt/cosmo || git clone https://github.com/jart/cosmopolitan /opt/cosmo
        cd /opt/cosmo
        make toolchain 2>/dev/null
        mkdir -p /opt/cosmos/bin
        /opt/cosmo/bin/cosmocc --update
        cd -
        test -d openssl || git clone --depth=1 https://github.com/openssl/openssl.git -b openssl-3.0 openssl
        cd openssl
        git apply ../.github/openssl_getrandom.diff
        ./config --with-rand-seed=getrandom no-asm no-shared no-dso no-engine no-dynamic-engine -DPURIFY CC=/opt/cosmo/bin/cosmocc
        find /opt/cosmo/tool/scripts/
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
        ./configure CC=/opt/cosmo/bin/cosmocc CRYPTO_CFLAGS="-I$PWD/openssl/include" CRYPTO_LIBS="-L$PWD/openssl -lcrypto" --disable-shared
        echo "#define ossl_unused"   >> config.h
        echo "#define ossl_inline"   >> config.h
        echo "#define __owur"        >> config.h
        echo "#define ossl_noreturn" >> config.h
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
        mkdir -p openpace_ape
        for file in openssl/apps/openssl src/eactest src/cvc-create src/cvc-print
        do
            objcopy -SO binary $file openpace_ape/${file##*/}.com
        done
        cp -r docs openpace_ape
        ;;
esac
