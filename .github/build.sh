#!/bin/sh

# CI script to build for "ubuntu", "mingw-32", "mingw-64", "macos", "coverity"

set -ex -o xtrace

DEPS="gengetopt help2man automake libtool"

case "$1" in
    ubuntu|coverity)
        DEPS="$DEPS gccgo golang-go openjdk-8-jdk openjdk-8-jre-headless python-dev ruby-dev swig xutils-dev doxygen"
        ;;
    mingw-32)
        DEPS="$DEPS mingw-w64-tools binutils-mingw-w64-i686 gcc-mingw-w64-i686"
        export ac_cv_func_malloc_0_nonnull=yes CC=i686-w64-mingw32-gcc AR=i686-w64-mingw32-ar RANLIB=i686-w64-mingw32-ranlib
        ;;
    mingw-64)
        DEPS="$DEPS mingw-w64-tools binutils-mingw-w64-x86-64 gcc-mingw-w64-x86-64"
        export ac_cv_func_malloc_0_nonnull=yes CC=x86_64-w64-mingw32-gcc AR=x86_64-w64-mingw32-ar RANLIB=x86_64-w64-mingw32-ranlib
        ;;
esac

case "$1" in
    ubuntu|coverity|mingw-32|mingw-64)
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
    mingw-32)
        test -d openssl || git clone --depth=1 https://github.com/openssl/openssl.git -b OpenSSL_1_0_2-stable openssl
        cd openssl
        ./Configure no-asm no-shared mingw -DPURIFY -static-libgcc
        make
        cd ..
        ;;
    mingw-64)
        test -d openssl || git clone --depth=1 https://github.com/openssl/openssl.git -b OpenSSL_1_0_2-stable openssl
        cd openssl
        ./Configure no-asm no-shared mingw64 -DPURIFY -static-libgcc
        make
        cd ..
        ;;
esac

autoreconf -vis

case "$1" in
    ubuntu|coverity)
        export GCCGOFLAGS="-static-libgcc $CFLAGS"
        ./configure --enable-python --enable-java --enable-ruby --enable-go
        ;;
    mingw-32)
        ./configure --host=i686-w64-mingw32   CRYPTO_CFLAGS="-I$PWD/openssl/include" CRYPTO_LIBS="-L$PWD/openssl -lcrypto" LDFLAGS=""
        ;;
    mingw-64)
        ./configure --host=x86_64-w64-mingw32 CRYPTO_CFLAGS="-I$PWD/openssl/include" CRYPTO_LIBS="-L$PWD/openssl -lcrypto"
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
    mingw-32|mingw-64|macos)
        make
        ;;
esac
