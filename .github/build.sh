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
        ;;
    mingw-64)
        DEPS="$DEPS mingw-w64-tools binutils-mingw-w64-x86-64 gcc-mingw-w64-x86-64"
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

autoreconf -vis

case "$1" in
    ubuntu|coverity)
        export GCCGOFLAGS="-static-libgcc $CFLAGS"
        ./configure --enable-python --enable-java --enable-ruby --enable-go
        ;;
    mingw-32|mingw-64|macos)
        ./configure --enable-openssl-install
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
    mingw-32)
        make win WIN_TOOL=i686-w64-mingw32
        ;;
    mingw-64)
        make win WIN_TOOL=x86_64-w64-mingw32
        ;;
    macos)
        make osx
        ;;
esac
