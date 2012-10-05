How to install and use OpenPACE
===============================

OpenPACE is based on the `OpenSSL <http://www.openssl.org">`_ library. It
consists of a series of patches for OpenSSL:

- file:`BP.patch`: Adds the elliptic curves defined in `RFC 5639
  <http://tools.ietf.org/html/rfc5639>`_ to OpenSSL. It was originally written
  by Annie Yousar from Humboldt University Berlin.
- file:`ibm4.patch`: Adds support for CMAC as well as GCM and CCM mode for AES.
  This patch was `originally
  <http://rt.openssl.org/Ticket/Display.html?user=guest&amp;pass=guest&amp;id=2092>`_
  written by Peter Waltenberg from IBM. It has already been merged into the 1.1
  branch of OpenSSL.
- file:`openpace.patch`: Adds support for PACE and handling of CV Certificates.

These patches need to be applied OpenSSL 1.0.0d in the above order. We also
provide a version of OpenSSL that is already patched.

In order to compile and install OpenPACE you need to use the following
commands::

    ./config shared experimental-pace -g --prefix=/opt/openpace
    make
    make install

To use OpenPACE with your application you need to link it against libcrypto and
provide the path to include and library files to the compiler. Here's an
example of how a gcc call for a program using OpenPACE might look like::

    env LD_LIBRARY_PATH=/opt/openpace/lib gcc -o foo foo.c -I /opt/openpace/include -L /opt/openpace/lib -lcrypto
