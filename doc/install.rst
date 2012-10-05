How to install and use OpenPACE
===============================

OpenPACE can uses GNU autotools and therefore can be easily build using the
following commands::

    autoreconf -si
    ./configure
    make
    make install

OpenPACE depends on the `OpenSSL <http://openssl.org>`_ library. Since PACE
uses CMAC, the currently unreleased version 1.0.2 of OpenSSL is required.
Furthermore, OpenPACE requires additional Object Identifiers (OIDs) and
therefore needs a patched version of OpenSSL. Due to these special
requirements, the make command downloads a recent snapshot of OpenSSL, applies
the necessary patches and builds OpenSSL. The OpenPACE library is then
statically linked against this local version of OpenSSL. This process can be
customized by a number of parameters for the `configure` command. See
`./configure -h` for details.
