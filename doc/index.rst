.. highlight:: sh

************************************
Welcome to OpenPACE's documentation!
************************************

.. include:: ../README

.. toctree::
    :hidden:

    protocols
    bindings/README.rst

Where to download OpenPACE
==========================

You can find the latest release of OpenPACE `here
<http://sourceforge.net/projects/openpace/>`_

Alternatively, you can clone our git repository::

    git clone git://openpace.git.sourceforge.net/gitroot/openpace/openpace

.. include install

How to install OpenPACE
=======================

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

How to use OpenPACE
===================

If you want to know how to use OpenPACE, have a look at our `API documentation
<_static/doxygen/html/modules.html>`_.

If you want to lear more about the EAC protocols, you can find a nice
:ref:`summary <protocols>`.

If you don't want to use C but another programming language for your project,
you can use our SWIG based :ref:`bindings`.

Where to get help
=================


If you find a bug or want to add a feature to OpenPACE, please use our `trackers
<http://sourceforge.net/tracker/?group_id=283121>`_ for contacting us.

