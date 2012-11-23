.. _bindings:

Bindings
========

pyPACE is a python wrapper for the `OpenPACE <http://openpace.sourceforge.net>`_
library. It's implemented using `SWIG <http://swig.org>`_ and therefore its's
easily portable to lots of different languages.

pyPACE is integrated into OpenPACE as of OpenPACE version 0.8.

.. toctree::

    python_api.rst

In order to use pyPACE you need to:

- Download and build OpenPACE
- Build pyPACE (needs to be linked against OpenPACE)
- Install pyPACE using distutils

Building pyPACE
---------------

Dependencies
^^^^^^^^^^^^

In order to build pyPACE you need to install the following packages:

- autoconf
- libtool
- gcc
- python-dev
- swig

Compiling
^^^^^^^^^

Once all the dependencies are installed, configuring and compiling pypace is easy::

    autoreconf -vsi
    ./configure PKG_CONFIG_PATH=/path/to/libeac.pc
    make
    make install

Make sure that OpenPACE is either statically linked against OpenSSL, or that
you link against a patched version of OpenSSL (see the OpenPACE Homepage for
details).

Running pyPACE
^^^^^^^^^^^^^^

In order to run programs that use pyPACE you have to set up the `LD_LIBRARY_PATH`
environment variable to point to the OpenPACE library. One way to do this is:

``export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/path/to/openpace/libs``

You also might need to setup the PYTHONPATH environment variable if you did not
install the bindings in a location already included in the PYTHONPATH.

In order to test your installation you can use the `test.py` script included in
pyPACE. Simply run the following command:

``python src/python/test.py``

Please note that currently does not work with python3.

JPace
-----

JPace is an (experimental) alternative to pyPACE for those who prefer to use
Java instead of python. In order to build JPace you need to pass the
``--enable-java`` parameter to configure. You also need to set the `JAVAC`
environment variable to your preferred java compiler.
