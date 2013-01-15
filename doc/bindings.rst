.. _bindings:

Including OpenPACE in other programming languages
=================================================

OpenPACE uses `SWIG <http://swig.org>`_ to offer bindings in other programming
languages. [#f1]_ The bindings are easily portable to lots of different
languages. Currently OpenPACE encompasses easy-to-use wrappers for Python and
Java.

.. toctree::
    :hidden:

    python_api.rst


Using OpenPACE in Python
------------------------

In order to run programs that use pyPACE you have to set up the `LD_LIBRARY_PATH`
environment variable to point to the OpenPACE library. One way to do this is::

    export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/path/to/libeac

You also might need to setup the PYTHONPATH environment variable if you did not
install the bindings in a location already included in the PYTHONPATH.

In order to test your installation you can use the ``test.py`` script included in
OpenPACE. Simply run the following command::

    python src/python/test.py

Please note that currently the Python bindings do not work with Python 3.

You may have a look at the `Emulator for the German Identity Card
<http://vsmartcard.sourceforge.net/virtualsmartcard/README.html>`_ to see the
Python bindings in action. Unfortunately, OpenPACE's Python bindings are
currently :ref:`poorly documented <python_api>`.


Using OpenPACE in Java
----------------------

The OpenPACE Java bindings are experimental and currently disabled by default.
You need to configure OpenPACE with ``--enable-java`` to build and install
them. You may set the `JAVAC` environment variable to your preferred Java
compiler.


.. [#f1]
    `pyPACE <http://pypace.sourceforge.net>`_ has been integrated into OpenPACE
    as of version 0.8.
