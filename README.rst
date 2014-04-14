
Welcome to OpenPACE's documentation!
************************************

[image]


Summary
^^^^^^^

Cryptographic library for EAC version 2

:Authors:
   * Frank Morgner

   * Dominik Oepen

:License:
   GPL version 3

:Tested Platforms:
   * Windows

   * Linux (Debian, Ubuntu, SUSE, OpenMoko)

   * FreeBSD

   * Mac OS

   * Solaris

   * Android

   * Javascript

OpenPACE implements Extended Access Control (EAC) version 2 as
specified in BSI TR-03110 [1]. OpenPACE comprises support for the
following protocols:

:Password Authenticated Connection Establishment (PACE):
   Establish a secure channel with a strong key between two parties
   that only share a weak secret.

:Terminal Authentication (TA):
   Verify/prove the terminal's certificate (or rather certificate
   chain) and secret key.

:Chip Authentication (CA):
   Establish a secure channel based on the chip's static key pair
   proving its authenticy.

Furthermore, OpenPACE also supports Card Verifiable Certificates (CV
Certificates) as well as easy to use wrappers for using the
established secure channels.

The handlers for looking up trust anchors during TA (Terminal
Authenticatation) and CA (Chip Authentication) (i.e. the CSCA (Country
Verifying Certificate Authority) and the CSCA (Country Signing
Certificate Authority) certificates) can be customized. By default,
the appropriate certificates will be looked up in the file system.

OpenPACE supports all variants of PACE (Password Authenticated
Connection Establishment) (DH/ECDH, GM/IM), TA (Terminal
Authenticatation) (RSASSA-PKCS1-v1_5/RSASSA-PSS/ECDSA), CA (Chip
Authentication) (DH/ECDH) and all standardized domain parameters
(GFP/ECP).

OpenPACE is implemented as C-library and comes with native language
wrappers for:

* Python

* Ruby

* Javascript

* Java

* Go

Note: OpenPACE only implements the cryptographic protocols of the EAC
  (Extended Access Control). If you actually want to exchange data
  with a smart card, you need to take care of formatting and sending
  the data in the form of APDUs. If this is what you're trying to do,
  you should have a look at the **npa-tool** of the nPA Smart Card
  Library [2].


Download OpenPACE
=================

You can find the latest release of OpenPACE on Sourceforge.

Alternatively, you can clone our git repository:

::

   git clone git://git.code.sf.net/p/openpace/git openpace


Install OpenPACE
================

OpenPACE uses the GNU Build System to compile and install. If you are
unfamiliar with it, please have a look at ``INSTALL``. If you can not
find it, you are probably working bleeding edge in the repository.
Run the following command in ``openpace`` to get the missing standard
auxiliary files:

::

   autoreconf --verbose --install

To configure (**configure --help** lists possible options), build and
install OpenPACE now do the following:

::

   ./configure
   make
   make install

OpenPACE depends on the OpenSSL [3] library. Since PACE (Password
Authenticated Connection Establishment) uses CMAC and the Brainpool
curves, the currently unreleased version 1.0.2 of OpenSSL is required.

Furthermore, additional object identifiers from BSI TR-03110 [1] are
required. You have two options to get them to work:

1. Let OpenPACE load the object identifiers at runtime

2. Patch OpenSSL to include the identifiers

The first option allows you to install an unchanged version of OpenSSL
to your system. However, performance will be slightly worse and there
are some limitations. For example, you won't be able to use the new
NIDs as labels in a switch statement and you need to make sure to call
``EAC_init()`` first.  For patching OpenSSL we provide ``oids.patch``.
You can configure OpenPACE with *--enable-openssl-install*, which will
automatically download, patch, build and install OpenSSL if needed.


Cross compiling OpenPACE
------------------------

We have added some scripts for the ease of cross compiling for Windows
and Android. Both are tested with Debian wheezy. First create a
working ``Makefile``:

::

   test -x configure || autoreconf --verbose --install
   ./configure


Compiling for Windows
~~~~~~~~~~~~~~~~~~~~~

Cross compilation for Windows can be done with:

::

   make win

+------------------+----------------------+---------------------------------------------------------------------------------------------+
| Make Variable    | Default              | Meaning                                                                                     |
+==================+======================+=============================================================================================+
| ``WIN_TOOL``     | ``i686-w64-mingw32`` | cross compiler                                                                              |
+------------------+----------------------+---------------------------------------------------------------------------------------------+
| ``WIN_TOOL_DIR`` | ``/usr/${WIN_TOOL}`` | root directory of the cross compiler containing the ``lib`` and ``include`` folders         |
+------------------+----------------------+---------------------------------------------------------------------------------------------+

On successfull compilation, the Windows binaries can be found in
``openpace-0.9_win32``.


Compiling for Android
~~~~~~~~~~~~~~~~~~~~~

Cross compilation for Android can be done with:

::

   make android

+-------------------------------+--------------------------------------------------------------------------------+-------------------------------------------------------+
| Make Variable                 | Default                                                                        | Meaning                                               |
+===============================+================================================================================+=======================================================+
| ``ANDROID_ARCH``              | ``arm``                                                                        | target Architecture                                   |
+-------------------------------+--------------------------------------------------------------------------------+-------------------------------------------------------+
| ``ANDROID_TOOL``              | ``${ANDROID_ARCH}-linux-androideabi``                                          | cross compiler                                        |
+-------------------------------+--------------------------------------------------------------------------------+-------------------------------------------------------+
| ``MAKE_STANDALONE_TOOLCHAIN`` | ``${HOME}/.local/opt/android-ndk-r9/build/tools/make-standalone-toolchain.sh`` | location of the NDK script for creating the toolchain |
+-------------------------------+--------------------------------------------------------------------------------+-------------------------------------------------------+

On successfull compilation, the Android binaries can be found in
``openpace-0.9_$*ANDROID_ARCH*``.

.. _javascript-api:


Compiling for Javascript
~~~~~~~~~~~~~~~~~~~~~~~~

Technically the process for getting OpenPACE into Javascript is
similar to cross compiling. With Emscripten [5] the library is
compiled into LLVM bytecode and then translated into Javascript. Use
the following command:

::

   make emscripten

+-------------------------------+------------------------------------+--------------------------------------------------------------------------------+
| Make Variable                 | Default                            | Meaning                                                                        |
+===============================+====================================+================================================================================+
| ``EMSCRIPTEN_DIR``            | ``${HOME}/.local/src/emscripten``  | root directory of emscripten containing the ``system/include/libc`` folder     |
+-------------------------------+------------------------------------+--------------------------------------------------------------------------------+

On successfull compilation, the compiled bitcode files can be found in
``openpace-0.9_bc``. You can run our testsuite completely in
Javascript or in your browser:

::

   nodejs openpace-0.9_bc/eactest.js
   # WARNING: Our tests are very time consuming and might stall your browser for a moment or two...
   firefox openpace-0.9_bc/eactest.html

Warning: Javascript cryptography is considered harmful [6]. You may want to
  think twice before using the Javascript version of OpenPACE.


How to use OpenPACE
===================

OpenPACE is a native C library on top of OpenSSL. If you want to know
how to use OpenPACE from C/C++, have a look at our API documentation.

OpenPACE uses SWIG [4] to offer bindings in some more programming
languages. The bindings are easily portable to lots of different
languages. Currently, native language bindings need to be explicitly
turned on with ``./configure --enable-...``

If you have chosen to install OpenPACE in a non-standard location you
have to set up the ``LD_LIBRARY_PATH`` environment variable correctly.
One way to do this is:

::

   export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/path/to/libeac

If OpenPACE is compiled for Javascript, it results in a standalone
Javascript file that can be used without special requirements.

More details and a number of examples are covered here:

* `Usage of OpenPACE <usage.rst>`_
  * `Using OpenPACE in C/C++ <usage.rst#using-openpace-in-c-c>`_
  * `Using OpenPACE in Python <usage.rst#using-openpace-in-python>`_
  * `Using OpenPACE in Ruby <usage.rst#using-openpace-in-ruby>`_
  * `Using OpenPACE in Go <usage.rst#using-openpace-in-go>`_
  * `Using OpenPACE in Java <usage.rst#using-openpace-in-java>`_
  * `Using OpenPACE in Javascript
    <usage.rst#using-openpace-in-javascript>`_
  * `References <usage.rst#references>`_

Where to get help
=================

Do you have questions, suggestions or contributions? Feedback of any
kind is more than welcome! You can contact us through our GitHub
repositories or the project trackers.


Further Reading
===============

* `Extended Access Control Specification <protocols.rst>`_
  * `Password Authenticated Connection Establishment
    <protocols.rst#password-authenticated-connection-establishment>`_
    * `Protocol Specification <protocols.rst#protocol-specification>`_
    * `ECDH Mapping <protocols.rst#ecdh-mapping>`_
    * `DH Mapping <protocols.rst#dh-mapping>`_
  * `Terminal Authentication <protocols.rst#terminal-authentication>`_
    * `Protocol Specification <protocols.rst#id3>`_
  * `Chip Authentication <protocols.rst#chip-authentication>`_
    * `Protocol Specification <protocols.rst#id4>`_
  * `References <protocols.rst#references>`_

References
==========

[1] https://www.bsi.bund.de/ContentBSI/Publikationen/TechnischeRichtlinien/tr03110/index_htm.html

[2] http://vsmartcard.sourceforge.net/npa/README.html

[3] http://openssl.org

[4] http://swig.org

[5] https://github.com/kripken/emscripten

[6] http://www.matasano.com/articles/javascript-cryptography
