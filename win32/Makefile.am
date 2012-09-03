EXTRA_DIST = gentoo.config-1.0.0


all-local:
	@echo Use \`$(MAKE) win\` to cross compile for Windows

MINGW ?= x86_64-w64-mingw32

LIBEAC=$(WIN32_DIR)/bin/libeac.dll
MINGW_DIR=/usr/$(MINGW)
OPENSSL_BRANCH=OpenSSL_1_0_2-stable
OPENSSL_CONFIGURE=$(OPENSSL_DIR)/Configure
OPENSSL_DIR=$(abs_builddir)/openssl
OPENSSL_LIBEAY32=$(WIN32_DIR)/bin/libeay32.dll
OPENSSL_MAKEFILE=$(OPENSSL_DIR)/Makefile
WIN32_DIR=$(abs_top_builddir)/$(PACKAGE_TARNAME)-$(PACKAGE_VERSION)_win32


$(OPENSSL_CONFIGURE):
	$(CVS) -d anonymous@cvs.openssl.org:/openssl-cvs co -r$(OPENSSL_BRANCH) `basename $(OPENSSL_DIR)`

$(OPENSSL_MAKEFILE): $(OPENSSL_CONFIGURE)
	$(PATCH) --directory=$(OPENSSL_DIR) -p1 < $(abs_top_srcdir)/oids.patch
	cd $(OPENSSL_DIR) \
		&& $(OPENSSL_CONFIGURE) shared no-asm --cross-compile-prefix=$(MINGW)- --prefix=/ `$(abs_srcdir)/gentoo.config-1.0.0 $(MINGW)`

$(OPENSSL_LIBEAY32): $(OPENSSL_MAKEFILE)
	$(MAKE) -C $(OPENSSL_DIR) update
	$(MAKE) -C $(OPENSSL_DIR)
	$(MAKE) -C $(OPENSSL_DIR) install_sw INSTALL_PREFIX=$(WIN32_DIR)


$(LIBEAC): $(OPENSSL_LIBEAY32)
	cd $(abs_top_builddir) && ./configure \
		--prefix=/ \
		--host=$(MINGW) --target=$(MINGW) \
		PKG_CONFIG_SYSROOT_DIR=$(WIN32_DIR) \
		PKG_CONFIG_LIBDIR=$(WIN32_DIR)/lib/pkgconfig \
		CFLAGS=-I$(MINGW_DIR)/include \
		LDFLAGS=-L$(MINGW_DIR)/lib
	$(MAKE) -C $(abs_top_builddir) install DESTDIR=$(WIN32_DIR)


win: $(LIBEAC)

clean-local:
	rm -rf $(WIN32_DIR)

distclean-local:
	rm -rf $(OPENSSL_DIR)
