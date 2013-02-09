EXTRA_DIST = gentoo.config-1.0.0


all-local:
	@echo Use \`$(MAKE) win\` to cross compile for Windows

win: $(LIBEAC)

clean-local:
	rm -rf $(WIN32_DIR)



MINGW     = i686-w64-mingw32
WIN32_DIR = $(abs_top_builddir)/$(PACKAGE_TARNAME)-$(PACKAGE_VERSION)_win32

LIBEAC    = $(WIN32_DIR)/bin/libeac.dll
MINGW_DIR = /usr/$(MINGW)



$(LIBEAC):
	test ! -r $(top_builddir)/Makefile \
		|| $(MAKE) -C $(top_builddir) maintainer-clean
	cd $(top_builddir) && ./configure \
		--prefix=/ \
		--host=$(MINGW) --target=$(MINGW) \
		--enable-openssl-install \
		OPENSSL_CONFIGURE_FLAGS="shared no-asm --cross-compile-prefix=$(MINGW)- --prefix=/ `$(abs_srcdir)/gentoo.config-1.0.0 $(MINGW)`"
		CFLAGS=-I$(MINGW_DIR)/include \
		LDFLAGS=-L$(MINGW_DIR)/lib
	$(MAKE) -C $(top_builddir) install DESTDIR=$(WIN32_DIR)
