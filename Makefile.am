ACLOCAL_AMFLAGS = -I m4
SUBDIRS = src win32

EXTRA_DIST = libeac.pc.in bootstrap oids.patch

if WIN32
WS2_32 = -lws2_32
endif

do_subst = $(SED) \
	   -e 's,[@]PKG_REQUIRES[@],$(PKG_REQUIRES),g' \
	   -e 's,[@]PACKAGE_NAME[@],$(PACKAGE_NAME),g' \
	   -e 's,[@]VERSION[@],$(VERSION),g' \
	   -e 's,[@]WS2_32[@],$(WS2_32),g' \
	   -e 's,[@]exec_prefix[@],$(exec_prefix),g' \
	   -e 's,[@]includedir[@],$(includedir),g' \
	   -e 's,[@]libdir[@],$(libdir),g' \
	   -e 's,[@]prefix[@],$(prefix),g'

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libeac.pc

libeac.pc: libeac.pc.in
	$(do_subst) < $(srcdir)/libeac.pc.in > libeac.pc

win:
	$(MAKE) -C win32 $@

clean-local:
	rm -f libeac.pc

check-local:
	$(builddir)/src/eactest


# Install OpenSSL
install-openssl:
	$(MAKE) -C src $@
