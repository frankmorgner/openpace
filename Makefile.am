ACLOCAL_AMFLAGS = -I m4
SUBDIRS = src win32 bindings

EXTRA_DIST = libeac.pc.in bootstrap oids.patch
DISTCHECK_CONFIGURE_FLAGS = --enable-python --enable-java

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

if PYTHON_ENABLED
check-local: test-test.py test-eactest

else
check-local: test-eactest

endif

test-eactest:
	$(builddir)/src/eactest

test-test.py:
	cp $(builddir)/bindings/python/build/*/_pace.*so $(builddir)/bindings/python
	env LD_LIBRARY_PATH=$(abs_builddir)/bindings/python:$(abs_builddir)/src/.libs:$(abs_builddir)/src/openssl \
		DYLD_LIBRARY_PATH=$${LD_LIBRARY_PATH} SHLIB_PATH=$${LD_LIBRARY_PATH} LIBPATH=$${LD_LIBRARY_PATH}\
		PYTHONPATH=$(abs_builddir)/bindings/python \
		$(PYTHON) $(srcdir)/bindings/python/test.py \
		|| (rm $(builddir)/bindings/python/_pace.*so && false)
	rm $(builddir)/bindings/python/_pace.*so
