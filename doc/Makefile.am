SUBDIRS = _static bindings

EXTRA_DIST = Doxyfile.in conf.py.in index.rst.in index.rst protocols.rst protocols.rst Makefile.sphinx

do_subst = $(SED) \
	   -e 's,[@]PACKAGE_NAME[@],$(PACKAGE_NAME),g' \
	   -e 's,[@]PACKAGE_BUGREPORT[@],$(PACKAGE_BUGREPORT),g' \
	   -e 's,[@]PACKAGE_VERSION[@],$(PACKAGE_VERSION),g'


doc: $(top_srcdir)/src/eac/*.h *.in
	$(do_subst) < Doxyfile.in > Doxyfile
	doxygen Doxyfile
	$(do_subst) < conf.py.in > conf.py
	$(do_subst) < index.rst.in > index.rst
	env LD_LIBRARY_PATH=`pwd`/../bindings/python:`pwd`/../src/.libs:`pwd`/../src/openssl \
		DYLD_LIBRARY_PATH=$${LD_LIBRARY_PATH} SHLIB_PATH=$${LD_LIBRARY_PATH} LIBPATH=$${LD_LIBRARY_PATH} \
		$(MAKE) -f Makefile.sphinx html
	touch doc
