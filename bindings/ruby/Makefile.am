INTERFACES = $(srcdir)/../ca.i \
			 $(srcdir)/../cvc.i \
			 $(srcdir)/../eac.i \
			 $(srcdir)/../pace.i \
			 $(srcdir)/../ta.i \
			 $(srcdir)/../objects.i \
			 $(srcdir)/../util.i

BUILT_SOURCES = pace_wrap.c

EXTRA_DIST = example.rb extconf.rb.in
CLEANFILES = $(BUILT_SOURCES)

do_subst=$(SED)\
	-e's,[@]prefix[@],$(prefix),g'\
	-e's,[@]CFLAGS[@],$(CFLAGS),g'\
	-e's,[@]LDFLAGS[@],$(LDFLAGS),g'\
	-e's,[@]CPPFLAGS[@],$(CPPFLAGS),g'\
	-e's,[@]CRYPTO_CFLAGS[@],$(CRYPTO_CFLAGS),g'\
	-e's,[@]CRYPTO_LIBS[@],'"$(CRYPTO_LIBS)"',g'\
	-e's,[@]OPENPACE_CFLAGS[@],-I$(abs_top_srcdir)/src,g'\
	-e's,[@]OPENPACE_LIBS[@],$(abs_top_builddir)/src/.libs/libeac.so,g'

$(BUILT_SOURCES): $(INTERFACES)

ext/extconf.rb: extconf.rb.in
	mkdir -p ext
	$(do_subst) < $(srcdir)/extconf.rb.in > ext/extconf.rb

pace_wrap.c:
	$(SWIG) -ruby -outdir $(builddir) -I$(srcdir)/.. pace.i

ext/Makefile: ext/extconf.rb pace_wrap.c $(top_builddir)/src/libeac.la
	cd ext && $(RUBY) extconf.rb

ext/pace.so: ext/Makefile
	$(MAKE) -C ext

all-local: ext/pace.so

clean-local:
	$(MAKE) clean -C ext

distclean-local:
	rm -rf ext

install-exec-local:
	$(MAKE) install -C ext
