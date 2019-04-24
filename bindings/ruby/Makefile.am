INTERFACES = $(srcdir)/../ca.i \
			 $(srcdir)/../cvc.i \
			 $(srcdir)/../eac.i \
			 $(srcdir)/../ta.i \
			 $(srcdir)/../objects.i \
			 $(srcdir)/../util.i

BUILT_SOURCES = eac_wrap.c

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

ext/extconf.rb: $(srcdir)/extconf.rb.in
	mkdir -p ext
	@$(do_subst) < $(srcdir)/extconf.rb.in > ext/extconf.rb

eac_wrap.c:
	$(SWIG) -ruby -outdir $(builddir) -o eac_wrap.c -I$(srcdir)/.. $(srcdir)/../eac.i

ext/Makefile: ext/extconf.rb eac_wrap.c $(top_builddir)/src/libeac.la
	cd ext && $(RUBY) extconf.rb
	echo '' >> ext/Makefile
	echo 'uninstall:' >> ext/Makefile
	echo '	$$(RM) $$(RUBYARCHDIR)/$$(DLLIB)' >> ext/Makefile

ext/eac.so: ext/Makefile
	$(MAKE) -C ext

all-local: ext/eac.so

clean-local:
	$(MAKE) clean -C ext || true

distclean-local:
	rm -rf ext

install-exec-local:
	rm -f ext/.RUBYARCHDIR.time
	(test -z "$(DESTDIR)" \
		&& $(MAKE) install -C ext DESTDIR=$(prefix)) \
		|| $(MAKE) install -C ext DESTDIR=$(DESTDIR)

uninstall-local:
	(test -z "$(DESTDIR)" \
		&& $(MAKE) uninstall -C ext DESTDIR=$(prefix)) \
		|| $(MAKE) uninstall -C ext DESTDIR=$(DESTDIR)
