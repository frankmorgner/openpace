INTERFACES = $(srcdir)/../ca.i \
			 $(srcdir)/../cvc.i \
			 $(srcdir)/../eac.i \
			 $(srcdir)/../pace.i \
			 $(srcdir)/../ta.i \
			 $(srcdir)/../objects.i \
			 $(srcdir)/../util.i

BUILT_SOURCES = pace_wrap.c

EXTRA_DIST = example.go
CLEANFILES = $(BUILT_SOURCES) pace.go

lib_LTLIBRARIES = libgopace.la

libgopace_la_SOURCES = pace_wrap.c
libgopace_la_CFLAGS  = -I$(top_srcdir)/src $(CRYPTO_CFLAGS)
libgopace_la_LDFLAGS = $(top_builddir)/src/libeac.la $(CRYPTO_LIBS)

$(BUILT_SOURCES): $(INTERFACES)
	$(SWIG) -go -gccgo -intgosize 32 -outdir $(builddir) -I$(srcdir)/.. pace.i

pace.o: $(BUILT_SOURCES)
	$(GCCGO) -c pace.go

example.o: example.go
	$(GCCGO) -c example.go

example: example.o pace.o
	$(GCCGO) example.o pace.o libgopace_la-pace_wrap.o $(top_builddir)/src/.libs/libeac.a $(CRYPTO_LIBS) -o example

all-local: pace.o example

clean-local:
	rm -f example example.o
	rm -f pace.o

distclean-local:
	rm -f $(BUILT_SOURCES)
