EXTRA_DIST = JPace.java

lib_LTLIBRARIES = libjpace.la

libjpace_la_SOURCES = pace_wrap.c
libjpace_la_CFLAGS = $(OPENPACE_CFLAGS) $(OPENSSL_CFLAGS) $(JAVA_INCLUDES)
libjpace_la_LDFLAGS = $(OPENPACE_LIBS) $(OPENSSL_LIBS)

pace_wrap.c:
	$(SWIG) -java -outdir $(builddir) -I$(top_srcdir)/src pace.i


all-local: JPace.class

JPace.class: JPace.java pace_wrap.c
	$(JAVAC) -d $(builddir) -sourcepath $(srcdir) $(srcdir)/JPace.java

clean-local:
	rm -f *.class pace_wrap.c
	rm -f SWIGTYPE_p_*.java pace*.java s_type.java
