INTERFACES = $(srcdir)/../ca.i \
			 $(srcdir)/../cvc.i \
			 $(srcdir)/../eac.i \
			 $(srcdir)/../pace.i \
			 $(srcdir)/../ta.i \
			 $(srcdir)/../objects.i \
			 $(srcdir)/../util.i

BUILT_SOURCES_SWIG = eacConstants.java \
					 eac.java \
					 eacJNI.java \
					 s_type.java \
					 SWIGTYPE_p_BUF_MEM.java \
					 SWIGTYPE_p_CVC_CERTIFICATE_DESCRIPTION.java \
					 SWIGTYPE_p_CVC_CERT.java \
					 SWIGTYPE_p_CVC_CHAT.java \
					 SWIGTYPE_p_EAC_CTX.java \
					 SWIGTYPE_p_PACE_SEC.java \
					 SWIGTYPE_p_p_BUF_MEM.java \
					 SWIGTYPE_p_p_char.java \
					 SWIGTYPE_p_size_t.java \
					 SWIGTYPE_p_unsigned_char.java \
					 eac_wrap.c

CLASSES_SWIG = SWIGTYPE_p_BUF_MEM.class \
			   SWIGTYPE_p_CVC_CERT.class \
			   SWIGTYPE_p_CVC_CERTIFICATE_DESCRIPTION.class \
			   SWIGTYPE_p_CVC_CHAT.class \
			   SWIGTYPE_p_EAC_CTX.class \
			   SWIGTYPE_p_PACE_SEC.class \
			   SWIGTYPE_p_p_BUF_MEM.class \
			   SWIGTYPE_p_p_char.class \
			   SWIGTYPE_p_size_t.class \
			   SWIGTYPE_p_unsigned_char.class \
			   eacConstants.class \
			   eacJNI.class \
			   s_type.class \
			   eac.class

CLASSES_EXAMPLE = EAC_Example.class

EXTRA_DIST = EAC_Example.java
CLEANFILES = $(CLASSES_SWIG) $(CLASSES_EXAMPLE) $(BUILT_SOURCES_SWIG)

lib_LTLIBRARIES = libjeac.la

openpace_javadir = $(pkgdatadir)/java
openpace_java_DATA = EAC_Example.java $(CLASSES_EXAMPLE) $(CLASSES_SWIG)

libjeac_la_SOURCES = eac_wrap.c
libjeac_la_CFLAGS  = -I$(top_srcdir)/src $(CRYPTO_CFLAGS) $(JAVA_CFLAGS)
libjeac_la_LDFLAGS = $(top_builddir)/src/libeac.la $(CRYPTO_LIBS)

$(BUILT_SOURCES_SWIG): $(INTERFACES)
	$(SWIG) -java -outdir $(builddir) -o eac_wrap.c -I$(srcdir)/.. $(srcdir)/../eac.i

libjeac_la-local: $(BUILT_SOURCES_SWIG)

all-local: $(CLASSES_EXAMPLE)

$(CLASSES_EXAMPLE): $(srcdir)/EAC_Example.java $(BUILT_SOURCES_SWIG)
	$(JAVAC) $(JAVACFLAGS) -d $(builddir) -sourcepath $(builddir) $(srcdir)/EAC_Example.java

%.class: %.java
	$(JAVAC) $(JAVACFLAGS) -d $(builddir) -sourcepath $(builddir) $*.java
