#MAKEFLAGS         += -rR --no-print-directory

# workaround for old patch versions on Solaris
PATCH := $(shell [ -x /bin/gpatch ] && echo /bin/gpatch || echo patch)
# On Solaris you might also want to put the directories of the gnu-utils first
# in the path (see http://www.cozmanova.com/node/10)
# export PATH=/usr/local/bin:/usr/local/sbin:/usr/local/ssl/bin:/usr/sfw/sbin/:/usr/sfw/bin:/usr/sbin:/usr/bin:/usr/ccs/bin
#
OPENSSL_VERSION=1.0.0c

all: patch_with_openpace
	$(MAKE) Makefile -C openssl-$(OPENSSL_VERSION) || \
	    (cd openssl-$(OPENSSL_VERSION) && sleep 1 && ./config experimental-pace)
	$(MAKE) -C openssl-$(OPENSSL_VERSION)

# see http://rt.openssl.org/Ticket/Display.html?id=2092&user=guest&pass=guest
# This patch is modified to be compliant with OpenSSL $(OPENSSL_VERSION) 
patch_with_cmac: openssl-$(OPENSSL_VERSION)
	[ -r openssl-$(OPENSSL_VERSION)/crypto/cmac/cmac.h ] || (\
	    $(PATCH) -d openssl-$(OPENSSL_VERSION) -p1 < ibm4_2.patch && \
	    ln -s ../../crypto/cmac/cmac.h openssl-$(OPENSSL_VERSION)/include/openssl)
	echo "Patched OpenSSL with CMAC"

patch_with_brainpool: openssl-$(OPENSSL_VERSION)
	grep brainpool openssl-$(OPENSSL_VERSION)/crypto/ec/ec_curve.c > /dev/null || \
	    patch -d openssl-$(OPENSSL_VERSION) -p1 < BP.patch
	echo "Patched OpenSSL with Brainpool curves"

patch_with_openpace: patch_with_brainpool patch_with_cmac
	[ -r openssl-$(OPENSSL_VERSION)/crypto/pace/pace.h ] || (\
	    $(PATCH) -d openssl-$(OPENSSL_VERSION) -p1 < OpenPACE.patch && \
	    ln -s ../../crypto/pace/pace.h openssl-$(OPENSSL_VERSION)/include/openssl && \
	    ln -s ../crypto/pace/pacetest.c openssl-$(OPENSSL_VERSION)/test && \
	    ln -s ../../crypto/cv_cert/cv_cert.h openssl-$(OPENSSL_VERSION)/include/openssl && \
	    ln -s ../crypto/cv_cert/cv_cert_test.c openssl-$(OPENSSL_VERSION)/test)
	echo "Patched OpenSSL with OpenPACE"

test: all
	openssl-$(OPENSSL_VERSION)/util/shlib_wrap.sh openssl-$(OPENSSL_VERSION)/test/pacetest
	openssl-$(OPENSSL_VERSION)/util/shlib_wrap.sh openssl-$(OPENSSL_VERSION)/test/cv_cert_test -f cvca-eid.cv

openssl-$(OPENSSL_VERSION): openssl-$(OPENSSL_VERSION).tar.gz
	gunzip -c openssl-$(OPENSSL_VERSION).tar.gz | tar xf -

openssl-$(OPENSSL_VERSION).tar.gz:
	wget http://www.openssl.org/source/openssl-$(OPENSSL_VERSION).tar.gz

clean:
	rm -rf openssl-$(OPENSSL_VERSION)

dist-clean: clean
	rm -rf openssl-$(OPENSSL_VERSION).tar.gz
