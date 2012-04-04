#MAKEFLAGS         += -rR --no-print-directory

# workaround for old patch versions on Solaris
PATCH := $(shell [ -x /bin/gpatch ] && echo /bin/gpatch || echo patch)
# On Solaris you might also want to put the directories of the gnu-utils first
# in the path (see http://www.cozmanova.com/node/10)
# export PATH=/usr/local/bin:/usr/local/sbin:/usr/local/ssl/bin:/usr/sfw/sbin/:/usr/sfw/bin:/usr/sbin:/usr/bin:/usr/ccs/bin
#
OPENSSL_VERSION=1.0.1

all: patch_with_openpace
	$(MAKE) Makefile -C openpace || \
	    (cd openpace && sleep 1 && ./config experimental-pace)
	$(MAKE) -C openpace

patch_with_brainpool: openpace
	grep brainpool openpace/crypto/ec/ec_curve.c > /dev/null || \
	    patch -d openpace -p1 < BP.patch
	echo "Patched OpenSSL with Brainpool curves"

patch_with_openpace: patch_with_brainpool
	[ -r openpace/crypto/eac/pace.h ] || (\
	    $(PATCH) -d openpace -p1 < OpenPACE.patch && \
	    ln -s ../../crypto/eac/pace.h openpace/include/openssl && \
	    ln -s ../crypto/eac/eactest.c openpace/test && \
	    ln -s ../../crypto/eac/cv_cert.h openpace/include/openssl && \
	    ln -s /../crypto/eac/cv_cert_test.c openpace/test && \
	    ln -s ../../crypto/eac/ta.h openpace/include/openssl && \
	    ln -s ../../crypto/eac/ca.h openpace/include/openssl && \
	    ln -s ../../crypto/eac/eac.h openpace/include/openssl)
	echo "Patched OpenSSL with OpenPACE"

test: all
	openpace/util/shlib_wrap.sh openpace/test/eactest
	for file in cv_cert/*.cvcert; do \
		openpace/util/shlib_wrap.sh \
			openpace/test/cv_cert_test -f "$$file"; \
		done

openpace: openssl-$(OPENSSL_VERSION)
	cp -r openssl-$(OPENSSL_VERSION) openpace

openssl-$(OPENSSL_VERSION): openssl-$(OPENSSL_VERSION).tar.gz
	gunzip -c openssl-$(OPENSSL_VERSION).tar.gz | tar xf -

openssl-$(OPENSSL_VERSION).tar.gz:
	wget http://www.openssl.org/source/openssl-$(OPENSSL_VERSION).tar.gz

clean:
	rm -rf openpace

dist-clean: clean
	rm -rf openssl-$(OPENSSL_VERSION) openssl-$(OPENSSL_VERSION).tar.gz
