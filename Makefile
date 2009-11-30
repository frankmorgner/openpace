#MAKEFLAGS         += -rR --no-print-directory

all: patch
	$(MAKE) Makefile -C openssl-1.0.0-beta4 || \
	    (cd openssl-1.0.0-beta4 && sleep 1 && ./config experimental-pace -g)
	$(MAKE) -C openssl-1.0.0-beta4

patch: openssl-1.0.0-beta4
	# see http://rt.openssl.org/Ticket/Display.html?id=2092&user=guest&pass=guest
	[ ! -r openssl-1.0.0-beta4/crypto/cmac/cmac.h ] && \
	    patch -d openssl-1.0.0-beta4 -p1 < ibm4.patch && \
	    ln -s ../../crypto/cmac/cmac.h openssl-1.0.0-beta4/include/openssl || \
	    echo Never mind.
	grep brainpool openssl-1.0.0-beta4/crypto/ec/ec_curve.c > /dev/null || \
	    patch -d openssl-1.0.0-beta4 -p1 < BP.patch
	[ ! -r openssl-1.0.0-beta4/crypto/pace/pace.h ] && \
	    patch -d openssl-1.0.0-beta4 -p1 < OpenPACE.patch && \
	    ln -s ../../crypto/pace/pace.h openssl-1.0.0-beta4/include/openssl || \
	    echo Never mind.

openssl-1.0.0-beta4: openssl-1.0.0-beta4.tar.gz
	tar xzf openssl-1.0.0-beta4.tar.gz

openssl-1.0.0-beta4.tar.gz:
	wget http://www.openssl.org/source/openssl-1.0.0-beta4.tar.gz

clean: 
	rm -rf \
	    openssl-1.0.0-beta4.tar.gz \
	    openssl-1.0.0-beta4
