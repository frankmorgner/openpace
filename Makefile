#MAKEFLAGS         += -rR --no-print-directory

all: patch
	cd openssl-1.0.0-beta3 && ./config experimental-pace -g
	$(MAKE) -C openssl-1.0.0-beta3

patch: openssl-1.0.0-beta3
	# see http://rt.openssl.org/Ticket/Display.html?id=2092&user=guest&pass=guest
	[ ! -r openssl-1.0.0-beta3/crypto/cmac/cmac.h ] && \
	    patch -d openssl-1.0.0-beta3 --strip 1 < ibm4.patch && \
	    ln -sv ../../crypto/cmac/cmac.h openssl-1.0.0-beta3/include/openssl || \
	    echo Never mind.
	grep brainpool openssl-1.0.0-beta3/crypto/ec/ec_curve.c > /dev/null || \
	    patch -d openssl-1.0.0-beta3 --strip 1 < BP.patch
	[ ! -r openssl-1.0.0-beta3/crypto/pace/pace.h ] && \
	    patch -d openssl-1.0.0-beta3 --strip 1 < OpenPACE.patch && \
	    ln -sv ../../crypto/pace/pace.h openssl-1.0.0-beta3/include/openssl || \
	    echo Never mind.

openssl-1.0.0-beta3:
	wget http://www.openssl.org/source/openssl-1.0.0-beta3.tar.gz
	tar xzf openssl-1.0.0-beta3.tar.gz

clean: 
	rm -rf \
	    openssl-1.0.0-beta3.tar.gz \
	    openssl-1.0.0-beta3
