EXTRA_DIST = gentoo.config-1.0.0


all-local:
	@echo Use \`$(MAKE) win\` to cross compile for Windows
	@echo Use \`$(MAKE) android\` to cross compile for Android
	@echo Use \`$(MAKE) emscripten\` to cross compile for Javascript



EMSCRIPTEN_DIR ?= ${HOME}/.local/src/emscripten
EMSCRIPTEN_TARGETDIR = $(abs_top_builddir)/$(PACKAGE_TARNAME)-$(PACKAGE_VERSION)_bc

emscripten:
	cd $(top_builddir) && emconfigure ./configure \
		--prefix=/ \
		--enable-openssl-install \
		CFLAGS="-O2 -Wno-warn-absolute-paths" \
		OPENSSL_CONFIGURE_FLAGS="no-asm no-shared no-hw no-threads no-dso --prefix=/ BSD-x86 -I$(EMSCRIPTEN_DIR)/system/include/libc -O2 -Wno-warn-absolute-paths"
	emmake $(MAKE) -C $(top_builddir) install DESTDIR=$(EMSCRIPTEN_TARGETDIR)
	emcc -O2 $(top_builddir)/src/eactest-eactest.o $(EMSCRIPTEN_TARGETDIR)/lib/libeac.a $(EMSCRIPTEN_TARGETDIR)/lib/libcrypto.a -o $(EMSCRIPTEN_TARGETDIR)/eactest.html
	emcc -O2 $(top_builddir)/src/eactest-eactest.o $(EMSCRIPTEN_TARGETDIR)/lib/libeac.a $(EMSCRIPTEN_TARGETDIR)/lib/libcrypto.a -o $(EMSCRIPTEN_TARGETDIR)/eactest.js



WIN_TOOL ?= i686-w64-mingw32
WIN_TOOL_DIR ?= /usr/$(WIN_TOOL)
WIN_TARGETDIR = $(abs_top_builddir)/$(PACKAGE_TARNAME)-$(PACKAGE_VERSION)_win32

win:
	$(MAKE) cross \
		TOOL=$(WIN_TOOL) \
		TOOL_DIR=$(WIN_TOOL_DIR) \
		TARGETDIR=$(WIN_TARGETDIR) \
		ENABLE_PYTHON="" \
		LIBEAC=$(WIN_TARGETDIR)/bin/libeac-0.dll



ANDROID_ARCH ?= arm
ANDROID_TOOL ?= $(ANDROID_ARCH)-linux-androideabi
ANDROID_TOOL_DIR ?= $(abs_builddir)/ndk
ANDROID_TARGETDIR = $(abs_top_builddir)/$(PACKAGE_TARNAME)-$(PACKAGE_VERSION)_$(ANDROID_ARCH)
MAKE_STANDALONE_TOOLCHAIN ?= $${HOME}/.local/opt/android-ndk-r9/build/tools/make-standalone-toolchain.sh

android:
	test -d $(ANDROID_TOOL_DIR) \
		|| $(MAKE_STANDALONE_TOOLCHAIN) --install-dir=$(ANDROID_TOOL_DIR) --arch=$(ANDROID_ARCH)
	env PATH=$(ANDROID_TOOL_DIR)/bin:$${PATH} $(MAKE) cross \
		TOOL=$(ANDROID_TOOL) \
		TOOL_DIR=$(ANDROID_TOOL_DIR) \
		TARGETDIR=$(ANDROID_TARGETDIR) \
		ENABLE_PYTHON=--enable-python \
		LIBEAC=$(ANDROID_TARGETDIR)/lib/libeac.so



clean-local:
	rm -rf $(TARGETDIR)



CROSS_COMPILE = $(TOOL)-

cross: $(LIBEAC)

$(LIBEAC):
	cd $(top_builddir) && ./configure \
		--prefix=/ \
		--host=$(TOOL) --target=$(TOOL) \
		--enable-openssl-install \
		$(ENABLE_PYTHON) \
		CFLAGS="-I$(TOOL_DIR)/include -I$(TOOL_DIR)/include/python2.7" \
		LDFLAGS=-L$(TOOL_DIR)/lib
	env CROSS_COMPILE=$(CROSS_COMPILE) \
		$(MAKE) -C $(top_builddir) install DESTDIR=$(TARGETDIR)
