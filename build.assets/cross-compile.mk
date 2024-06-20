# Makefile for building cross-compilers with crosstool-ng, building
# the third-party C library dependencies for Teleport.

ARCH ?= $(shell go env GOARCH)

# Default parallelism of builds
NPROC ?= $(shell nproc)

# mk_dir = $(shell git rev-parse --show-toplevel)/build.assets
mk_dir = $(dir $(firstword $(MAKEFILE_LIST)))
BUILDDIR = $(abspath $(mk_dir)/../build)

# THIRDPARTY_DIR is the root of where third-party libraries and programs are
# downloaded, built and installed.
THIRDPARTY_DIR ?= $(BUILDDIR)/thirdparty

# THIRDPARTY_DLDIR holds downloaded tarballs of third-party libraries and
# programs so we don't have to keep downloading them. It is safe to delete.
THIRDPARTY_DLDIR = $(THIRDPARTY_DIR)/download

# THIRDPARTY_PREFIX is the root of where architecture-specific third-party
# libraries are installed. Each architecture has its own directory as libraries
# are architecture-specific. THIRDPARTY_SRCDIR is the directory where the source
# for third-party is extracted and built. Each architecture has its own
# extracted source as the build is done within the source tree.
THIRDPARTY_PREFIX = $(THIRDPARTY_DIR)/$(ARCH)
THIRDPARTY_SRCDIR = $(THIRDPARTY_PREFIX)/src

# THIRDPARTY_HOST_PREFIX is the root of where host-specific third-party
# programs are installed, such as ct-ng and the compilers it builds. These
# run on the host that is running the build, regardless of that host
# architecture. THIRDPARTY_HOST_SRCDIR is the directory where the source
# for host-specific third-party applications is extracted and built.
THIRDPARTY_HOST_PREFIX = $(THIRDPARTY_DIR)/host
THIRDPARTY_HOST_SRCDIR = $(THIRDPARTY_HOST_PREFIX)/src

# -----------------------------------------------------------------------------
# tp-src-dir and tp-src-host-dir expand to the source directory for a third-
# party source directory which has the version of the source appended. It
# is used with `$(call ...)`, like `$(call tp-src-dir,zlib)` or
# `$(call tp-src-host-dir,ctng)`.
tp-src-dir = $(THIRDPARTY_SRCDIR)/$1-$($1_VERSION)
tp-src-host-dir = $(THIRDPARTY_HOST_SRCDIR)/$1-$($1_VERSION)

# -----------------------------------------------------------------------------
# crosstool-ng
#
# crosstool-ng is a host tool - it runs on the build host. It is installed in
# $(THIRDPARTY_HOST_PREFIX).

ctng_VERSION = 1.26.0
ctng_GIT_REF = crosstool-ng-$(ctng_VERSION)
ctng_GIT_REF_HASH = 334f6d6479096b20e80fd39e35f404319bc251b5
ctng_GIT_REPO = https://github.com/crosstool-ng/crosstool-ng
ctng_SRCDIR = $(call tp-src-host-dir,ctng)

.PHONY: install-ctng
install-ctng: fetch-git-ctng
	cd $(ctng_SRCDIR) && ./bootstrap
	cd $(ctng_SRCDIR) && ./configure --prefix=$(THIRDPARTY_HOST_PREFIX)
	$(MAKE) -C $(ctng_SRCDIR) -j$(NPROC)
	$(MAKE) -C $(ctng_SRCDIR) install

# -----------------------------------------------------------------------------
# Crosstool-ng compilers
#
# We use crosstool-ng, installed in $(THIRDPARTY_HOST_PREFIX) to build a
# compiler and glibc for each of the architectures: amd64, arm64, 386 and arm.
# These architecture names are as Go names them. The architecture of the
# toolchain to build is specified by the $(ARCH) variable.

CTNG_BUILDDIR = $(THIRDPARTY_PREFIX)/ctng
$(CTNG_BUILDDIR):
	mkdir -p $@

# Run a ctng command, copying the architecture-specific config into a build directory
# and saving it again after if it has changed. Useful to reconfigure and to build
# ctng. e.g.:
# make ARCH=amd64 ctng-menuconfig
# make ARCH=amd64 ctng-build
CTNG_DEFCONFIG = $(CTNG_BUILDDIR)/defconfig
CTNG_CONFIG = $(CTNG_BUILDDIR)/.config

# Create a defconfig if it does not exist
$(mk_dir)/ct-ng-configs/$(ARCH).defconfig:
	touch $@

# Copy the defconfig into the build dir
$(CTNG_DEFCONFIG): $(mk_dir)/ct-ng-configs/$(ARCH).defconfig | $(CTNG_BUILDDIR)
	cp $^ $@

# Create an expanded config from the defconfig
$(CTNG_CONFIG): $(CTNG_DEFCONFIG)
	cd $(CTNG_BUILDDIR) && $(THIRDPARTY_HOST_PREFIX)/bin/ct-ng defconfig

# Run `ct-ng menuconfig` on the arch-specific config from the defconfig in build.assets
# and copy it back when finished with menuconfig
.PHONY: ctng-menuconfig
ctng-menuconfig: $(CTNG_CONFIG) | $(CTNG_BUILDDIR)
	cd $(CTNG_BUILDDIR) && $(THIRDPARTY_HOST_PREFIX)/bin/ct-ng menuconfig
	cd $(CTNG_BUILDDIR) && $(THIRDPARTY_HOST_PREFIX)/bin/ct-ng savedefconfig
	cp $(CTNG_BUILDDIR)/defconfig $(mk_dir)/ct-ng-configs/$(ARCH).defconfig

# Build the toolchain with the config in the defconfig for the architecture. We need to
# clear out some env vars because ct-ng does not want them set. We export a couple of
# vars because we reference them in the config.
# The config specifies where the toolchain is installed ($(THIRDPARTY_HOST_PREFIX)/TARGET).
.PHONY: ctng-build
ctng-build: $(CTNG_CONFIG) | $(CTNG_BUILDDIR)
	@mkdir -p $(THIRDPARTY_DLDIR)
	cd $(CTNG_BUILDDIR) && \
		THIRDPARTY_HOST_PREFIX=$(THIRDPARTY_HOST_PREFIX) \
		THIRDPARTY_DLDIR=$(THIRDPARTY_DLDIR) \
		$(THIRDPARTY_HOST_PREFIX)/bin/ct-ng build

# =============================================================================
# clang-12
#
# We need to build clang-12 ourselves because we need a specific version (12.0.0)
# for FIPS compliance. That version of clang is needed to build boringssl
# for use by rust to build rdp-client (via the boring-sys crate).
#
# clang is built for the host system, using the host system compiler, not ctng.

clang_VERSION = 12.0.0
clang_GIT_REF = llvmorg-$(clang_VERSION)
clang_GIT_REF_HASH = d28af7c654d8db0b68c175db5ce212d74fb5e9bc
clang_GIT_REPO = https://github.com/llvm/llvm-project.git
clang_SRCDIR = $(call tp-src-host-dir,clang)

.PHONY: fetch-clang configure-clang install-clang
fetch-clang: fetch-git-clang
configure-clang: fetch-clang
	cd $(clang_SRCDIR) && cmake \
		-DCMAKE_BUILD_TYPE=Release \
		-DCMAKE_INSTALL_PREFIX=$(THIRDPARTY_HOST_PREFIX) \
		-DLLVM_ENABLE_PROJECTS=clang \
		-DLLVM_BUILD_TOOLS=ON \
		-G "Unix Makefiles" llvm
install-clang: configure-clang
	cd $(clang_SRCDIR) && \
		$(MAKE) -j$(NPROC) \
			install-llvm-strip \
			install-clang-format \
			install-clang \
			install-clang-resource-headers \
			install-libclang

# =============================================================================
# Environment setup for building with ctng toolchain
#
# If we have a ctng cross compiler for the target arch, use it unless
# USE_CTNG is `no` or empty.

CTNG_TARGET = $(CTNG_TARGET_$(ARCH))
CTNG_TARGET_amd64 = x86_64-glibc217-linux-gnu
CTNG_TARGET_arm64 = aarch64-glibc217-linux-gnu
CTNG_TARGET_386 = i686-glibc217-linux-gnu
CTNG_TARGET_arm = armv7-glibc217-linux-gnueabi

# The crosstool/toolchain architecture is a little different to the Go
# architecture. It's possible that this is just libpam specific as that
# is all that currently uses this var.
CTNG_ARCH = $(CTNG_ARCH_$(ARCH))
CTNG_ARCH_amd64 = amd64
CTNG_ARCH_arm64 = arm64
CTNG_ARCH_arm = arm
CTNG_ARCH_386 = i686

# CROSS_COMPILE defines the environment variables that need to be set to
# cross compile using crosstool. It defines a set of environment variables
# that prefix a shell command invocation (like FOO=bar cmd, to run cmd with
# $FOO set to "bar"). It prefixes build commands that do cross-compilation.
C_INCLUDE_PATH = $(THIRDPARTY_PREFIX)/include
LIBRARY_PATH = $(THIRDPARTY_PREFIX)/lib
PKG_CONFIG_PATH = $(THIRDPARTY_PREFIX)/lib/pkgconfig

define CROSS_COMPILE
PATH=$(THIRDPARTY_HOST_PREFIX)/$(CTNG_TARGET)/bin:$(PATH) \
CC=$(CTNG_TARGET)-gcc \
CXX=$(CTNG_TARGET)-g++ \
LD=$(CTNG_TARGET)-ld \
C_INCLUDE_PATH=$(C_INCLUDE_PATH) \
LIBRARY_PATH=$(LIBRARY_PATH) \
PKG_CONFIG_PATH=$(PKG_CONFIG_PATH)
endef

# cross-compile can be called with a make target (TARGET=foo) to run that target
# with the cross compilation environment set up.
# currently unused - just an idea that is perhaps not working out.
.PHONY: cross-compile
cross-compile: export PATH = $(THIRDPARTY_HOST_PREFIX)/$(CTNG_TARGET)/bin:$(PATH)
cross-compile: export CC = $(CTNG_TARGET)-gcc
cross-compile: export CXX = $(CTNG_TARGET)-g++
cross-compile: export LD = $(CTNG_TARGET)-ld
cross-compile: export C_INCLUDE_PATH = $(THIRDPARTY_PREFIX)/include
cross-compile: export LIBRARY_PATH = $(THIRDPARTY_PREFIX)/lib
cross-compile: export PKG_CONFIG_PATH = $(THIRDPARTY_PREFIX)/lib/pkgconfig
cross-compile:
	$(MAKE) $(TARGET)

# Old way of setting up environment. It's a bit inflexible and sets it up
# for all targets in the makefile. To be removed.

#ifneq ($(CTNG_TARGET),)
#ifneq ($(wildcard $(THIRDPARTY_HOST_PREFIX)/$(CTNG_TARGET)/bin),)
#ifneq ($(filter-out $(USE_CTNG),no),)

#PATH := $(THIRDPARTY_HOST_PREFIX)/$(CTNG_TARGET)/bin:$(PATH)
#CC = $(CTNG_TARGET)-gcc
#CXX = $(CTNG_TARGET)-g++
#LD = $(CTNG_TARGET)-ld
#CMAKE_LINKER = $(LD)
#export CC CXX LD PATH CMAKE_LINKER

# Set vars used by the toolchain to find include directories and libraries and
# for pkg-config to find third-party configs.
#C_INCLUDE_PATH = $(THIRDPARTY_PREFIX)/include
#LIBRARY_PATH = $(THIRDPARTY_PREFIX)/lib
#PKG_CONFIG_PATH = $(THIRDPARTY_PREFIX)/lib/pkgconfig
#export C_INCLUDE_PATH LIBRARY_PATH PKG_CONFIG_PATH

#TARGET_BORING_BSSL_FIPS_SYSROOT = $(THIRDPARTY_HOST_PREFIX)/$(CTNG_TARGET)/$(CTNG_TARGET)/sysroot
#HOST_BORING_BSSL_FIPS_SYSROOT = $(THIRDPARTY_HOST_PREFIX)/$(CTNG_TARGET)/$(CTNG_TARGET)/sysroot
#CMAKE_SYSROOT = $(THIRDPARTY_HOST_PREFIX)/$(CTNG_TARGET)/$(CTNG_TARGET)/sysroot
#CMAKE_FIND_ROOT_PATH = $(THIRDPARTY_HOST_PREFIX)/$(CTNG_TARGET)/$(CTNG_TARGET)/sysroot
#CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER = $(CXX)
#export TARGET_BORING_BSSL_FIPS_SYSROOT
#export HOST_BORING_BSSL_FIPS_SYSROOT
#export CMAKE_SYSROOT
#export CMAKE_FIND_ROOT_PATH
#export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER

#endif
#endif
#endif

# =============================================================================
# Building Teleport
#
# These are temporary targets during development of this makefile. Once complete,
# the targets in build.assets/Makefile will do the teleport build.

FEATURES_amd64 = PIV=yes FIDO2=yes
FEATURES_arm64 = PIV=yes FIDO2=yes
FEATURES_386 =
FEATURES_arm =
BUILD_FEATURES = $(FEATURES_$(ARCH))

.PHONY: build-teleport
build-teleport:
	$(MAKE) -C $(mk_dir) \
		OS=linux ARCH=$(ARCH) CGO_ENABLED=1 $(BUILD_FEATURES) BUILDDIR=$(BUILDDIR) \
		release

.PHONY: build-teleport-oss
build-teleport-oss: BUILDDIR = build/$(ARCH)/oss
build-teleport-oss: mk_dir = ..
build-teleport-oss: build-teleport

.PHONY: build-teleport-ent
build-teleport-ent: BUILDDIR = ../build/$(ARCH)/ent
build-teleport-ent: mk_dir = ../e
build-teleport-ent: build-teleport

.PHONY: build-teleport-fips
build-teleport-fips: BUILDDIR = ../build/$(ARCH)/fips
build-teleport-fips: BUILD_FEATURES += FIPS=yes
build-teleport-fips: export GOEXPERIMENT = boringcrypto
build-teleport-fips: export OPENSSL_FIPS = 1
build-teleport-fips: build-teleport-ent

.PHONY: build-rdp
build-rdp: BUILDDIR = ../build/$(ARCH)/fips
build-rdp: BUILD_FEATURES += FIPS=yes
build-rdp: export GOEXPERIMENT = boringcrypto
build-rdp: export OPENSSL_FIPS = 1
build-rdp: mk_dir = ..
build-rdp:
	echo $${CMAKE_SYSROOT}
	$(CROSS_COMPILE) $(MAKE) -C $(mk_dir) \
		OS=linux ARCH=$(ARCH) CGO_ENABLED=1 $(BUILD_FEATURES) BUILDDIR=$(BUILDDIR) \
		rdpclient

# =============================================================================
# Third-party libraries needed to build Teleport.
#
# We build these libraries ourself and statically link them into the Teleport
# binary as we need them build with PIE (Position Independent Executable) mode
# so as to make use of ASLR (Address Space Layout Randomization). We cannot
# rely on a host OS/packager to have built them this way.

THIRDPARTY_LIBS = zlib zstd libelf libbpf libtirpc libpam libudev_zero \
		  libcbor openssl libfido2 libpcsclite

.PHONY: thirdparty-build-libs tp-build-all
thirdparty-build-libs: $(addprefix tp-build-,$(THIRDPARTY_LIBS))
tp-build-all: thirdparty-build-libs

# -----------------------------------------------------------------------------
# zlib

zlib_VERSION = 1.3.1
zlib_GIT_REF = v$(zlib_VERSION)
zlib_GIT_REF_HASH = 51b7f2abdade71cd9bb0e7a373ef2610ec6f9daf
zlib_GIT_REPO = https://github.com/madler/zlib
zlib_SRCDIR = $(call tp-src-dir,zlib)

.PHONY: tp-build-zlib
tp-build-zlib: fetch-git-zlib
	cd $(zlib_SRCDIR) && \
		$(CROSS_COMPILE) ./configure --prefix="$(THIRDPARTY_PREFIX)" --static
	$(CROSS_COMPILE) $(MAKE) -C $(zlib_SRCDIR) CFLAGS+=-fPIE -j$(NPROC)
	$(CROSS_COMPILE) $(MAKE) -C $(zlib_SRCDIR) install

# -----------------------------------------------------------------------------
# zstd

zstd_VERSION = 1.5.6
zstd_GIT_REF = v$(zstd_VERSION)
zstd_GIT_REF_HASH = 794ea1b0afca0f020f4e57b6732332231fb23c70
zstd_GIT_REPO = https://github.com/facebook/zstd
zstd_SRCDIR = $(call tp-src-dir,zstd)

.PHONY: tp-build-zstd
tp-build-zstd: fetch-git-zstd
	$(CROSS_COMPILE) $(MAKE) -C $(zstd_SRCDIR) CPPFLAGS_STATICLIB+=-fPIE -j$(NPROC)
	$(CROSS_COMPILE) $(MAKE) -C $(zstd_SRCDIR) install PREFIX=$(THIRDPARTY_PREFIX)

# -----------------------------------------------------------------------------
# libelf

libelf_VERSION = 0.191
libelf_GIT_REF = v$(libelf_VERSION)
libelf_GIT_REF_HASH = b80c36da9d70158f9a38cfb9af9bb58a323a5796
libelf_GIT_REPO = https://github.com/arachsys/libelf
libelf_SRCDIR = $(call tp-src-dir,libelf)

.PHONY: tp-build-libelf
tp-build-libelf: fetch-git-libelf
	$(CROSS_COMPILE) $(MAKE) -C $(libelf_SRCDIR) CFLAGS+=-fPIE -j$(NPROC) libelf.a
	$(CROSS_COMPILE) $(MAKE) -C $(libelf_SRCDIR) install-headers install-static PREFIX=$(THIRDPARTY_PREFIX)

# -----------------------------------------------------------------------------
# libbpf

libbpf_VERSION = 1.4.0
libbpf_GIT_REF = v$(libbpf_VERSION)
libbpf_GIT_REF_HASH = 20ea95b4505c477af3b6ff6ce9d19cee868ddc5d
libbpf_GIT_REPO = https://github.com/libbpf/libbpf
libbpf_SRCDIR = $(call tp-src-dir,libbpf)

.PHONY: tp-build-libbpf
tp-build-libbpf: fetch-git-libbpf
	$(CROSS_COMPILE) $(MAKE) -C $(libbpf_SRCDIR)/src \
		BUILD_STATIC_ONLY=y EXTRA_CFLAGS=-fPIE PREFIX=$(THIRDPARTY_PREFIX) LIBSUBDIR=lib V=1 \
		install install_uapi_headers

# -----------------------------------------------------------------------------
# libtirpc

libtirpc_VERSION = 1.3.4
libtirpc_SHA1 = 63c800f81f823254d2706637bab551dec176b99b
libtirpc_DOWNLOAD_URL = https://zenlayer.dl.sourceforge.net/project/libtirpc/libtirpc/$(libtirpc_VERSION)/libtirpc-$(libtirpc_VERSION).tar.bz2
libtirpc_STRIP_COMPONENTS = 1
libtirpc_SRCDIR = $(call tp-src-dir,libtirpc)

.PHONY: tp-build-libtirpc
tp-build-libtirpc: fetch-https-libtirpc
	cd $(libtirpc_SRCDIR) && \
		$(CROSS_COMPILE) CFLAGS=-fPIE ./configure \
		--prefix=$(THIRDPARTY_PREFIX) \
		--enable-shared=no \
		--disable-gssapi \
		$(if $(CTNG_TARGET),--host=$(CTNG_TARGET))
	$(CROSS_COMPILE) $(MAKE) -C $(libtirpc_SRCDIR) -j$(NPROC)
	$(CROSS_COMPILE) $(MAKE) -C $(libtirpc_SRCDIR) install

# -----------------------------------------------------------------------------
# libpam

libpam_VERSION = 1.6.1
libpam_GIT_REF = v$(libpam_VERSION)
libpam_GIT_REF_HASH = 9438e084e2b318bf91c3912c0b8ff056e1835486
libpam_GIT_REPO = https://github.com/linux-pam/linux-pam
libpam_SRCDIR = $(call tp-src-dir,libpam)

.PHONY: tp-build-libpam
tp-build-libpam: fetch-git-libpam
	cd $(libpam_SRCDIR) && \
		$(CROSS_COMPILE) ./autogen.sh
	cd $(libpam_SRCDIR) && \
		$(CROSS_COMPILE) CFLAGS=-fPIE ./configure --prefix=$(THIRDPARTY_PREFIX) \
		--disable-doc --disable-examples \
		--includedir=$(THIRDPARTY_PREFIX)/include/security \
		$(if $(CTNG_ARCH),--host=$(CTNG_ARCH))
	$(CROSS_COMPILE) $(MAKE) -C $(libpam_SRCDIR) -j$(NPROC)
	$(CROSS_COMPILE) $(MAKE) -C $(libpam_SRCDIR) install

# -----------------------------------------------------------------------------
# libudev-zero

libudev_zero_VERSION = 1.0.3
libudev_zero_GIT_REF = $(libudev_zero_VERSION)
libudev_zero_GIT_REF_HASH = ee32ac5f6494047b9ece26e7a5920650cdf46655
libudev_zero_GIT_REPO = https://github.com/illiliti/libudev-zero
libudev_zero_SRCDIR = $(call tp-src-dir,libudev_zero)

.PHONY: tp-build-libudev_zero
tp-build-libudev_zero: fetch-git-libudev_zero
	$(CROSS_COMPILE) $(MAKE) -C $(libudev_zero_SRCDIR) \
		PREFIX=$(THIRDPARTY_PREFIX) \
		install-static -j$(NPROC)

# -----------------------------------------------------------------------------
# libcbor

libcbor_VERSION = 0.10.2
libcbor_GIT_REF = v$(libcbor_VERSION)
libcbor_GIT_REF_HASH = efa6c0886bae46bdaef9b679f61f4b9d8bc296ae
libcbor_GIT_REPO = https://github.com/PJK/libcbor
libcbor_SRCDIR = $(call tp-src-dir,libcbor)

.PHONY: tp-build-libcbor
tp-build-libcbor: fetch-git-libcbor
	cd $(libcbor_SRCDIR) && \
		$(CROSS_COMPILE) cmake \
		-DCMAKE_INSTALL_PREFIX=$(THIRDPARTY_PREFIX) \
		-DCMAKE_POSITION_INDEPENDENT_CODE=ON \
		-DCMAKE_BUILD_TYPE=Release \
		-DWITH_EXAMPLES=OFF \
		.
	$(CROSS_COMPILE) $(MAKE) -C $(libcbor_SRCDIR) -j$(NPROC)
	$(CROSS_COMPILE) $(MAKE) -C $(libcbor_SRCDIR) install

# -----------------------------------------------------------------------------
# openssl

openssl_VERSION = 3.0.13
openssl_GIT_REF = openssl-$(openssl_VERSION)
openssl_GIT_REF_HASH = 85cf92f55d9e2ac5aacf92bedd33fb890b9f8b4c
openssl_GIT_REPO = https://github.com/openssl/openssl
openssl_SRCDIR = $(call tp-src-dir,openssl)

openssl_TARGET_linux_amd64 = linux-x86_64
openssl_TARGET_linux_arm64 = linux-aarch64
openssl_TARGET_linux_386 = linux-x86
#openssl_TARGET_linux_arm = linux-generic32
openssl_TARGET_linux_arm = linux-armv4
openssl_TARGET = $(or $(openssl_TARGET_linux_$(ARCH)),$(error Unsupported ARCH ($(ARCH)) for openssl))

.PHONY: tp-build-openssl
tp-build-openssl: fetch-git-openssl
	cd $(openssl_SRCDIR) && \
		$(CROSS_COMPILE) ./config "$(openssl_TARGET)" enable-fips --release -fPIC no-shared \
		--prefix=$(THIRDPARTY_PREFIX) \
		--libdir=$(THIRDPARTY_PREFIX)/lib
	$(CROSS_COMPILE) $(MAKE) -C $(openssl_SRCDIR) -j$(NPROC)
	$(CROSS_COMPILE) $(MAKE) -C $(openssl_SRCDIR) install_sw install_ssldirs install_fips
	sed "s|@@PREFIX@@|${THIRDPARTY_PREFIX}|" \
		< pkgconfig/crosstool/libcrypto-static.pc \
		> $(PKG_CONFIG_PATH)/libcrypto-static.pc

# -----------------------------------------------------------------------------
# libfido2

libfido2_VERSION = 1.14.0
libfido2_GIT_REF = $(libfido2_VERSION)
libfido2_GIT_REF_HASH = 1a9d335c8f0e821f9eff27482fdda96e59a4f577
libfido2_GIT_REPO = https://github.com/Yubico/libfido2
libfido2_SRCDIR = $(call tp-src-dir,libfido2)

.PHONY: tp-build-libfido2
tp-build-libfido2: fetch-git-libfido2
	cd $(libfido2_SRCDIR) && \
		$(CROSS_COMPILE) cmake \
		-DCMAKE_C_FLAGS="-ldl -pthread" \
		-DBUILD_SHARED_LIBS=OFF \
		-DCMAKE_INSTALL_PREFIX=$(THIRDPARTY_PREFIX) \
		-DCMAKE_POSITION_INDEPENDENT_CODE=ON \
		-DCMAKE_BUILD_TYPE=Release \
		-DBUILD_EXAMPLES=OFF \
		-DBUILD_MANPAGES=OFF \
		-DBUILD_TOOLS=OFF \
		.
	$(CROSS_COMPILE) $(MAKE) -C $(libfido2_SRCDIR) -j$(NPROC)
	$(CROSS_COMPILE) $(MAKE) -C $(libfido2_SRCDIR) install
	sed "s|@@PREFIX@@|${THIRDPARTY_PREFIX}|" \
		< pkgconfig/crosstool/libfido2-static.pc \
		> $(PKG_CONFIG_PATH)/libfido2-static.pc

# -----------------------------------------------------------------------------
# libpcsclite
#
# Needed fir PIV support in teleport and tsh

libpcsclite_VERSION = 1.9.9-teleport
libpcsclite_GIT_REF = $(libpcsclite_VERSION)
libpcsclite_GIT_REF_HASH = eb815b51504024c2218471736ba651cef147f368
libpcsclite_GIT_REPO = https://github.com/gravitational/PCSC
libpcsclite_SRCDIR = $(call tp-src-dir,libpcsclite)

.PHONY: tp-build-libpcsclite
tp-build-libpcsclite: fetch-git-libpcsclite
	cd $(libpcsclite_SRCDIR) && $(CROSS_COMPILE) ./bootstrap
	cd $(libpcsclite_SRCDIR) && $(CROSS_COMPILE) ./configure \
		$(if $(CTNG_TARGET),--target=$(CTNG_TARGET)) \
		$(if $(CTNG_TARGET),--host=$(CTNG_TARGET)) \
		--prefix="$(THIRDPARTY_PREFIX)" \
		--enable-static --with-pic \
		--disable-libsystemd --with-systemdsystemunitdir=no
	$(CROSS_COMPILE) $(MAKE) -C $(libpcsclite_SRCDIR)/src -j$(NPROC) PROGRAMS= all
	$(CROSS_COMPILE) $(MAKE) -C $(libpcsclite_SRCDIR)/src PROGRAMS= install

# -----------------------------------------------------------------------------
# Helpers

tp-clean-%:
	-rm -rf $(call tp-src-dir,$*)
	-$(if $(tp-download-url),rm $(tp-download-filename))

# Create top-level directories when required
$(THIRDPARTY_SRCDIR) $(THIRDPARTY_HOST_SRCDIR) $(THIRDPARTY_DLDIR):
	mkdir -p $@

# vars for fetch-git-%. `$*` represents the `%` match.
tp-git-ref = $($*_GIT_REF)
tp-git-repo = $($*_GIT_REPO)
tp-git-ref-hash = $($*_GIT_REF_HASH)
tp-git-src-dir = $($*_SRCDIR)
define tp-git-fetch-cmd
	git -C "$(dir $(tp-git-src-dir))" \
		-c advice.detachedHead=false clone --depth=1 \
		--branch=$(tp-git-ref) $(tp-git-repo) "$(tp-git-src-dir)"
endef

# Fetch source via git.
fetch-git-%:
	mkdir -p $(dir $(tp-git-src-dir))
	$(if $(wildcard $(tp-git-src-dir)),,$(tp-git-fetch-cmd))
	@if [ "$$(git -C "$(tp-git-src-dir)" rev-parse HEAD)" != "$(tp-git-ref-hash)" ]; then \
		echo "Found unexpected HEAD commit for $(1)"; \
		echo "Expected: $(tp-git-ref-hash)"; \
		echo "Got: $$(git -C "$(tp-git-src-dir)" rev-parse HEAD)"; \
		exit 1; \
	fi

# vars for fetch-https-%. `$*` represents the `%` match.
tp-download-url = $($*_DOWNLOAD_URL)
tp-sha1 = $($*_SHA1)
tp-download-filename = $(THIRDPARTY_DLDIR)/$(notdir $(tp-download-url))
tp-strip-components = $($*_STRIP_COMPONENTS)
tp-https-download-cmd = curl -fsSL --output "$(tp-download-filename)" "$(tp-download-url)"
tp-https-src-dir = $(call tp-src-dir,$*)
define tp-https-extract-tar-cmd
	@echo "$(tp-sha1)  $(tp-download-filename)" | sha1sum --check
	mkdir -p "$(tp-https-src-dir)"
	tar -x -a \
		--file="$(tp-download-filename)" \
		--directory="$(tp-https-src-dir)" \
		--strip-components="$(tp-strip-components)"
endef

# Fetch source tarball via https
fetch-https-%:
	@mkdir -p $(THIRDPARTY_DLDIR) $(dir $(tp-https-src-dir))
	$(if $(wildcard $(tp-download-filename)),,$(tp-https-download-cmd))
	$(if $(wildcard $(tp-https-src-dir)),,$(tp-https-extract-tar-cmd))

diagnose:
	@echo mk_dir = $(mk_dir)
	@echo BUILDDIR = $(BUILDDIR)
	@echo THIRDPARTY_DIR = $(THIRDPARTY_DIR)
	@echo THIRDPARTY_DLDIR = $(THIRDPARTY_DLDIR)
	@echo THIRDPARTY_PREFIX = $(THIRDPARTY_PREFIX)
	@echo THIRDPARTY_SRCDIR = $(THIRDPARTY_SRCDIR)
	@echo THIRDPARTY_HOST_PREFIX = $(THIRDPARTY_HOST_PREFIX)
	@echo THIRDPARTY_HOST_SRCDIR = $(THIRDPARTY_HOST_SRCDIR)
	@echo CTNG_TARGET = $(CTNG_TARGET)
	@echo PATH = $(PATH)

tp-clean-%:
	cd $($*_SRCDIR) && $(MAKE) clean

tp-sh-%:
	cd $($*_SRCDIR) && bash
