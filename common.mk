# Common makefile shared between Teleport OSS and Ent.

# -----------------------------------------------------------------------------
# libbpf detection
#
# Requirements for building with BFP support:
# * clang and llvm-strip programs
# * linux on amd64 or amd64
# * libbpf (the bpf/bpf.h header file)
#   * The centos7 buildbox puts this in /usr/libbpf-1.2.2
#   * The ng buildbox puts this on C_INCLUDE_PATH
#   * Native/local builds has this at /usr/include
# * Either using a cross-compiling buildbox or is a native build
#
# The default is without BPF support unless all the critera are met.
#
# TODO(camh): Remove /usr/libbpf-1.2.2 when old buildboxes are replaced by ng

with_bpf := no
BPF_MESSAGE := without-BPF-support

CLANG ?= $(shell which clang || which clang-12)
LLVM_STRIP ?= $(shell which llvm-strip || which llvm-strip-12)

# libbpf version required by the build.
LIBBPF_VER := 1.2.2

LIBBPF_HEADER_CANDIDATES := $(subst :, ,$(C_INCLUDE_PATH)) /usr/libbpf-$(LIBBPF_VER)/include /usr/include
LIBBPF_H := $(firstword $(wildcard $(addsuffix /bpf/bpf.h,$(LIBBPF_HEADER_CANDIDATES))))

# Is this build targeting the same OS & architecture it is being compiled on, or
# will it require cross-compilation? We need to know this (especially for ARM) so we
# can set the cross-compiler path (and possibly feature flags) correctly.
IS_NATIVE_BUILD ?= $(filter $(ARCH),$(shell go env GOARCH))
IS_CROSS_COMPILE_BB = $(filter $(BUILDBOX_MODE),cross)

# Only build with BPF if clang and llvm-strip are installed.
ifneq (,$(and $(CLANG),$(LLVM_STRIP)))

# Only build with BPF for linux/amd64 and linux/arm64.
# Other builds have compilation issues that require fixing.
ifneq (,$(filter $(OS)/$(ARCH),linux/amd64 linux/arm64))

# Only build with BPF if we found the bpf.h header file
ifneq (,$(LIBBPF_H))

# Only build with BPF if its a native build or in a cross-compiling buildbox.
ifneq (,$(or $(IS_NATIVE_BUILD),$(IS_CROSS_COMPILE_BB)))

with_bpf := yes
BPF_TAG := bpf
BPF_MESSAGE := with-BPF-support
KERNEL_ARCH := $(shell uname -m | sed 's/x86_64/x86/g; s/aarch64/arm64/g')
ER_BPF_BUILDDIR := lib/bpf/bytecode
BPF_INCLUDES := -I/usr/libbpf-$(LIBBPF_VER)/include

# Get Clang's default includes on this system. We'll explicitly add these dirs
# to the includes list when compiling with `-target bpf` because otherwise some
# architecture-specific dirs will be "missing" on some architectures/distros -
# headers such as asm/types.h, asm/byteorder.h, asm/socket.h, asm/sockios.h,
# sys/cdefs.h etc. might be missing.
#
# Use '-idirafter': Don't interfere with include mechanics except where the
# build would have failed anyways.
CLANG_BPF_SYS_INCLUDES = $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

# Add library path for CentOS 7 buildbox.
# TODO(camh): Remove when that buildbox is decomissioned.
STATIC_LIBS += -L/usr/libbpf-${LIBBPF_VER}/lib64/

# gcc does not use LIBRARY_PATH when cross-compiling, so explicitly add those
# paths to the linker command line.
STATIC_LIBS += $(addprefix -L,$(subst :, ,$(LIBRARY_PATH)))

# Libraries needed for or by BPF
STATIC_LIBS += -lbpf -lelf -lz

# Link static version of libraries required by Teleport (bpf, pcsc) to reduce
# system dependencies. Avoid dependencies on dynamic libraries if we already
# link the static version using --as-needed.
CGOFLAG = CGO_ENABLED=1 CGO_CFLAGS="$(BPF_INCLUDES)" CGO_LDFLAGS="-Wl,-Bstatic $(STATIC_LIBS) -Wl,-Bdynamic -Wl,--as-needed"
CGOFLAG_TSH = CGO_ENABLED=1 CGO_LDFLAGS="-Wl,-Bstatic $(STATIC_LIBS_TSH) -Wl,-Bdynamic -Wl,--as-needed"

endif # IS_NATIVE_BUILD || IS_CROSS_COMPILE_BB
endif # bpf/bpf.h found
endif # OS/ARCH == linux/amd64 OR linux/arm64
endif # clang and llvm-strip found

.PHONY: diag-bpf-vars
diag-bpf-vars:
	@echo clang: $(CLANG)
	@echo llvm-strip: $(LLVM_STRIP)
	@echo os/arch: $(OS)-$(ARCH)
	@echo bpf.h: $(LIBBPF_H)
	@echo is-native: $(IS_NATIVE_BUILD)
	@echo is-cross: $(IS_CROSS_COMPILE_BB)
	@echo buildbox-mode: $(BUILDBOX_MODE)
