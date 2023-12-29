# Common makefile shared between Teleport OSS and Ent.

# Is this build targeting the same OS & architecture it is being compiled on, or
# will it require cross-compilation? We need to know this (especially for ARM) so we
# can set the cross-compiler path (and possibly feature flags) correctly.
IS_NATIVE_BUILD ?= $(if $(filter $(ARCH), $(shell go env GOARCH)),"yes","no")

# BPF support will only be built into Teleport if headers exist at build time.
BPF_MESSAGE := without-BPF-support

# We don't compile BPF for anything except linux/amd64 and linux/arm64 for now,
# as other builds have compilation issues that require fixing.
with_bpf := no
ifeq ("$(OS)","linux")
# True if $ARCH == amd64 || $ARCH == arm64
ifneq (,$(filter "$(ARCH)","amd64" "arm64"))
# We only support BPF in native builds
ifeq ($(IS_NATIVE_BUILD),"yes")
with_bpf := yes
BPF_TAG := bpf
BPF_MESSAGE := with-BPF-support
CLANG ?= $(shell which clang || which clang-12)
INCLUDES :=

# Link static version of libraries required by Teleport (pcsc) to reduce system dependencies. Avoid dependencies on dynamic libraries if we already link the static version using --as-needed.
CGOFLAG = CGO_ENABLED=1 CGO_LDFLAGS="-Wl,-Bstatic $(STATIC_LIBS) -Wl,-Bdynamic -Wl,--as-needed"
CGOFLAG_TSH = CGO_ENABLED=1 CGO_LDFLAGS="-Wl,-Bstatic $(STATIC_LIBS_TSH) -Wl,-Bdynamic -Wl,--as-needed"
endif # IS_NATIVE_BUILD == yes
endif # ARCH == amd64 OR arm64
endif # OS == linux
