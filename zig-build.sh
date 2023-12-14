#!/bin/bash

set -e

# Works only with zig 0.11 due to https://github.com/ziglang/zig/issues/18009

# All build have PAM disabled due to includes macro redefinition (it can probably be fixed)
# ARM64 build without BPF as I don't have arm64 version of libbpf.

# Get the x86_64 build root
CONT_ID=$(docker run -d public.ecr.aws/gravitational/teleport-buildbox-centos7:teleport15)
docker export ${CONT_ID} -o centos7.tar

mkdir -p buildroot
cd buildroot && tar xvf ../centos7.tar && cd ..

# Clean the docker container
docker export ${CONT_ID} -o centos7.tar
docker stop ${CONT_ID}
docker rm ${CONT_ID}

# Build the project
CC="zig cc -target x86_64-linux-gnu.2.17 -lunwind -L$(pwd)/buildroot/usr/lib64/ --sysroot=$(pwd)/buildroot" CXX="zig c++ -target x86_64-linux-gnu.2.17 -lunwind --sysroot=$(pwd)/buildroot" make

mv build build_x86_64

# aarch64-linux-gnu
# Install rust for aarch64
# rustup target add aarch64-unknown-linux-gnu

# tsh doesn't build with zig yet; reason https://github.com/golang/go/issues/22040
CC="zig cc -target aarch64-linux-gnu.2.17 -lunwind" CXX="zig c++ -target aarch64-linux-gnu.2.17 -lunwind" GOARCH=arm64 RUST_TARGET_ARCH=aarch64-unknown-linux-gnu make build/teleport
CC="zig cc -target aarch64-linux-gnu.2.17 -lunwind" CXX="zig c++ -target aarch64-linux-gnu.2.17 -lunwind" GOARCH=arm64 RUST_TARGET_ARCH=aarch64-unknown-linux-gnu make build/tctl
CC="zig cc -target aarch64-linux-gnu.2.17 -lunwind" CXX="zig c++ -target aarch64-linux-gnu.2.17 -lunwind" GOARCH=arm64 RUST_TARGET_ARCH=aarch64-unknown-linux-gnu make build/tbot

mv build build_aarch64

# armeb-linux-gnueabihf

CC="zig cc -target arm-linux-gnueabihf.2.17" CXX="zig c++ -target arm-linux-gnueabihf.2.17" GOARCH=arm make

mv build build_arm

# Zig doesn't support i386 yet https://github.com/ziglang/zig/issues/1929