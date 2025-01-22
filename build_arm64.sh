#!/bin/sh

# Copyright (c) 2025 Chunghan Yi <chunghan.yi@gmail.com>
# SPDX-License-Identifier: MIT

#YOUR_LOCAL_PATH=XXX
#TOOLCHAIN_PATH=$YOUR_LOCAL_PATH/friendlywrt23-rk3568/friendlywrt/staging_dir/toolchain-aarch64_generic_gcc-12.3.0_musl/bin

export PATH=$TOOLCHAIN_PATH:$PATH
export STAGING_DIR=$TOOLCHAIN_PATH/..

export CC=aarch64-openwrt-linux-musl-gcc
export CPP=aarch64-openwrt-linux-musl-g++
export AR=aarch64-openwrt-linux-musl-ar
export RANLIB=aarch64-openwrt-linux-musl-ranlib

if [ -d ./build ]; then
	rm -rf ./build > /dev/null 2>&1
	if [ -d ./external/spdlog ]; then
		rm -rf ./external > /dev/null 2>&1
	fi
fi

WGAC_PATH=$(pwd)
if [ ! -d ./external/spdlog ]; then
	mkdir -p external > /dev/null 2>&1
	cd external
	git clone https://github.com/gabime/spdlog
	cd spdlog
	mkdir build && cd build

	cmake -DCMAKE_SYSTEM_NAME=Linux -DCMAKE_SYSTEM_PROCESSOR=arm64v8 \
		-DCMAKE_CXX_COMPILER=$TOOLCHAIN_PATH/aarch64-openwrt-linux-musl-g++ \
		..
	make

	if [ ! -d $WGAC_PATH/external/lib ]; then
		mkdir $WGAC_PATH/external/lib > /dev/null 2>&1
	fi
	cp ./libspdlog.a ../../lib > /dev/null 2>&1
	cd ..
	cp -R ./include ../lib > /dev/null 2>&1
	cd $WGAC_PATH
fi

if [ ! -d ./build ]; then
	mkdir -p build
fi
cd build
cmake .. && make
