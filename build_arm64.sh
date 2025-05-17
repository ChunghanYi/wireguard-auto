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

build_it()
{
	WGAC_PATH=$(pwd)
	if [ $1 = "release" ]; then
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

		if [ ! -d ./external/boost_1_88_0 ]; then
			cd external
			if [ ! -r boost_1_88_0.tar.gz ]; then
				wget https://archives.boost.io/release/1.88.0/source/boost_1_88_0.tar.gz
			fi
			tar xvzf boost_1_88_0.tar.gz > /dev/null 2>&1
			cd boost_1_88_0
			cp ../misc/user-config.jam . > /dev/null 2>&1
			./bootstrap.sh
			./b2 toolset=gcc-arm64 target-os=linux --user-config=user-config.jam --without-context --without-coroutine --without-python -threading=multi

			cd $WGAC_PATH
		fi

		if [ ! -d ./external/libsodium-stable ]; then
			cd external
			if [ ! -r libsodium-1.0.20-stable.tar.gz ]; then
				wget https://download.libsodium.org/libsodium/releases/libsodium-1.0.20-stable.tar.gz
			fi
			tar xvzf libsodium-1.0.20-stable.tar.gz > /dev/null 2>&1
			cd libsodium-stable
			mkdir -p output
			./configure --host=aarch64-openwrt-linux-musl --prefix=$(pwd)/output
			make clean; make
			make install
			cd $WGAC_PATH
        fi

		if [ ! -d ./external/hiredis-1.3.0 ]; then
			cd external
			if [ ! -r hiredis-1.3.0.tar.gz ]; then
				rm -f ./v1.3.0.tar.gz* > /dev/null 2>&1
				wget https://github.com/redis/hiredis/archive/refs/tags/v1.3.0.tar.gz
				mv v1.3.0.tar.gz hiredis-1.3.0.tar.gz > /dev/null 2>&1
			fi
			tar xvzf hiredis-1.3.0.tar.gz > /dev/null 2>&1
			cd hiredis-1.3.0
			mkdir -p build > /dev/null 2>&1
			cd build; cmake ..
			make
			#make install
			cp -r libhiredis.so* ../../lib > /dev/null 2>&1
			mkdir -p ../../lib/include/hiredis > /dev/null 2>&1
			cp -r ../*.h ../../lib/include/hiredis > /dev/null 2>&1
			cd $WGAC_PATH
		fi

		if [ -d ./lib/wg-tools ]; then
			cd ./lib/wg-tools
			make -f ./Makefile.arm64 clean
			make -f ./Makefile.arm64 target=linux
			cd $WGAC_PATH
		fi

		#for wg autoconnect client/server
		if [ ! -d ./build ]; then
			mkdir -p build
		fi
		cd build
		cmake .. && make

	elif [ $1 = "clean" ]; then
		rm -rf ./build > /dev/null 2>&1
		rm -rf ./external/lib > /dev/null 2>&1
		rm -rf ./external/spdlog > /dev/null 2>&1
		rm -rf ./external/boost_1_88_0 > /dev/null 2>&1
		rm -rf ./external/libsodium-stable > /dev/null 2>&1
		rm -rf ./external/hiredis-1.3.0 > /dev/null 2>&1
	fi
}

start_now()
{
	if [ $# -eq 0 ]; then
		echo "Usage: $0 release|clean"
		exit 0
	fi
	build_it $1
}

start_now $1
